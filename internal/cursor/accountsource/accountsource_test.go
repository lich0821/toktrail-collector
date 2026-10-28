package accountsource

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/protocol"
)

// Synthetic placeholders only: no real device, secret or server is ever
// read from the environment.
const (
	testDeviceID     = "dev-cursor-test-1"
	testDeviceSecret = "synthetic-device-secret-0123456789abcdef"
	// marker is untrusted server free text; it must never surface in any
	// collector error.
	marker = "UNTRUSTED-SERVER-FREETEXT-71af"
)

func testOptions(serverURL string) Options {
	return Options{
		ServerURL:       serverURL,
		DeviceID:        testDeviceID,
		DeviceSecret:    testDeviceSecret,
		ConsentRevision: 7,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errorEnvelope(code string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": marker}}
}

func TestEnableSendsDeviceAuthConsentRevisionAndSourceType(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"ok", http.StatusOK},
		{"created", http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method %s", r.Method)
				}
				if r.URL.Path != "/v1/account-sources/enable" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer "+testDeviceID+"."+testDeviceSecret {
					t.Errorf("unexpected Authorization header %q", got)
				}
				if got := r.Header.Get("X-Consent-Revision"); got != "7" {
					t.Errorf("unexpected X-Consent-Revision header %q", got)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("unexpected Content-Type header %q", got)
				}
				var body struct {
					SourceType string `json:"sourceType"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode body: %v", err)
				}
				if body.SourceType != protocol.SourceType {
					t.Errorf("unexpected sourceType %q", body.SourceType)
				}
				writeJSON(w, tc.status, map[string]any{"source": map[string]any{
					"sourceInstanceId": "src-inst-9",
					"sourceType":       protocol.SourceType,
					"state":            "active",
					"fenceVersion":     3,
					"nextRevision":     41,
				}})
			}))
			defer server.Close()
			src, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
			if err != nil {
				t.Fatal(err)
			}
			if src.SourceInstanceID != "src-inst-9" || src.SourceType != protocol.SourceType || src.State != "active" || src.FenceVersion != 3 || src.NextRevision != 41 {
				t.Fatalf("unexpected source: %#v", src)
			}
		})
	}
}

// A 409 means another device owns the executor slot: the collector
// surfaces the conflict and never retries or takes over.
func TestEnableExecutorConflictIsNeverTakenOver(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeJSON(w, http.StatusConflict, errorEnvelope("source_executor_mismatch"))
	}))
	defer server.Close()
	_, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
	if err == nil {
		t.Fatal("expected an executor conflict error")
	}
	if !errors.Is(err, ErrExecutorConflict) {
		t.Fatalf("expected ErrExecutorConflict, got %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("the collector must send exactly one enable request, sent %d", got)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error echoes untrusted server message: %v", err)
	}
	if strings.Contains(err.Error(), testDeviceSecret) {
		t.Fatalf("error leaks the device secret: %v", err)
	}
}

func TestEnableRejectsErrorsWithoutEchoingServerMessage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   any
	}{
		{"unauthorized", http.StatusUnauthorized, errorEnvelope("unauthorized")},
		{"device revoked", http.StatusForbidden, errorEnvelope("device_revoked")},
		{"server error", http.StatusInternalServerError, errorEnvelope("internal_error")},
		{"store unavailable", http.StatusServiceUnavailable, errorEnvelope("store_unavailable")},
		{"ok without source", http.StatusOK, map[string]any{"source": nil}},
		{"ok with empty source id", http.StatusOK, map[string]any{"source": map[string]any{"sourceInstanceId": "  "}}},
		{"ok with malformed json", http.StatusOK, json.RawMessage("{not json")},
		{"conflict with empty body", http.StatusConflict, map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, tc.body)
			}))
			defer server.Close()
			src, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
			if err == nil {
				t.Fatalf("expected an error, got source %#v", src)
			}
			if tc.status == http.StatusConflict && !errors.Is(err, ErrExecutorConflict) {
				t.Fatalf("expected ErrExecutorConflict, got %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error echoes untrusted server message: %v", err)
			}
			if strings.Contains(err.Error(), testDeviceSecret) {
				t.Fatalf("error leaks the device secret: %v", err)
			}
		})
	}
}

func TestEnableDoesNotFollowRedirect(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect target received the Authorization header")
		}
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer server.Close()
	_, err := Enable(t.Context(), testOptions(server.URL), protocol.SourceType)
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if hit.Load() {
		t.Fatal("the redirect was followed")
	}
	if strings.Contains(err.Error(), testDeviceSecret) {
		t.Fatalf("error leaks the device secret: %v", err)
	}
}

// capabilitiesDoc mirrors the real GET /v1/capabilities response shape.
func capabilitiesDoc(features ...string) map[string]any {
	return map[string]any{
		"service":         "toktrail-server",
		"version":         "test",
		"protocolVersion": 1,
		"maxBatchRecords": 500,
		"maxBodyBytes":    1 << 20,
		"timeZone":        "Asia/Shanghai",
		"features":        features,
	}
}

func TestRequireCapabilityAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device bool
	}{
		{"with device credentials", true},
		{"without device credentials", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method %s", r.Method)
				}
				if r.URL.Path != "/v1/capabilities" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
				}
				if len(body) != 0 {
					t.Errorf("the capability probe must carry no request body, got %q", body)
				}
				wantAuth := ""
				if tc.device {
					wantAuth = "Bearer " + testDeviceID + "." + testDeviceSecret
				}
				if got := r.Header.Get("Authorization"); got != wantAuth {
					t.Errorf("unexpected Authorization header %q", got)
				}
				writeJSON(w, http.StatusOK, capabilitiesDoc(
					"collector-generated-device-secret",
					"bind-request-replay",
					"batch-idempotency",
					"subject-tombstone-change",
					"async-usage-projection",
					"usage-change-feed-pull",
					"account-sources",
				))
			}))
			defer server.Close()
			opt := testOptions(server.URL)
			if !tc.device {
				opt.DeviceID, opt.DeviceSecret = "", ""
			}
			if err := RequireCapability(t.Context(), opt); err != nil {
				t.Fatalf("expected the capability to be accepted: %v", err)
			}
		})
	}
}

// Every unverifiable outcome rejects the enable path: an old server
// (404), a server without the feature, a corrupt or oversized document,
// any other non-200.
func TestRequireCapabilityFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   any
		raw    string
	}{
		{"old server answers 404", http.StatusNotFound, errorEnvelope("not_found"), ""},
		{"plain text 404", http.StatusNotFound, nil, "404 page not found\n"},
		{"server error", http.StatusInternalServerError, errorEnvelope("internal_error"), ""},
		{"store unavailable", http.StatusServiceUnavailable, errorEnvelope("store_unavailable"), ""},
		{"feature missing", http.StatusOK, capabilitiesDoc("usage-snapshots", "app-control-plane"), ""},
		{"feature list empty", http.StatusOK, capabilitiesDoc(), ""},
		{"feature list null", http.StatusOK, map[string]any{"features": nil}, ""},
		{"near miss singular", http.StatusOK, capabilitiesDoc("account-source"), ""},
		{"near miss versioned", http.StatusOK, capabilitiesDoc("account-sources-v2"), ""},
		{"near miss case", http.StatusOK, capabilitiesDoc("ACCOUNT-SOURCES"), ""},
		{"malformed document", http.StatusOK, nil, "{not json"},
		{"empty document", http.StatusOK, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.raw != "" {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.raw)
					return
				}
				if tc.body == nil {
					tc.body = map[string]any{}
				}
				writeJSON(w, tc.status, tc.body)
			}))
			defer server.Close()
			if err := RequireCapability(t.Context(), testOptions(server.URL)); err == nil {
				t.Fatal("expected the capability check to fail closed")
			} else {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error echoes untrusted server message: %v", err)
				}
				if strings.Contains(err.Error(), testDeviceSecret) {
					t.Fatalf("error leaks the device secret: %v", err)
				}
			}
		})
	}
}

func TestRequireCapabilityRejectsOversizedDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxCapabilityBytes+1))
	}))
	defer server.Close()
	if err := RequireCapability(t.Context(), testOptions(server.URL)); err == nil {
		t.Fatal("expected an oversized capabilities document to be rejected")
	}
}

func TestRequireCapabilityTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	opt := testOptions(server.URL)
	opt.HTTPClient = &http.Client{Timeout: 80 * time.Millisecond}
	start := time.Now()
	err := RequireCapability(t.Context(), opt)
	close(release)
	if err == nil {
		t.Fatal("expected the hung server to time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	if strings.Contains(err.Error(), testDeviceSecret) {
		t.Fatalf("error leaks the device secret: %v", err)
	}
}

func TestRequireCapabilityDoesNotFollowRedirect(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect target received the Authorization header")
		}
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer server.Close()
	if err := RequireCapability(t.Context(), testOptions(server.URL)); err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if hit.Load() {
		t.Fatal("the redirect was followed")
	}
}

func TestRequireCapabilityRequiresServerURL(t *testing.T) {
	if err := RequireCapability(t.Context(), Options{}); err == nil {
		t.Fatal("expected an error for a missing server URL")
	}
}
