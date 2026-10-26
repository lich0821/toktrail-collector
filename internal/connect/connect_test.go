package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

type mockRunner struct {
	commands []string
}

func (m *mockRunner) Run(name string, args ...string) error {
	m.commands = append(m.commands, name+" "+strings.Join(args, " "))
	return nil
}

func TestConnectHappyPathAndRetry(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	// Create local mock directories for tools
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}

	validTicket := strings.Repeat("a", 64)

	// Mock toktrail-server for bind & collection
	var bindCalls int
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			bindCalls++
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["ticket"] == "" {
				t.Fatalf("missing ticket in bind req")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-test-1",
					"applicationId":     req["applicationId"],
					"externalSubjectId": req["externalSubjectId"],
					"deviceName":        req["deviceName"],
					"platform":          req["platform"],
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceId":         "dev-test-1",
				"consentRevision":  1,
				"uploadAuthorized": true,
				"publicAuthorized": true,
				"revoked":          false,
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer toktrailServer.Close()

	// Mock leaderboard connect endpoint
	leaderboardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/collector/connect" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("unexpected Authorization header: %s", auth)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-test",
			SubjectID:     "sub-test",
			Tools:         []string{"Codex", "Claude Code", "NonExistentTool"},
			Days:          30,
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer leaderboardServer.Close()

	binDir := t.TempDir()
	fakeBinary := filepath.Join(binDir, "toktrail")
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	runner := &mockRunner{}
	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, validTicket)

	// 1. First run: should bind device, authorize Codex (Claude Code doesn't exist locally), install service, run initial collection
	res, err := Run(context.Background(), Options{
		URL:             connectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.DeviceID != "dev-test-1" {
		t.Fatalf("expected deviceId dev-test-1, got %s", res.DeviceID)
	}
	if res.SkippedBind {
		t.Fatalf("expected first run to not skip bind")
	}
	if bindCalls != 1 {
		t.Fatalf("expected 1 bind call, got %d", bindCalls)
	}
	if len(res.AuthorizedTools) != 1 || res.AuthorizedTools[0] != "Codex" {
		t.Fatalf("expected only Codex authorized, got %#v", res.AuthorizedTools)
	}

	// Verify state in stateDir:
	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.ConnectReceiptHash == "" {
		t.Fatalf("expected ConnectReceiptHash to be saved")
	}
	if st.PendingConnectReceiptHash != "" {
		t.Fatalf("expected PendingConnectReceiptHash to be cleared")
	}

	// Verify grants in stateDir:
	grantStore := grants.New(stateDir)
	enabled, err := grantStore.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || enabled[0].Source != "codex-jsonl" {
		t.Fatalf("expected only codex-jsonl grant enabled, got %#v", enabled)
	}

	// 2. Retry run with same connect URL: bind MUST be skipped!
	res2, err := Run(context.Background(), Options{
		URL:             connectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("retry Run failed: %v", err)
	}
	if !res2.SkippedBind {
		t.Fatalf("expected retry to skip bind, but SkippedBind was false")
	}
	if bindCalls != 1 {
		t.Fatalf("expected bindCalls to still be 1 after retry, got %d", bindCalls)
	}

	// 3. New connect with DIFFERENT ticket/URL: bind MUST NOT be skipped!
	differentTicket := strings.Repeat("f", 64)
	diffConnectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, differentTicket)
	res3, err := Run(context.Background(), Options{
		URL:             diffConnectURL,
		StateDir:        stateDir,
		HomeDir:         homeDir,
		BinaryPath:      fakeBinary,
		HTTPClient:      leaderboardServer.Client(),
		SchedulerRunner: runner,
	})
	if err != nil {
		t.Fatalf("run with different ticket failed: %v", err)
	}
	if res3.SkippedBind {
		t.Fatalf("expected different ticket to not skip bind")
	}
	if bindCalls != 2 {
		t.Fatalf("expected 2 bind calls, got %d", bindCalls)
	}
}

func TestConnectCrashRecovery(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()

	validTicket := strings.Repeat("b", 64)
	strippedURL := "http://127.0.0.1:9999/api/collector/connect"
	fingerprint := computeReceiptFingerprint(validTicket, strippedURL)

	// Simulate crash or failed bind: device has PendingConnectReceiptHash, but NO atomic proof.
	// shouldSkipBind MUST be false to prevent false skips on rerun!
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		DeviceID:                  "dev-crashed-1",
		ServerURL:                 "http://127.0.0.1:8888",
		ApplicationID:             "app-1",
		ExternalSubjectID:         "sub-1",
		ConsentRevision:           1,
		PendingConnectReceiptHash: fingerprint,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		SchemaVersion: 1,
		ServerURL:     "http://127.0.0.1:8888",
		ApplicationID: "app-1",
		SubjectID:     "sub-1",
		Tools:         []string{"Codex"},
		Days:          30,
		ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	bindFp := "some-bind-fp"
	if shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be false for pending receipt without atomic proof")
	}

	// Now set atomic proof via ConnectReceiptHash
	st.ConnectReceiptHash = fingerprint
	st.PendingConnectReceiptHash = ""
	if !shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be true when ConnectReceiptHash matches")
	}

	// Or atomic proof via LastBindFingerprint
	st.ConnectReceiptHash = ""
	st.LastBindFingerprint = bindFp
	if !shouldSkipBind(st, fingerprint, bindFp, cfg) {
		t.Fatalf("shouldSkipBind should be true when LastBindFingerprint matches")
	}
	_ = homeDir
}

func TestConnectHistoryCutoffUpdate(t *testing.T) {
	stateDir := t.TempDir()
	store := statedir.New(stateDir)

	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	cutoff90 := now.AddDate(0, 0, -90)
	cutoff7 := now.AddDate(0, 0, -7)

	// Device originally bound with 90 days
	oldTicket := strings.Repeat("a", 64)
	oldServerURL := "http://127.0.0.1:8888"
	oldFp := computeReceiptFingerprint(oldTicket, oldServerURL+"/api/collector/connect")
	if err := store.Save(statedir.DeviceState{
		DeviceID:           "dev-history-1",
		ServerURL:          oldServerURL,
		ApplicationID:      "app-1",
		ExternalSubjectID:  "sub-1",
		ConsentRevision:    1,
		ConnectReceiptHash: oldFp,
		HistoryFrom:        &cutoff90,
		HistoryDays:        90,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Same receipt retry keeps the pinned cutoff90
	cfg90 := Config{
		SchemaVersion: 1,
		ServerURL:     oldServerURL,
		ApplicationID: "app-1",
		SubjectID:     "sub-1",
		Tools:         []string{"Codex"},
		Days:          90,
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	st, _ := store.Load()
	bindFp90 := "bind-90"
	if !shouldSkipBind(st, oldFp, bindFp90, cfg90) {
		t.Fatalf("expected skip bind for same receipt")
	}
	if st.HistoryDays != 90 || !st.HistoryFrom.Equal(cutoff90) {
		t.Fatalf("expected retry to preserve 90 days cutoff")
	}

	// 2. New connect link with 7 days
	newTicket := strings.Repeat("b", 64)
	newFp := computeReceiptFingerprint(newTicket, oldServerURL+"/api/collector/connect")
	cfg7 := Config{
		SchemaVersion: 1,
		ServerURL:     oldServerURL,
		ApplicationID: "app-1",
		SubjectID:     "sub-1",
		Tools:         []string{"Codex"},
		Days:          7,
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	bindFp7 := "bind-7"
	if shouldSkipBind(st, newFp, bindFp7, cfg7) {
		t.Fatalf("expected shouldSkipBind to be false for new 7-day link")
	}

	// Simulate binding with new link
	st.ConnectReceiptHash = newFp
	st.HistoryFrom = &cutoff7
	st.HistoryDays = 7
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, _ := store.Load()
	if loaded.HistoryDays != 7 || !loaded.HistoryFrom.Equal(cutoff7) {
		t.Fatalf("expected HistoryDays to be updated to 7 and cutoff updated, got %d, %v", loaded.HistoryDays, loaded.HistoryFrom)
	}
}

func TestConnectSecurityAndValidation(t *testing.T) {
	validTicket := strings.Repeat("c", 64)
	validURL := "https://leaderboard.example.com/api/collector/connect#" + validTicket

	// Test URL parsing
	t.Run("missing_fragment", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect")
		if err == nil || !strings.Contains(err.Error(), "missing connect ticket") {
			t.Fatalf("expected missing ticket error, got %v", err)
		}
	})

	t.Run("invalid_ticket_length", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect#1234")
		if err == nil || !strings.Contains(err.Error(), "must be 64-character hex") {
			t.Fatalf("expected ticket length error, got %v", err)
		}
	})

	t.Run("non_hex_ticket", func(t *testing.T) {
		nonHex := strings.Repeat("z", 64)
		_, _, err := parseAndValidateConnectURL("https://example.com/connect#" + nonHex)
		if err == nil || !strings.Contains(err.Error(), "must be 64-character hex") {
			t.Fatalf("expected hex ticket error, got %v", err)
		}
	})

	t.Run("insecure_remote_http", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("http://example.com/connect#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "only permitted for loopback") {
			t.Fatalf("expected loopback error for http, got %v", err)
		}
	})

	t.Run("loopback_http_allowed", func(t *testing.T) {
		for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
			u, ticket, err := parseAndValidateConnectURL(fmt.Sprintf("http://%s:8080/connect#%s", host, validTicket))
			if err != nil {
				t.Fatalf("expected loopback http to succeed for %s, got %v", host, err)
			}
			if ticket != validTicket {
				t.Fatalf("unexpected ticket: %s", ticket)
			}
			if strings.Contains(u, "#") {
				t.Fatalf("stripped URL must not contain fragment: %s", u)
			}
		}
	})

	t.Run("userinfo_rejected", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://user:pass@example.com/connect#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "userinfo") {
			t.Fatalf("expected userinfo rejection, got %v", err)
		}
	})

	t.Run("query_rejected", func(t *testing.T) {
		_, _, err := parseAndValidateConnectURL("https://example.com/connect?token=123#" + validTicket)
		if err == nil || !strings.Contains(err.Error(), "query parameters") {
			t.Fatalf("expected query rejection, got %v", err)
		}
	})

	t.Run("no_ticket_leak_in_errors", func(t *testing.T) {
		testErr := fmt.Errorf("connection to %s failed: secret is %s", validURL, validTicket)
		sanitized := sanitizeError(testErr, validTicket)
		if strings.Contains(sanitized.Error(), validTicket) {
			t.Fatalf("sanitized error leaked ticket: %s", sanitized.Error())
		}
		if !strings.Contains(sanitized.Error(), "[REDACTED]") {
			t.Fatalf("sanitized error should redact ticket: %s", sanitized.Error())
		}
	})
}

func TestConnectConfigValidation(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	validTicket := strings.Repeat("d", 64)

	makeServer := func(handler http.HandlerFunc) *httptest.Server {
		return httptest.NewServer(handler)
	}

	t.Run("redirect_rejected", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/other", http.StatusFound)
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
			t.Fatalf("expected redirect error, got %v", err)
		}
	})

	t.Run("schema_version_mismatch", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 2})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "unsupported connect schemaVersion") {
			t.Fatalf("expected schemaVersion error, got %v", err)
		}
	})

	t.Run("expired_expiresAt", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://localhost:8080",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          30,
				ExpiresAt:     now.Add(-1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected expired error, got %v", err)
		}
	})

	t.Run("invalid_days", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://localhost:8080",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          15, // must be 7, 30, or 90
				ExpiresAt:     now.Add(1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "invalid days") {
			t.Fatalf("expected invalid days error, got %v", err)
		}
	})

	t.Run("insecure_server_url", func(t *testing.T) {
		s := makeServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(Config{
				SchemaVersion: 1,
				ServerURL:     "http://insecure-remote.example.com",
				ApplicationID: "app-1",
				SubjectID:     "sub-1",
				Tools:         []string{"Codex"},
				Days:          7,
				ExpiresAt:     now.Add(1 * time.Hour).Format(time.RFC3339),
			})
		})
		defer s.Close()
		_, err := fetchConnectConfig(context.Background(), s.Client(), s.URL, validTicket, now)
		if err == nil || !strings.Contains(err.Error(), "serverUrl must use HTTPS") {
			t.Fatalf("expected insecure serverUrl error, got %v", err)
		}
	})
}

func TestConnectLockContention(t *testing.T) {
	stateDir := t.TempDir()
	validTicket := strings.Repeat("e", 64)

	leaderboardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Config{
			SchemaVersion: 1,
			ServerURL:     "http://localhost:8080",
			ApplicationID: "app-1",
			SubjectID:     "sub-1",
			Tools:         []string{"Codex"},
			Days:          7,
			ExpiresAt:     time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer leaderboardServer.Close()

	// Acquire lock beforehand to simulate contention
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", leaderboardServer.URL, validTicket)
	_, err = Run(context.Background(), Options{
		URL:        connectURL,
		StateDir:   stateDir,
		HTTPClient: leaderboardServer.Client(),
	})
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("expected runlock.ErrBusy on locked stateDir, got %v", err)
	}
}
