package syncclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"toktrail-collector/internal/local/statedir"
)

// ackTestSecret is a synthetic device secret for the ack fixtures.
const ackTestSecret = "ack-test-secret-0123456789abcdef0123456789abcdef"

// newAckTestStore saves a synthetic bound device pointing at serverURL.
func newAckTestStore(t *testing.T, serverURL string) statedir.Store {
	t.Helper()
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{ServerURL: serverURL, DeviceID: "dev-1", DeviceSecret: ackTestSecret}); err != nil {
		t.Fatal(err)
	}
	return store
}

// ackReceipt is the success echo served by the ack test fakes.
func ackReceipt(w http.ResponseWriter, revision int64, state string) {
	if state == "" {
		state = "applied"
	}
	writeJSON(w, http.StatusOK, map[string]any{"grantAck": map[string]any{
		"consentRevision":        revision,
		"currentConsentRevision": revision,
		"ackedState":             state,
		"ackedAt":                "2026-10-27T08:00:00Z",
	}})
}

// decodeJSONObject reads the whole body and decodes it as a flat JSON
// object; it fails the test on any transport or decoding error.
func decodeJSONObject(t *testing.T, r *http.Request) map[string]json.RawMessage {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("decode request body %s: %v", raw, err)
	}
	return obj
}

func decodeStrings(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode string array %s: %v", raw, err)
	}
	return out
}

// ---------------------------------------------------------------------------
// wire shapes
// ---------------------------------------------------------------------------

// A request without the capability fields is byte-compatible with the
// legacy protocol: neither key appears, so an old server sees the exact
// pre-capability payload.
func TestGrantAckRequestLegacyMarshalOmitsCapabilityFields(t *testing.T) {
	b, err := json.Marshal(GrantAckRequest{ConsentRevision: 5, ApplyState: "applied", CollectorVersion: "v0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["supportedTools"]; ok {
		t.Fatalf("legacy payload must omit supportedTools: %s", b)
	}
	if _, ok := obj["pendingReasons"]; ok {
		t.Fatalf("legacy payload must omit pendingReasons: %s", b)
	}
	if string(obj["consentRevision"]) != "5" || string(obj["applyState"]) != `"applied"` || string(obj["collectorVersion"]) != `"v0.2.1"` {
		t.Fatalf("unexpected legacy payload: %s", b)
	}
}

// A capability-bearing request distinguishes three pendingReasons wire
// states: an explicit [] ("no reasons", complete), sorted tool/code
// entries (complete), and an OMITTED field ("reasons unknown" — at least
// one restriction has no closed code). Only names and codes travel,
// never paths.
func TestGrantAckRequestCapabilityMarshalShapes(t *testing.T) {
	// Complete with no restricted tool: pendingReasons is [].
	b, err := json.Marshal(GrantAckRequest{ConsentRevision: 6, SupportedTools: []string{"Codex"}, PendingReasons: CompletePendingReasons()})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if got := decodeStrings(t, obj["supportedTools"]); len(got) != 1 || got[0] != "Codex" {
		t.Fatalf("unexpected supportedTools: %v", got)
	}
	if string(obj["pendingReasons"]) != "[]" {
		t.Fatalf("pendingReasons must be an explicit empty array, got %s", obj["pendingReasons"])
	}

	// Complete with restricted tools: the given entries travel verbatim
	// (the grant sync sends them sorted).
	b, err = json.Marshal(GrantAckRequest{
		ConsentRevision: 6,
		ApplyState:      "pending",
		SupportedTools:  []string{"Codex", "Claude Code"},
		PendingReasons: CompletePendingReasons(
			GrantAckPendingReason{Tool: "Codex", Code: PendingReasonMissingInput},
			GrantAckPendingReason{Tool: "FutureTool", Code: PendingReasonUnsupportedTool},
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	obj = map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	var reasons []GrantAckPendingReason
	if err := json.Unmarshal(obj["pendingReasons"], &reasons); err != nil {
		t.Fatal(err)
	}
	if len(reasons) != 2 || reasons[0] != (GrantAckPendingReason{Tool: "Codex", Code: "missing_input"}) ||
		reasons[1] != (GrantAckPendingReason{Tool: "FutureTool", Code: "unsupported_tool"}) {
		t.Fatalf("unexpected pendingReasons: %#v", reasons)
	}

	// Unknown reasons: a nil PendingReasons OMITS the field entirely (a
	// partial list or [] could be mistaken for a complete receipt) while
	// supportedTools still travels.
	b, err = json.Marshal(GrantAckRequest{ConsentRevision: 6, ApplyState: "pending", SupportedTools: []string{"Codex"}})
	if err != nil {
		t.Fatal(err)
	}
	obj = map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["pendingReasons"]; ok {
		t.Fatalf("unknown reasons must omit pendingReasons entirely, got %s", b)
	}
	if got := decodeStrings(t, obj["supportedTools"]); len(got) != 1 || got[0] != "Codex" {
		t.Fatalf("the supported-tools report must still travel, got %v", got)
	}

	// No payload shape ever carries a path separator.
	for _, payload := range []string{string(b)} {
		if strings.Contains(payload, "/") || strings.Contains(payload, "\\") {
			t.Fatalf("capability payload must not contain path separators: %s", payload)
		}
	}
}

// ---------------------------------------------------------------------------
// ReportGrantAck behavior
// ---------------------------------------------------------------------------

// The capability fields travel on the wire exactly as coordinated, and a
// conforming server's echo confirms the ack.
func TestReportGrantAckSendsCapabilityFields(t *testing.T) {
	var served map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/grant-ack" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		served = decodeJSONObject(t, r)
		state := "applied"
		var stateRaw string
		if err := json.Unmarshal(served["applyState"], &stateRaw); err == nil && stateRaw != "" {
			state = stateRaw
		}
		ackReceipt(w, 9, state)
	}))
	defer server.Close()
	store := newAckTestStore(t, server.URL)

	ack, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
		ConsentRevision: 9,
		ApplyState:      "pending",
		SupportedTools:  []string{"Claude Code", "Codex", "DeepSeek Harness"},
		PendingReasons:  CompletePendingReasons(GrantAckPendingReason{Tool: "FutureTool", Code: PendingReasonUnsupportedTool}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.ConsentRevision != 9 || ack.AckedState != "pending" {
		t.Fatalf("unexpected receipt: %#v", ack)
	}
	if got := decodeStrings(t, served["supportedTools"]); len(got) != 3 || got[0] != "Claude Code" || got[1] != "Codex" || got[2] != "DeepSeek Harness" {
		t.Fatalf("unexpected supportedTools on the wire: %v (served=%s)", got, served["supportedTools"])
	}
	if string(served["pendingReasons"]) != `[{"tool":"FutureTool","code":"unsupported_tool"}]` {
		t.Fatalf("unexpected pendingReasons on the wire: %s", served["pendingReasons"])
	}

	// An applied revision reports the capability list with an explicit
	// empty pendingReasons array (never a missing field).
	served = nil
	ack, err = ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
		ConsentRevision: 9,
		SupportedTools:  []string{"Codex"},
		PendingReasons:  CompletePendingReasons(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.ConsentRevision != 9 {
		t.Fatalf("unexpected receipt: %#v", ack)
	}
	if string(served["pendingReasons"]) != "[]" {
		t.Fatalf("an applied capability ack must send pendingReasons [], got %s", served["pendingReasons"])
	}

	// A revision with an unmappable restriction omits pendingReasons
	// (unknown) while the supported-tools report still travels.
	served = nil
	ack, err = ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
		ConsentRevision: 9,
		ApplyState:      "pending",
		SupportedTools:  []string{"Codex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.ConsentRevision != 9 {
		t.Fatalf("unexpected receipt: %#v", ack)
	}
	if _, ok := served["pendingReasons"]; ok {
		t.Fatalf("unknown reasons must omit pendingReasons on the wire, got %s", served["pendingReasons"])
	}
	if got := decodeStrings(t, served["supportedTools"]); len(got) != 1 || got[0] != "Codex" {
		t.Fatalf("the supported-tools report must still travel, got %v", got)
	}
}

// A validation-class rejection (400/422) of a payload that carried the
// capability fields yields the unknown-fields sentinel: the documented
// old-server signature that licenses exactly one legacy-shape retry.
func TestReportGrantAckUnknownFieldsSentinel(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		var carriedCapabilities bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			obj := decodeJSONObject(t, r)
			_, hasSupported := obj["supportedTools"]
			_, hasPending := obj["pendingReasons"]
			carriedCapabilities = hasSupported || hasPending
			writeJSON(w, status, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "unknown field"}})
		}))
		store := newAckTestStore(t, server.URL)

		_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
			ConsentRevision: 9,
			SupportedTools:  []string{"Codex"},
			PendingReasons:  CompletePendingReasons(GrantAckPendingReason{Tool: "FutureTool", Code: PendingReasonUnsupportedTool}),
		})
		server.Close()
		if !errors.Is(err, ErrAckUnknownFields) {
			t.Fatalf("HTTP %d: expected ErrAckUnknownFields, got %v", status, err)
		}
		if !carriedCapabilities {
			t.Fatalf("HTTP %d: the rejected payload must have carried the capability fields", status)
		}
	}
}

// A legacy-shaped payload rejected with 400 is an ordinary failure, never
// the unknown-fields sentinel: there is nothing to fall back from.
func TestReportGrantAckLegacyRejectionIsOrdinaryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obj := decodeJSONObject(t, r)
		if _, ok := obj["supportedTools"]; ok {
			t.Errorf("legacy payload must not carry supportedTools")
		}
		if _, ok := obj["pendingReasons"]; ok {
			t.Errorf("legacy payload must not carry pendingReasons")
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "unknown field"}})
	}))
	defer server.Close()
	store := newAckTestStore(t, server.URL)

	_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{ConsentRevision: 9, ApplyState: "applied"})
	if err == nil || errors.Is(err, ErrAckUnknownFields) {
		t.Fatalf("a legacy-payload rejection must be an ordinary error without the sentinel, got %v", err)
	}
}

// Authentication failures, scope changes, and a missing endpoint keep
// their own classification even while the payload carries the capability
// fields: nothing silently downgrades to a legacy retry.
func TestReportGrantAckOtherFailuresNeverTriggerUnknownFields(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   map[string]any
		verify func(t *testing.T, err error)
	}{
		{
			name:   "authentication failure",
			status: http.StatusUnauthorized,
			body:   map[string]any{"error": map[string]any{"code": "device_revoked", "message": "revoked"}},
			verify: func(t *testing.T, err error) {
				if !errors.Is(err, ErrDeviceRevoked) {
					t.Fatalf("expected ErrDeviceRevoked, got %v", err)
				}
			},
		},
		{
			name:   "scope changed",
			status: http.StatusConflict,
			body:   map[string]any{"error": map[string]any{"code": "scope_changed", "message": "moved on"}},
			verify: func(t *testing.T, err error) {
				if !errors.Is(err, ErrAckRevisionAdvanced) {
					t.Fatalf("expected ErrAckRevisionAdvanced, got %v", err)
				}
			},
		},
		{
			name:   "endpoint absent",
			status: http.StatusNotFound,
			body:   map[string]any{},
			verify: func(t *testing.T, err error) {
				if err == nil || !strings.Contains(err.Error(), "grant ack endpoint not available") {
					t.Fatalf("expected the endpoint-absent failure, got %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, tc.body)
			}))
			defer server.Close()
			store := newAckTestStore(t, server.URL)
			_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: server.URL}, GrantAckRequest{
				ConsentRevision: 9,
				SupportedTools:  []string{"Codex"},
				PendingReasons:  CompletePendingReasons(GrantAckPendingReason{Tool: "FutureTool", Code: PendingReasonUnsupportedTool}),
			})
			if errors.Is(err, ErrAckUnknownFields) {
				t.Fatalf("HTTP %d must never classify as unknown fields", tc.status)
			}
			if err == nil {
				t.Fatal("expected a failure")
			}
			tc.verify(t, err)
		})
	}
}

// The capability fields are validated locally before any network
// traffic: closed reason codes, the closed tool-name alphabet (which
// makes path leakage impossible), no duplicates, and a non-empty
// supportedTools list whenever the report is carried.
func TestReportGrantAckValidatesCapabilityFields(t *testing.T) {
	oversize := make([]string, maxAckCapabilityEntries+1)
	for i := range oversize {
		oversize[i] = "Tool" + strings.Repeat("x", 3) // distinct valid names
	}
	for i, name := range oversize {
		oversize[i] = name + string(rune('0'+i%10)) + string(rune('a'+i/10))
	}
	cases := []struct {
		name string
		req  GrantAckRequest
		want string
	}{
		{
			name: "path-like tool name in supportedTools",
			req:  GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"/Users/chuck/.codex"}},
			want: "tool-name alphabet",
		},
		{
			name: "path-like tool name in pendingReasons",
			req: GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"Codex"},
				PendingReasons: CompletePendingReasons(GrantAckPendingReason{Tool: "../../etc/passwd", Code: PendingReasonDisabled})},
			want: "tool-name alphabet",
		},
		{
			name: "windows path-like tool name",
			req:  GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{`C:\Users\chuck`}},
			want: "tool-name alphabet",
		},
		{
			name: "reason code outside the closed set",
			req: GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"Codex"},
				PendingReasons: CompletePendingReasons(GrantAckPendingReason{Tool: "Codex", Code: "directory_not_found"})},
			want: "outside the closed set",
		},
		{
			name: "empty reason code",
			req: GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"Codex"},
				PendingReasons: CompletePendingReasons(GrantAckPendingReason{Tool: "Codex", Code: ""})},
			want: "outside the closed set",
		},
		{
			name: "duplicate supported tool",
			req:  GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"Codex", "Codex"}},
			want: "more than once",
		},
		{
			name: "duplicate pending tool",
			req: GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"Codex"},
				PendingReasons: CompletePendingReasons(
					GrantAckPendingReason{Tool: "Codex", Code: PendingReasonDisabled},
					GrantAckPendingReason{Tool: "Codex", Code: PendingReasonMissingInput},
				)},
			want: "more than once",
		},
		{
			name: "capability report without a supported list",
			req: GrantAckRequest{ConsentRevision: 9,
				PendingReasons: CompletePendingReasons(GrantAckPendingReason{Tool: "Codex", Code: PendingReasonDisabled})},
			want: "non-empty supportedTools",
		},
		{
			name: "tool name longer than 64 characters",
			req:  GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"A" + strings.Repeat("b", 64)}},
			want: "tool-name alphabet",
		},
		{
			name: "leading punctuation in tool name",
			req:  GrantAckRequest{ConsentRevision: 9, SupportedTools: []string{"-Codex"}},
			want: "tool-name alphabet",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No server is needed: validation runs before the device
			// state is even loaded, so nothing reaches the network.
			store := statedir.New(t.TempDir())
			_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: "http://unused.invalid"}, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected a %q validation error, got %v", tc.want, err)
			}
		})
	}

	// The oversize list is rejected by count.
	store := statedir.New(t.TempDir())
	_, err := ReportGrantAck(t.Context(), store, Options{ServerURL: "http://unused.invalid"}, GrantAckRequest{
		ConsentRevision: 9, SupportedTools: oversize,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected the oversize supportedTools list to be rejected, got %v", err)
	}
}
