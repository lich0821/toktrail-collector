package collection

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

const testSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fakeServer stands in for the ingest server: it answers the device self
// preflight and accepts every batch. Only synthetic fixtures are ever sent.
func fakeServer(t *testing.T, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId":          "dev-1",
				"applicationId":     "app-1",
				"externalSubjectId": "sub-1",
				"deviceName":        "collector",
				"platform":          "darwin",
				"consentRevision":   7,
				"uploadAuthorized":  true,
				"publicAuthorized":  false,
				"revoked":           false,
				"checkedAt":         "2026-10-21T04:00:00Z",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid ingest body: %v", err)
			}
			writeJSONForTest(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-21T04:01:00Z",
			}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeJSONForTest(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// bindDevice writes a bound device state pointing at the fake server so the
// drain uses the injected HTTP transport without any implicit rebind.
func bindDevice(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL:    serverURL,
		DeviceID:     "dev-1",
		DeviceSecret: testSecret,
	}); err != nil {
		t.Fatal(err)
	}
}

// writeClaudeSession writes a synthetic Claude Code session directory with
// two assistant messages. No real user logs are ever read by these tests.
func writeClaudeSession(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func claudeLine(t *testing.T, timestamp, session, msgID string, usage map[string]any) string {
	line := map[string]any{
		"type":      "assistant",
		"timestamp": timestamp,
		"message":   map[string]any{"id": msgID, "usage": usage},
		"sessionId": session,
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func claudeUsage(input, cacheRead, cacheWrite, output any) map[string]any {
	return map[string]any{
		"input_tokens":                input,
		"cache_read_input_tokens":     cacheRead,
		"cache_creation_input_tokens": cacheWrite,
		"output_tokens":               output,
	}
}

// enableGrant records an explicit source grant for the periodic entry.
func enableGrant(t *testing.T, stateDir, source, input string) {
	t.Helper()
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
}

// writePendingBatch seeds the outbox with a minimal valid batch file, used
// to exercise the bounded drain without going through export.
func writePendingBatch(t *testing.T, stateDir, batchID string) {
	t.Helper()
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	payload := map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey":      batchID + "-record-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-21T04:00:00Z",
			"tool":           "usage-json",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "collection-test-1",
			"sourceType":     "fixture",
		}},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		Source:      "usage-json",
		Input:       path,
		RecordCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

// enableIdleGrant enables a grant over an empty session directory so the
// collection phase is a no-op and the drain can be exercised in isolation.
func enableIdleGrant(t *testing.T, stateDir string) {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// A second concurrent run must fail fast with the lock error and must not
// touch the network even though a granted input and pending batches exist.
func TestRunRefusesConcurrentRunWithoutNetwork(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	bindDevice(t, stateDir, server.URL)
	input := writeClaudeSession(t, filepath.Join(t.TempDir(), "sessions"), "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", filepath.Dir(input))
	writePendingBatch(t, stateDir, "batch-pending-lock-1")

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	_, err = Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, runlock.ErrBusy) {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("concurrent run must not touch the network, got %d requests", n)
	}
}

// No enabled grants means a no-op run that never touches the network, even
// with a bound device and pending batches present: validation happens
// strictly before any network use.
func TestRunWithNoGrantsUsesNoNetwork(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-pending-nogrants-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoGrants || res.Grants != 0 {
		t.Fatalf("expected no-grants no-op, got %#v", res)
	}
	if res.Skipped == "" {
		t.Fatal("expected a skip reason for the no-op run")
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("no-grants run must not touch the network, got %d requests", n)
	}
}

// A granted input that disappeared after the grant was recorded is skipped
// without failing the run and without any network traffic.
func TestRunSkipsMissingGrantedInputWithoutNetwork(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	input := writeClaudeSession(t, sessions, "s.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("nothing must be collected for a missing input: %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || res.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("expected one skipped grant outcome, got %#v", res.GrantOutcomes)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("run with only a missing input must not touch the network, got %d requests", n)
	}
}

// End to end: one periodic run exports the new observations from a granted
// input through the exportcommit WAL, then drains the batch through syncclient
// with the server's fresh-consent preflight intact. A second run over the
// unchanged input exports nothing and uses no network at all.
func TestRunCollectsExportsAndSyncsEndToEnd(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	bindDevice(t, stateDir, server.URL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-a.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-21T04:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	res, err := Run(t.Context(), Options{StateDir: stateDir, Now: func() time.Time {
		return time.Date(2026, 10, 21, 4, 2, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("expected one exported and one synced batch, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("outbox must be fully drained, got %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || !res.GrantOutcomes[0].Exported {
		t.Fatalf("expected the grant to be exported: %#v", res.GrantOutcomes)
	}
	if n := requests.Load(); n == 0 {
		t.Fatal("the first run must use the network for the preflight and upload")
	}

	// Second run: no new observations and an empty outbox must mean zero
	// new network requests.
	before := requests.Load()
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ExportedBatches != 0 || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("second run over unchanged input must be a no-op, got %#v", res2)
	}
	if len(res2.GrantOutcomes) != 1 || res2.GrantOutcomes[0].Skipped == "" {
		t.Fatalf("expected a skip reason for the unchanged input: %#v", res2.GrantOutcomes)
	}
	if n := requests.Load(); n != before {
		t.Fatalf("second run must not touch the network: %d -> %d requests", before, n)
	}
}

// The drain is bounded: with more pending batches than the batch limit the
// run stops after the limit and reports the remainder for the next run.
func TestRunDrainIsBounded(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-bounded-1")
	writePendingBatch(t, stateDir, "batch-bounded-2")
	writePendingBatch(t, stateDir, "batch-bounded-3")

	res, err := Run(t.Context(), Options{StateDir: stateDir, MaxBatches: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedBatches != 2 {
		t.Fatalf("expected exactly the bounded 2 batches synced, got %#v", res)
	}
	if res.PendingRemaining != 1 || res.DrainStopped == "" {
		t.Fatalf("expected one remaining batch and a stop reason, got %#v", res)
	}
	if n := requests.Load(); n != 4 { // 2 batches x (preflight + upload)
		t.Fatalf("unexpected network requests: %d", n)
	}

	// The next run continues the drain and finishes the outbox.
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SyncedBatches != 1 || res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected the remaining batch to drain, got %#v", res2)
	}
}

// A failed upload stops the drain without losing the pending batch: it
// stays in the outbox for the next scheduled run.
func TestRunStopsDrainOnUploadFailure(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	// The server answers the preflight but rejects every upload with a
	// server error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
				"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
				"deviceName": "collector", "platform": "darwin", "consentRevision": 7,
				"uploadAuthorized": true, "publicAuthorized": false, "revoked": false,
				"checkedAt": "2026-10-21T04:00:00Z",
			}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-fail-1")
	writePendingBatch(t, stateDir, "batch-fail-2")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected the upload failure to surface")
	}
	if res.SyncedBatches != 0 {
		t.Fatalf("nothing must be counted as synced, got %#v", res)
	}
	if res.PendingRemaining < 1 || res.DrainStopped == "" {
		t.Fatalf("expected pending remainder and a drain-stop reason, got %#v", res)
	}
	// The failed batch must still be recorded as pending, not lost.
	ledger := outbox.New(stateDir)
	remaining, err := countPending(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if remaining < 2 {
		t.Fatalf("both batches must remain pending after the failure, got %d", remaining)
	}
}

// An empty state directory must fail closed before any work: the required
// state dir is validated up front.
func TestRunRequiresStateDir(t *testing.T) {
	if _, err := Run(t.Context(), Options{}); err == nil {
		t.Fatal("expected an error for a missing state dir")
	}
	if _, err := Run(t.Context(), Options{StateDir: "   "}); err == nil {
		t.Fatal("expected an error for a blank state dir")
	}
}

// The scheduled drain only works against an already-bound device: an
// unbound state with pending batches must not attempt any network call and
// must report the missing binding.
func TestRunDrainRequiresBoundDevice(t *testing.T) {
	stateDir := t.TempDir()
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	// No bindDevice call: the state directory has no bound device.
	enableIdleGrant(t, stateDir)
	writePendingBatch(t, stateDir, "batch-unbound-1")

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected an error because no device is bound")
	}
	if res.PendingRemaining < 1 {
		t.Fatalf("the pending batch must stay in the outbox, got %#v", res)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("unbound drain must not touch the network, got %d requests", n)
	}
	_ = server // server only exists to prove nothing contacts it
}
