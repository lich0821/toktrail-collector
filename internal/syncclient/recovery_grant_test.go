package syncclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

// grantHeldEntry builds one synthetic quarantined record for the grant
// gate tests: a generic usage-json record (no message provenance) under
// the given (source, input) and quarantine revision.
func grantHeldEntry(source, input, recordKey string, revision int64) quarantine.Entry {
	raw := fmt.Sprintf(`{"recordKey":%q,"kind":"delta","occurredAt":"2026-10-20T10:00:00Z","tool":"usage-json","input":"10","cacheRead":"0","cacheWrite":"0","output":"5","adapterVersion":"test-adapter-1","sourceType":"fixture"}`, recordKey)
	return quarantine.Entry{
		Source:          source,
		Input:           input,
		RecordKey:       recordKey,
		Record:          json.RawMessage(raw),
		OriginBatchID:   "batch-quarantined-grant-1",
		Reason:          quarantine.ReasonToolNotAllowed,
		ConsentRevision: revision,
		QuarantinedAt:   time.Unix(1000000, 0).UTC(),
	}
}

// seedGrantQuarantine persists synthetic quarantine entries.
func seedGrantQuarantine(t *testing.T, stateDir string, entries ...quarantine.Entry) {
	t.Helper()
	if err := quarantine.New(stateDir).Append(entries); err != nil {
		t.Fatal(err)
	}
}

// grantInputFile creates an empty usage input file and returns its path.
func grantInputFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// unrestrictedServer serves a self view with the given revision and an
// unrestricted scope (no allowed tools, no time window) and rejects every
// other request: the recovery-only path must never POST.
func unrestrictedServer(t *testing.T, revision int64) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			serveSelfScoped(w, r, revision, nil, nil, nil)
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestQuarantineRecoveryRequiresEnabledLocalGrant: on a device with a
// configured grant store, recovery of a quarantined record requires an
// ENABLED grant for its exact (source, input). A grant closed the way
// connect closes tools that left the authorized list — the pair stays
// recorded, disabled — holds its records (ErrQuarantineHeld, a steady
// state) even under a strictly newer, unrestricted scope; re-enabling the
// grant re-authorizes recovery.
func TestQuarantineRecoveryRequiresEnabledLocalGrant(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	input := grantInputFile(t, "usage.jsonl")
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.New(stateDir).Disable(source, input); err != nil {
		t.Fatal(err)
	}
	seedGrantQuarantine(t, stateDir,
		grantHeldEntry(source, input, "record-grant-1", 8),
		grantHeldEntry(source, input, "record-grant-2", 8),
	)
	server := unrestrictedServer(t, 9)

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrQuarantineHeld) {
		t.Fatalf("expected ErrQuarantineHeld while the grant is closed, got %v", err)
	}
	entries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 2 {
		t.Fatalf("expected the records held by the closed grant, err=%v: %#v", qErr, entries)
	}
	out, lErr := outbox.New(stateDir).Load()
	if lErr != nil || len(out.Batches) != 0 {
		t.Fatalf("expected no recovery batch while the grant is closed, err=%v: %#v", lErr, out)
	}

	// Re-enabling the grant re-authorizes recovery under the same scope.
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 2 || result.Quarantined != 0 {
		t.Fatalf("expected both records recovered after the re-enable, got %#v", result)
	}
	entries, qErr = quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 0 {
		t.Fatalf("expected the quarantine drained after the re-enable, err=%v: %#v", qErr, entries)
	}
}

// TestQuarantineRecoveryGrantMustMatchSourceAndInput: an enabled grant for
// one input of a source does not authorize quarantined records of another
// input — the gate matches the full (source, input) pair, never the source
// alone.
func TestQuarantineRecoveryGrantMustMatchSourceAndInput(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	granted := grantInputFile(t, "granted.jsonl")
	other := grantInputFile(t, "other.jsonl")
	if _, err := grants.New(stateDir).Enable(source, granted); err != nil {
		t.Fatal(err)
	}
	seedGrantQuarantine(t, stateDir,
		grantHeldEntry(source, other, "record-other-input", 8),
	)
	server := unrestrictedServer(t, 9)

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrQuarantineHeld) {
		t.Fatalf("expected ErrQuarantineHeld for a record whose input has no grant, got %v", err)
	}
	entries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 1 {
		t.Fatalf("expected the record held, err=%v: %#v", qErr, entries)
	}
	out, lErr := outbox.New(stateDir).Load()
	if lErr != nil || len(out.Batches) != 0 {
		t.Fatalf("expected no recovery batch, err=%v: %#v", lErr, out)
	}
}

// TestQuarantineRecoveryGroupsBySourceAndInput: quarantined records of one
// source but different inputs recover into SEPARATE batches — one per
// (source, input) — so a batch never mixes records from different granted
// inputs and each recovery batch carries its own input provenance.
func TestQuarantineRecoveryGroupsBySourceAndInput(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	inputA := grantInputFile(t, "a.jsonl")
	inputB := grantInputFile(t, "b.jsonl")
	if _, err := grants.New(stateDir).Enable(source, inputA); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(stateDir).Enable(source, inputB); err != nil {
		t.Fatal(err)
	}
	seedGrantQuarantine(t, stateDir,
		grantHeldEntry(source, inputA, "record-a1", 8),
		grantHeldEntry(source, inputA, "record-a2", 8),
		grantHeldEntry(source, inputB, "record-b1", 8),
	)
	server := unrestrictedServer(t, 9)

	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 3 {
		t.Fatalf("expected all three records recovered, got %#v", result)
	}
	batchA := recoveryBatchID(source, 9, []string{"record-a1", "record-a2"})
	batchB := recoveryBatchID(source, 9, []string{"record-b1"})
	entryA := outboxEntryOf(t, stateDir, batchA)
	if entryA.Status != outbox.StatusPending || entryA.RecordCount != 2 || entryA.Source != source || entryA.Input != inputA {
		t.Fatalf("expected a pending recovery batch for input A with its own provenance, got %#v", entryA)
	}
	entryB := outboxEntryOf(t, stateDir, batchB)
	if entryB.Status != outbox.StatusPending || entryB.RecordCount != 1 || entryB.Source != source || entryB.Input != inputB {
		t.Fatalf("expected a separate pending recovery batch for input B, got %#v", entryB)
	}
	entries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 0 {
		t.Fatalf("expected the quarantine drained, err=%v: %#v", qErr, entries)
	}
}

// TestQuarantineRecoveryWithoutGrantConfigStaysGrantAgnostic: a device
// that never configured grants (no grants.json, no legacy sources.json) —
// the manual-sync-only legacy setup — keeps the historical behavior: the
// server scope alone decides recovery, and the recovery never creates or
// consults a grant store.
func TestQuarantineRecoveryWithoutGrantConfigStaysGrantAgnostic(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	// No grant store is created; the input path need not exist.
	seedGrantQuarantine(t, stateDir,
		grantHeldEntry(source, filepath.Join(t.TempDir(), "never-granted.jsonl"), "record-legacy-1", 8),
		grantHeldEntry(source, filepath.Join(t.TempDir(), "never-granted.jsonl"), "record-legacy-2", 8),
	)
	server := unrestrictedServer(t, 9)

	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 2 || result.Quarantined != 0 {
		t.Fatalf("expected the legacy device to recover on scope alone, got %#v", result)
	}
	if _, statErr := os.Lstat(grants.New(stateDir).Path()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the recovery must not create a grant store, stat err=%v", statErr)
	}
}

// TestQuarantineRecoveryUnreadableGrantStoreDeniesWithoutBlockingUpload:
// a configured grant store that cannot be loaded denies recovery (fail
// closed — authorization cannot be verified) but never blocks the ordinary
// upload of a pending batch: the batch still syncs and the quarantined
// record stays held.
func TestQuarantineRecoveryUnreadableGrantStoreDeniesWithoutBlockingUpload(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-unreadable-grants-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-upload-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	seedGrantQuarantine(t, stateDir,
		grantHeldEntry(source, batchFile, "record-held-unreadable", 8),
	)
	// A grant store that exists but cannot be loaded (unsupported
	// version): recovery must fail closed without erroring the upload.
	if err := os.WriteFile(grants.New(stateDir).Path(), []byte(`{"version":2,"grants":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			serveSelfScoped(w, r, 9, nil, nil, nil)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var got BatchRequest
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId": got.BatchID, "status": "accepted", "acceptedRecords": len(got.Records),
				"rejectedRecords": 0, "replay": false, "receivedAt": "2026-10-20T10:12:00Z",
			}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatalf("an unreadable grant store must not block the pending batch upload, got %v", err)
	}
	if result.Receipt.BatchID != batchID || result.Receipt.AcceptedRecords != 1 {
		t.Fatalf("expected the pending batch synced, got %#v", result)
	}
	if result.Recovered != 0 {
		t.Fatalf("recovery must fail closed on an unreadable grant store, got %#v", result)
	}
	entries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 1 {
		t.Fatalf("expected the quarantined record still held, err=%v: %#v", qErr, entries)
	}
	if entry := outboxEntryOf(t, stateDir, batchID); entry.Status != outbox.StatusSynced {
		t.Fatalf("expected the pending batch synced despite the grant store, got %#v", entry)
	}
}
