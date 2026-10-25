package collection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

// TestRC2_NetworkDisconnectionAndRetry_Acceptance tests fault tolerance when network
// fails during outbox drain (e.g. server down / connection refused).
// The test verifies:
// 1. Observations are exported into outbox batches and cursor is safely advanced.
// 2. Network connection failure stops the drain cleanly without losing pending batches.
// 3. Resuming collection after network restoration retries and successfully syncs pending batches.
// 4. No duplicate export or duplicate sync occurs.
func TestRC2_NetworkDisconnectionAndRetry_Acceptance(t *testing.T) {
	stateDir := t.TempDir()

	// 1. Setup a test server that can be shut down to simulate network drop
	var requests atomic.Int64
	server := fakeServer(t, &requests)
	serverURL := server.URL

	bindDevice(t, stateDir, serverURL)

	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session-rc2.jsonl",
		claudeLine(t, "2026-10-21T05:00:00Z", "s-rc2", "msg-1", claudeUsage(15, 2, 0, 8)),
		claudeLine(t, "2026-10-21T05:01:00Z", "s-rc2", "msg-2", claudeUsage(10, 0, 0, 5)))
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	// Simulate network outage: close the server immediately so connection will be refused
	server.Close()

	// Run collection during network outage
	res1, err := Run(t.Context(), Options{
		StateDir: stateDir,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 5, 2, 0, 0, time.UTC)
		},
	})

	// The run must return an error because the drain step could not reach the server
	if err == nil {
		t.Fatal("expected run error when server is offline/unreachable")
	}

	// However, local export must have succeeded atomically before the network failure
	if res1.ExportedBatches != 1 {
		t.Fatalf("expected 1 exported batch into outbox, got %d", res1.ExportedBatches)
	}
	if res1.PendingRemaining != 1 {
		t.Fatalf("expected 1 pending batch remaining in outbox, got %d", res1.PendingRemaining)
	}
	if !strings.Contains(res1.DrainStopped, "upload of batch") {
		t.Fatalf("expected drain stopped message mentioning batch upload failure, got: %s", res1.DrainStopped)
	}

	// Verify outbox state: the batch must be in 'pending' status
	ledger := outbox.New(stateDir)
	ob, err := ledger.Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	if len(ob.Batches) != 1 {
		t.Fatalf("expected exactly 1 batch in outbox, got %d", len(ob.Batches))
	}
	if ob.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("expected batch status to remain pending, got %s", ob.Batches[0].Status)
	}

	// Verify cursor was advanced: raw source logs were recorded in progress
	cursors, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load progress: %v", err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].BatchID != ob.Batches[0].BatchID {
		t.Fatalf("expected cursor advanced to batch %s, got %#v", ob.Batches[0].BatchID, cursors)
	}

	// 2. Restore network: start a new test server on a new URL, update device state
	requests.Store(0)
	restoredServer := fakeServer(t, &requests)
	defer restoredServer.Close()

	// Update device state server URL to restored server
	stStore := statedir.New(stateDir)
	st, err := stStore.Load()
	if err != nil {
		t.Fatalf("load device state: %v", err)
	}
	st.ServerURL = restoredServer.URL
	if err := stStore.Save(st); err != nil {
		t.Fatalf("save device state: %v", err)
	}

	// Run collection again with network restored
	res2, err := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: restoredServer.URL,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 5, 5, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("expected successful run after network restored, got: %v", err)
	}

	// No new raw input changed, so 0 newly exported batches
	if res2.ExportedBatches != 0 {
		t.Fatalf("expected 0 new exported batches on unchanged input, got %d", res2.ExportedBatches)
	}
	// The pending batch from run 1 must now be successfully synced
	if res2.SyncedBatches != 1 {
		t.Fatalf("expected 1 synced batch from pending outbox, got %d", res2.SyncedBatches)
	}
	if res2.PendingRemaining != 0 {
		t.Fatalf("expected 0 pending remaining, got %d", res2.PendingRemaining)
	}
	if res2.DrainStopped != "" {
		t.Fatalf("drain should not have stopped early, got: %s", res2.DrainStopped)
	}

	// Verify outbox status updated to synced
	ob2, err := ledger.Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	if len(ob2.Batches) != 1 {
		t.Fatalf("expected 1 batch in outbox, got %d", len(ob2.Batches))
	}
	if ob2.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("expected batch status to be synced, got %s", ob2.Batches[0].Status)
	}
	if ob2.Batches[0].AcceptedRecords != 2 {
		t.Fatalf("expected 2 accepted records, got %d", ob2.Batches[0].AcceptedRecords)
	}

	// Verify state receipt recorded
	st2, err := stStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st2.LastSyncBatchID != ob.Batches[0].BatchID || st2.LastSyncStatus != "accepted" {
		t.Fatalf("unexpected state receipt: %#v", st2)
	}
}

// TestRC2_InterruptedExportWAL_CrashedRunRecoveredOnIdlePeriodic_Acceptance verifies that
// when an uncommitted export-transaction.json is left behind from an interrupted/crashed run,
// the next periodic collection automatically recovers the pending batch, records it in the
// outbox, advances cursors, cleans up the journal, and drains the batch to the server
// even when all configured source grants are currently idle (0 new records).
func TestRC2_InterruptedExportWAL_CrashedRunRecoveredOnIdlePeriodic_Acceptance(t *testing.T) {
	stateDir := t.TempDir()

	var requests atomic.Int64
	server := fakeServer(t, &requests)
	defer server.Close()

	bindDevice(t, stateDir, server.URL)

	// Configure an idle grant (empty sessions directory)
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)

	// Prepare a real batch payload using usage-json adapter
	crashInputDir := t.TempDir()
	crashInput := filepath.Join(crashInputDir, "usage.json")
	usageJSON := `{"records":[{"recordKey":"k1","kind":"delta","occurredAt":"2026-10-21T05:00:00Z","tool":"claude-code","model":"claude-sonnet-4.5","input":"10","cacheRead":"0","cacheWrite":"0","output":"5","adapterVersion":"fixture-v1","sourceType":"fixture"}]}`
	if err := os.WriteFile(crashInput, []byte(usageJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	batchFile := filepath.Join(stateDir, "batches", "batch-crash-recovered.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{
		Input:   crashInput,
		Output:  batchFile,
		BatchID: "batch-crash-recovered",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write export-transaction.json directly to simulate crash before CommitExport finished
	journalJSON, err := json.MarshalIndent(map[string]any{
		"output":      batchFile,
		"batchId":     "batch-crash-recovered",
		"payload":     string(prepared.Payload),
		"source":      adapter.UsageJSONSource,
		"input":       crashInput,
		"recordCount": prepared.Records,
		"committedAt": "2026-10-21T05:50:00Z",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	txFile := filepath.Join(stateDir, "export-transaction.json")
	if err := os.WriteFile(txFile, journalJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify journal exists before collection runs
	if _, err := os.Stat(txFile); err != nil {
		t.Fatalf("expected export-transaction.json to exist before collection: %v", err)
	}

	// Run periodic collection: grant is idle, but entrance recovery must recover and drain WAL batch
	res, err := Run(t.Context(), Options{
		StateDir:  stateDir,
		ServerURL: server.URL,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("collection.Run failed: %v", err)
	}

	// The idle grant produced 0 new batches, but the crashed batch was recovered and synced
	if res.ExportedBatches != 0 {
		t.Fatalf("expected 0 exported batches from idle grant, got %d", res.ExportedBatches)
	}
	if res.SyncedBatches != 1 {
		t.Fatalf("expected 1 synced batch from recovered WAL, got %d", res.SyncedBatches)
	}
	if res.PendingRemaining != 0 {
		t.Fatalf("expected 0 pending remaining, got %d", res.PendingRemaining)
	}

	// Verify journal was deleted after recovery
	if _, err := os.Stat(txFile); !os.IsNotExist(err) {
		t.Fatalf("expected export-transaction.json to be deleted after recovery, err=%v", err)
	}

	// Verify outbox has the recovered batch in synced state
	ob, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load outbox: %v", err)
	}
	if len(ob.Batches) != 1 {
		t.Fatalf("expected 1 batch in outbox, got %d", len(ob.Batches))
	}
	if ob.Batches[0].BatchID != "batch-crash-recovered" {
		t.Fatalf("expected batch-crash-recovered in outbox, got %s", ob.Batches[0].BatchID)
	}
	if ob.Batches[0].Status != outbox.StatusSynced {
		t.Fatalf("expected synced status, got %s", ob.Batches[0].Status)
	}

	// Verify progress ledger cursor was safely advanced
	cur, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatalf("load progress: %v", err)
	}
	if len(cur.Cursors) != 1 || cur.Cursors[0].BatchID != "batch-crash-recovered" {
		t.Fatalf("expected cursor advanced to batch-crash-recovered, got %#v", cur)
	}
}
