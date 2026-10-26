package exportcommit

import (
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

// TestRC2_InterruptedWALRecovery_Acceptance tests crash recovery of uncommitted WAL journals.
func TestRC2_InterruptedWALRecovery_Acceptance(t *testing.T) {
	dir := t.TempDir()
	input := writeUsageInput(t, dir)
	output := filepath.Join(dir, "recovered-rc2-batch.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{Input: input, Output: output, BatchID: "batch-recover-rc2"})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := journalFromOptions(ExportOptions{StateDir: dir, Prepared: prepared, Source: adapter.UsageJSONSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: Simulate crash after journal write
	if err := writeJournal(dir, journal); err != nil {
		t.Fatal(err)
	}

	// Verify journal exists before recovery
	if _, err := os.Stat(JournalPath(dir)); err != nil {
		t.Fatalf("expected journal to exist before recovery: %v", err)
	}

	// Step 2: Perform recovery
	res, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if !res.Recovered || res.BatchID != "batch-recover-rc2" {
		t.Fatalf("unexpected recovery result: %#v", res)
	}

	// Verify batch file was materialized
	assertBatchFile(t, output, "batch-recover-rc2", 1)

	// Verify batch was registered in outbox as pending
	pending, ok, err := outbox.New(dir).NextPending()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || pending.BatchID != "batch-recover-rc2" || pending.File != output {
		t.Fatalf("unexpected recovered outbox entry: %#v ok=%v", pending, ok)
	}

	// Verify progress cursor was advanced
	cursors, err := progress.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].BatchID != "batch-recover-rc2" {
		t.Fatalf("unexpected recovered cursor: %#v", cursors)
	}

	// Verify journal was safely removed
	if _, err := os.Stat(JournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("journal should be removed after recovery, stat err=%v", err)
	}

	// Step 3: Idempotent recovery
	res2, err := Recover(dir)
	if err != nil {
		t.Fatalf("subsequent recover should succeed cleanly: %v", err)
	}
	if res2.Recovered {
		t.Fatalf("subsequent recover should not re-recover: %#v", res2)
	}
}

// TestRC2_CorruptedWAL_FailsClosed_Acceptance tests that a truncated or malformed WAL journal
// fails closed safely without corrupting outbox or progress state.
func TestRC2_CorruptedWAL_FailsClosed_Acceptance(t *testing.T) {
	dir := t.TempDir()

	// Truncated invalid JSON
	corruptBytes := []byte(`{"output": "truncated-file.json", "batchId": "b1"`)
	if err := os.WriteFile(JournalPath(dir), corruptBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Recover(dir)
	if err == nil {
		t.Fatalf("expected error on corrupt journal, got result: %#v", res)
	}

	// Verify no dirty state in outbox
	ob, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ob.Batches) != 0 {
		t.Fatalf("outbox must remain empty on corrupt recovery failure, got %d batches", len(ob.Batches))
	}
}
