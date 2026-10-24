package syncclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

func TestCodexDuplicateQuarantinePreservesOriginalProvenance(t *testing.T) {
	dir := t.TempDir()
	raw := json.RawMessage(`{"recordKey":"codex-jsonl:abc:2","inputTokens":"99"}`)
	file := filepath.Join(dir, "old.json")
	payload, _ := json.Marshal(BatchRequest{BatchID: "old", Records: []json.RawMessage{raw}})
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "old", Source: "codex-jsonl", Input: "/granted", File: file, Status: outbox.StatusReorganized}}}); err != nil {
		t.Fatal(err)
	}
	prev := quarantine.Entry{Source: "codex-jsonl", Input: "/granted", RecordKey: "codex-jsonl:abc:2", Record: raw, OriginBatchID: "old", Reason: quarantine.ReasonBeforeHistoryFrom, ConsentRevision: 1, QuarantinedAt: time.Unix(100, 0).UTC()}
	store := quarantine.New(dir)
	if err := store.Append([]quarantine.Entry{prev}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(store.Path())
	duplicate := prev
	duplicate.OriginBatchID = "duplicate"
	duplicate.QuarantinedAt = time.Now()
	if err := appendScopeQuarantine(dir, []quarantine.Entry{duplicate}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(store.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("original quarantine provenance changed")
	}
	duplicate.Record = json.RawMessage(`{"recordKey":"codex-jsonl:abc:2","inputTokens":"100"}`)
	if err := appendScopeQuarantine(dir, []quarantine.Entry{duplicate}); err == nil {
		t.Fatal("changed content accepted")
	}
	duplicate = prev
	duplicate.OriginBatchID = "duplicate"
	duplicate.Input = "/another"
	if err := appendScopeQuarantine(dir, []quarantine.Entry{duplicate}); err == nil {
		t.Fatal("different input accepted")
	}
	duplicate = prev
	duplicate.OriginBatchID = "duplicate"
	duplicate.ConsentRevision = 2
	if err := appendScopeQuarantine(dir, []quarantine.Entry{duplicate}); err == nil {
		t.Fatal("different consent accepted")
	}
	after, _ = os.ReadFile(store.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("failed conflict changed quarantine")
	}
}
func TestScopeContinuationRequiresCompletedWAL(t *testing.T) {
	dir := t.TempDir()
	ledger := outbox.New(dir)
	if err := ledger.Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "old", Status: outbox.StatusReorganized}}}); err != nil {
		t.Fatal(err)
	}
	ok, err := ScopeReorganizationComplete(dir, "old")
	if err != nil || !ok {
		t.Fatalf("completed %v %v", ok, err)
	}
	if err := os.WriteFile(filepath.Join(dir, reorgJournalFileName), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	ok, err = ScopeReorganizationComplete(dir, "old")
	if err != nil || ok {
		t.Fatalf("incomplete WAL allowed continuation %v %v", ok, err)
	}
}
