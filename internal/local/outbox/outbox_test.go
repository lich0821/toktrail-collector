package outbox

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestOutboxAddNextAndMarkSynced(t *testing.T) {
	store := New(t.TempDir())
	entry, err := store.AddPending(AddBatchOptions{
		BatchID:     "batch-1",
		File:        "batch.json",
		Source:      "usage-json",
		Input:       "records.json",
		RecordCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.BatchID != "batch-1" || entry.Status != StatusPending || entry.RecordCount != 2 || entry.CreatedAt.IsZero() {
		t.Fatalf("unexpected pending entry: %#v", entry)
	}
	pending, ok, err := store.NextPending()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || pending.BatchID != "batch-1" || pending.File != "batch.json" {
		t.Fatalf("unexpected next pending: %#v ok=%v", pending, ok)
	}
	receivedAt := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	if err := store.MarkSynced(Receipt{BatchID: "batch-1", Status: "accepted", AcceptedRecords: 2, ReceivedAt: receivedAt}); err != nil {
		t.Fatal(err)
	}
	_, ok, err = store.NextPending()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no pending entries after mark synced")
	}
	out, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != StatusSynced || out.Batches[0].SyncedAt != receivedAt || out.Batches[0].AcceptedRecords != 2 || out.Batches[0].RejectedRecords != 0 {
		t.Fatalf("unexpected outbox after sync: %#v", out)
	}
	b, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rejectedRecords": 0`) {
		t.Fatalf("expected explicit zero rejected record count in outbox JSON: %s", string(b))
	}
}

func TestOutboxAddPendingRejectsInvalidInput(t *testing.T) {
	store := New(t.TempDir())
	cases := []AddBatchOptions{
		{BatchID: "", File: "batch.json", RecordCount: 1},
		{BatchID: "batch-1", File: "", RecordCount: 1},
		{BatchID: "batch-1", File: "batch.json", RecordCount: -1},
	}
	for _, tc := range cases {
		if _, err := store.AddPending(tc); err == nil {
			t.Fatalf("expected invalid outbox input to fail: %#v", tc)
		}
	}
	out, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 0 {
		t.Fatalf("invalid entries should not be saved: %#v", out)
	}
}

func TestOutboxAddPendingReopensExistingBatch(t *testing.T) {
	store := New(t.TempDir())
	if _, err := store.AddPending(AddBatchOptions{BatchID: "batch-1", File: "old.json", RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSynced(Receipt{BatchID: "batch-1", Status: "accepted", AcceptedRecords: 1, ReceivedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	entry, err := store.AddPending(AddBatchOptions{BatchID: "batch-1", File: "new.json", RecordCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Status != StatusPending || entry.File != "new.json" || entry.RecordCount != 3 || !entry.SyncedAt.IsZero() {
		t.Fatalf("expected reopened pending entry: %#v", entry)
	}
}
