package progress

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestAdvanceCreatesAndReplacesCursor(t *testing.T) {
	store := New(t.TempDir())
	at := time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC)
	cursor, err := store.Advance(AdvanceOptions{Source: "codex-jsonl", Input: "/tmp/sessions", BatchID: "batch-1", RecordCount: 2, AdvancedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Source != "codex-jsonl" || cursor.InputHash == "" || cursor.BatchID != "batch-1" || cursor.RecordCount != 2 || !cursor.AdvancedAt.Equal(at) {
		t.Fatalf("unexpected cursor: %#v", cursor)
	}
	if _, err := store.Advance(AdvanceOptions{Source: "codex-jsonl", Input: "/tmp/sessions", BatchID: "batch-2", RecordCount: 3, AdvancedAt: at.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	ledger, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Cursors) != 1 || ledger.Cursors[0].BatchID != "batch-2" || ledger.Cursors[0].RecordCount != 3 {
		t.Fatalf("expected replaced cursor: %#v", ledger)
	}
	b, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"source": "codex-jsonl"`) || !strings.Contains(text, `"batchId": "batch-2"`) {
		t.Fatalf("unexpected cursor file: %s", text)
	}
}

func TestConfirmMarksServerAckWatermark(t *testing.T) {
	store := New(t.TempDir())
	advancedAt := time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC)
	confirmedAt := advancedAt.Add(time.Hour)
	if _, err := store.Advance(AdvanceOptions{Source: "codex-jsonl", Input: "/tmp/sessions", BatchID: "batch-1", RecordCount: 2, AdvancedAt: advancedAt}); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.Confirm(ConfirmOptions{Source: "codex-jsonl", Input: "/tmp/sessions", BatchID: "batch-1", RecordCount: 2, Status: "accepted", ConfirmedAt: confirmedAt})
	if err != nil {
		t.Fatal(err)
	}
	if cursor.BatchID != "batch-1" || cursor.ConfirmedBatchID != "batch-1" || cursor.ConfirmedRecordCount != 2 || cursor.ConfirmedStatus != "accepted" || cursor.ConfirmedAt == nil || !cursor.ConfirmedAt.Equal(confirmedAt) {
		t.Fatalf("unexpected confirmed cursor: %#v", cursor)
	}
	ledger, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Cursors) != 1 || ledger.Cursors[0].ConfirmedBatchID != "batch-1" || ledger.Cursors[0].BatchID != "batch-1" {
		t.Fatalf("unexpected ledger after confirm: %#v", ledger)
	}
}
