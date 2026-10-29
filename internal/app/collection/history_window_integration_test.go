package collection

import (
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

// History widening must recover records filtered during a previous scan,
// even when the second scan produces no new records and the outbox is empty.
func TestHistoryWindowWidenThenNarrow(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 11)
	narrow := "2026-10-20T00:00:00Z"
	server.mu.Lock()
	server.historyFrom = &narrow
	server.mu.Unlock()
	bindDevice(t, stateDir, server.URL)

	input := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, input, "history.jsonl",
		claudeLine(t, "2026-10-10T12:00:00Z", "s1", "old-message", claudeUsage(10, 0, 0, 1)),
		claudeLine(t, "2026-10-25T12:00:00Z", "s2", "new-message", claudeUsage(20, 0, 0, 2)))
	enableGrant(t, stateDir, "claude-code-jsonl", input)
	opt := Options{StateDir: stateDir, HomeDir: t.TempDir(), Now: func() time.Time {
		return time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	}}
	first, err := Run(t.Context(), opt)
	if err != nil {
		t.Fatalf("initial 7-day sync: %v", err)
	}
	if first.SyncedRecords != 1 {
		t.Fatalf("initial sync should contain only recent usage: %+v", first)
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one older quarantined record: entries=%v err=%v", entries, err)
	}

	wide := "2026-09-27T00:00:00Z"
	server.mu.Lock()
	server.historyFrom = &wide
	server.view.revision = 12
	server.mu.Unlock()
	second, err := Run(t.Context(), opt)
	if err != nil {
		t.Fatalf("widened 30-day sync: %v", err)
	}
	if second.Recovered != 1 || second.SyncedRecords != 1 || second.PendingRemaining != 0 {
		t.Fatalf("older usage was not fully recovered: %+v", second)
	}
	entries, err = quarantine.New(stateDir).Load()
	if err != nil || len(entries) != 0 {
		t.Fatalf("recovered entry remains quarantined: entries=%v err=%v", entries, err)
	}

	writeClaudeSession(t, input, "later.jsonl",
		claudeLine(t, "2026-12-24T12:00:00Z", "s3", "later-message", claudeUsage(30, 0, 0, 3)))
	laterCutoff := "2026-12-19T00:00:00Z"
	opt.Now = func() time.Time { return time.Date(2026, 12, 26, 0, 0, 0, 0, time.UTC) }
	server.mu.Lock()
	server.historyFrom = &laterCutoff
	server.view.revision = 13
	server.mu.Unlock()
	third, err := Run(t.Context(), opt)
	if err != nil {
		t.Fatalf("narrowed 7-day sync: %v", err)
	}
	if third.SyncedRecords != 1 {
		t.Fatalf("expected only the new seven-day usage to sync: %+v", third)
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Batches) != 3 {
		t.Fatalf("expected both prior batches and one new batch to remain, got %d", len(ledger.Batches))
	}
	for _, batch := range ledger.Batches {
		if batch.Status != outbox.StatusSynced {
			t.Fatalf("previously synced data changed after narrowing: %+v", batch)
		}
	}
}
