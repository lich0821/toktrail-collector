package filtertxn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
)

func uint64Ptr(v uint64) *uint64 { return &v }

func testJournal() Journal {
	created := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return Journal{
		Schema: SchemaVersion,
		Source: "claude-code-jsonl",
		Input:  "/tmp/sessions",
		Quarantine: []quarantine.Entry{{
			Source:          "claude-code-jsonl",
			RecordKey:       "rec-old-1",
			Record:          []byte(`{"recordKey":"rec-old-1","occurredAt":"2026-10-01T00:00:00Z"}`),
			OriginBatchID:   "batch-1",
			Reason:          quarantine.ReasonBeforeHistoryFrom,
			ConsentRevision: 7,
			QuarantinedAt:   created,
		}},
		Baselines: []progress.MessagePendingUpdate{{
			MessageID: "msg-old-1",
			RecordKey: "rec-old-1",
			To:        &progress.MessageUsageState{Input: uint64Ptr(100)},
		}},
		CreatedAt: created,
	}
}

func quarantineEntries(t *testing.T, dir string) []quarantine.Entry {
	t.Helper()
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func messageProgress(t *testing.T, dir, source, messageID string) progress.MessageProgress {
	t.Helper()
	messages, _, err := progress.New(dir).MessageProgressFor(source)
	if err != nil {
		t.Fatal(err)
	}
	return messages[messageID]
}

func journalExists(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(JournalPath(dir))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

func TestCommitAppliesBothHalvesAndRemovesJournal(t *testing.T) {
	dir := t.TempDir()
	if err := Commit(dir, testJournal()); err != nil {
		t.Fatal(err)
	}
	entries := quarantineEntries(t, dir)
	if len(entries) != 1 || entries[0].RecordKey != "rec-old-1" || entries[0].Reason != quarantine.ReasonBeforeHistoryFrom || entries[0].ConsentRevision != 7 {
		t.Fatalf("unexpected quarantine entries: %#v", entries)
	}
	entry := messageProgress(t, dir, "claude-code-jsonl", "msg-old-1")
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected confirmed baseline 100 for msg-old-1, got %#v", entry)
	}
	if journalExists(t, dir) {
		t.Fatal("journal must be removed after a successful commit")
	}
}

func TestCommitReplayIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := Commit(dir, testJournal()); err != nil {
			t.Fatalf("commit %d: %v", i+1, err)
		}
	}
	if entries := quarantineEntries(t, dir); len(entries) != 1 {
		t.Fatalf("expected exactly one quarantine entry after replay, got %#v", entries)
	}
	entry := messageProgress(t, dir, "claude-code-jsonl", "msg-old-1")
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected unchanged confirmed baseline 100 after replay, got %#v", entry)
	}
	if journalExists(t, dir) {
		t.Fatal("journal must be removed after replay")
	}
}

func TestCommitRequiresStateDir(t *testing.T) {
	if err := Commit("  ", testJournal()); err == nil || !strings.Contains(err.Error(), "state dir") {
		t.Fatalf("expected missing state dir error, got %v", err)
	}
}

func TestCommitRejectsMalformedJournal(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Journal)
		wantMsg string
	}{
		{"schema", func(j *Journal) { j.Schema = 99 }, "unsupported schema"},
		{"createdAt", func(j *Journal) { j.CreatedAt = time.Time{} }, "createdAt"},
		{"entry key", func(j *Journal) { j.Quarantine[0].RecordKey = " " }, "record key"},
		{"entry reason", func(j *Journal) { j.Quarantine[0].Reason = "" }, "reason"},
		{"entry quarantinedAt", func(j *Journal) { j.Quarantine[0].QuarantinedAt = time.Time{} }, "quarantinedAt"},
		{"baseline message", func(j *Journal) { j.Baselines[0].MessageID = "" }, "message id"},
		{"baseline to", func(j *Journal) { j.Baselines[0].To = nil }, "to-state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			journal := testJournal()
			tc.mutate(&journal)
			err := Commit(dir, journal)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("expected %q error, got %v", tc.wantMsg, err)
			}
			if entries := quarantineEntries(t, dir); len(entries) != 0 {
				t.Fatalf("rejected journal must not touch the quarantine store, got %#v", entries)
			}
			if journalExists(t, dir) {
				t.Fatal("rejected journal must not leave a journal file behind")
			}
		})
	}
}

func TestRecoverCompletesUnappliedJournal(t *testing.T) {
	dir := t.TempDir()
	// A crash between journal write and the first apply step: the journal
	// exists, neither store was touched.
	if err := writeJournal(dir, testJournal()); err != nil {
		t.Fatal(err)
	}
	recovered, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("expected recovery to report a replayed journal")
	}
	if entries := quarantineEntries(t, dir); len(entries) != 1 || entries[0].RecordKey != "rec-old-1" {
		t.Fatalf("unexpected quarantine entries after recovery: %#v", entries)
	}
	entry := messageProgress(t, dir, "claude-code-jsonl", "msg-old-1")
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected recovered baseline 100, got %#v", entry)
	}
	if journalExists(t, dir) {
		t.Fatal("journal must be removed after recovery")
	}
}

func TestRecoverCompletesPartiallyAppliedJournal(t *testing.T) {
	dir := t.TempDir()
	journal := testJournal()
	// A crash between the two apply steps: the quarantine half is already
	// durable, the baseline half is missing, and the journal is still there.
	if err := quarantine.New(dir).Append(journal.Quarantine); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(dir); err != nil {
		t.Fatal(err)
	}
	entry := messageProgress(t, dir, "claude-code-jsonl", "msg-old-1")
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected recovered baseline 100, got %#v", entry)
	}
	if entries := quarantineEntries(t, dir); len(entries) != 1 {
		t.Fatalf("expected a single quarantine entry after partial-apply recovery, got %#v", entries)
	}
	if journalExists(t, dir) {
		t.Fatal("journal must be removed after recovery")
	}
}

func TestRecoverWithoutJournalIsNoop(t *testing.T) {
	dir := t.TempDir()
	recovered, err := Recover(dir)
	if err != nil || recovered {
		t.Fatalf("expected no recovery without a journal, got recovered=%v err=%v", recovered, err)
	}
	if entries := quarantineEntries(t, dir); len(entries) != 0 {
		t.Fatalf("no-op recovery must not touch the quarantine store, got %#v", entries)
	}
}

func TestRecoverFailsClosedOnCorruptJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(JournalPath(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(dir); err == nil || !strings.Contains(err.Error(), "failing closed") {
		t.Fatalf("expected fail-closed corrupt journal error, got %v", err)
	}
	if entries := quarantineEntries(t, dir); len(entries) != 0 {
		t.Fatalf("corrupt journal must not touch the quarantine store, got %#v", entries)
	}
	if _, statErr := os.Stat(progress.New(dir).MessageProgressPath()); !os.IsNotExist(statErr) {
		t.Fatalf("corrupt journal must not create message progress state, stat err=%v", statErr)
	}
	if !journalExists(t, dir) {
		t.Fatal("corrupt journal must be left in place for the user to decide")
	}
}

func TestRecoverKeepsJournalWhenApplyFailsThenSucceedsAfterRepair(t *testing.T) {
	dir := t.TempDir()
	journal := testJournal()
	if err := writeJournal(dir, journal); err != nil {
		t.Fatal(err)
	}
	// The baseline half cannot be applied: message progress is corrupt.
	progressPath := progress.New(dir).MessageProgressPath()
	if err := os.WriteFile(progressPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Recover(dir)
	if err == nil || !strings.Contains(err.Error(), "confirm skipped history baseline") {
		t.Fatalf("expected baseline apply error, got %v", err)
	}
	if !journalExists(t, dir) {
		t.Fatal("journal must survive a failed apply for replay")
	}
	// The quarantine half was already applied; the baseline half was not.
	if entries := quarantineEntries(t, dir); len(entries) != 1 {
		t.Fatalf("expected the quarantine half applied, got %#v", entries)
	}
	// Repair the store: with the corrupt file gone, no baseline can have
	// been written, so the replay must still have work to do.
	if err := os.Remove(progressPath); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(progressPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no message progress after repair, stat err=%v", statErr)
	}
	recovered, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("expected the repaired replay to report recovery")
	}
	entry := messageProgress(t, dir, "claude-code-jsonl", "msg-old-1")
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected recovered baseline 100, got %#v", entry)
	}
	if entries := quarantineEntries(t, dir); len(entries) != 1 {
		t.Fatalf("expected a single quarantine entry after repair, got %#v", entries)
	}
	if journalExists(t, dir) {
		t.Fatal("journal must be removed after successful replay")
	}
}

func TestJournalPathLivesInStateDir(t *testing.T) {
	if got, want := JournalPath(filepath.Join("x", "y")), filepath.Join("x", "y", "filter-transaction.json"); got != want {
		t.Fatalf("JournalPath = %q, want %q", got, want)
	}
}
