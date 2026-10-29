package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/filtertxn"
	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

func TestFilterHistoryCutoff(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(0, 0, -7)

	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		DeviceID:    "dev-filter-1",
		HistoryFrom: &cutoff,
		HistoryDays: 7,
	}); err != nil {
		t.Fatal(err)
	}

	oldTime := cutoff.Add(-1 * time.Hour).Format(time.RFC3339)
	newTime := cutoff.Add(1 * time.Hour).Format(time.RFC3339)

	records := []adapter.Record{
		{
			"recordKey":  "rec-old-1",
			"occurredAt": oldTime,
			"source":     adapter.ClaudeCodeJSONLSource,
		},
		{
			"recordKey":  "rec-new-1",
			"occurredAt": newTime,
			"source":     adapter.ClaudeCodeJSONLSource,
		},
	}

	tokVal := uint64(100)
	updates := []progress.MessagePendingUpdate{
		{
			MessageID: "msg-old",
			RecordKey: "rec-old-1",
			To: &progress.MessageUsageState{
				Input: &tokVal,
			},
		},
		{
			MessageID: "msg-new",
			RecordKey: "rec-new-1",
			To: &progress.MessageUsageState{
				Input: &tokVal,
			},
		},
	}

	opt := adapter.Options{
		Source:   adapter.ClaudeCodeJSONLSource,
		StateDir: stateDir,
	}

	keptRecords, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err != nil {
		t.Fatalf("FilterHistoryCutoff failed: %v", err)
	}

	if len(keptRecords) != 1 || adapter.StringField(keptRecords[0], "recordKey") != "rec-new-1" {
		t.Fatalf("expected 1 kept record 'rec-new-1', got %v", keptRecords)
	}
	if len(keptUpdates) != 1 || keptUpdates[0].RecordKey != "rec-new-1" {
		t.Fatalf("expected 1 kept update 'rec-new-1', got %v", keptUpdates)
	}

	// Verify old message baseline was established in progress store
	pStore := progress.New(stateDir)
	messages, _, err := pStore.LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	oldMsgKey := adapter.ClaudeCodeJSONLSource + "\x00msg-old"
	entry, ok := messages[oldMsgKey]
	if !ok || entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected confirmed baseline for old message to be set to 100, got: %#v", entry)
	}

	// Verify old record was quarantined with ReasonBeforeHistoryFrom
	qStore := quarantine.New(stateDir)
	entries, err := qStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old-1" || entries[0].Reason != quarantine.ReasonBeforeHistoryFrom {
		t.Fatalf("expected 1 quarantine entry for rec-old-1 with reason %s, got %#v", quarantine.ReasonBeforeHistoryFrom, entries)
	}
}

func TestUnlimitedHistoryKeepsOlderRecords(t *testing.T) {
	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{DeviceID: "dev-unlimited"}); err != nil {
		t.Fatal(err)
	}
	records := []adapter.Record{
		{"recordKey": "older-than-90-days", "occurredAt": "2025-01-01T00:00:00Z"},
		{"recordKey": "recent", "occurredAt": "2026-10-25T12:00:00Z"},
	}
	kept, _, err := FilterHistoryCutoff(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: stateDir}, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || adapter.StringField(kept[0], "recordKey") != "older-than-90-days" {
		t.Fatalf("unlimited history dropped records: %v", kept)
	}
}

func TestHistoryCutoffPropagatesStateErrors(t *testing.T) {
	for _, tc := range []struct {
		file string
		want string
	}{
		{"device.json", "load history cutoff"},
		{"message-progress.json", "confirm skipped history baseline"},
		{"scope-quarantine.json", "quarantine skipped history"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			cutoff := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
			opt := adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}
			if tc.file == "device.json" {
				opt.HistoryFrom = nil
			}
			records := []adapter.Record{{"recordKey": "old", "occurredAt": cutoff.Add(-time.Hour).Format(time.RFC3339)}}
			count := uint64(100)
			updates := []progress.MessagePendingUpdate{{MessageID: "old", RecordKey: "old", To: &progress.MessageUsageState{Input: &count}}}
			_, _, err := FilterHistoryCutoff(opt, records, updates)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

// TestFilterHistoryCutoffKeepsRecordAtExactCutoff pins the strictly-before
// semantics of the range filter: a record at the cutoff itself is in scope.
func TestFilterHistoryCutoffKeepsRecordAtExactCutoff(t *testing.T) {
	cutoff := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	records := []adapter.Record{
		{"recordKey": "rec-at-cutoff", "occurredAt": cutoff.Format(time.RFC3339)},
		{"recordKey": "rec-before-cutoff", "occurredAt": cutoff.Add(-time.Second).Format(time.RFC3339)},
	}
	kept, _, err := FilterHistoryCutoff(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: t.TempDir(), HistoryFrom: &cutoff}, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || adapter.StringField(kept[0], "recordKey") != "rec-at-cutoff" {
		t.Fatalf("expected only the record at the exact cutoff to be kept, got %v", kept)
	}
}

// TestFilterHistoryCutoffManagedOverlayGovernsCutoff verifies the range
// filter honors the server-confirmed managed consent cutoff over the
// bind-time device cutoff, and stamps quarantine entries with the overlay's
// consent revision so recovery needs a strictly newer revision.
func TestFilterHistoryCutoffManagedOverlayGovernsCutoff(t *testing.T) {
	dir := t.TempDir()
	deviceCutoff := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "dev-overlay", HistoryFrom: &deviceCutoff, HistoryDays: 30}); err != nil {
		t.Fatal(err)
	}
	overlayCutoff := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if err := managedconsent.New(dir).Save(managedconsent.Overlay{
		SchemaVersion:   managedconsent.SchemaVersion,
		ConsentRevision: 9,
		HistoryFrom:     &overlayCutoff,
		AppliedAt:       time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	records := []adapter.Record{
		// After the device cutoff but before the overlay cutoff: only the
		// overlay can drop it.
		{"recordKey": "rec-between", "occurredAt": "2026-10-15T00:00:00Z"},
		{"recordKey": "rec-after", "occurredAt": "2026-10-25T00:00:00Z"},
	}
	kept, _, err := FilterHistoryCutoff(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir}, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || adapter.StringField(kept[0], "recordKey") != "rec-after" {
		t.Fatalf("expected the overlay cutoff to drop rec-between, got %v", kept)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-between" {
		t.Fatalf("expected rec-between quarantined, got %#v", entries)
	}
	if entries[0].ConsentRevision != 9 {
		t.Fatalf("expected quarantine entry to carry the overlay revision 9, got %#v", entries[0])
	}
}

// TestFilterHistoryCutoffManagedOverlayUnlimitedOverridesBindCutoff pins
// the widening path: once the grant protocol has been seen, an explicit nil
// HistoryFrom means unlimited history and must NOT fall back to the
// bind-time device cutoff.
func TestFilterHistoryCutoffManagedOverlayUnlimitedOverridesBindCutoff(t *testing.T) {
	dir := t.TempDir()
	deviceCutoff := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "dev-unlimited-overlay", HistoryFrom: &deviceCutoff, HistoryDays: 30}); err != nil {
		t.Fatal(err)
	}
	if err := managedconsent.New(dir).Save(managedconsent.Overlay{
		SchemaVersion:   managedconsent.SchemaVersion,
		ConsentRevision: 11,
		AppliedAt:       time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	records := []adapter.Record{{"recordKey": "rec-old", "occurredAt": "2026-10-01T00:00:00Z"}}
	kept, _, err := FilterHistoryCutoff(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir}, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 {
		t.Fatalf("unlimited overlay must keep records before the bind-time cutoff, got %v", kept)
	}
	if entries, err := quarantine.New(dir).Load(); err != nil || len(entries) != 0 {
		t.Fatalf("unlimited overlay must not quarantine anything, entries=%#v err=%v", entries, err)
	}
}

// TestFilterHistoryCutoffRerunIsIdempotent verifies repeated execution with
// identical inputs: same partition result, exactly one quarantine entry,
// the baseline adopted only once, and no journal left behind.
func TestFilterHistoryCutoffRerunIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	count := uint64(100)
	records := []adapter.Record{
		{"recordKey": "rec-old", "occurredAt": "2026-10-15T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource},
		{"recordKey": "rec-new", "occurredAt": "2026-10-20T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource},
	}
	updates := []progress.MessagePendingUpdate{
		{MessageID: "msg-old", RecordKey: "rec-old", To: &progress.MessageUsageState{Input: &count}},
		{MessageID: "msg-new", RecordKey: "rec-new", To: &progress.MessageUsageState{Input: &count}},
	}
	opt := adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}
	for run := 1; run <= 2; run++ {
		kept, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if len(kept) != 1 || adapter.StringField(kept[0], "recordKey") != "rec-new" || len(keptUpdates) != 1 || keptUpdates[0].RecordKey != "rec-new" {
			t.Fatalf("run %d: unexpected partition result kept=%v updates=%v", run, kept, keptUpdates)
		}
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old" {
		t.Fatalf("expected exactly one quarantine entry for rec-old, got %#v", entries)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	entry := messages[adapter.ClaudeCodeJSONLSource+"\x00msg-old"]
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected confirmed baseline 100 for msg-old, got %#v", entry)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("journal must be removed after each run, stat err=%v", statErr)
	}
}

// TestFilterHistoryCutoffHealsQuarantineWithoutBaseline models the
// residual crash window the apply order guards: the quarantine half of a
// transaction is durable, the baseline half is missing, and even the
// journal is gone. Because the baseline was never written, the adapter
// re-emits the skipped interval, the filter re-derives the same
// transaction, and the state converges. (With the reverse order — baseline
// without quarantine — this state is a permanent loss; see
// TestLegacyBaselineWithoutQuarantineLosesRecord.)
func TestFilterHistoryCutoffHealsQuarantineWithoutBaseline(t *testing.T) {
	dir := t.TempDir()
	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	oldRecord := adapter.Record{"recordKey": "rec-old", "occurredAt": "2026-10-15T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource}
	raw, err := json.Marshal(oldRecord)
	if err != nil {
		t.Fatal(err)
	}
	// The quarantine half survived a crash; no baseline, no journal.
	if err := quarantine.New(dir).Append([]quarantine.Entry{{
		Source:        adapter.ClaudeCodeJSONLSource,
		RecordKey:     "rec-old",
		Record:        raw,
		OriginBatchID: "batch-crashed",
		Reason:        quarantine.ReasonBeforeHistoryFrom,
		QuarantinedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	}}); err != nil {
		t.Fatal(err)
	}
	count := uint64(100)
	records := []adapter.Record{oldRecord, {"recordKey": "rec-new", "occurredAt": "2026-10-20T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource}}
	updates := []progress.MessagePendingUpdate{
		{MessageID: "msg-old", RecordKey: "rec-old", To: &progress.MessageUsageState{Input: &count}},
		{MessageID: "msg-new", RecordKey: "rec-new", To: &progress.MessageUsageState{Input: &count}},
	}
	opt := adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}
	kept, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || adapter.StringField(kept[0], "recordKey") != "rec-new" || len(keptUpdates) != 1 {
		t.Fatalf("unexpected partition result kept=%v updates=%v", kept, keptUpdates)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	entry := messages[adapter.ClaudeCodeJSONLSource+"\x00msg-old"]
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected the missing baseline to be re-established, got %#v", entry)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old" {
		t.Fatalf("expected a single quarantine entry after healing, got %#v", entries)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("journal must be removed after healing, stat err=%v", statErr)
	}
}

// TestFilterHistoryCutoffRecoversInterruptedTransaction is the main fault
// test for the journal: the baseline half of the transaction fails (message
// progress is corrupt), leaving the journal behind with the quarantine half
// applied. After the store is repaired, the next filter call — which by
// then sees nothing to skip anymore — must still replay the journal to
// completion before doing anything else.
func TestFilterHistoryCutoffRecoversInterruptedTransaction(t *testing.T) {
	dir := t.TempDir()
	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	count := uint64(100)
	records := []adapter.Record{
		{"recordKey": "rec-old", "occurredAt": "2026-10-15T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource},
		{"recordKey": "rec-new", "occurredAt": "2026-10-20T00:00:00Z", "source": adapter.ClaudeCodeJSONLSource},
	}
	updates := []progress.MessagePendingUpdate{
		{MessageID: "msg-old", RecordKey: "rec-old", To: &progress.MessageUsageState{Input: &count}},
		{MessageID: "msg-new", RecordKey: "rec-new", To: &progress.MessageUsageState{Input: &count}},
	}
	opt := adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}

	// Crash simulation: the baseline store is unreadable exactly when the
	// transaction tries to apply its second half.
	progressPath := progress.New(dir).MessageProgressPath()
	if err := os.WriteFile(progressPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := FilterHistoryCutoff(opt, records, updates)
	if err == nil || !strings.Contains(err.Error(), "confirm skipped history baseline") {
		t.Fatalf("expected the interrupted transaction to fail on the baseline half, got %v", err)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old" {
		t.Fatalf("expected the quarantine half applied before the failure, got %#v", entries)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); statErr != nil {
		t.Fatalf("journal must survive the interrupted apply, stat err=%v", statErr)
	}

	// Repair the store; the next run sees only the post-cutoff record (the
	// crashed run's batch was never committed), so nothing new is skipped —
	// yet the pending transaction must still be completed first.
	if err := os.Remove(progressPath); err != nil {
		t.Fatal(err)
	}
	kept, keptUpdates, err := FilterHistoryCutoff(opt, records[1:], updates[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || len(keptUpdates) != 1 {
		t.Fatalf("unexpected partition result kept=%v updates=%v", kept, keptUpdates)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	entry := messages[adapter.ClaudeCodeJSONLSource+"\x00msg-old"]
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected the recovered transaction to establish the msg-old baseline, got %#v", entry)
	}
	entries, err = quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old" {
		t.Fatalf("expected a single quarantine entry after recovery, got %#v", entries)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("journal must be removed after recovery, stat err=%v", statErr)
	}
}

// TestFilterHistoryCutoffFailsClosedOnCorruptJournal verifies a torn or
// foreign-schema journal stops the filter instead of being guessed away.
func TestFilterHistoryCutoffFailsClosedOnCorruptJournal(t *testing.T) {
	dir := t.TempDir()
	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filtertxn.JournalPath(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	records := []adapter.Record{{"recordKey": "rec-new", "occurredAt": "2026-10-20T00:00:00Z"}}
	_, _, err := FilterHistoryCutoff(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}, records, nil)
	if err == nil || !strings.Contains(err.Error(), "recover pending history-filter transaction") {
		t.Fatalf("expected fail-closed recovery error, got %v", err)
	}
	if inner := err.Error(); !strings.Contains(inner, "failing closed") {
		t.Fatalf("expected the fail-closed journal error to surface, got %v", err)
	}
}

// TestLegacyBaselineWithoutQuarantineLosesRecord documents, end to end
// through the real claude-code-jsonl adapter, why the baseline must never
// be written ahead of the quarantine entries. It recreates the exact state
// a pre-transaction collector left behind when it crashed between the two
// writes: the message baseline is confirmed, the quarantine entry is
// missing. The adapter then sees zero growth and never re-emits the
// interval, so no later run can quarantine (and later recover) the record.
//
// This is an honest limitation, not a guarantee of repair: state directories
// already damaged this way cannot be reconstructed here, because the raw
// record bytes are gone and re-deriving the interval from the source logs
// would be guessing. The journal exists so this state can no longer be
// produced; the control run in this test shows what a healthy run does.
func TestLegacyBaselineWithoutQuarantineLosesRecord(t *testing.T) {
	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

	run := func(t *testing.T, simulateLegacyCrash bool) {
		dir := t.TempDir()
		sessions := filepath.Join(dir, "sessions")
		if err := os.MkdirAll(sessions, 0o700); err != nil {
			t.Fatal(err)
		}
		writeClaudeSessionJSONL(t, filepath.Join(sessions, "session-a.jsonl"),
			claudeSessionFixture("2026-10-15T01:00:00Z", "msg_old", 10, 5))
		if simulateLegacyCrash {
			// The pre-fix crash state: baseline written, quarantine lost.
			input, cacheRead, cacheWrite, output := uint64(10), uint64(0), uint64(0), uint64(5)
			if err := progress.New(dir).EstablishConfirmedBaseline(adapter.ClaudeCodeJSONLSource, []progress.MessagePendingUpdate{{
				MessageID: "msg_old",
				RecordKey: "rec-old",
				To:        &progress.MessageUsageState{Input: &input, CacheRead: &cacheRead, CacheWrite: &cacheWrite, Output: &output},
			}}); err != nil {
				t.Fatal(err)
			}
		}
		prepared, err := PrepareExport(adapter.Options{
			Source:      adapter.ClaudeCodeJSONLSource,
			Input:       sessions,
			Output:      filepath.Join(dir, "batch.json"),
			BatchID:     "batch-legacy",
			StateDir:    dir,
			HistoryFrom: &cutoff,
		})
		if err != nil {
			t.Fatal(err)
		}
		entries, err := quarantine.New(dir).Load()
		if err != nil {
			t.Fatal(err)
		}
		if simulateLegacyCrash {
			if prepared.Records != 0 {
				t.Fatalf("legacy crash state: expected the adapter to suppress the interval, got %d records", prepared.Records)
			}
			if len(entries) != 0 {
				t.Fatalf("legacy crash state: quarantine store should stay empty, got %#v", entries)
			}
		} else {
			// Control: without the orphaned baseline the same input is
			// skipped by the filter and durably quarantined, so a later
			// widening of the history window can recover it.
			if prepared.Records != 0 {
				t.Fatalf("control: expected the pre-cutoff record to be filtered out, got %d records", prepared.Records)
			}
			if len(entries) != 1 {
				t.Fatalf("control: expected the skipped record to be quarantined, got %#v", entries)
			}
		}
	}
	t.Run("control", func(t *testing.T) { run(t, false) })
	t.Run("legacy crash state", func(t *testing.T) { run(t, true) })
}

// writePendingFilterJournal simulates the on-disk state of a crash between
// journal write and journal apply: the full transaction intent is durable,
// but neither store was touched.
func writePendingFilterJournal(t *testing.T, dir string, journal filtertxn.Journal) {
	t.Helper()
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filtertxn.JournalPath(dir), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestPrepareExportRecoversPendingJournalBeforeAdapterLoad pins the recovery
// placement: a pending filter transaction is replayed BEFORE the adapter
// loads records. With the baseline half of the pending journal applied
// first, the claude-code-jsonl adapter sees the confirmed baseline, emits no
// interval, and the filter has nothing to skip — proving the adapter read
// converged state. (Had the adapter loaded first, it would have re-emitted
// the full interval and the filter would have quarantined it.)
func TestPrepareExportRecoversPendingJournalBeforeAdapterLoad(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	writeClaudeSessionJSONL(t, filepath.Join(sessions, "session-a.jsonl"),
		claudeSessionFixture("2026-10-15T01:00:00Z", "msg_old", 10, 5))

	input, cacheRead, cacheWrite, output := uint64(10), uint64(0), uint64(0), uint64(5)
	writePendingFilterJournal(t, dir, filtertxn.Journal{
		Schema:    filtertxn.SchemaVersion,
		Source:    adapter.ClaudeCodeJSONLSource,
		Input:     sessions,
		Baselines: []progress.MessagePendingUpdate{{MessageID: "msg_old", RecordKey: "rec-old", To: &progress.MessageUsageState{Input: &input, CacheRead: &cacheRead, CacheWrite: &cacheWrite, Output: &output}}},
		CreatedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	})

	cutoff := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	prepared, err := PrepareExport(adapter.Options{
		Source:      adapter.ClaudeCodeJSONLSource,
		Input:       sessions,
		Output:      filepath.Join(dir, "batch.json"),
		BatchID:     "batch-recover",
		StateDir:    dir,
		HistoryFrom: &cutoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Records != 0 {
		t.Fatalf("expected the recovered baseline to suppress the interval before the adapter ran, got %d records", prepared.Records)
	}
	messages, _, err := progress.New(dir).LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	entry := messages[adapter.ClaudeCodeJSONLSource+"\x00msg_old"]
	if entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 10 {
		t.Fatalf("expected the pending journal's baseline to be applied, got %#v", entry)
	}
	entries, err := quarantine.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("recovery before the adapter load must not re-quarantine the interval, got %#v", entries)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("journal must be removed after recovery, stat err=%v", statErr)
	}
}

// TestScanStaysReadOnlyWithPendingJournal pins the deliberate boundary:
// Scan (and Preview) never mutate state — diagnostic.Privacy promises no
// state mutation — so a pending filter journal is left for the next export
// to recover rather than being replayed by a read.
func TestScanStaysReadOnlyWithPendingJournal(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	writeClaudeSessionJSONL(t, filepath.Join(sessions, "session-a.jsonl"),
		claudeSessionFixture("2026-10-15T01:00:00Z", "msg_old", 10, 5))

	input, cacheRead, cacheWrite, output := uint64(10), uint64(0), uint64(0), uint64(5)
	writePendingFilterJournal(t, dir, filtertxn.Journal{
		Schema:    filtertxn.SchemaVersion,
		Source:    adapter.ClaudeCodeJSONLSource,
		Input:     sessions,
		Baselines: []progress.MessagePendingUpdate{{MessageID: "msg_old", RecordKey: "rec-old", To: &progress.MessageUsageState{Input: &input, CacheRead: &cacheRead, CacheWrite: &cacheWrite, Output: &output}}},
		CreatedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	})

	res, err := Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: sessions, StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	// The adapter read the pre-recovery state (no baseline yet), so the
	// interval is reported; the point of this test is that Scan leaves the
	// pending journal untouched for the next export to converge.
	if res.RecordCount != 1 {
		t.Fatalf("expected the unrecovered interval to be scanned, got %d records", res.RecordCount)
	}
	if _, statErr := os.Stat(filtertxn.JournalPath(dir)); statErr != nil {
		t.Fatalf("read-only Scan must leave the pending journal in place, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(progress.New(dir).MessageProgressPath()); !os.IsNotExist(statErr) {
		t.Fatalf("read-only Scan must not write message progress, stat err=%v", statErr)
	}
}

func claudeSessionFixture(timestamp, msgID string, input, output int) map[string]any {
	return map[string]any{
		"type":      "assistant",
		"timestamp": timestamp,
		"message": map[string]any{
			"id": msgID,
			"usage": map[string]any{
				"input_tokens":                input,
				"cache_read_input_tokens":     0,
				"cache_creation_input_tokens": 0,
				"output_tokens":               output,
			},
		},
	}
}

func writeClaudeSessionJSONL(t *testing.T, path string, lines ...map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, line := range lines {
		if err := enc.Encode(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
