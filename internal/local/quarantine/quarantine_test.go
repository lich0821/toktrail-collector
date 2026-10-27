package quarantine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/progress"
)

func entryFor(key, originBatchID string, record json.RawMessage) Entry {
	return Entry{
		Source:          "usage-json",
		Input:           "/tmp/usage.jsonl",
		RecordKey:       key,
		Record:          record,
		OriginBatchID:   originBatchID,
		Reason:          ReasonToolNotAllowed,
		ConsentRevision: 8,
		QuarantinedAt:   time.Date(2026, 10, 20, 10, 5, 0, 0, time.UTC),
	}
}

func rawRecord(key, tool string) json.RawMessage {
	return json.RawMessage(`{"recordKey":"` + key + `","kind":"delta","occurredAt":"2026-10-20T10:40:00Z","tool":"` + tool + `","input":"7","cacheRead":"0","cacheWrite":"0","output":"2","adapterVersion":"t","sourceType":"fixture"}`)
}

func TestLoadMissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for a missing store, got %#v", entries)
	}
}

func TestAppendPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := store.Append([]Entry{entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "record-a" || entries[0].Reason != ReasonToolNotAllowed {
		t.Fatalf("expected the entry to survive a reload: %#v", entries)
	}
	if entries[0].QuarantinedAt.IsZero() {
		t.Fatal("expected the quarantined timestamp to default to now when unset")
	}
}

func TestAppendRequiresRecordKey(t *testing.T) {
	dir := t.TempDir()
	entry := entryFor("", "batch-1", rawRecord("record-a", "other-tool"))
	if err := New(dir).Append([]Entry{entry}); err == nil || !strings.Contains(err.Error(), "quarantine entry requires a record key") {
		t.Fatalf("expected the missing record key error, got %v", err)
	}
}

func TestAppendDedupesReplays(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	original := entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))
	if err := store.Append([]Entry{original}); err != nil {
		t.Fatal(err)
	}
	// Exact replay: same key, origin batch and record content → no-op.
	if err := store.Append([]Entry{original}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected dedupe to a single entry, got %#v", entries)
	}
	// A re-serialized record with different formatting is still the same
	// record: the store file re-indents embedded records on save/reload, so
	// the dedupe comparison must be formatting-stable.
	reformatted := json.RawMessage("{\n  \"recordKey\": \"record-a\",\n  \"kind\": \"delta\",\n  \"occurredAt\": \"2026-10-20T10:40:00Z\",\n  \"tool\": \"other-tool\",\n  \"input\": \"7\",\n  \"cacheRead\": \"0\",\n  \"cacheWrite\": \"0\",\n  \"output\": \"2\",\n  \"adapterVersion\": \"t\",\n  \"sourceType\": \"fixture\"\n}")
	replay := entryFor("record-a", "batch-1", reformatted)
	if err := New(dir).Append([]Entry{replay}); err != nil {
		t.Fatalf("expected a formatting-only difference to dedupe, got %v", err)
	}
	entries, err = New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected a single entry after the reformatted replay, got %#v", entries)
	}
}

func TestAppendConflictingRecordFails(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := store.Append([]Entry{entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))}); err != nil {
		t.Fatal(err)
	}
	// Same key, different record content: fatal, never a silent overwrite.
	conflict := entryFor("record-a", "batch-1", rawRecord("record-a", "yet-another-tool"))
	err := store.Append([]Entry{conflict})
	if err == nil || !strings.Contains(err.Error(), "conflicts with an already-quarantined entry") {
		t.Fatalf("expected the conflict error, got %v", err)
	}
	// Same key, different origin batch but identical record content: a
	// replay of the same quarantine identity, merged (see
	// TestAppendSameRecordDifferentOriginMerges), never a hard error that
	// would stop collection.
	replayed := entryFor("record-a", "batch-2", rawRecord("record-a", "other-tool"))
	if err := store.Append([]Entry{replayed}); err != nil {
		t.Fatalf("expected the same record under a different origin to merge, got %v", err)
	}
	// The store is unchanged in count and keeps the original provenance.
	entries, loadErr := New(dir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(entries) != 1 || entries[0].OriginBatchID != "batch-1" {
		t.Fatalf("expected a single entry with the original origin: %#v", entries)
	}
}

// TestAppendSameRecordDifferentOriginMerges covers the multi-origin replay:
// the same record quarantined again from a later batch must not error (the
// rc.3 field failure), must stay a single entry, must keep the original
// origin provenance, must refresh a strictly newer consent revision (so
// recovery keeps requiring a newer revision and cannot loop), and must fill
// in message provenance only when the stored entry lacks it.
func TestAppendSameRecordDifferentOriginMerges(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	original := entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))
	if err := store.Append([]Entry{original}); err != nil {
		t.Fatal(err)
	}
	rebatched := entryFor("record-a", "batch-2", rawRecord("record-a", "other-tool"))
	rebatched.Reason = ReasonBeforeHistoryFrom
	rebatched.ConsentRevision = original.ConsentRevision + 1
	rebatched.MessageID = "msg-a"
	rebatched.FromState = &progress.MessageUsageState{Input: u64ptr(3)}
	rebatched.ToState = &progress.MessageUsageState{Input: u64ptr(7)}
	if err := store.Append([]Entry{rebatched}); err != nil {
		t.Fatalf("expected the multi-origin replay to merge, got %v", err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected a single merged entry, got %#v", entries)
	}
	got := entries[0]
	if got.OriginBatchID != "batch-1" {
		t.Fatalf("expected the original origin to be preserved, got %s", got.OriginBatchID)
	}
	if got.ConsentRevision != original.ConsentRevision+1 || got.Reason != ReasonBeforeHistoryFrom {
		t.Fatalf("expected the newer revision and reason to win, got revision %d reason %s", got.ConsentRevision, got.Reason)
	}
	if got.MessageID != "msg-a" || got.FromState == nil || got.ToState == nil {
		t.Fatalf("expected the missing message provenance to be filled in, got %#v", got)
	}
	// A replay carrying an older revision must not roll anything back, and
	// message provenance already present is never overwritten.
	older := entryFor("record-a", "batch-3", rawRecord("record-a", "other-tool"))
	older.ConsentRevision = original.ConsentRevision
	older.MessageID = "msg-a"
	older.FromState = &progress.MessageUsageState{Input: u64ptr(3)}
	older.ToState = &progress.MessageUsageState{Input: u64ptr(7)}
	if err := store.Append([]Entry{older}); err != nil {
		t.Fatalf("expected the older-revision replay to be a no-op, got %v", err)
	}
	entries, err = New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].MessageID != "msg-a" || entries[0].ConsentRevision != original.ConsentRevision+1 {
		t.Fatalf("expected the stored metadata to be untouched by the older replay: %#v", entries)
	}
	// Conflicting message provenance across origins is rejected, never
	// silently resolved, and never drops the stored original entry.
	before, readErr := os.ReadFile(store.Path())
	if readErr != nil {
		t.Fatal(readErr)
	}
	wrongMessage := entryFor("record-a", "batch-4", rawRecord("record-a", "other-tool"))
	wrongMessage.ConsentRevision = original.ConsentRevision + 2
	wrongMessage.MessageID = "msg-other"
	wrongMessage.FromState = &progress.MessageUsageState{Input: u64ptr(3)}
	err = store.Append([]Entry{wrongMessage})
	if err == nil || !strings.Contains(err.Error(), "message msg-a vs msg-other") {
		t.Fatalf("expected the message provenance conflict error, got %v", err)
	}
	wrongState := entryFor("record-a", "batch-5", rawRecord("record-a", "other-tool"))
	wrongState.ConsentRevision = original.ConsentRevision + 2
	wrongState.MessageID = "msg-a"
	wrongState.FromState = &progress.MessageUsageState{Input: u64ptr(999)}
	wrongState.ToState = &progress.MessageUsageState{Input: u64ptr(7)}
	err = store.Append([]Entry{wrongState})
	if err == nil || !strings.Contains(err.Error(), "interval state differs") {
		t.Fatalf("expected the interval state conflict error, got %v", err)
	}
	after, readErr := os.ReadFile(store.Path())
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected metadata conflict must not modify the stored entry")
	}
	// Genuinely different content under any origin stays fatal.
	conflict := entryFor("record-a", "batch-6", rawRecord("record-a", "yet-another-tool"))
	conflict.ConsentRevision = original.ConsentRevision + 5
	err = store.Append([]Entry{conflict})
	if err == nil || !strings.Contains(err.Error(), "conflicts with an already-quarantined entry") {
		t.Fatalf("expected the content conflict error, got %v", err)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := store.Append([]Entry{
		entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool")),
		entryFor("record-b", "batch-1", rawRecord("record-b", "usage-json")),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove([]RemoveKey{{Source: "usage-json", RecordKey: "record-a"}}); err != nil {
		t.Fatal(err)
	}
	// Replayed removals, including unknown identities, are no-ops.
	if err := store.Remove([]RemoveKey{
		{Source: "usage-json", RecordKey: "record-a"},
		{Source: "usage-json", RecordKey: "record-b"},
		{Source: "usage-json", RecordKey: "record-missing"},
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected an empty store, got %#v", entries)
	}
	if err := store.Remove(nil); err != nil {
		t.Fatalf("expected a nil removal to be a no-op, got %v", err)
	}
}

// TestSameKeyAcrossSourcesCoexist: the record key alone is not unique —
// generic usage-json inputs can produce the same key under different
// grants. The compound identity (source + key) keeps both entries, and
// dedupe/conflict checks never mix them up.
func TestSameKeyAcrossSourcesCoexist(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	first := entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))
	second := entryFor("record-a", "batch-2", rawRecord("record-a", "other-tool"))
	second.Source = "codex"
	if err := store.Append([]Entry{first, second}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected both sources' entries to coexist, got %#v", entries)
	}
	sources := map[string]bool{}
	for _, entry := range entries {
		sources[entry.Source] = true
	}
	if !sources["usage-json"] || !sources["codex"] {
		t.Fatalf("expected one entry per source, got %#v", entries)
	}
	// An exact replay of either entry dedupes against its own source only.
	if err := store.Append([]Entry{first}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append([]Entry{second}); err != nil {
		t.Fatal(err)
	}
	entries, err = New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected replays to dedupe per source, got %#v", entries)
	}
	// A conflicting record under one source never touches the other.
	conflict := entryFor("record-a", "batch-1", rawRecord("record-a", "yet-another-tool"))
	conflict.Source = "codex"
	err = store.Append([]Entry{conflict})
	if err == nil || !strings.Contains(err.Error(), "conflicts with an already-quarantined entry") {
		t.Fatalf("expected the cross-source conflict error, got %v", err)
	}
}

// TestRemoveNeverTouchesOtherSource: removing one source's quarantine must
// never silently drop an entry of a different source that happens to share
// the same record key.
func TestRemoveNeverTouchesOtherSource(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	shared := entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))
	other := entryFor("record-a", "batch-2", rawRecord("record-a", "other-tool"))
	other.Source = "codex"
	if err := store.Append([]Entry{shared, other}); err != nil {
		t.Fatal(err)
	}
	// Recovering the usage-json entry removes exactly that identity.
	if err := store.Remove([]RemoveKey{{Source: "usage-json", RecordKey: "record-a"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Source != "codex" || entries[0].RecordKey != "record-a" {
		t.Fatalf("expected the codex entry to survive the usage-json removal, got %#v", entries)
	}
	// A key-only match under a different source is a no-op, not a removal.
	if err := store.Remove([]RemoveKey{{Source: "usage-json", RecordKey: "record-a"}}); err != nil {
		t.Fatal(err)
	}
	entries, err = New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Source != "codex" {
		t.Fatalf("expected the codex entry untouched by the replayed removal, got %#v", entries)
	}
}

func TestCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := os.WriteFile(store.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(dir).Load()
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("expected the corrupt store error, got %v", err)
	}
	// Append must also refuse to run on top of a corrupt store.
	if err := store.Append([]Entry{entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))}); err == nil {
		t.Fatal("expected Append to fail on a corrupt store")
	}
}

func TestPathLayout(t *testing.T) {
	if got, want := New("/tmp/state").Path(), filepath.Join("/tmp/state", "scope-quarantine.json"); got != want {
		t.Fatalf("store path = %q, want %q", got, want)
	}
}

func TestEntryStatesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	entry := entryFor("record-a", "batch-1", rawRecord("record-a", "other-tool"))
	entry.MessageID = "msg-a"
	entry.FromState = &progress.MessageUsageState{Input: u64ptr(3)}
	entry.ToState = &progress.MessageUsageState{Input: u64ptr(7), Output: u64ptr(2)}
	if err := store.Append([]Entry{entry}); err != nil {
		t.Fatal(err)
	}
	entries, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one entry: %#v", entries)
	}
	got := entries[0]
	if got.MessageID != "msg-a" || got.FromState == nil || got.FromState.Input == nil || *got.FromState.Input != 3 || got.ToState == nil || *got.ToState.Input != 7 || *got.ToState.Output != 2 {
		t.Fatalf("expected the message provenance to round-trip: %#v", got)
	}
}

func u64ptr(v uint64) *uint64 { return &v }
