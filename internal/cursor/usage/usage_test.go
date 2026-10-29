// Synthetic unit tests for the usage normalizer and its local event
// ledger. All events, accounts and subjects are synthetic; nothing reads
// a real Cursor state or credential.
package usage_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
)

var (
	subjectNS   = identity.SubjectNamespace("app_test0001", "subject-1")
	testAccount = "user_testaccounta"
	baseTS      = time.Date(2026, 10, 28, 11, 30, 0, 0, time.UTC).UnixMilli()
)

// fullEvent carries all four token counts; partialEvent leaves
// CacheRead/CacheWrite unknown (nil).
func fullEvent(id string, in, cacheRead, cacheWrite, out int64) api.UsageEvent {
	return api.UsageEvent{
		UsageEventID: id, TimestampMS: baseTS, Model: "claude-sonnet-4-5",
		InputTokens: &in, CacheReadTokens: &cacheRead, CacheWriteTokens: &cacheWrite, OutputTokens: &out,
	}
}

func partialEvent(id string, in, out int64) api.UsageEvent {
	return api.UsageEvent{
		UsageEventID: id, TimestampMS: baseTS, Model: "claude-sonnet-4-5",
		InputTokens: &in, OutputTokens: &out,
	}
}

func eventKey(t *testing.T, id string) string {
	t.Helper()
	key, err := identity.EventKey(subjectNS, testAccount, id)
	if err != nil {
		t.Fatalf("derive event key: %v", err)
	}
	return key
}

func freshCache(t *testing.T) (*usage.EventCache, string) {
	t.Helper()
	dir := t.TempDir()
	cache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	return cache, dir
}

// commitRound applies staged entries, commits and reopens the cache,
// mirroring one durable round.
func commitRound(t *testing.T, dir string, staged map[string]usage.CacheEntry) *usage.EventCache {
	t.Helper()
	cache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	cache.Apply(staged)
	if err := cache.Commit(); err != nil {
		t.Fatalf("commit cache: %v", err)
	}
	reloaded, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("reload cache: %v", err)
	}
	return reloaded
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestNormalizeFirstCollection covers the first pull: every event with a
// stable id becomes one record carrying the round revision, the derived
// event key and the wire envelope; unknown counts stay nil; the live
// cache is untouched until Apply.
func TestNormalizeFirstCollection(t *testing.T) {
	cache, _ := freshCache(t)
	e1 := fullEvent("evt-0001", 100, 10, 20, 50)
	e2 := partialEvent("evt-0002", 7, 3)

	records, staged, stats, err := usage.Normalize([]api.UsageEvent{e1, e2}, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if stats.NewRecords != 2 || stats.ReplacedRecords != 0 || stats.SkippedUnchanged != 0 || stats.SkippedNoStableID != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(records) != 2 || len(staged) != 2 {
		t.Fatalf("records=%d staged=%d, want 2/2", len(records), len(staged))
	}
	first, second := records[0], records[1]
	if first.EventKey != eventKey(t, "evt-0001") || first.Revision != 5 || first.Kind != "event" ||
		first.Tool != protocol.Tool || first.AdapterVersion != usage.AdapterVersion || first.SourceType != protocol.SourceType {
		t.Fatalf("record envelope: %+v", first)
	}
	if first.OccurredAt != time.UnixMilli(baseTS).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("occurredAt %q", first.OccurredAt)
	}
	if deref(first.Input) != "100" || deref(first.CacheRead) != "10" || deref(first.CacheWrite) != "20" || deref(first.Output) != "50" {
		t.Fatalf("token counts: in=%s cr=%s cw=%s out=%s", deref(first.Input), deref(first.CacheRead), deref(first.CacheWrite), deref(first.Output))
	}
	// Unknown counts stay unknown on the wire.
	if second.CacheRead != nil || second.CacheWrite != nil {
		t.Fatalf("unknown counts must stay nil, got cr=%v cw=%v", second.CacheRead, second.CacheWrite)
	}
	if deref(second.Input) != "7" || deref(second.Output) != "3" {
		t.Fatalf("known counts must carry: in=%s out=%s", deref(second.Input), deref(second.Output))
	}
	for i, rec := range records {
		if err := rec.Validate(); err != nil {
			t.Fatalf("record %d must be wire-valid: %v", i, err)
		}
	}
	// The live cache is read-only here.
	if _, ok := cache.Get(eventKey(t, "evt-0001")); ok {
		t.Fatal("normalize must not mutate the live cache before Apply")
	}
	entry, ok := staged[eventKey(t, "evt-0001")]
	if !ok || entry.Revision != 5 || entry.Digest == "" {
		t.Fatalf("staged entry: %+v ok=%t", entry, ok)
	}
	cache.Apply(staged)
	if entry, ok := cache.Get(eventKey(t, "evt-0001")); !ok || entry.Revision != 5 {
		t.Fatalf("applied entry: %+v ok=%t", entry, ok)
	}
}

// TestNormalizeRepeatedUnchanged covers the repeat pull: identical events
// are skipped, producing no records and no staged entries.
func TestNormalizeRepeatedUnchanged(t *testing.T) {
	cache, dir := freshCache(t)
	events := []api.UsageEvent{fullEvent("evt-0001", 100, 10, 20, 50), partialEvent("evt-0002", 7, 3)}
	_, staged, _, err := usage.Normalize(events, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)

	records, staged2, stats, err := usage.Normalize(events, subjectNS, testAccount, 6, cache)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if stats.SkippedUnchanged != 2 || stats.NewRecords != 0 || stats.ReplacedRecords != 0 {
		t.Fatalf("repeat stats: %+v", stats)
	}
	if len(records) != 0 || len(staged2) != 0 {
		t.Fatalf("repeat produced records=%d staged=%d, want 0/0", len(records), len(staged2))
	}
}

// TestNormalizeSameIDReplaceUpwardAndDownward covers same-usageEventId
// corrections in BOTH directions: the stored event is REPLACED (never
// max-merged), and the cache records the downward digest so a repeat of
// the corrected values is unchanged.
func TestNormalizeSameIDReplaceUpwardAndDownward(t *testing.T) {
	cache, dir := freshCache(t)

	up := func(in, out int64) []api.UsageEvent { return []api.UsageEvent{fullEvent("evt-0001", in, 0, 0, out)} }

	records, staged, stats, err := usage.Normalize(up(100, 50), subjectNS, testAccount, 5, cache)
	if err != nil || stats.NewRecords != 1 {
		t.Fatalf("round 1: %+v err=%v", stats, err)
	}
	cache = commitRound(t, dir, staged)

	// Upward correction.
	records, staged, stats, err = usage.Normalize(up(200, 80), subjectNS, testAccount, 6, cache)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if stats.ReplacedRecords != 1 || stats.NewRecords != 0 {
		t.Fatalf("upward stats: %+v", stats)
	}
	if len(records) != 1 || records[0].Revision != 6 || deref(records[0].Input) != "200" {
		t.Fatalf("upward record: %+v", records[0])
	}
	cache = commitRound(t, dir, staged)

	// Downward correction: replace, never max-merge.
	records, staged, stats, err = usage.Normalize(up(50, 20), subjectNS, testAccount, 7, cache)
	if err != nil {
		t.Fatalf("round 3: %v", err)
	}
	if stats.ReplacedRecords != 1 {
		t.Fatalf("downward stats: %+v", stats)
	}
	if len(records) != 1 || deref(records[0].Input) != "50" || deref(records[0].Output) != "20" {
		t.Fatalf("downward record must carry the lowered counts: in=%s out=%s", deref(records[0].Input), deref(records[0].Output))
	}
	cache = commitRound(t, dir, staged)

	// Repeating the corrected values is unchanged: the cache stored the
	// downward digest, not a historical maximum.
	_, staged, stats, err = usage.Normalize(up(50, 20), subjectNS, testAccount, 8, cache)
	if err != nil {
		t.Fatalf("round 4: %v", err)
	}
	if stats.SkippedUnchanged != 1 || stats.ReplacedRecords != 0 {
		t.Fatalf("post-correction stats: %+v", stats)
	}
	if len(staged) != 0 {
		t.Fatal("an unchanged event must not restage")
	}
}

// TestNormalizeRevisionGuardAboveCachedRevision covers the stale-seeding
// guard: when the cached revision for an event is at or above the round
// revision, the replacement bumps past it instead of colliding.
func TestNormalizeRevisionGuardAboveCachedRevision(t *testing.T) {
	cache, dir := freshCache(t)
	events := []api.UsageEvent{fullEvent("evt-0001", 100, 0, 0, 50)}
	_, staged, _, err := usage.Normalize(events, subjectNS, testAccount, 10, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)

	records, staged, stats, err := usage.Normalize([]api.UsageEvent{fullEvent("evt-0001", 90, 0, 0, 40)}, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if stats.ReplacedRecords != 1 || len(records) != 1 {
		t.Fatalf("guard stats: %+v", stats)
	}
	if records[0].Revision != 11 {
		t.Fatalf("replacement revision %d, want 11 (cached 10 + 1)", records[0].Revision)
	}
	if staged[eventKey(t, "evt-0001")].Revision != 11 {
		t.Fatal("the staged entry must carry the guarded revision")
	}
}

// TestNormalizeSkipsNoStableID covers rows without a stable upstream
// event id: they are counted and skipped, never guessed into an identity.
func TestNormalizeSkipsNoStableID(t *testing.T) {
	cache, _ := freshCache(t)
	idless := partialEvent("", 7, 3)
	idless.UsageEventID = ""
	withID := fullEvent("evt-0001", 1, 0, 0, 1)

	records, staged, stats, err := usage.Normalize([]api.UsageEvent{idless, withID}, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if stats.SkippedNoStableID != 1 || stats.NewRecords != 1 || len(records) != 1 || len(staged) != 1 {
		t.Fatalf("idless stats: %+v records=%d staged=%d", stats, len(records), len(staged))
	}
}

// TestNormalizeRejectsInvalidInput covers the fail-closed validations.
func TestNormalizeRejectsInvalidInput(t *testing.T) {
	cache, _ := freshCache(t)
	events := []api.UsageEvent{fullEvent("evt-0001", 1, 0, 0, 1)}

	if _, _, _, err := usage.Normalize(events, subjectNS, testAccount, 0, cache); err == nil {
		t.Fatal("round revision 0 must be rejected")
	}
	noTimestamp := fullEvent("evt-0002", 1, 0, 0, 1)
	noTimestamp.TimestampMS = 0
	if _, _, _, err := usage.Normalize([]api.UsageEvent{noTimestamp}, subjectNS, testAccount, 5, cache); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("missing timestamp must be rejected, got %v", err)
	}
	// An unusable subject namespace must fail identity derivation rather
	// than fabricate keys.
	if _, _, _, err := usage.Normalize(events, "", testAccount, 5, cache); err == nil {
		t.Fatal("an empty subject namespace must be rejected")
	}
}

// TestNormalizeNilVersusZeroCounts covers the unknown/known boundary: a
// nil count and an explicit zero are different facts, so the correction
// from unknown to zero replaces the record.
func TestNormalizeNilVersusZeroCounts(t *testing.T) {
	cache, dir := freshCache(t)
	_, staged, _, err := usage.Normalize([]api.UsageEvent{partialEvent("evt-0001", 7, 3)}, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)

	zeroed := fullEvent("evt-0001", 7, 0, 0, 3)
	records, _, stats, err := usage.Normalize([]api.UsageEvent{zeroed}, subjectNS, testAccount, 6, cache)
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if stats.ReplacedRecords != 1 {
		t.Fatalf("unknown→zero must replace, stats: %+v", stats)
	}
	if len(records) != 1 || records[0].CacheRead == nil || deref(records[0].CacheRead) != "0" {
		t.Fatalf("the explicit zero must carry on the wire: %+v", records[0])
	}
}

// TestNormalizeForceReemitUnchanged covers the ForceReemitUnchanged
// option (reinstall recovery): unchanged events are re-emitted as
// records carrying the round revision instead of being skipped, the
// staged entries restage at the fresh revision with the same digest, and
// a later default round skips them again — the option changes one round,
// never the ledger semantics.
func TestNormalizeForceReemitUnchanged(t *testing.T) {
	cache, dir := freshCache(t)
	events := []api.UsageEvent{fullEvent("evt-0001", 100, 10, 20, 50), partialEvent("evt-0002", 7, 3)}
	_, staged, _, err := usage.Normalize(events, subjectNS, testAccount, 5, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)
	key1 := eventKey(t, "evt-0001")
	before, _ := cache.Get(key1)

	records, staged2, stats, err := usage.NormalizeWithOptions(events, subjectNS, testAccount, 6, cache, usage.NormalizeOptions{ForceReemitUnchanged: true})
	if err != nil {
		t.Fatalf("forced round: %v", err)
	}
	if stats.ReemittedRecords != 2 || stats.NewRecords != 0 || stats.ReplacedRecords != 0 || stats.SkippedUnchanged != 0 {
		t.Fatalf("forced stats: %+v", stats)
	}
	if len(records) != 2 || len(staged2) != 2 {
		t.Fatalf("forced records=%d staged=%d, want 2/2", len(records), len(staged2))
	}
	for i, rec := range records {
		if err := rec.Validate(); err != nil {
			t.Fatalf("re-emitted record %d must be wire-valid: %v", i, err)
		}
		if rec.Revision != 6 {
			t.Fatalf("re-emitted revision %d, want the round revision 6", rec.Revision)
		}
	}
	if records[0].EventKey != key1 || records[1].EventKey != eventKey(t, "evt-0002") {
		t.Fatal("re-emitted records must keep their event keys")
	}
	entry, ok := staged2[key1]
	if !ok || entry.Revision != 6 || entry.Digest == "" || entry.Digest != before.Digest {
		t.Fatalf("staged re-emit: %+v ok=%t (before %+v)", entry, ok, before)
	}
	cache = commitRound(t, dir, staged2)
	if entry, ok := cache.Get(key1); !ok || entry.Revision != 6 || entry.Digest != before.Digest {
		t.Fatalf("applied re-emit: %+v ok=%t", entry, ok)
	}

	// A later default round skips the unchanged events again.
	_, staged3, stats, err := usage.Normalize(events, subjectNS, testAccount, 7, cache)
	if err != nil {
		t.Fatalf("post round: %v", err)
	}
	if stats.SkippedUnchanged != 2 || stats.ReemittedRecords != 0 || len(staged3) != 0 {
		t.Fatalf("post-forced stats: %+v staged=%d", stats, len(staged3))
	}
}

// TestNormalizeForceReemitRevisionGuard pins the forced re-emit revision
// floor: the re-emitted revision is never at or below the cached revision
// for the event, even when the round revision is lower (stale-seeding
// edge: the license was rebuilt while the ledger survived).
func TestNormalizeForceReemitRevisionGuard(t *testing.T) {
	cache, dir := freshCache(t)
	events := []api.UsageEvent{fullEvent("evt-0001", 100, 0, 0, 50)}
	_, staged, _, err := usage.Normalize(events, subjectNS, testAccount, 10, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)

	records, staged2, stats, err := usage.NormalizeWithOptions(events, subjectNS, testAccount, 5, cache, usage.NormalizeOptions{ForceReemitUnchanged: true})
	if err != nil {
		t.Fatalf("forced round: %v", err)
	}
	if stats.ReemittedRecords != 1 || len(records) != 1 {
		t.Fatalf("guard stats: %+v records=%d", stats, len(records))
	}
	if records[0].Revision != 11 {
		t.Fatalf("re-emitted revision %d, want 11 (cached 10 + 1)", records[0].Revision)
	}
	if entry, ok := staged2[eventKey(t, "evt-0001")]; !ok || entry.Revision != 11 {
		t.Fatalf("the staged re-emit must carry the guarded revision: %+v ok=%t", entry, ok)
	}
}

// TestNormalizeForceReemitMixedRound verifies the per-event accounting
// inside one forced round: an unchanged event, a changed event and a new
// event count separately (re-emitted / replaced / new).
func TestNormalizeForceReemitMixedRound(t *testing.T) {
	cache, dir := freshCache(t)
	_, staged, _, err := usage.Normalize([]api.UsageEvent{
		fullEvent("evt-keep", 5, 0, 0, 5),
		fullEvent("evt-chg", 5, 0, 0, 5),
	}, subjectNS, testAccount, 3, cache)
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	cache = commitRound(t, dir, staged)

	records, _, stats, err := usage.NormalizeWithOptions([]api.UsageEvent{
		fullEvent("evt-keep", 5, 0, 0, 5), // unchanged → re-emitted
		fullEvent("evt-chg", 9, 0, 0, 9),  // changed → replaced
		fullEvent("evt-new", 1, 0, 0, 1),  // never seen → new
	}, subjectNS, testAccount, 4, cache, usage.NormalizeOptions{ForceReemitUnchanged: true})
	if err != nil {
		t.Fatalf("forced round: %v", err)
	}
	if stats.ReemittedRecords != 1 || stats.ReplacedRecords != 1 || stats.NewRecords != 1 || stats.SkippedUnchanged != 0 {
		t.Fatalf("mixed forced stats: %+v", stats)
	}
	if len(records) != 3 {
		t.Fatalf("mixed forced records: %d", len(records))
	}
	for _, rec := range records {
		if rec.Revision != 4 {
			t.Fatalf("record %s revision %d, want the round revision 4", rec.EventKey, rec.Revision)
		}
	}
}

// TestEventCacheApplyCommitReloadDelete covers the ledger persistence:
// commit is a no-op when clean, Apply+Commit persists (0600 on POSIX), reload
// round-trips, corrupt files fail closed, and DeleteCacheFile removes
// exactly once.
func TestEventCacheApplyCommitReloadDelete(t *testing.T) {
	dir := t.TempDir()
	cache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if err := cache.Commit(); err != nil {
		t.Fatalf("clean commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cursor-events.json")); !os.IsNotExist(err) {
		t.Fatalf("a clean commit must not create the ledger file: %v", err)
	}

	key := eventKey(t, "evt-0001")
	cache.Apply(map[string]usage.CacheEntry{key: {Revision: 3, Digest: "deadbeef"}})
	if err := cache.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "cursor-events.json"))
	if err != nil {
		t.Fatalf("ledger file: %v", err)
	}
	// Windows reports synthesized Unix permission bits, not its ACLs.
	// Keep reload/corruption/deletion coverage on every platform below.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger permissions %v, want 0600", info.Mode().Perm())
	}
	reloaded, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if entry, ok := reloaded.Get(key); !ok || entry.Revision != 3 || entry.Digest != "deadbeef" {
		t.Fatalf("reload round-trip: %+v ok=%t", entry, ok)
	}

	if err := os.WriteFile(filepath.Join(dir, "cursor-events.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := usage.LoadCache(dir); err == nil {
		t.Fatal("a corrupt ledger must fail closed")
	}

	removed, err := usage.DeleteCacheFile(dir)
	if err != nil || !removed {
		t.Fatalf("delete: removed=%t err=%v", removed, err)
	}
	if removed, err := usage.DeleteCacheFile(dir); err != nil || removed {
		t.Fatalf("second delete: removed=%t err=%v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cursor-events.json")); !os.IsNotExist(err) {
		t.Fatal("the ledger file must be gone")
	}
}
