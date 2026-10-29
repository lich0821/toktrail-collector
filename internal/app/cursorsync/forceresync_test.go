// Forced-resync (reinstall recovery) scenarios for cursorsync.Sync:
// Options.ForceResync forces one full-window pull over the current
// authorization that re-emits unchanged events at fresh revisions
// dominating both the local and the server-delivered nextRevision —
// without ever clearing the persistent event cache or resetting the
// revision memory — while pending batches, failed rounds and the
// authorization preflight keep their normal protections.
package cursorsync_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
)

// TestSyncForceResyncReemitsUnchanged is the core reinstall scenario: a
// healthy, fully-synced source with a warm cache and a same-day watermark
// would normally skip everything. A forced round re-pulls the whole
// authorized window, re-emits the unchanged events (not skipped) at the
// folded round revision, uploads them through the normal durable outbox,
// keeps the cache (entries restaged at the fresh revision), advances the
// revision monotonically and stamps the daily full-pull clock. A later
// normal round skips unchanged again — the force lasts exactly one round.
func TestSyncForceResyncReemitsUnchanged(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	e1 := ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	e2 := ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3)
	h.pull.setEvents(e1, e2)

	// Round 1 (normal): both events are new and uploaded; the cache and
	// the daily full-pull clock are warm, so a same-day round 2 would be
	// an overlap pull that skips everything.
	res1, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if res1.NewRecords != 2 || res1.SyncedBatches != 1 || res1.PendingRemaining != 0 {
		t.Fatalf("round 1: %+v", res1)
	}
	lic1 := loadLicense(t, h.dir)
	if lic1.NextRevision != 2 || lic1.PullWatermark == nil || lic1.LastFullPullAt == nil {
		t.Fatalf("round 1 license: %+v", lic1)
	}

	// Round 2 (forced): the whole authorized window is pulled again and
	// the unchanged events are re-emitted, not skipped.
	opt := h.options()
	opt.ForceResync = true
	res2, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("forced round: %v", err)
	}
	calls := h.pull.callLog()
	if len(calls) != 2 || !calls[1].from.IsZero() {
		t.Fatalf("the forced round must pull the whole authorized window, got %+v", calls)
	}
	if res2.ReemittedRecords != 2 || res2.NewRecords != 0 || res2.ReplacedRecords != 0 || res2.SkippedUnchanged != 0 {
		t.Fatalf("forced round stats: %+v", res2)
	}
	if res2.ExportedBatches != 1 || res2.SyncedBatches != 1 || res2.SyncedRecords != 2 || res2.PendingRemaining != 0 {
		t.Fatalf("forced round upload: %+v", res2)
	}
	// The information travels in ReemittedRecords alone: a fully
	// successful forced round must set no Note, or consumers keying
	// success on an empty Note (the periodic layer's synced/leaderboard
	// status receipt) would suppress it.
	if res2.Note != "" {
		t.Fatalf("a fully successful forced round must set no note, got %q", res2.Note)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 2 || len(batches[1].Records) != 2 {
		t.Fatalf("forced upload batches: %+v", batches)
	}
	wantKeys := keySet([]protocol.Event{
		{EventKey: expectedEventKey(t, accountA, "evt-0001")},
		{EventKey: expectedEventKey(t, accountA, "evt-0002")},
	})
	if !keySetEqual(wantKeys, keySet(batches[1].Records)) {
		t.Fatal("the forced round must re-deliver the unchanged events")
	}
	for _, rec := range batches[1].Records {
		if rec.Revision != 2 {
			t.Fatalf("re-emitted revision %d, want the folded round revision 2 (max of local 2 and server 1)", rec.Revision)
		}
	}
	lic2 := loadLicense(t, h.dir)
	if lic2.NextRevision != 3 {
		t.Fatalf("nextRevision %d after the forced round, want the monotonic 3", lic2.NextRevision)
	}
	if lic2.PullWatermark == nil || !lic2.PullWatermark.Equal(baseTime) {
		t.Fatalf("watermark after the forced round: %+v", lic2.PullWatermark)
	}
	cache := loadCache(t, h.dir)
	for _, id := range []string{"evt-0001", "evt-0002"} {
		if entry, ok := cache.Get(expectedEventKey(t, accountA, id)); !ok || entry.Revision != 2 {
			t.Fatalf("cache entry %s must be restaged at the fresh revision (never cleared): %+v ok=%t", id, entry, ok)
		}
	}

	// Round 3 (normal, same day): unchanged events are skipped again.
	res3, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("round 3: %v", err)
	}
	if res3.SkippedUnchanged != 2 || res3.ReemittedRecords != 0 || res3.ExportedBatches != 0 {
		t.Fatalf("round 3 must skip unchanged again: %+v", res3)
	}
}

// TestSyncForceResyncRevisionDominatesLocalServerAndCache pins the
// re-emit revision floor at the sync level: after a server-side rebuild
// raised the server-delivered nextRevision to 10 while the local license
// remembers 4, and the surviving event ledger holds the event at 12 (the
// stale-seeding edge), the forced re-emission carries revision 13 —
// above the server's 10, the local 4 and the cached 12 — and the license
// advances monotonically past it.
func TestSyncForceResyncRevisionDominatesLocalServerAndCache(t *testing.T) {
	h := newHarness(t)
	// The server was rebuilt: same source instance and fence, but the
	// server-delivered nextRevision moved up to 10.
	h.srv.setSource(protocol.Source{
		SourceInstanceID: "src_inst_1",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     10,
	})
	license := activeLicenseForA()
	license.NextRevision = 4 // local memory: revisions 1..3 assigned before
	watermark := baseTime.Add(-2 * time.Hour)
	license.PullWatermark = &watermark
	fullAt := baseTime
	license.LastFullPullAt = &fullAt // same UTC day: without force, an overlap pull
	h.writeLicense(t, license)

	// The event ledger holds the event at revision 12 — above both
	// nextRevision memories (the license was rebuilt while the cache
	// survived). Seed it through the real normalizer so the digest
	// matches what the forced round will pull.
	event := ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	h.pull.setEvents(event)
	cache, err := usage.LoadCache(h.dir)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	_, staged, _, err := usage.Normalize([]api.UsageEvent{event}, identity.SubjectNamespace(testApplication, testSubject), accountA, 12, cache)
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	cache.Apply(staged)
	if err := cache.Commit(); err != nil {
		t.Fatalf("commit cache: %v", err)
	}

	opt := h.options()
	opt.ForceResync = true
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("forced round: %v", err)
	}
	calls := h.pull.callLog()
	if len(calls) != 1 || !calls[0].from.IsZero() {
		t.Fatalf("the forced round must pull the whole authorized window despite the same-day watermark, got %+v", calls)
	}
	if res.ReemittedRecords != 1 || res.NewRecords != 0 || res.SkippedUnchanged != 0 {
		t.Fatalf("forced round stats: %+v", res)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 1 || len(batches[0].Records) != 1 {
		t.Fatalf("forced upload: %+v", batches)
	}
	if rec := batches[0].Records[0]; rec.Revision != 13 {
		t.Fatalf("re-emitted revision %d, want 13 (above cached 12, server 10, local 4)", rec.Revision)
	}
	lic := loadLicense(t, h.dir)
	if lic.NextRevision != 14 {
		t.Fatalf("nextRevision %d after the forced round, want the monotonic 14", lic.NextRevision)
	}
	if entry, ok := loadCache(t, h.dir).Get(expectedEventKey(t, accountA, "evt-0001")); !ok || entry.Revision != 13 {
		t.Fatalf("cache must restage at the fresh revision: %+v ok=%t", entry, ok)
	}
}

// TestSyncForceResyncProtectsPendingAndFailedRounds verifies the durable
// protections around a forced round: a pre-existing pending batch drains
// first with its immutable revisions, an offline forced round leaves its
// re-emitted batch durably pending (watermark, cache and revision memory
// already advanced — never reported as zero usage), and the next normal
// round drains that batch unchanged without re-pulling anything.
func TestSyncForceResyncProtectsPendingAndFailedRounds(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	e1 := ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	e2 := ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3)
	h.pull.setEvents(e1, e2)

	// Round 1 (normal): both events uploaded, cache warm.
	if _, err := cursorsync.Sync(context.Background(), h.options(), syncGate()); err != nil {
		t.Fatalf("round 1: %v", err)
	}

	// Round 2 (forced, upload offline): the forced re-emitted batch stays
	// durably pending; the cache, watermark and revision memory keep the
	// advanced state (a failed round is never a zero-usage round).
	h.srv.setIngestFails(true)
	opt := h.options()
	opt.ForceResync = true
	res2, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err == nil || !strings.Contains(err.Error(), "upload cursor batch") {
		t.Fatalf("the offline forced round must fail on upload, got %v", err)
	}
	if res2.ReemittedRecords != 2 || res2.ExportedBatches != 1 || res2.SyncedBatches != 0 {
		t.Fatalf("offline forced round: %+v", res2)
	}
	if pendingCount(t, h.dir) != 1 {
		t.Fatalf("pending=%d after the offline forced round, want 1", pendingCount(t, h.dir))
	}
	lic := loadLicense(t, h.dir)
	if lic.PullWatermark == nil || !lic.PullWatermark.Equal(baseTime) || lic.NextRevision != 3 {
		t.Fatalf("the offline forced round must keep the advanced memory: %+v", lic)
	}
	if entry, ok := loadCache(t, h.dir).Get(expectedEventKey(t, accountA, "evt-0001")); !ok || entry.Revision != 2 {
		t.Fatalf("the re-emitted cache entry must survive the failed upload: %+v ok=%t", entry, ok)
	}

	// Round 3 (normal retry, server back): the pending forced batch drains
	// with its immutable revisions; nothing is re-emitted or re-pulled.
	h.srv.setIngestFails(false)
	res3, err := cursorsync.Sync(context.Background(), h.options(), syncGate())
	if err != nil {
		t.Fatalf("retry round: %v", err)
	}
	if res3.SyncedBatches != 1 || res3.SyncedRecords != 2 || res3.PendingRemaining != 0 {
		t.Fatalf("retry round: %+v", res3)
	}
	if res3.ReemittedRecords != 0 || res3.SkippedUnchanged != 2 || res3.ExportedBatches != 0 {
		t.Fatalf("the retry must drain the pending batch without re-emitting: %+v", res3)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 2 || len(batches[1].Records) != 2 {
		t.Fatalf("server batches after retry: %+v", batches)
	}
	for _, rec := range batches[1].Records {
		if rec.Revision != 2 {
			t.Fatalf("the drained forced record revision %d, want the immutable 2", rec.Revision)
		}
	}
	if loadLicense(t, h.dir).NextRevision != 3 {
		t.Fatal("the retry must not advance nextRevision")
	}
}

// TestSyncForceResyncDrainsPendingFirstWithImmutableRevisions verifies the
// ordering protection: a pre-existing pending batch (older revisions)
// uploads before the forced round's re-emitted batch (fresh revisions),
// both through the same durable outbox, so an older fact never lands
// after the newer replacement of the same event.
func TestSyncForceResyncDrainsPendingFirstWithImmutableRevisions(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	license := activeLicenseForA()
	watermark := baseTime.Add(-2 * time.Hour)
	license.PullWatermark = &watermark
	h.writeLicense(t, license)
	seedPendingBatch(t, h.dir, "seed-batch-1", 2)
	e1 := ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50)
	e2 := ev("evt-0002", baseTime.Add(-40*time.Minute), 7, 0, 0, 3)
	h.pull.setEvents(e1, e2)

	opt := h.options()
	opt.ForceResync = true
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("forced round with pending backlog: %v", err)
	}
	if res.SyncedBatches != 2 || res.PendingRemaining != 0 {
		t.Fatalf("forced round drain: %+v", res)
	}
	// A fully successful forced round (even one that also drained a
	// backlog) must set no Note, so the periodic layer's synced status
	// receipt keeps flowing; ReemittedRecords carries the information.
	if res.Note != "" {
		t.Fatalf("a fully successful forced round must set no note, got %q", res.Note)
	}
	_, _, _, _, batches := h.srv.stats()
	if len(batches) != 2 {
		t.Fatalf("server batches: %d", len(batches))
	}
	if batches[0].BatchID != "seed-batch-1" {
		t.Fatalf("the pre-existing pending batch must upload first, got %q", batches[0].BatchID)
	}
	for _, rec := range batches[0].Records {
		if rec.Revision != 1 {
			t.Fatalf("the seeded batch must keep its immutable revisions, got %d", rec.Revision)
		}
	}
	// roundRevision = max(local 1, server 1) = 1: the re-emitted records
	// carry the fresh folded revision.
	for _, rec := range batches[1].Records {
		if rec.Revision != 1 {
			t.Fatalf("re-emitted revision %d, want the folded round revision 1", rec.Revision)
		}
	}
}

// TestSyncForceResyncRespectsAuthorization verifies a forced round never
// bypasses the authorization preflight: a narrowed server scope skips the
// round before any credential read, pull or upload, exactly like a
// normal round.
func TestSyncForceResyncRespectsAuthorization(t *testing.T) {
	h := newHarness(t)
	h.srv.setSource(defaultSource())
	h.writeLicense(t, activeLicenseForA())
	h.srv.setAllowedTools([]string{"ClaudeCode", "Codex"})
	h.pull.setEvents(ev("evt-0001", baseTime.Add(-30*time.Minute), 100, 0, 0, 50))

	opt := h.options()
	opt.ForceResync = true
	res, err := cursorsync.Sync(context.Background(), opt, syncGate())
	if err != nil {
		t.Fatalf("forced round under a narrowed scope: %v", err)
	}
	if res.Ran || !strings.Contains(res.Skipped, "not allowed by the effective server grant scope") {
		t.Fatalf("a forced round must not bypass the server scope: ran=%t skipped=%q", res.Ran, res.Skipped)
	}
	if len(h.pull.callLog()) != 0 || h.auth.fetchCount() != 0 {
		t.Fatal("an out-of-scope forced round must neither pull nor read the credential")
	}
	if _, _, ingest, _, _ := h.srv.stats(); ingest != 0 {
		t.Fatal("an out-of-scope forced round must not upload")
	}
}
