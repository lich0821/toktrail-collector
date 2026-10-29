// Package usage normalizes pulled Cursor usage snapshots into the
// account-level source-batch wire records (internal/cursor/protocol) and
// keeps the local per-source event ledger used for dedupe and replacement.
//
// Parsing and revision assignment are pure and tested with synthetic
// fixtures only. Raw upstream responses are never persisted: events are
// projected to protocol.Event values in memory and the local cache keeps
// only pseudonymous event identities, revisions and counter digests.
//
// Unknown counters stay unknown: an absent upstream count (nil) is
// preserved as an absent wire field, never filled with zero.
package usage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
)

// AdapterVersion labels the normalization output on the wire.
const AdapterVersion = "cursor-dashboard-api-v1"

// NormalizeStats reports what one normalization round produced.
type NormalizeStats struct {
	NewRecords       int
	ReplacedRecords  int
	SkippedUnchanged int
	// SkippedNoStableID counts rows without a stable upstream event id:
	// they cannot receive a stable eventKey and are never guessed into
	// one (a fabricated identity would double-count the event).
	SkippedNoStableID int
	// ReemittedRecords counts unchanged events re-emitted (instead of
	// skipped) because NormalizeOptions.ForceReemitUnchanged was set:
	// their content matches the cached entry, but the round re-delivers
	// them so a rebuilt or reinstalled deployment recovers the full
	// authorized range. They are neither new nor replaced — the server
	// already holds the same fact; the re-delivery re-asserts it at a
	// fresh revision.
	ReemittedRecords int
}

// NormalizeOptions extends Normalize with per-round behavioral switches.
// The zero value preserves the default semantics exactly.
type NormalizeOptions struct {
	// ForceReemitUnchanged re-emits unchanged events (same content digest
	// as the cached entry) as records carrying a fresh revision instead
	// of skipping them. The fresh revision is the round revision — which
	// the caller derives as the max of the local and the server-delivered
	// nextRevision — bumped past the event's cached revision whenever
	// needed, so the re-delivery can never be stale against either
	// memory. The cache itself is never cleared: a re-emitted entry
	// simply restages at the fresh revision with the same digest, keeping
	// the ledger monotonic.
	//
	// This powers reinstall recovery (cursorsync.Options.ForceResync):
	// the server's view of the account source is rebuilt from the
	// currently authorized window even when the local cache considers
	// every event unchanged.
	ForceReemitUnchanged bool
}

// Normalize converts one round's collapsed snapshots into upload records
// with the default options. See NormalizeWithOptions for the full
// contract.
func Normalize(events []api.UsageEvent, subjectID, accountID string, roundRevision int64, cache *EventCache) ([]protocol.Event, map[string]CacheEntry, NormalizeStats, error) {
	return NormalizeWithOptions(events, subjectID, accountID, roundRevision, cache, NormalizeOptions{})
}

// NormalizeWithOptions converts one round's collapsed snapshots into
// upload records under the given per-round options.
//
// Input must already be collapsed per response (api.CollapseSnapshots):
// rows sharing a UsageEventID are cumulative snapshot re-deliveries of one
// billable event and must NEVER be summed. Across pulls this layer
// REPLACES the stored event for a usageEventId (never max-merges) so
// upstream corrections, including downward ones, apply.
//
// Revision rule: all new and changed events in one round share the round
// revision (roundRevision, assigned by the caller from the license
// NextRevision and persisted with the batch before upload); unchanged
// events (same counter digest as the cache) are skipped — unless
// opts.ForceReemitUnchanged re-emits them (see NormalizeOptions). A
// per-event guard keeps the assigned revision strictly above any cached
// revision for the same event, so a replacement (or a forced re-emission)
// can never collide with the fact it replaces.
//
// The cache is read-only here: staged entries are returned separately and
// must be applied (EventCache.Apply + Commit) by the caller only after
// the resulting batch is durable in the cursor outbox — a failed or
// interrupted round therefore never pollutes the live cache. Error
// messages never embed raw upstream event ids (they are untrusted data).
func NormalizeWithOptions(events []api.UsageEvent, subjectID, accountID string, roundRevision int64, cache *EventCache, opts NormalizeOptions) ([]protocol.Event, map[string]CacheEntry, NormalizeStats, error) {
	if roundRevision < 1 {
		return nil, nil, NormalizeStats{}, errors.New("round revision must be positive")
	}
	var records []protocol.Event
	staged := map[string]CacheEntry{}
	stats := NormalizeStats{}
	for _, ev := range events {
		id := strings.TrimSpace(ev.UsageEventID)
		if id == "" {
			stats.SkippedNoStableID++
			continue
		}
		eventKey, err := identity.EventKey(subjectID, accountID, id)
		if err != nil {
			return nil, nil, NormalizeStats{}, fmt.Errorf("cursor event identity derivation failed: %w", err)
		}
		if ev.TimestampMS == 0 {
			return nil, nil, NormalizeStats{}, errors.New("cursor usage event is missing its timestamp")
		}
		digest := eventDigest(ev)
		cached, has := cache.Get(eventKey)
		unchanged := has && cached.Digest == digest
		if unchanged && !opts.ForceReemitUnchanged {
			stats.SkippedUnchanged++
			continue
		}
		rev := roundRevision
		if has && cached.Revision >= rev {
			// Never reuse or regress below a revision this event already
			// carries (stale seeding edge): bump past it. For a forced
			// re-emission this also guarantees the re-delivered revision
			// stays strictly above the event's cached revision.
			rev = cached.Revision + 1
		}
		rec := protocol.Event{
			EventKey:       eventKey,
			Revision:       rev,
			Kind:           "event",
			OccurredAt:     time.UnixMilli(ev.TimestampMS).UTC().Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: AdapterVersion,
			SourceType:     protocol.SourceType,
		}
		if m := strings.TrimSpace(ev.Model); m != "" {
			rec.Model = &m
		}
		rec.Input = decimalOfPtr(ev.InputTokens)
		rec.CacheRead = decimalOfPtr(ev.CacheReadTokens)
		rec.CacheWrite = decimalOfPtr(ev.CacheWriteTokens)
		rec.Output = decimalOfPtr(ev.OutputTokens)
		records = append(records, rec)
		staged[eventKey] = CacheEntry{Revision: rev, Digest: digest}
		switch {
		case unchanged:
			stats.ReemittedRecords++
		case has:
			stats.ReplacedRecords++
		default:
			stats.NewRecords++
		}
	}
	return records, staged, stats, nil
}

// decimalOfPtr preserves the unknown: a nil count stays nil on the wire.
func decimalOfPtr(v *int64) *string {
	if v == nil {
		return nil
	}
	s := strconv.FormatInt(*v, 10)
	return &s
}

// eventDigest fingerprints the identity-relevant content of an event:
// timestamp, model and the four counters (nil kept distinct from zero via
// a sentinel). The event id participates via the eventKey the digest is
// stored under; tokens, account ids and costs never enter the digest.
func eventDigest(ev api.UsageEvent) string {
	h := sha256.New()
	frame := func(s string) {
		var n [8]byte
		n[0] = byte(len(s) >> 56)
		n[1] = byte(len(s) >> 48)
		n[2] = byte(len(s) >> 40)
		n[3] = byte(len(s) >> 32)
		n[4] = byte(len(s) >> 24)
		n[5] = byte(len(s) >> 16)
		n[6] = byte(len(s) >> 8)
		n[7] = byte(len(s))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(s))
	}
	num := func(v *int64) {
		if v == nil {
			frame("\x00nil")
			return
		}
		frame(strconv.FormatInt(*v, 10))
	}
	frame("cursor-event-digest/v1")
	frame(fmt.Sprintf("%d", ev.TimestampMS))
	frame(strings.TrimSpace(ev.Model))
	num(ev.InputTokens)
	num(ev.CacheReadTokens)
	num(ev.CacheWriteTokens)
	num(ev.OutputTokens)
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// EventCache: the local per-source event ledger (cursor-events.json)
// ---------------------------------------------------------------------------

const cacheFileName = "cursor-events.json"

// CacheEntry is the last produced revision and content digest of one
// eventKey. It is the dedupe/replace memory for pulls; the server remains
// the authority through (subject, eventKey) idempotency. When the local
// cache is lost, the nextRevision seed raised from the server self view
// keeps re-emitted facts above the stored revisions, so recovery replaces
// instead of going stale.
type CacheEntry struct {
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
}

// EventCache is the durable local event ledger. Reads are cheap; staged
// updates from Normalize are applied and committed by the caller only
// after the resulting batch is durable.
type EventCache struct {
	path    string
	entries map[string]CacheEntry
	dirty   bool
}

func LoadCache(stateDir string) (*EventCache, error) {
	c := &EventCache{
		path:    filepath.Join(strings.TrimSpace(stateDir), cacheFileName),
		entries: map[string]CacheEntry{},
	}
	b, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var stored map[string]CacheEntry
	if err := json.Unmarshal(b, &stored); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", c.path, err)
	}
	if stored != nil {
		c.entries = stored
	}
	return c, nil
}

// Get returns the cached entry for an eventKey.
func (c *EventCache) Get(eventKey string) (CacheEntry, bool) {
	e, ok := c.entries[eventKey]
	return e, ok
}

// Apply merges staged entries produced by Normalize into the live cache
// (in memory). Callers apply only after the resulting batch is durable;
// Commit persists.
func (c *EventCache) Apply(staged map[string]CacheEntry) {
	if len(staged) == 0 {
		return
	}
	for k, v := range staged {
		c.entries[k] = v
	}
	c.dirty = true
}

// Commit atomically persists applied entries (0600, temp plus rename). It
// is a no-op when nothing changed.
func (c *EventCache) Commit() error {
	if !c.dirty {
		return nil
	}
	keys := make([]string, 0, len(c.entries))
	for k := range c.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]CacheEntry, len(keys))
	for _, k := range keys {
		ordered[k] = c.entries[k]
	}
	b, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), "cursor-events.*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return err
	}
	tmpName = ""
	c.dirty = false
	return nil
}

// DeleteCacheFile removes the event cache (logout --purge-cache). It
// reports whether a file was removed.
func DeleteCacheFile(stateDir string) (bool, error) {
	path := filepath.Join(strings.TrimSpace(stateDir), cacheFileName)
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
