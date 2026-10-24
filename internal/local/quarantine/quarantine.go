// Package quarantine persists records that were removed from a batch by
// a consent-scope reorganization because they fall outside the live scope.
// Entries are recoverable: once the scope is re-authorized to include them
// again, sync re-batches them under their original record key. A quarantined
// record is never counted as accepted and never advances any baseline; the
// store only ever holds the raw record plus enough provenance to rebuild a
// batch and to restore per-message pending intervals.
package quarantine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/progress"
)

const quarantineFileName = "scope-quarantine.json"

// Reasons a record can be outside scope. They mirror the server's scope
// evaluation exactly.
const (
	ReasonToolNotAllowed    = "tool_not_allowed"
	ReasonBeforeHistoryFrom = "before_history_from"
	ReasonAfterUploadUntil  = "after_upload_until"
)

// Entry is one quarantined record. Record is the verbatim raw JSON from the
// origin batch; its recordKey must stay stable so scope recovery can re-send
// the exact same record (the server's dedup/replay semantics then apply
// unchanged). Message-backed sources also persist the message id and the
// interval states so recovery can restore the pending interval without ever
// re-baselining.
type Entry struct {
	Source          string                      `json:"source"`
	Input           string                      `json:"input,omitempty"`
	RecordKey       string                      `json:"recordKey"`
	Record          json.RawMessage             `json:"record"`
	OriginBatchID   string                      `json:"originBatchId"`
	Reason          string                      `json:"reason"`
	ConsentRevision int64                       `json:"consentRevision"`
	QuarantinedAt   time.Time                   `json:"quarantinedAt"`
	MessageID       string                      `json:"messageId,omitempty"`
	FromState       *progress.MessageUsageState `json:"fromState,omitempty"`
	ToState         *progress.MessageUsageState `json:"toState,omitempty"`
}

type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, quarantineFileName) }

func (s Store) Load() ([]Entry, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", s.Path(), err)
	}
	return entries, nil
}

func (s Store) save(entries []Entry) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if entries == nil {
		entries = []Entry{}
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

// sameRecordJSON compares two raw records canonically. The store file is
// written with MarshalIndent, which re-indents embedded records when they
// round-trip through save/Load, so raw byte equality would spuriously report
// conflicts on replayed entries. Compacting both sides makes the comparison
// formatting-stable while still rejecting genuinely different content.
func sameRecordJSON(a, b []byte) bool {
	var ca, cb bytes.Buffer
	if err := json.Compact(&ca, a); err != nil {
		return false
	}
	if err := json.Compact(&cb, b); err != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// identityOf is the compound identity of a quarantined record: source plus
// record key. The record key alone is NOT unique across the store — generic
// usage-json inputs can produce the same record key under different sources
// (adapters that hash their source into the key are safe by construction,
// but nothing guarantees that) — so dedupe and removal always pair the key
// with its source. Removing by key alone could silently drop another
// source's quarantined record.
func identityOf(source, recordKey string) string {
	return source + "\x00" + recordKey
}

// Append adds entries, deduplicating by compound identity (source + record
// key). An entry whose identity is already quarantined is a replay: it is
// accepted only when the origin batch and raw record are identical;
// anything else is an error (never silently overwrite a quarantined record
// with different content). The same record key under a different source is
// a distinct quarantine identity and coexists.
func (s Store) Append(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	current, err := s.Load()
	if err != nil {
		return err
	}
	existing := make(map[string]Entry, len(current))
	for _, entry := range current {
		existing[identityOf(entry.Source, entry.RecordKey)] = entry
	}
	changed := false
	for _, entry := range entries {
		if strings.TrimSpace(entry.RecordKey) == "" {
			return errors.New("quarantine entry requires a record key")
		}
		if entry.QuarantinedAt.IsZero() {
			entry.QuarantinedAt = time.Now().UTC()
		}
		if prev, ok := existing[identityOf(entry.Source, entry.RecordKey)]; ok {
			if prev.OriginBatchID != entry.OriginBatchID || !sameRecordJSON(prev.Record, entry.Record) {
				return fmt.Errorf("quarantine entry for record %s conflicts with an already-quarantined entry (origin %s vs %s)", entry.RecordKey, prev.OriginBatchID, entry.OriginBatchID)
			}
			continue
		}
		existing[identityOf(entry.Source, entry.RecordKey)] = entry
		changed = true
	}
	if !changed {
		return nil
	}
	merged := make([]Entry, 0, len(existing))
	// Preserve original order, then new entries in arrival order.
	for _, entry := range current {
		merged = append(merged, existing[identityOf(entry.Source, entry.RecordKey)])
	}
	seen := make(map[string]bool, len(current))
	for _, entry := range current {
		seen[identityOf(entry.Source, entry.RecordKey)] = true
	}
	for _, entry := range entries {
		if !seen[identityOf(entry.Source, entry.RecordKey)] {
			merged = append(merged, existing[identityOf(entry.Source, entry.RecordKey)])
			seen[identityOf(entry.Source, entry.RecordKey)] = true
		}
	}
	return s.save(merged)
}

// RemoveKey identifies one quarantined record by its compound identity:
// source plus record key. Removing by record key alone would also drop
// another source's entry that happens to share the key.
type RemoveKey struct {
	Source    string
	RecordKey string
}

// Remove drops the entries matching the given compound identities. Missing
// identities are ignored, so replayed recovery journals stay idempotent. An
// entry whose record key matches under a different source is never touched.
func (s Store) Remove(keys []RemoveKey) error {
	if len(keys) == 0 {
		return nil
	}
	current, err := s.Load()
	if err != nil {
		return err
	}
	drop := make(map[RemoveKey]bool, len(keys))
	for _, key := range keys {
		key.Source = strings.TrimSpace(key.Source)
		key.RecordKey = strings.TrimSpace(key.RecordKey)
		drop[key] = true
	}
	remaining := current[:0:0]
	for _, entry := range current {
		if drop[RemoveKey{Source: entry.Source, RecordKey: entry.RecordKey}] {
			continue
		}
		remaining = append(remaining, entry)
	}
	if len(remaining) == len(current) {
		return nil
	}
	return s.save(remaining)
}
