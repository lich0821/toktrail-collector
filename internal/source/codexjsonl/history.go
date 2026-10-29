package codexjsonl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// Immutable Codex line keys remain known across pending, ACK and scope
// quarantine. Read the existing immutable files rather than introducing a
// second index whose crash recovery could diverge from the export WAL.
func filterKnownCodexRecords(stateDir string, records []adapter.Record) ([]adapter.Record, error) {
	known := make(map[string][]byte)
	remember := func(raw []byte) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var rec adapter.Record
		if err := dec.Decode(&rec); err != nil {
			return err
		}
		key, _ := rec["recordKey"].(string)
		if key == "" {
			return fmt.Errorf("stored Codex record has no key")
		}
		canonical, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if prev, ok := known[key]; ok && !bytes.Equal(prev, canonical) {
			return fmt.Errorf("stored Codex record %s has conflicting content", key)
		}
		known[key] = canonical
		return nil
	}
	outboxLedger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range outboxLedger.Batches {
		if entry.Source != "codex-jsonl" {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown Codex outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read Codex history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("Codex history batch identity mismatch")
		}
		for _, rec := range batch.Records {
			if err := remember(rec); err != nil {
				return nil, err
			}
		}
	}
	quarantine, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range quarantine {
		if entry.Source != "codex-jsonl" {
			continue
		}
		if err := remember(entry.Record); err != nil {
			return nil, err
		}
	}
	// Override baseline: an explicitly confirmed override pass may have
	// declared the current scan authoritative for some keys. Confirmed
	// overrides supersede the stored payloads for baseline comparison
	// (the old files stay untouched on disk); a pending override blocks
	// the whole scan fail-closed until the pass finishes or is abandoned.
	if err := overrides.ApplyToBaseline(stateDir, "codex-jsonl", known); err != nil {
		return nil, err
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, rec := range records {
		key, _ := rec["recordKey"].(string)
		canonical, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if prior, ok := known[key]; ok {
			if !bytes.Equal(prior, canonical) {
				return nil, fmt.Errorf("Codex record %s changed after export or after an override baseline; refusing to overwrite immutable history (re-run toktrail resync --all --replace-existing to adopt the current scan)", key)
			}
			continue
		}
		fresh = append(fresh, rec)
	}
	return fresh, nil
}
