package syncclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

// A terminal ledger entry alone is insufficient: a reorganization writes it
// before quarantine/cursor changes. A surviving WAL means commit is incomplete.
func ScopeReorganizationComplete(stateDir, batchID string) (bool, error) {
	if _, err := os.Stat(filepath.Join(stateDir, reorgJournalFileName)); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return false, err
	}
	for _, entry := range out.Batches {
		if entry.BatchID == batchID {
			return entry.Status == outbox.StatusReorganized, nil
		}
	}
	return false, nil
}

func canonicalCodexRecord(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	return json.Marshal(rec)
}

// Older collectors re-exported immutable Codex lines into new batches.
// Recover such WALs without overwriting the original quarantine provenance.
// This exception is deliberately limited to identical Codex line records with
// no message intervals, matching scope metadata and a verifiable old batch.
// The general quarantine Append contract remains strict for every source.
func appendScopeQuarantine(stateDir string, entries []quarantine.Entry) error {
	store := quarantine.New(stateDir)
	current, err := store.Load()
	if err != nil {
		return err
	}
	existing := make(map[string]quarantine.Entry, len(current))
	for _, entry := range current {
		existing[entry.Source+"\x00"+entry.RecordKey] = entry
	}
	outboxLedger, err := outbox.New(stateDir).Load()
	if err != nil {
		return err
	}
	origins := make(map[string]outbox.BatchEntry, len(outboxLedger.Batches))
	for _, entry := range outboxLedger.Batches {
		origins[entry.BatchID] = entry
	}
	verified := make(map[string]map[string][]byte)
	normalized := append([]quarantine.Entry(nil), entries...)
	for i, entry := range normalized {
		prev, ok := existing[entry.Source+"\x00"+entry.RecordKey]
		if !ok || prev.OriginBatchID == entry.OriginBatchID {
			continue
		}
		if entry.Source != "codex-jsonl" || !strings.HasPrefix(entry.RecordKey, "codex-jsonl:") ||
			prev.Input != entry.Input || prev.Reason != entry.Reason || prev.ConsentRevision != entry.ConsentRevision ||
			entry.MessageID != "" || prev.MessageID != "" || entry.FromState != nil || entry.ToState != nil || prev.FromState != nil || prev.ToState != nil {
			return fmt.Errorf("conflicting quarantine provenance for %s", entry.RecordKey)
		}
		candidate, err := canonicalCodexRecord(entry.Record)
		if err != nil {
			return err
		}
		prior, err := canonicalCodexRecord(prev.Record)
		if err != nil {
			return err
		}
		if !bytes.Equal(candidate, prior) {
			return fmt.Errorf("conflicting quarantined Codex content for %s", entry.RecordKey)
		}
		original, ok := origins[prev.OriginBatchID]
		if !ok || original.Source != entry.Source || original.Input != entry.Input || original.Status != outbox.StatusReorganized {
			return fmt.Errorf("cannot verify original Codex quarantine batch for %s", entry.RecordKey)
		}
		records, cached := verified[original.BatchID]
		if !cached {
			raw, err := os.ReadFile(original.File)
			if err != nil {
				return err
			}
			var batch BatchRequest
			if err := json.Unmarshal(raw, &batch); err != nil {
				return err
			}
			if batch.BatchID != original.BatchID {
				return fmt.Errorf("original Codex quarantine batch identity mismatch")
			}
			records = make(map[string][]byte, len(batch.Records))
			for _, rec := range batch.Records {
				key, err := recordKeyOf(rec)
				if err != nil {
					return err
				}
				canonical, err := canonicalCodexRecord(rec)
				if err != nil {
					return err
				}
				if old, ok := records[key]; ok && !bytes.Equal(old, canonical) {
					return fmt.Errorf("original Codex batch has conflicting records")
				}
				records[key] = canonical
			}
			verified[original.BatchID] = records
		}
		if !bytes.Equal(records[entry.RecordKey], prior) {
			return fmt.Errorf("Codex quarantine does not match immutable original batch")
		}
		normalized[i] = prev
	}
	return store.Append(normalized)
}
