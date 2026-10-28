package deepseekharness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// filterKnownDSHRecords drops records whose recordKey was already exported
// (or quarantined) for the deepseek-harness source, making the stateless
// full rescan idempotent. Immutable line keys remain known across pending,
// ACK and scope quarantine: the existing immutable files are read rather
// than introducing a second index whose crash recovery could diverge from
// the export WAL. Stored content for a known key must be byte-identical to
// the freshly loaded record, except for the v1 compatibility upgrade from
// model=unknown to a recorded DSH model id; every other drift fails closed
// instead of silently overwriting immutable history.
func sameDSHRecordAllowingModelUpgrade(a, b []byte) bool {
	var left, right adapter.Record
	if err := json.Unmarshal(a, &left); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &right); err != nil {
		return false
	}
	lm := adapter.StringField(left, "model")
	rm := adapter.StringField(right, "model")
	if lm == rm {
		return false
	}
	if lm != "unknown" && rm != "unknown" {
		return false
	}
	left["model"] = "unknown"
	right["model"] = "unknown"
	lc, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rc, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(lc, rc)
}

func filterKnownDSHRecords(stateDir string, records []adapter.Record) ([]adapter.Record, error) {
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
			return fmt.Errorf("stored DeepSeek Harness record has no key")
		}
		canonical, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if prev, ok := known[key]; ok && !bytes.Equal(prev, canonical) {
			if !sameDSHRecordAllowingModelUpgrade(prev, canonical) {
				return fmt.Errorf("stored DeepSeek Harness record %s has conflicting content", key)
			}
		}
		known[key] = canonical
		return nil
	}
	outboxLedger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range outboxLedger.Batches {
		if entry.Source != adapter.DeepSeekHarnessSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown DeepSeek Harness outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read DeepSeek Harness history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("DeepSeek Harness history batch identity mismatch")
		}
		for _, rec := range batch.Records {
			if err := remember(rec); err != nil {
				return nil, err
			}
		}
	}
	store, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range store {
		if entry.Source != adapter.DeepSeekHarnessSource {
			continue
		}
		if err := remember(entry.Record); err != nil {
			return nil, err
		}
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, rec := range records {
		key, _ := rec["recordKey"].(string)
		canonical, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if prior, ok := known[key]; ok {
			if !bytes.Equal(prior, canonical) && !sameDSHRecordAllowingModelUpgrade(prior, canonical) {
				return nil, fmt.Errorf("DeepSeek Harness record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, rec)
	}
	return fresh, nil
}
