package workbuddyjsonl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// Adapter exposes the WorkBuddy source to the collector pipeline.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.WorkBuddyJSONLSource,
		Description: "WorkBuddy request usage JSONL",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return LoadRecords(opt.Input)
		},
		FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
			if strings.TrimSpace(opt.StateDir) == "" {
				return records, nil
			}
			return filterKnownRecords(opt.StateDir, records)
		},
	}
}

// filterKnownRecords checks immutable outbox and quarantine records, so
// repeated full scans cannot enqueue the same request again.
func filterKnownRecords(stateDir string, records []adapter.Record) ([]adapter.Record, error) {
	known := make(map[string][]byte)
	remember := func(raw []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var record adapter.Record
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		key := adapter.StringField(record, "recordKey")
		if key == "" {
			return fmt.Errorf("stored WorkBuddy record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored WorkBuddy record %s has conflicting content", key)
		}
		known[key] = canonical
		return nil
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range ledger.Batches {
		if entry.Source != adapter.WorkBuddyJSONLSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown WorkBuddy outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read WorkBuddy history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("WorkBuddy history batch identity mismatch")
		}
		for _, record := range batch.Records {
			if err := remember(record); err != nil {
				return nil, err
			}
		}
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Source == adapter.WorkBuddyJSONLSource {
			if err := remember(entry.Record); err != nil {
				return nil, err
			}
		}
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, record := range records {
		key := adapter.StringField(record, "recordKey")
		canonical, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if previous, exists := known[key]; exists {
			if !bytes.Equal(previous, canonical) {
				return nil, fmt.Errorf("WorkBuddy record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}
