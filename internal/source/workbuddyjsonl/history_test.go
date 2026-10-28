package workbuddyjsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/source/adapter"
)

// Export idempotency tests for FilterForExport: repeated full rescans must
// not re-export requests already present in immutable outbox or quarantine
// history, and any content drift for a known request — including a changed
// model identifier — fails closed instead of overwriting history.

// writeStoredBatch persists one batch of records as a pending outbox batch
// for the WorkBuddy source, standing in for a previously exported history.
func writeStoredBatch(t *testing.T, stateDir, batchID string, records []adapter.Record) {
	t.Helper()
	type batchFile struct {
		BatchID string            `json:"batchId"`
		Records []json.RawMessage `json:"records"`
	}
	bf := batchFile{BatchID: batchID}
	for _, rec := range records {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		bf.Records = append(bf.Records, raw)
	}
	body, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	path := filepath.Join(stateDir, batchID+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write batch file: %v", err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		Source:      adapter.WorkBuddyJSONLSource,
		RecordCount: len(records),
	}); err != nil {
		t.Fatalf("add pending batch: %v", err)
	}
}

// loadOneRecord parses a single fixture request into its record.
func loadOneRecord(t *testing.T) adapter.Record {
	t.Helper()
	root := t.TempDir()
	writeJSONL(t, filepath.Join(root, "project-a", "session.jsonl"),
		wbRecord("call-1", "msg-1", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`))
	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Quarantined != 0 {
		t.Fatalf("fixture must produce exactly one clean record: %#v", res)
	}
	return res.Records[0]
}

// withModel returns a copy of the record carrying the given model value.
func withModel(t *testing.T, record adapter.Record, model string) adapter.Record {
	t.Helper()
	out := make(adapter.Record, len(record))
	for k, v := range record {
		out[k] = v
	}
	out["model"] = model
	return out
}

// Identical records — including identical recorded models — remain known:
// repeated rescans of unchanged input re-export nothing.
func TestFilterForExportKeepsIdenticalRecordKnown(t *testing.T) {
	loaded := loadOneRecord(t)
	if loaded["model"] != "private-route" {
		t.Fatalf("fixture record must carry the recorded model, got %#v", loaded["model"])
	}
	stateDir := t.TempDir()
	writeStoredBatch(t, stateDir, "wb-history-1", []adapter.Record{loaded})

	fresh, err := Adapter().FilterForExport(adapter.Options{Source: adapter.WorkBuddyJSONLSource, StateDir: stateDir}, []adapter.Record{loaded})
	if err != nil {
		t.Fatalf("identical record must stay known without error: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("identical known record re-emitted: %#v", fresh)
	}
}

// A stored record with one recorded model and a fresh scan of the same
// request carrying a different model is content drift and must fail closed
// instead of overwriting immutable history.
func TestFilterForExportRejectsChangedStoredModel(t *testing.T) {
	loaded := loadOneRecord(t)
	stateDir := t.TempDir()
	writeStoredBatch(t, stateDir, "wb-history-1", []adapter.Record{withModel(t, loaded, "another-model")})

	if _, err := Adapter().FilterForExport(adapter.Options{Source: adapter.WorkBuddyJSONLSource, StateDir: stateDir}, []adapter.Record{loaded}); err == nil {
		t.Fatal("changed stored model must fail export filtering")
	}
}
