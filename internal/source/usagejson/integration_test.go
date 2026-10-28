package usagejson_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/usagejson"
)

var exportFields = []string{"recordKey", "groupKey", "resetKey", "kind", "occurredAt", "tool", "model", "input", "cacheRead", "cacheWrite", "output", "adapterVersion", "sourceType", "mutationType"}

func TestInvalidUTF8UsageJSONFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte("{\"model\":\""+string([]byte{0xff})+"\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := usagejson.LoadRecords(path); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 must fail before decoding: %v", err)
	}
}

func TestInvalidModelIsNotDroppedDuringExport(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{{
		"recordKey": "invalid-model", "kind": "delta", "occurredAt": "2026-10-20T01:00:00Z",
		"tool": "Codex", "model": map[string]any{"id": "not-a-string"},
		"input": "1", "output": "1", "adapterVersion": "test", "sourceType": "fixture",
	}})
	_, err := pipeline.PrepareExport(adapter.Options{Input: input, Output: filepath.Join(t.TempDir(), "batch.json"), BatchID: "invalid-model"})
	if err == nil || !strings.Contains(err.Error(), "model") {
		t.Fatalf("invalid model should fail export: %v", err)
	}
}

func TestScanSupportsServerFixtureFormat(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{
		{"name": "complete", "record": map[string]any{
			"recordKey":      "fixture:1",
			"groupKey":       nil,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     "2026-10-20T01:00:00Z",
			"tool":           "codex",
			"model":          nil,
			"input":          "100",
			"cacheRead":      "20",
			"cacheWrite":     "5",
			"output":         "50",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		}},
		{"name": "missing-cache", "record": map[string]any{
			"recordKey":      "fixture:2",
			"groupKey":       nil,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     "2026-10-20T02:00:00Z",
			"tool":           "dsh",
			"model":          nil,
			"input":          "100",
			"cacheRead":      nil,
			"cacheWrite":     nil,
			"output":         "50",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		}},
	})
	res, err := pipeline.Scan(adapter.Options{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 || res.ValidRecords != 2 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan counts: %#v", res)
	}
	if res.KnownIncludeRecords != 1 || res.KnownExcludeRecords != 2 {
		t.Fatalf("unexpected known token counts: %#v", res)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 175 {
		t.Fatalf("unexpected include tokens: %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 300 {
		t.Fatalf("unexpected exclude tokens: %#v", res.TokensExclude)
	}
	if res.Tools["codex"] != 1 || res.Tools["dsh"] != 1 || res.EarliestOccurredAt == nil || res.LatestOccurredAt == nil {
		t.Fatalf("unexpected scan metadata: %#v", res)
	}
}

func TestPreviewMarksInvalidRecords(t *testing.T) {
	input := writeJSONFile(t, map[string]any{"records": []map[string]any{{
		"recordKey":      "bad-1",
		"kind":           "bad-kind",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"input":          "1",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "1",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
	}}})
	rows, err := pipeline.Preview(adapter.Options{Input: input, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Valid || rows[0].Error == "" {
		t.Fatalf("expected invalid preview row: %#v", rows)
	}
}

func TestScanReportsRecordTokenSumOverflowAsUnknown(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{
		{"record": map[string]any{
			"recordKey":      "overflow-1",
			"groupKey":       nil,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     "2026-10-20T01:00:00Z",
			"tool":           "codex",
			"model":          nil,
			"input":          "18446744073709551615",
			"cacheRead":      "1",
			"cacheWrite":     "0",
			"output":         "0",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		}},
	})
	res, err := pipeline.Scan(adapter.Options{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.KnownIncludeRecords != 0 || res.TokensInclude != nil {
		t.Fatalf("expected include tokens to be unknown on overflow: %#v", res)
	}
	if res.KnownExcludeRecords != 1 || res.TokensExclude == nil || *res.TokensExclude != math.MaxUint64 {
		t.Fatalf("expected exclude tokens to remain known: %#v", res)
	}
	rows, err := pipeline.Preview(adapter.Options{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].Valid || rows[0].Include != nil || rows[0].Exclude == nil || *rows[0].Exclude != math.MaxUint64 {
		t.Fatalf("unexpected preview row: %#v", rows)
	}
}

func TestScanRejectsIncludeTokenTotalOverflow(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{
		{"record": overflowTotalRecord("overflow-include-1", "9223372036854775808", "0")},
		{"record": overflowTotalRecord("overflow-include-2", "9223372036854775808", "0")},
	})
	_, err := pipeline.Scan(adapter.Options{Input: input})
	if err == nil {
		t.Fatal("expected aggregate include token overflow to be rejected")
	}
	if !strings.Contains(err.Error(), "include token total overflow") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScanRejectsExcludeTokenTotalOverflow(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{
		{"record": overflowTotalRecord("overflow-exclude-1", "18446744073709551615", "1")},
		{"record": overflowTotalRecord("overflow-exclude-2", "18446744073709551615", "1")},
	})
	_, err := pipeline.Scan(adapter.Options{Input: input})
	if err == nil {
		t.Fatal("expected aggregate exclude token overflow to be rejected")
	}
	if !strings.Contains(err.Error(), "exclude token total overflow") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportWritesBatchWithValidRecords(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{{
		"recordKey":      "record-1",
		"groupKey":       nil,
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"model":          nil,
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
	}})
	out := filepath.Join(t.TempDir(), "batch.json")
	res, err := pipeline.Export(adapter.Options{Input: input, Output: out, BatchID: "batch-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.BatchID != "batch-1" || res.Records != 1 || res.Output != out {
		t.Fatalf("unexpected export result: %#v", res)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var batch adapter.Batch
	if err := json.Unmarshal(b, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.BatchID != "batch-1" || len(batch.Records) != 1 || batch.Records[0]["recordKey"] != "record-1" {
		t.Fatalf("unexpected batch payload: %#v", batch)
	}
}

func TestLoadRecordsWhitelistsFreeFormFields(t *testing.T) {
	input := writeJSONFile(t, map[string]any{"records": []map[string]any{
		{
			"recordKey":      "privacy-1",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T01:00:00Z",
			"tool":           "codex",
			"model":          "company-private-route-42",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
			"sessionId":      "sess-secret-123",
			"path":           "/Users/example/secret/project",
			"prompt":         "draft the acquisition memo",
			"nested":         map[string]any{"deep": "leak"},
			"modelRoute":     []any{"internal-gateway", "finetune-42"},
		},
		{
			"recordKey":      "privacy-2",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T02:00:00Z",
			"tool":           "Codex",
			"model":          "gpt-4o",
			"input":          "1",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "1",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
			"modelRoute":     "openai-public-must-survive-registry-check",
		},
		{
			"recordKey":      "privacy-3",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T03:00:00Z",
			"tool":           "Claude Code",
			"model":          "claude-sonnet-4-5",
			"input":          "2",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "2",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		},
		{
			"recordKey":      "privacy-4",
			"kind":           "delta",
			"occurredAt":     "2026-10-20T04:00:00Z",
			"tool":           "Claude Code",
			"model":          "claude-internal-preview",
			"input":          "3",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "3",
			"adapterVersion": "fixture-v1",
			"sourceType":     "fixture",
		},
	}})
	records, err := usagejson.LoadRecords(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}
	allowed := map[string]bool{}
	for _, field := range exportFields {
		allowed[field] = true
	}
	for idx, record := range records {
		for field := range record {
			if !allowed[field] {
				t.Errorf("record %d leaked non-whitelisted field %q: %#v", idx, field, record[field])
			}
		}
	}
	if records[0]["model"] != "company-private-route-42" {
		t.Fatalf("expected recorded model, got %#v", records[0]["model"])
	}
	if records[1]["model"] != "gpt-4o" {
		t.Fatalf("expected public OpenAI model to survive, got %#v", records[1]["model"])
	}
	if records[2]["model"] != "claude-sonnet-4-5" {
		t.Fatalf("expected public Claude model to survive, got %#v", records[2]["model"])
	}
	if records[3]["model"] != "claude-internal-preview" {
		t.Fatalf("expected recorded Claude model, got %#v", records[3]["model"])
	}
	// The idempotent identity is untouched by the projection.
	for idx, key := range []string{"privacy-1", "privacy-2", "privacy-3", "privacy-4"} {
		if records[idx]["recordKey"] != key {
			t.Fatalf("record %d changed recordKey to %#v", idx, records[idx]["recordKey"])
		}
	}
	// Re-loading the same input yields the same sanitized keys (idempotent
	// rescans keep stable server-side dedup identities).
	again, err := usagejson.LoadRecords(input)
	if err != nil {
		t.Fatal(err)
	}
	for idx := range records {
		if again[idx]["recordKey"] != records[idx]["recordKey"] {
			t.Fatalf("record %d key unstable across scans: %#v vs %#v", idx, records[idx]["recordKey"], again[idx]["recordKey"])
		}
	}
}

// TestSanitizeUsageJSONRecordDoesNotMutateInput verifies the projection
// builds a new map instead of editing the decoded input in place.
func TestExportWritesOnlyWhitelistedFields(t *testing.T) {
	input := writeJSONFile(t, []map[string]any{{
		"recordKey":      "export-privacy-1",
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"model":          "company-private-route-42",
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
		"sessionId":      "sess-secret-123",
		"path":           "/Users/example/secret/project",
		"prompt":         "draft the acquisition memo",
	}})
	out := filepath.Join(t.TempDir(), "batch.json")
	if _, err := pipeline.Export(adapter.Options{Input: input, Output: out, BatchID: "batch-privacy-1"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sess-secret-123") || strings.Contains(string(b), "secret/project") || strings.Contains(string(b), "acquisition memo") {
		t.Fatalf("batch payload leaked private input content: %s", b)
	}
	var batch adapter.Batch
	if err := json.Unmarshal(b, &batch); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, field := range exportFields {
		allowed[field] = true
	}
	for idx, record := range batch.Records {
		for field := range record {
			if !allowed[field] {
				t.Errorf("batch record %d leaked non-whitelisted field %q", idx, field)
			}
		}
		if record["model"] != "company-private-route-42" {
			t.Errorf("batch record %d model changed: %#v", idx, record["model"])
		}
	}
}
func overflowTotalRecord(key, input, cacheRead string) map[string]any {
	return map[string]any{
		"recordKey":      key,
		"groupKey":       nil,
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"model":          nil,
		"input":          input,
		"cacheRead":      cacheRead,
		"cacheWrite":     "0",
		"output":         "0",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
	}
}

func codexCount(timestamp string, input, cacheRead, cacheWrite, output uint64) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{"total_token_usage": map[string]any{
				"input_tokens":             input,
				"cached_input_tokens":      cacheRead,
				"cache_write_input_tokens": cacheWrite,
				"output_tokens":            output,
			}},
		},
	}
}

func codexNullInfo(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": nil,
			"rate_limits": map[string]any{
				"limit_requests": 5000,
			},
		},
	}
}

func codexAbsentInfo(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
		},
	}
}

func writeJSONLFile(t *testing.T, path string, lines []map[string]any) {
	t.Helper()
	var b strings.Builder
	for _, line := range lines {
		payload, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(payload)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, body any) string {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadRecordsWhitelistsFreeFormFields locks the privacy projection of
// free-form usage-json inputs: unknown free-form fields (session ids, file
// paths, prompts, nested objects) must never survive into the records that
// validation, scan, preview, export, and outbox serialization consume, while
// protocol values and the idempotent recordKey stay byte-identical.
