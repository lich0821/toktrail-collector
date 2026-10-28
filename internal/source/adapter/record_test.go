package adapter

import (
	"testing"
)

func TestParseUintRejectsOverflow(t *testing.T) {
	if _, ok := ParseUint("18446744073709551616"); ok {
		t.Fatal("expected uint64 overflow to be rejected")
	}
}

func TestSanitizeUsageJSONRecordDoesNotMutateInput(t *testing.T) {
	record := Record{
		"recordKey":  "stable-key",
		"kind":       "delta",
		"tool":       "codex",
		"model":      "company-private-route-42",
		"sessionId":  "sess-secret-123",
		"prompt":     "secret",
		"input":      "10",
		"cacheRead":  "0",
		"cacheWrite": "0",
		"output":     "5",
		"occurredAt": "2026-10-20T01:00:00Z",
	}
	sanitized := sanitizeUsageJSONRecord(record)
	if _, ok := sanitized["sessionId"]; ok {
		t.Fatal("sanitized record leaked sessionId")
	}
	if _, ok := sanitized["prompt"]; ok {
		t.Fatal("sanitized record leaked prompt")
	}
	if sanitized["model"] != "unknown" {
		t.Fatalf("expected model unknown, got %#v", sanitized["model"])
	}
	if record["sessionId"] != "sess-secret-123" || record["prompt"] != "secret" || record["model"] != "company-private-route-42" {
		t.Fatalf("sanitize mutated the original input map: %#v", record)
	}
	if record["recordKey"] != "stable-key" || sanitized["recordKey"] != "stable-key" {
		t.Fatalf("recordKey must stay stable: %#v vs %#v", record, sanitized)
	}
}

func TestDeepSeekHarnessRecordedModelProjection(t *testing.T) {
	if got := DeepSeekHarnessRecordedModel(" deepseek-flash "); got != "deepseek-flash" {
		t.Fatalf("model = %q, want deepseek-flash", got)
	}
	if got := DeepSeekHarnessRecordedModel("bad\nmodel"); got != "unknown" {
		t.Fatalf("control-bearing model must collapse to unknown, got %q", got)
	}
	record := Record{
		"recordKey":      "dsh-key",
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "DeepSeek Harness",
		"model":          "deepseek-flash",
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "test",
		"sourceType":     "deepseek-harness",
	}
	if !RecordIsUploadSafe(record) {
		t.Fatalf("DSH recorded model should be upload-safe: %#v", record)
	}
}

// TestExportWritesOnlyWhitelistedFields asserts the on-disk batch payload —
// the artifact sync uploads verbatim — contains only protocol fields.
