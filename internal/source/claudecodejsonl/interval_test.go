package claudecodejsonl

import (
	"testing"
	"time"
	"toktrail-collector/internal/local/progress"
)

func TestClaudeCodeJSONLQuarantinedIntervalIsSkippedWithDiagnostic(t *testing.T) {
	messages := []claudeCodeMessage{{
		ID:        "m1",
		Model:     "claude-x",
		Timestamp: time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC),
		Usage:     claudeCodeUsage{Input: u64ptr(10), Output: u64ptr(5)},
		File:      "session.jsonl",
		Line:      1,
	}}
	progressByMessage := map[string]progress.MessageProgress{
		"m1": {
			QuarantinedKey:      "m1|0,0,0,0|10,0,0,5",
			QuarantinedReason:   "tool_not_allowed",
			QuarantinedRevision: 8,
			UpdatedAt:           time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC),
		},
	}
	records, updates, issues := buildClaudeCodeRecords(messages, progressByMessage)
	if len(records) != 0 || len(updates) != 0 {
		t.Fatalf("expected the quarantined message to emit no records or updates: %#v %#v", records, updates)
	}
	if len(issues) != 1 {
		t.Fatalf("expected exactly one diagnostic, got %#v", issues)
	}
	want := "interval m1|0,0,0,0|10,0,0,5 is quarantined outside the consent scope (tool_not_allowed); waiting for scope recovery before it is re-sent"
	if issues[0].Reason != want {
		t.Fatalf("diagnostic = %q, want %q", issues[0].Reason, want)
	}
	if issues[0].File != "session.jsonl" || issues[0].Line != 1 {
		t.Fatalf("expected the diagnostic to point at the source line: %#v", issues[0])
	}

	// Control: without the quarantine marker the same message exports.
	records, updates, issues = buildClaudeCodeRecords(messages, map[string]progress.MessageProgress{})
	if len(records) != 1 || len(updates) != 1 || len(issues) != 0 {
		t.Fatalf("expected the control message to export one record: %#v %#v %#v", records, updates, issues)
	}
}

func u64ptr(v uint64) *uint64 { return &v }
