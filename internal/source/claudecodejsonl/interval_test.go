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

// TestClaudeCodeModelMergeState locks the per-message model state machine
// behind the history collection: model-less snapshots keep the recorded
// identifier, a second distinct identifier conflicts into "unknown" with one
// diagnostic, a message that never records a model resolves to "unknown"
// with one local value-free diagnostic, and the usage representative
// selection stays untouched throughout.
func TestClaudeCodeModelMergeState(t *testing.T) {
	final := map[string]*claudeCodeMessage{}
	quarantine := &claudeCodeQuarantine{}
	observe := func(model claudeModelSnapshot, usage claudeCodeUsage, stamp time.Time, line int) {
		applyClaudeObservation(final, claudeCodeObservation{
			MessageID: "m1",
			Timestamp: stamp,
			Usage:     usage,
			Model:     model,
			File:      "session.jsonl",
			Line:      line,
		}, quarantine)
	}
	base := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)

	// First snapshot records the identifier and the baseline usage.
	observe(claudeModelSnapshot{present: true, value: "claude-sonnet-4-5"}, claudeCodeUsage{Input: u64ptr(10), Output: u64ptr(5)}, base, 1)
	// A newer snapshot without a model keeps the identifier and advances usage.
	observe(claudeModelSnapshot{}, claudeCodeUsage{Input: u64ptr(12), Output: u64ptr(6)}, base.Add(time.Second), 2)
	message := final["m1"]
	if message.modelObserved != "claude-sonnet-4-5" || message.modelConflict {
		t.Fatalf("expected the recorded identifier to survive a model-less snapshot: %#v", message)
	}
	if message.Usage.Input == nil || *message.Usage.Input != 12 {
		t.Fatalf("expected usage to follow the newest snapshot: %#v", message.Usage)
	}
	message.resolveClaudeModel(quarantine)
	if message.Model != "claude-sonnet-4-5" {
		t.Fatalf("expected verbatim model resolution, got %q", message.Model)
	}
	if quarantine.total != 0 || len(quarantine.issues) != 0 {
		t.Fatalf("model-less snapshots must not be errors: %#v", quarantine.issues)
	}

	// A conflicting identifier on any later snapshot flips the message to
	// unknown with exactly one diagnostic; usage is unaffected.
	observe(claudeModelSnapshot{present: true, value: "claude-opus-4-5"}, claudeCodeUsage{Input: u64ptr(12), Output: u64ptr(6)}, base.Add(2*time.Second), 3)
	message = final["m1"]
	if !message.modelConflict {
		t.Fatalf("expected the distinct identifier to conflict: %#v", message)
	}
	if message.Usage.Input == nil || *message.Usage.Input != 12 {
		t.Fatalf("expected the conflict to leave usage untouched: %#v", message.Usage)
	}
	message.resolveClaudeModel(quarantine)
	if message.Model != "unknown" {
		t.Fatalf("expected conflicted model to resolve to unknown, got %q", message.Model)
	}
	if len(quarantine.issues) != 1 || quarantine.total != 0 {
		t.Fatalf("expected one non-quarantining conflict diagnostic: %#v total=%d", quarantine.issues, quarantine.total)
	}
	want := `model conflict on one message id: earlier snapshots record "claude-sonnet-4-5", this snapshot records "claude-opus-4-5"; reporting unknown instead of guessing`
	if quarantine.issues[0].Reason != want || quarantine.issues[0].File != "session.jsonl" || quarantine.issues[0].Line != 3 {
		t.Fatalf("unexpected conflict diagnostic: %#v", quarantine.issues[0])
	}

	// Further snapshots (same, conflicting, or model-less) add nothing.
	observe(claudeModelSnapshot{present: true, value: "claude-sonnet-4-5"}, claudeCodeUsage{Input: u64ptr(12), Output: u64ptr(6)}, base.Add(3*time.Second), 4)
	observe(claudeModelSnapshot{present: true, value: "claude-haiku-4-5"}, claudeCodeUsage{Input: u64ptr(12), Output: u64ptr(6)}, base.Add(4*time.Second), 5)
	observe(claudeModelSnapshot{}, claudeCodeUsage{Input: u64ptr(12), Output: u64ptr(6)}, base.Add(5*time.Second), 6)
	if len(quarantine.issues) != 1 {
		t.Fatalf("expected the conflict to be diagnosed once: %#v", quarantine.issues)
	}
	message.resolveClaudeModel(quarantine)
	if message.Model != "unknown" {
		t.Fatalf("expected the conflict to stay sticky, got %q", message.Model)
	}

	// A message that never sees a model resolves to the explicit unknown
	// mapping with one local, value-free diagnostic at its usage
	// representative — not a quarantine, not a guess.
	observe2 := func(model claudeModelSnapshot, line int) {
		applyClaudeObservation(final, claudeCodeObservation{
			MessageID: "m2",
			Timestamp: base.Add(time.Duration(line) * time.Second),
			Usage:     claudeCodeUsage{Input: u64ptr(1)},
			Model:     model,
			File:      "session.jsonl",
			Line:      line,
		}, quarantine)
	}
	observe2(claudeModelSnapshot{}, 10)
	observe2(claudeModelSnapshot{}, 11)
	m2 := final["m2"]
	m2.resolveClaudeModel(quarantine)
	if m2.Model != "unknown" {
		t.Fatalf("expected missing model to map to unknown, got %q", m2.Model)
	}
	if len(quarantine.issues) != 2 || quarantine.total != 0 {
		t.Fatalf("expected the missing-model diagnostic without quarantine: %#v total=%d", quarantine.issues, quarantine.total)
	}
	if quarantine.issues[1].Reason != claudeMissingModelReason || quarantine.issues[1].File != "session.jsonl" || quarantine.issues[1].Line != 10 {
		t.Fatalf("expected the value-free diagnostic at the usage representative, got %#v", quarantine.issues[1])
	}

	// A literal recorded "unknown" identifier is data, not a gap: it never
	// triggers the missing-model diagnostic.
	applyClaudeObservation(final, claudeCodeObservation{
		MessageID: "m3",
		Timestamp: base.Add(20 * time.Second),
		Usage:     claudeCodeUsage{Input: u64ptr(2)},
		Model:     claudeModelSnapshot{present: true, value: "unknown"},
		File:      "session.jsonl",
		Line:      20,
	}, quarantine)
	m3 := final["m3"]
	m3.resolveClaudeModel(quarantine)
	if m3.Model != "unknown" {
		t.Fatalf("expected the literal unknown identifier to be kept, got %q", m3.Model)
	}
	if len(quarantine.issues) != 2 || quarantine.total != 0 {
		t.Fatalf("a literal unknown model must not be misreported as missing: %#v total=%d", quarantine.issues, quarantine.total)
	}
}
