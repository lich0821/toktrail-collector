package registry

import (
	"path/filepath"
	"testing"
)

func TestLookupTool(t *testing.T) {
	tests := []struct {
		input     string
		wantTool  string
		wantSrc   string
		wantFound bool
	}{
		{"Codex", "Codex", "codex-jsonl", true},
		{"codex", "Codex", "codex-jsonl", true},
		{"  CODEX  ", "Codex", "codex-jsonl", true},
		{"Claude Code", "Claude Code", "claude-code-jsonl", true},
		{"claude code", "Claude Code", "claude-code-jsonl", true},
		{"claude-code", "Claude Code", "claude-code-jsonl", true},
		{"claudecode", "Claude Code", "claude-code-jsonl", true},
		{"Unknown", "", "", false},
		{"", "", "", false},
		{"Cursor", "", "", false},
		{"../../etc", "", "", false},
	}

	for _, tc := range tests {
		spec, found := LookupTool(tc.input)
		if found != tc.wantFound {
			t.Errorf("LookupTool(%q) found=%v, want=%v", tc.input, found, tc.wantFound)
		}
		if found && spec.Tool != tc.wantTool {
			t.Errorf("LookupTool(%q) tool=%q, want=%q", tc.input, spec.Tool, tc.wantTool)
		}
		if found && spec.Source != tc.wantSrc {
			t.Errorf("LookupTool(%q) source=%q, want=%q", tc.input, spec.Source, tc.wantSrc)
		}
	}
}

func TestResolveDefaultInput(t *testing.T) {
	spec, found := LookupTool("Codex")
	if !found {
		t.Fatal("Codex not found")
	}
	home := filepath.Join("test", "home")
	resolved := spec.ResolveDefaultInput(home)
	expected := filepath.Join("test", "home", ".codex", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Claude Code")
	if !found {
		t.Fatal("Claude Code not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".claude", "projects")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}
}
