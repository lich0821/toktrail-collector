package grants

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyConnectGrants(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	inputCodex := filepath.Join(dir, "codex-sessions")
	if err := os.MkdirAll(inputCodex, 0o700); err != nil {
		t.Fatal(err)
	}
	inputClaude := filepath.Join(dir, "claude-projects")
	if err := os.MkdirAll(inputClaude, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. Initial connect with Codex and Claude Code.
	active, err := store.ApplyConnectGrants([]Grant{
		{Source: "codex-jsonl", Input: inputCodex},
		{Source: "claude-code-jsonl", Input: inputClaude},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active grants, got %d", len(active))
	}

	// 2. Second connect with ONLY Codex: Claude Code must be disabled!
	active, err = store.ApplyConnectGrants([]Grant{
		{Source: "codex-jsonl", Input: inputCodex},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Source != "codex-jsonl" {
		t.Fatalf("expected only codex-jsonl active, got: %#v", active)
	}

	// Verify on-disk config shows Claude Code is disabled, not missing.
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 2 {
		t.Fatalf("expected 2 recorded grants (1 enabled, 1 disabled), got %d", len(cfg.Grants))
	}
	for _, g := range cfg.Grants {
		if g.Source == "claude-code-jsonl" && g.Enabled {
			t.Fatalf("claude-code-jsonl should be disabled, but was enabled")
		}
		if g.Source == "codex-jsonl" && !g.Enabled {
			t.Fatalf("codex-jsonl should be enabled, but was disabled")
		}
	}

	// 3. Connect with empty authorized list (e.g. no local tools exist):
	// All previously enabled grants must become disabled.
	active, err = store.ApplyConnectGrants([]Grant{})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active grants, got %d", len(active))
	}

	enabled, err := store.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected store.Enabled() to return 0, got %d", len(enabled))
	}
}
