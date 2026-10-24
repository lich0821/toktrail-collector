package grants

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeInputFile(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"records\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnableDisableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if _, err := store.Enable("usage-json", writeInputFile(t, dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	grants, err := store.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Source != "usage-json" || !grants[0].Enabled {
		t.Fatalf("unexpected grants: %#v", grants)
	}
	if _, err := store.Enable("codex-jsonl", writeInputFile(t, dir, "sessions")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Disable("usage-json", filepath.Join(dir, "a.json")); err != nil || !found {
		t.Fatalf("disable failed: found=%v err=%v", found, err)
	}
	grants, err = store.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Source != "codex-jsonl" {
		t.Fatalf("expected only codex grant enabled: %#v", grants)
	}
	// Disabling an unrecorded grant pair is not an error (found=false);
	// disabling an already-disabled grant stays a no-op success.
	if _, found, err := store.Disable("claude-code-jsonl", filepath.Join(dir, "never.json")); err != nil || found {
		t.Fatalf("unrecorded disable: found=%v err=%v", found, err)
	}
	if _, found, err := store.Disable("usage-json", filepath.Join(dir, "a.json")); err != nil || !found {
		t.Fatalf("idempotent disable: found=%v err=%v", found, err)
	}
}

func TestEnableRejectsUnknownSource(t *testing.T) {
	dir := t.TempDir()
	input := writeInputFile(t, dir, "a.json")
	if _, err := New(dir).Enable("not-a-source", input); err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("expected unknown source error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, configFileName)); !os.IsNotExist(err) {
		t.Fatal("rejected grant must not be written to disk")
	}
}

func TestEnableRejectsRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeInputFile(t, dir, "a.json")
	if _, err := New(dir).Enable("usage-json", "a.json"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestEnableRejectsMissingInput(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	if _, err := New(dir).Enable("usage-json", missing); err == nil {
		t.Fatal("expected missing input error")
	}
}

func TestLoadRejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(Config{Version: 99, Grants: nil})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Load(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error, got %v", err)
	}
}

func TestLoadMissingConfigIsEmpty(t *testing.T) {
	grants, err := New(t.TempDir()).Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected no grants, got %#v", grants)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if _, err := store.Enable("usage-json", writeInputFile(t, dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Windows mode bits do not represent NTFS access control.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 config, got %#o", info.Mode().Perm())
	}
}

func TestEnabledSkipsDisabledGrants(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	input := writeInputFile(t, dir, "a.json")
	if _, err := store.Enable("usage-json", input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Disable("usage-json", input); err != nil {
		t.Fatal(err)
	}
	grants, err := store.Enabled()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected zero enabled grants, got %#v", grants)
	}
}
