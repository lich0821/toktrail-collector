package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// migrationFixture preserves literal fixture bytes except for the drive prefix
// required by Windows absolute paths. Assertions compare the exact written bytes.
func migrationFixture(t *testing.T, raw string) []byte {
	t.Helper()
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(t.TempDir())
		raw = strings.ReplaceAll(raw, `"input": "/`, `"input": "`+volume+`/`)
	}
	return []byte(raw)
}

func writeLegacyConfig(t *testing.T, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, legacyConfigFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCurrentConfig(t *testing.T, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, configFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// 1. missing: neither grants.json nor sources.json exists.
func TestRegressionMissing(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("expected nil error on missing configs, got %v", err)
	}
	if cfg.Version != 1 || len(cfg.Grants) != 0 {
		t.Fatalf("expected empty config version 1, got %#v", cfg)
	}

	enabled, err := store.Enabled()
	if err != nil {
		t.Fatalf("expected nil error on Enabled(), got %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected zero enabled grants, got %#v", enabled)
	}

	if err := store.MigrateLegacy(); err != nil {
		t.Fatalf("expected MigrateLegacy() to succeed as no-op, got %v", err)
	}

	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatal("grants.json must not be created when legacy is missing")
	}
	if _, err := os.Stat(store.LegacyPath()); !os.IsNotExist(err) {
		t.Fatal("sources.json must not be created")
	}
}

// 2. both: current grants.json and legacy sources.json both exist -> current always wins, legacy untouched.
func TestRegressionBothCurrentWins(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/from/legacy",
      "enabled": true
    }
  ]
}`)
	currentBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "codex-jsonl",
      "input": "/path/from/current",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)
	writeCurrentConfig(t, dir, currentBytes)

	// Load() must return current config
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Source != "codex-jsonl" {
		t.Fatalf("expected current grants.json to win, got %#v", cfg)
	}

	// MigrateLegacy() must be a no-op, never clobber current
	if err := store.MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy failed: %v", err)
	}

	// Verify current file unchanged
	curData, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(curData, currentBytes) {
		t.Fatalf("grants.json was modified: got %s, want %s", curData, currentBytes)
	}

	// Verify legacy file unchanged
	legData, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legData, legacyBytes) {
		t.Fatalf("sources.json was modified: got %s, want %s", legData, legacyBytes)
	}
}

// 3. current empty: current grants.json with empty grants wins over non-empty legacy.
func TestRegressionCurrentEmptyWins(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/from/legacy",
      "enabled": true
    }
  ]
}`))
	writeCurrentConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": []
}`))

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("expected empty grants from current config, got %#v", cfg.Grants)
	}

	enabled, err := store.Enabled()
	if err != nil {
		t.Fatalf("Enabled failed: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected zero enabled grants, got %#v", enabled)
	}

	if err := store.MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy failed: %v", err)
	}

	// Current file must still be empty
	cfg, err = store.Load()
	if err != nil || len(cfg.Grants) != 0 {
		t.Fatalf("current empty file was clobbered: %#v", cfg)
	}
}

// 4. current corrupt: corrupt current grants.json must NOT fall back to legacy sources.json.
func TestRegressionCurrentCorruptDoesNotFallback(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/from/legacy",
      "enabled": true
    }
  ]
}`))
	corruptBytes := migrationFixture(t, `{"version": 1, "grants": [corrupt JSON`)
	writeCurrentConfig(t, dir, corruptBytes)

	// Load() must fail on corrupt current file and NOT fall back
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "invalid source grant config") {
		t.Fatalf("expected invalid source grant config error, got %v", err)
	}

	// MigrateLegacy() must also fail and not clobber
	if err := store.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "invalid source grant config") {
		t.Fatalf("expected MigrateLegacy error on corrupt current, got %v", err)
	}

	curData, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(curData, corruptBytes) {
		t.Fatal("corrupt current grants.json was clobbered")
	}
}

// 5. legacy corrupt: grants.json absent, sources.json corrupt.
func TestRegressionLegacyCorrupt(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	writeLegacyConfig(t, dir, migrationFixture(t, `{"version": 1, "grants": [corrupt legacy`))

	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "invalid source grant config") {
		t.Fatalf("expected invalid source grant config error on Load, got %v", err)
	}
	if err := store.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "invalid source grant config") {
		t.Fatalf("expected invalid source grant config error on MigrateLegacy, got %v", err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatal("grants.json must not be created when legacy is corrupt")
	}
}

// 6. version: unsupported version in legacy or current.
func TestRegressionVersion(t *testing.T) {
	// Case A: legacy version 2, current absent
	dirA := t.TempDir()
	storeA := New(dirA)
	writeLegacyConfig(t, dirA, migrationFixture(t, `{"version": 2, "grants": []}`))
	if _, err := storeA.Load(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error on Load, got %v", err)
	}
	if err := storeA.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error on MigrateLegacy, got %v", err)
	}

	// Case B: current version 2, legacy valid version 1
	dirB := t.TempDir()
	storeB := New(dirB)
	writeLegacyConfig(t, dirB, migrationFixture(t, `{"version": 1, "grants": [{"source":"usage-json","input":"/p","enabled":true}]}`))
	writeCurrentConfig(t, dirB, migrationFixture(t, `{"version": 2, "grants": []}`))
	if _, err := storeB.Load(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error on Load, got %v", err)
	}
	if err := storeB.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error on MigrateLegacy, got %v", err)
	}
}

// 7. invalid source in legacy: unknown source adapter.
func TestRegressionInvalidSource(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "unknown-source-xyz",
      "input": "/path/to/something",
      "enabled": true
    }
  ]
}`))

	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("expected unknown source error on Load, got %v", err)
	}
	if err := store.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("expected unknown source error on MigrateLegacy, got %v", err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatal("grants.json must not be created when source is invalid")
	}
}

// 8. path: invalid path in legacy (relative or empty).
func TestRegressionInvalidPath(t *testing.T) {
	// Relative path
	dir := t.TempDir()
	store := New(dir)
	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "relative/path/to/file",
      "enabled": true
    }
  ]
}`))
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error on Load, got %v", err)
	}
	if err := store.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error on MigrateLegacy, got %v", err)
	}

	// Empty path
	dir2 := t.TempDir()
	store2 := New(dir2)
	writeLegacyConfig(t, dir2, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "",
      "enabled": true
    }
  ]
}`))
	if _, err := store2.Load(); err == nil || !strings.Contains(err.Error(), "input path is required") {
		t.Fatalf("expected required input path error on Load, got %v", err)
	}
	if err := store2.MigrateLegacy(); err == nil || !strings.Contains(err.Error(), "input path is required") {
		t.Fatalf("expected required input path error on MigrateLegacy, got %v", err)
	}
}

// 9. disabled: disabled grants in legacy preserved; current disabled wins over legacy enabled.
func TestRegressionDisabledGrants(t *testing.T) {
	// Legacy has disabled grant
	dir := t.TempDir()
	store := New(dir)
	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/legacy",
      "enabled": false
    }
  ]
}`))

	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Enabled {
		t.Fatalf("expected disabled grant, got %#v", cfg.Grants)
	}
	enabled, err := store.Enabled()
	if err != nil || len(enabled) != 0 {
		t.Fatalf("expected zero enabled grants, got %#v", enabled)
	}

	if err := store.MigrateLegacy(); err != nil {
		t.Fatal(err)
	}

	// Post-migration grants.json must preserve enabled: false
	cfg, err = store.Load()
	if err != nil || len(cfg.Grants) != 1 || cfg.Grants[0].Enabled {
		t.Fatalf("expected migrated grant to remain disabled, got %#v", cfg)
	}

	// Current disabled wins over legacy enabled
	dir2 := t.TempDir()
	store2 := New(dir2)
	writeLegacyConfig(t, dir2, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/file",
      "enabled": true
    }
  ]
}`))
	writeCurrentConfig(t, dir2, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/file",
      "enabled": false
    }
  ]
}`))

	cfg, err = store2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Enabled {
		t.Fatalf("expected current disabled grant to win, got %#v", cfg.Grants)
	}
	enabled, err = store2.Enabled()
	if err != nil || len(enabled) != 0 {
		t.Fatalf("expected zero enabled grants, got %#v", enabled)
	}
}

// 10. dangling symlink:
// - grants.json is a dangling symlink -> NOT truly absent, fails without falling back.
// - legacy sources.json is a dangling symlink -> fails.
func TestRegressionDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping symlink tests on windows")
	}

	// Case A: grants.json is a dangling symlink, legacy is valid
	dir := t.TempDir()
	store := New(dir)
	writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/file",
      "enabled": true
    }
  ]
}`))
	targetPath := filepath.Join(dir, "nonexistent-target")
	if err := os.Symlink(targetPath, store.Path()); err != nil {
		t.Fatal(err)
	}

	// Load() must fail and NOT fall back to sources.json
	if _, err := store.Load(); err == nil {
		t.Fatal("expected error on dangling symlink grants.json, got nil")
	}

	// MigrateLegacy() must fail and NOT clobber the dangling symlink
	if err := store.MigrateLegacy(); err == nil {
		t.Fatal("expected error on MigrateLegacy with dangling symlink, got nil")
	}

	fi, err := os.Lstat(store.Path())
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("dangling symlink was clobbered or removed")
	}

	// Case B: grants.json absent, sources.json is dangling symlink
	dir2 := t.TempDir()
	store2 := New(dir2)
	if err := os.Symlink(targetPath, store2.LegacyPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Load(); err == nil {
		t.Fatal("expected error on dangling symlink sources.json, got nil")
	}
	if err := store2.MigrateLegacy(); err == nil {
		t.Fatal("expected error on MigrateLegacy with dangling legacy symlink, got nil")
	}
}

// 11. publication error: hardlink failure (e.g. ENOTSUP) fails closed, leaves no temp files.
func TestRegressionPublicationErrorFailClosed(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/legacy",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	// Mock linkFile to return ENOTSUP
	origLink := linkFile
	linkFile = func(oldname, newname string) error {
		return syscall.ENOTSUP
	}
	defer func() { linkFile = origLink }()

	err := store.MigrateLegacy()
	if !errors.Is(err, syscall.ENOTSUP) {
		t.Fatalf("expected ENOTSUP, got %v", err)
	}

	// grants.json must NOT exist
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatal("grants.json must not exist after publication error")
	}

	// sources.json must be retained untouched
	data, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, legacyBytes) {
		t.Fatal("sources.json bytes modified")
	}

	// Verify no stray temp files left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("found stray temp file: %s", entry.Name())
		}
	}
}

// 12. repeat: multiple calls to MigrateLegacy are idempotent.
func TestRegressionRepeatIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/legacy",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	for i := 0; i < 5; i++ {
		if err := store.MigrateLegacy(); err != nil {
			t.Fatalf("iteration %d: MigrateLegacy failed: %v", i, err)
		}
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Source != "usage-json" {
		t.Fatalf("unexpected grants: %#v", cfg)
	}

	// sources.json retained
	data, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, legacyBytes) {
		t.Fatal("sources.json bytes modified")
	}
}

// 13. concurrent: concurrent calls to MigrateLegacy all succeed, no corruption, exclusive publication.
func TestRegressionConcurrentMigrateLegacy(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/legacy",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	const goroutines = 25
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = store.MigrateLegacy()
		}(i)
	}
	wg.Wait()

	for idx, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", idx, err)
		}
	}

	// Validate resulting grants.json
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Source != "usage-json" {
		t.Fatalf("unexpected grants: %#v", cfg)
	}

	// Permissions check
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 config, got %#o", info.Mode().Perm())
	}

	// Verify no stray temp files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("found stray temp file: %s", entry.Name())
		}
	}
}

// 14. race current appears: during migration, current file appears concurrently before hardlink.
func TestRegressionRaceCurrentAppears(t *testing.T) {
	// Subtest 1: Authoritative current appears valid -> MigrateLegacy loads it, returns nil, never clobbers.
	t.Run("valid current appears", func(t *testing.T) {
		dir := t.TempDir()
		store := New(dir)
		writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/legacy/path",
      "enabled": true
    }
  ]
}`))

		authoritativeCurrent := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "codex-jsonl",
      "input": "/authoritative/path",
      "enabled": true
    }
  ]
}`)
		origLink := linkFile
		linkFile = func(oldname, newname string) error {
			// Simulate concurrent creator creating grants.json right before hardlink
			if err := os.WriteFile(newname, authoritativeCurrent, 0o600); err != nil {
				return err
			}
			return os.Link(oldname, newname) // will return os.ErrExist
		}
		defer func() { linkFile = origLink }()

		if err := store.MigrateLegacy(); err != nil {
			t.Fatalf("expected nil error on race with valid current, got %v", err)
		}

		// Current config must be the authoritative one, not legacy
		cfg, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Grants) != 1 || cfg.Grants[0].Source != "codex-jsonl" {
			t.Fatalf("authoritative config was clobbered: %#v", cfg)
		}
	})

	// Subtest 2: Authoritative current appears corrupt -> MigrateLegacy loads it, surfaces error, never clobbers.
	t.Run("corrupt current appears", func(t *testing.T) {
		dir := t.TempDir()
		store := New(dir)
		writeLegacyConfig(t, dir, migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/legacy/path",
      "enabled": true
    }
  ]
}`))

		corruptCurrent := migrationFixture(t, `{"version": 1, "grants": [corrupt JSON`)
		origLink := linkFile
		linkFile = func(oldname, newname string) error {
			if err := os.WriteFile(newname, corruptCurrent, 0o600); err != nil {
				return err
			}
			return os.Link(oldname, newname) // will return os.ErrExist
		}
		defer func() { linkFile = origLink }()

		err := store.MigrateLegacy()
		if err == nil || !strings.Contains(err.Error(), "invalid source grant config") {
			t.Fatalf("expected invalid config error on corrupt current race, got %v", err)
		}

		// Verify corrupt file was not clobbered
		data, err := os.ReadFile(store.Path())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, corruptCurrent) {
			t.Fatal("corrupt file was overwritten")
		}
	})
}

// 15. other state untouched: legacy bytes retained, other files in directory untouched.
func TestRegressionOtherStateUntouched(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "usage-json",
      "input": "/path/to/legacy",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	// Create other unrelated files and subdirectories
	unrelatedFile := filepath.Join(dir, "token.key")
	if err := os.WriteFile(unrelatedFile, []byte("secret-token-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	subFile := filepath.Join(subDir, "cache.db")
	if err := os.WriteFile(subFile, []byte("database-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := store.MigrateLegacy(); err != nil {
		t.Fatal(err)
	}

	// Verify legacy file retained
	legData, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legData, legacyBytes) {
		t.Fatal("legacy bytes changed")
	}

	// Verify unrelated file untouched
	tokData, err := os.ReadFile(unrelatedFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(tokData) != "secret-token-bytes" {
		t.Fatal("unrelated file changed")
	}

	// Verify sub file untouched
	subData, err := os.ReadFile(subFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(subData) != "database-bytes" {
		t.Fatal("sub file changed")
	}
}

// 16. input existence not required to migrate: exact source, input, flags, timestamps, and order preserved.
func TestRegressionInputExistenceNotRequiredAndExactPreservation(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	addedAt1 := time.Date(2025, 3, 10, 14, 30, 0, 0, time.UTC)
	editedAt1 := time.Date(2025, 3, 11, 9, 15, 0, 0, time.UTC)
	addedAt2 := time.Date(2025, 4, 1, 12, 0, 0, 0, time.UTC)

	// Non-existent paths!
	input1 := filepath.Join(t.TempDir(), "missing-a.json")
	input2 := filepath.Join(t.TempDir(), "missing-b.jsonl")

	cfgIn := Config{
		Version: 1,
		Grants: []Grant{
			{
				Source:   "usage-json",
				Input:    input1,
				Enabled:  false,
				AddedAt:  addedAt1,
				EditedAt: editedAt1,
			},
			{
				Source:  "codex-jsonl",
				Input:   input2,
				Enabled: true,
				AddedAt: addedAt2,
			},
		},
	}
	b, err := json.MarshalIndent(cfgIn, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyConfig(t, dir, b)

	// Read-only Load() works even with non-existent input paths
	cfgLoaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfgLoaded.Grants) != 2 {
		t.Fatalf("expected 2 grants, got %#v", cfgLoaded)
	}

	// MigrateLegacy() works without requiring inputs to exist
	if err := store.MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy failed: %v", err)
	}

	// Load migrated config
	cfgMigrated, err := store.Load()
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}
	if len(cfgMigrated.Grants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(cfgMigrated.Grants))
	}

	// Check grant 0 exact fields
	g0 := cfgMigrated.Grants[0]
	if g0.Source != "usage-json" || g0.Input != input1 || g0.Enabled != false {
		t.Fatalf("grant 0 fields mismatch: %#v", g0)
	}
	if !g0.AddedAt.Equal(addedAt1) || !g0.EditedAt.Equal(editedAt1) {
		t.Fatalf("grant 0 timestamps mismatch: addedAt=%v, editedAt=%v", g0.AddedAt, g0.EditedAt)
	}

	// Check grant 1 exact fields
	g1 := cfgMigrated.Grants[1]
	if g1.Source != "codex-jsonl" || g1.Input != input2 || g1.Enabled != true {
		t.Fatalf("grant 1 fields mismatch: %#v", g1)
	}
	if !g1.AddedAt.Equal(addedAt2) {
		t.Fatalf("grant 1 timestamps mismatch: addedAt=%v", g1.AddedAt)
	}

	// Permissions check: private 0600
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %#o", info.Mode().Perm())
	}
}

// 17. Enable integration:
// - validates arguments first
// - calls MigrateLegacy before modifying
// - preserves existing legacy grant and adds new grant
func TestRegressionEnableWithLegacy(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "codex-jsonl",
      "input": "/legacy/session/path",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	// Valid input file to enable
	newInput := writeInputFile(t, dir, "new_adapter.json")

	// Call Enable
	grant, err := store.Enable("usage-json", newInput)
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if grant.Source != "usage-json" || !grant.Enabled {
		t.Fatalf("unexpected grant returned: %#v", grant)
	}

	// grants.json must now have BOTH the legacy grant and the new grant
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 2 {
		t.Fatalf("expected 2 grants, got %d: %#v", len(cfg.Grants), cfg.Grants)
	}
	if cfg.Grants[0].Source != "codex-jsonl" || cfg.Grants[1].Source != "usage-json" {
		t.Fatalf("expected order preserved, got %#v", cfg.Grants)
	}

	// sources.json must still exist and be untouched
	legData, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legData, legacyBytes) {
		t.Fatal("sources.json was modified")
	}

	// Test validation happens BEFORE migration:
	// If sources.json is corrupt but Enable arguments are invalid, argument error must be returned
	dirCorrupt := t.TempDir()
	storeCorrupt := New(dirCorrupt)
	writeLegacyConfig(t, dirCorrupt, []byte("corrupt JSON"))

	// Unknown source
	if _, err := storeCorrupt.Enable("unknown-adapter", newInput); err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("expected unknown source error, got %v", err)
	}

	// Relative path
	if _, err := storeCorrupt.Enable("usage-json", "relative/path"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}

	// Missing input
	if _, err := storeCorrupt.Enable("usage-json", filepath.Join(dirCorrupt, "missing.json")); err == nil {
		t.Fatal("expected missing input error")
	}
}

// 18. Disable integration:
// - validates arguments first
// - calls MigrateLegacy before modifying
// - legacy grant is migrated and marked disabled
func TestRegressionDisableWithLegacy(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	legacyPath := filepath.ToSlash(filepath.Join(dir, "legacy", "session", "path"))
	legacyBytes := migrationFixture(t, `{
  "version": 1,
  "grants": [
    {
      "source": "codex-jsonl",
      "input": "`+legacyPath+`",
      "enabled": true
    }
  ]
}`)
	writeLegacyConfig(t, dir, legacyBytes)

	// Call Disable on the legacy grant
	grant, found, err := store.Disable("codex-jsonl", legacyPath)
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if !found || grant.Enabled {
		t.Fatalf("expected found=true and Enabled=false, got found=%v, grant=%#v", found, grant)
	}

	// grants.json must have the grant disabled
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Enabled {
		t.Fatalf("expected grant disabled in grants.json, got %#v", cfg.Grants)
	}

	// sources.json must still exist and still have enabled=true
	legData, err := os.ReadFile(store.LegacyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legData, legacyBytes) {
		t.Fatal("sources.json was modified")
	}

	// Argument validation happens BEFORE migration
	dirCorrupt := t.TempDir()
	storeCorrupt := New(dirCorrupt)
	writeLegacyConfig(t, dirCorrupt, []byte("corrupt JSON"))

	// Unknown source
	if _, _, err := storeCorrupt.Disable("unknown-adapter", "/path"); err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("expected unknown source error, got %v", err)
	}

	// Relative path
	if _, _, err := storeCorrupt.Disable("codex-jsonl", "relative/path"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

// 19. save atomicity and permissions
func TestRegressionSaveAtomicityAndPermissions(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	input := writeInputFile(t, dir, "input.json")
	grant, err := store.Enable("usage-json", input)
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %#o", info.Mode().Perm())
	}

	// Disable it to test save on existing config
	_, found, err := store.Disable(grant.Source, grant.Input)
	if err != nil || !found {
		t.Fatalf("Disable failed: found=%v, err=%v", found, err)
	}

	info, err = os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %#o", info.Mode().Perm())
	}

	// Verify no stray temp files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("stray temp file found: %s", entry.Name())
		}
	}
}
