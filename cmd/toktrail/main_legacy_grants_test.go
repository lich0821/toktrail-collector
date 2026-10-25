package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
)

func TestLegacySourcesListIsReadOnlyAndDisableMigratesUnderLock(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "offline-input") // Listing/migration must not scan or require input availability.
	stamp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	legacy := grants.Config{Version: 1, Grants: []grants.Grant{{
		Source: "codex-jsonl", Input: input, Enabled: true, AddedAt: stamp,
	}}}
	body, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, "sources.json")
	if err := os.WriteFile(legacyPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	store := grants.New(dir)
	if err := runSourcesList([]string{"--state-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only listing created current config: %v", err)
	}

	lock, err := runlock.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--state-dir", dir, "--source", "codex-jsonl", "--input", input}
	blockedErr := runSourcesDisable(args)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(blockedErr, runlock.ErrBusy) {
		t.Fatalf("expected lock rejection before migration: %v", blockedErr)
	}
	if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("busy command migrated config: %v", err)
	}

	if err := runSourcesDisable(args); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Grants) != 1 || cfg.Grants[0].Enabled || cfg.Grants[0].Input != input || !cfg.Grants[0].AddedAt.Equal(stamp) {
		t.Fatalf("disable lost migrated grant or its original timestamp: %#v", cfg)
	}
	if cfg.Grants[0].EditedAt.IsZero() {
		t.Fatal("explicit disable did not record edit timestamp")
	}
	oldBody, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldBody, body) {
		t.Fatal("migration or disable changed the retained legacy config")
	}
	// A later invocation must not revive the still-enabled legacy entry.
	if err := runSourcesList([]string{"--state-dir", dir}); err != nil {
		t.Fatal(err)
	}
	enabled, err := store.Enabled()
	if err != nil || len(enabled) != 0 {
		t.Fatalf("legacy config resurrected revoked grant: %#v, %v", enabled, err)
	}
}
