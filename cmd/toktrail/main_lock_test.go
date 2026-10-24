package main

import (
	"errors"
	"os"
	"testing"

	"toktrail-collector/internal/local/runlock"
)

func TestStateCommandsRejectConcurrentAccessBeforeAnyWork(t *testing.T) {
	dir := t.TempDir()
	lock, err := runlock.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	commands := map[string]func([]string) error{
		"bind": runBind, "status": runStatus, "scan": runScan,
		"preview": runPreview, "export": runExport, "sync": runSync,
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			if err := run([]string{"--state-dir", dir}); !errors.Is(err, runlock.ErrBusy) {
				t.Fatalf("expected state lock rejection before command work, got %v", err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ".collector.lock" {
		t.Fatalf("blocked commands must not create credentials, journals or outbox: %v", entries)
	}
}
