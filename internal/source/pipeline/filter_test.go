package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

func TestFilterHistoryCutoff(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(0, 0, -7)

	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		DeviceID:    "dev-filter-1",
		HistoryFrom: &cutoff,
		HistoryDays: 7,
	}); err != nil {
		t.Fatal(err)
	}

	oldTime := cutoff.Add(-1 * time.Hour).Format(time.RFC3339)
	newTime := cutoff.Add(1 * time.Hour).Format(time.RFC3339)

	records := []adapter.Record{
		{
			"recordKey":  "rec-old-1",
			"occurredAt": oldTime,
			"source":     adapter.ClaudeCodeJSONLSource,
		},
		{
			"recordKey":  "rec-new-1",
			"occurredAt": newTime,
			"source":     adapter.ClaudeCodeJSONLSource,
		},
	}

	tokVal := uint64(100)
	updates := []progress.MessagePendingUpdate{
		{
			MessageID: "msg-old",
			RecordKey: "rec-old-1",
			To: &progress.MessageUsageState{
				Input: &tokVal,
			},
		},
		{
			MessageID: "msg-new",
			RecordKey: "rec-new-1",
			To: &progress.MessageUsageState{
				Input: &tokVal,
			},
		},
	}

	opt := adapter.Options{
		Source:   adapter.ClaudeCodeJSONLSource,
		StateDir: stateDir,
	}

	keptRecords, keptUpdates, err := FilterHistoryCutoff(opt, records, updates)
	if err != nil {
		t.Fatalf("FilterHistoryCutoff failed: %v", err)
	}

	if len(keptRecords) != 1 || adapter.StringField(keptRecords[0], "recordKey") != "rec-new-1" {
		t.Fatalf("expected 1 kept record 'rec-new-1', got %v", keptRecords)
	}
	if len(keptUpdates) != 1 || keptUpdates[0].RecordKey != "rec-new-1" {
		t.Fatalf("expected 1 kept update 'rec-new-1', got %v", keptUpdates)
	}

	// Verify old message baseline was established in progress store
	pStore := progress.New(stateDir)
	messages, _, err := pStore.LoadMessageProgress()
	if err != nil {
		t.Fatal(err)
	}
	oldMsgKey := adapter.ClaudeCodeJSONLSource + "\x00msg-old"
	entry, ok := messages[oldMsgKey]
	if !ok || entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 100 {
		t.Fatalf("expected confirmed baseline for old message to be set to 100, got: %#v", entry)
	}

	// Verify old record was quarantined with ReasonBeforeHistoryFrom
	qStore := quarantine.New(stateDir)
	entries, err := qStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "rec-old-1" || entries[0].Reason != quarantine.ReasonBeforeHistoryFrom {
		t.Fatalf("expected 1 quarantine entry for rec-old-1 with reason %s, got %#v", quarantine.ReasonBeforeHistoryFrom, entries)
	}
}

func TestHistoryCutoffPropagatesStateErrors(t *testing.T) {
	for _, tc := range []struct {
		file string
		want string
	}{
		{"device.json", "load history cutoff"},
		{"message-progress.json", "confirm skipped history baseline"},
		{"scope-quarantine.json", "quarantine skipped history"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			cutoff := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
			opt := adapter.Options{Source: adapter.ClaudeCodeJSONLSource, StateDir: dir, HistoryFrom: &cutoff}
			if tc.file == "device.json" {
				opt.HistoryFrom = nil
			}
			records := []adapter.Record{{"recordKey": "old", "occurredAt": cutoff.Add(-time.Hour).Format(time.RFC3339)}}
			count := uint64(100)
			updates := []progress.MessagePendingUpdate{{MessageID: "old", RecordKey: "old", To: &progress.MessageUsageState{Input: &count}}}
			_, _, err := FilterHistoryCutoff(opt, records, updates)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}
