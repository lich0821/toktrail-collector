package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

// FilterHistoryCutoff drops records whose occurredAt timestamp is strictly before the
// configured HistoryFrom cutoff (either provided in opt or loaded from opt.StateDir).
//
// To prevent cumulative baseline re-exports or replaying tokens from zero:
//  1. For Claude Code messages whose intervals are skipped, their To state is recorded
//     directly into message progress as Confirmed baseline via EstablishConfirmedBaseline.
//  2. Skipped records are quarantined with quarantine.ReasonBeforeHistoryFrom so that
//     adapters (like codex-jsonl) and sync reconciliation recognize them as known/handled
//     and do not re-emit them in subsequent runs.
func FilterHistoryCutoff(opt adapter.Options, records []adapter.Record, updates []progress.MessagePendingUpdate) ([]adapter.Record, []progress.MessagePendingUpdate, error) {
	cutoff := opt.HistoryFrom
	if cutoff == nil && strings.TrimSpace(opt.StateDir) != "" {
		st, err := statedir.New(opt.StateDir).Load()
		if err != nil {
			return nil, nil, fmt.Errorf("load history cutoff: %w", err)
		}
		if st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
			cutoff = st.HistoryFrom
		}
	}
	if cutoff == nil || cutoff.IsZero() {
		return records, updates, nil
	}

	kept := make([]adapter.Record, 0, len(records))
	skipped := make([]adapter.Record, 0)
	skippedKeys := make(map[string]bool)

	for _, rec := range records {
		tsStr := adapter.StringField(rec, "occurredAt")
		ts, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, tsStr)
		}
		if err == nil && ts.Before(*cutoff) {
			skipped = append(skipped, rec)
			if key := adapter.StringField(rec, "recordKey"); key != "" {
				skippedKeys[key] = true
			}
			continue
		}
		kept = append(kept, rec)
	}

	if len(skipped) == 0 {
		return records, updates, nil
	}

	// Partition message updates
	keptUpdates := make([]progress.MessagePendingUpdate, 0, len(updates))
	skippedUpdates := make([]progress.MessagePendingUpdate, 0)
	for _, u := range updates {
		if skippedKeys[u.RecordKey] {
			skippedUpdates = append(skippedUpdates, u)
		} else {
			keptUpdates = append(keptUpdates, u)
		}
	}

	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir != "" {
		// Advance baseline for skipped message intervals so they don't replay deltas from 0
		if len(skippedUpdates) > 0 {
			if err := progress.New(stateDir).EstablishConfirmedBaseline(opt.Source, skippedUpdates); err != nil {
				return nil, nil, fmt.Errorf("confirm skipped history baseline: %w", err)
			}
		}

		// Quarantine skipped records with ReasonBeforeHistoryFrom
		entries := make([]quarantine.Entry, 0, len(skipped))
		now := time.Now().UTC()
		for _, r := range skipped {
			key := adapter.StringField(r, "recordKey")
			if key == "" {
				continue
			}
			raw, err := json.Marshal(r)
			if err != nil {
				continue
			}
			entries = append(entries, quarantine.Entry{
				Source:        opt.Source,
				Input:         opt.Input,
				RecordKey:     key,
				Record:        raw,
				OriginBatchID: opt.BatchID,
				Reason:        quarantine.ReasonBeforeHistoryFrom,
				QuarantinedAt: now,
			})
		}
		if len(entries) > 0 {
			if err := quarantine.New(stateDir).Append(entries); err != nil {
				return nil, nil, fmt.Errorf("quarantine skipped history: %w", err)
			}
		}
	}

	return kept, keptUpdates, nil
}
