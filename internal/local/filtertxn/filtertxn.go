// Package filtertxn makes the history-cutoff filter's two durable side
// effects — quarantining skipped records and establishing Claude Code
// message baselines — one crash-safe, replayable transaction, using the
// same write-ahead journal pattern as internal/local/exportcommit:
//
//  1. the full intent (quarantine entries plus baseline updates) is
//     journaled atomically before any store is touched;
//  2. every step is applied idempotently, the quarantine store first and
//     the message baselines last;
//  3. the journal is removed only after every step succeeded;
//  4. the next export (PrepareExport recovers before the adapter loads
//     records) or FilterHistoryCutoff call replays a leftover journal to
//     completion before any new transaction starts.
//
// The apply order matters. A crash between the two writes is only
// self-healing when the quarantine store is written first: without a
// baseline the claude-code-jsonl adapter re-emits the skipped interval, so
// the next filter run re-derives the same transaction even if the journal
// itself is lost. With the baseline written first (the pre-journal order),
// a crash before the quarantine write is a permanent loss: the baseline
// suppresses re-emission (zero delta), the quarantine entries can never be
// re-created, and widening the history window later cannot recover the
// skipped records. The journal closes that window; the apply order keeps
// the residual single-write window on the self-healing side.
//
// Old state compatibility: both apply steps are the same store calls the
// filter performed before this package existed (quarantine.Append and
// progress.EstablishConfirmedBaseline), so state directories written by
// older collectors are read and extended unchanged, and replaying a journal
// over such state is safe. One legacy state cannot be repaired: a baseline
// that an older collector wrote before crashing in front of the quarantine
// write has already suppressed re-emission, and the raw record bytes needed
// to re-create the missing quarantine entry are gone. Re-deriving that
// interval from the source logs would be guessing, which this package
// refuses; those records stay unquarantined (never re-uploaded, and not
// recoverable by scope widening). The journal guarantees that no NEW such
// state can be created.
//
// Recovery placement and serialization: a pending journal must be replayed
// before any adapter loads the state it governs (the export pipeline
// recovers ahead of its adapter load), so records are computed against
// converged state. The journal is a single per-state-directory slot and its
// create→apply→remove cycle carries no intra-process lock; like
// exportcommit's journal it relies on the caller's runlock serialization
// around state-directory access. Recovery and commit are idempotent, so a
// replay is always safe.
package filtertxn

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
)

const journalFileName = "filter-transaction.json"

// SchemaVersion is the only journal schema this package accepts.
const SchemaVersion = 1

// Journal is the durable intent of one history-cutoff filter transaction:
// the raw records to quarantine (reason before_history_from) and the Claude
// Code message baselines to establish so the skipped history is never
// replayed from zero. Both halves describe the same skipped records;
// applying only one of them is exactly the crash state this package exists
// to repair.
type Journal struct {
	Schema     int                             `json:"schema"`
	Source     string                          `json:"source"`
	Input      string                          `json:"input,omitempty"`
	Quarantine []quarantine.Entry              `json:"quarantine,omitempty"`
	Baselines  []progress.MessagePendingUpdate `json:"baselines,omitempty"`
	CreatedAt  time.Time                       `json:"createdAt"`
}

// Commit durably applies one filter transaction: the journal is written
// atomically first, then every step is applied idempotently, then the
// journal is removed. A crash or a step error at any point leaves the
// journal behind for Recover to replay. Committing the same transaction
// twice is a no-op: the quarantine store dedupes canonically identical
// entries and baseline establishment only fills still-missing baselines.
func Commit(stateDir string, journal Journal) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return errors.New("history-filter transaction requires a state dir")
	}
	if len(journal.Quarantine) == 0 && len(journal.Baselines) == 0 {
		return nil
	}
	if err := journal.validate(); err != nil {
		return err
	}
	if err := writeJournal(stateDir, journal); err != nil {
		return err
	}
	if err := applyJournal(stateDir, journal); err != nil {
		return err
	}
	return removeJournal(stateDir)
}

// Recover replays a leftover history-filter transaction to completion and
// removes its journal. recovered reports whether a journal was found. A
// corrupt or foreign-schema journal is a hard error: the intent is unknown,
// so the caller must fail closed instead of guessing which half was applied.
func Recover(stateDir string) (recovered bool, err error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return false, nil
	}
	journal, ok, err := readJournal(stateDir)
	if err != nil || !ok {
		return false, err
	}
	if err := applyJournal(stateDir, journal); err != nil {
		return false, err
	}
	if err := removeJournal(stateDir); err != nil {
		return false, err
	}
	return true, nil
}

// JournalPath is the filter transaction journal location of a state dir.
func JournalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), journalFileName)
}

// applyJournal applies both halves idempotently, quarantine store first and
// message baselines last (see the package comment for why this order keeps
// every interruption point recoverable). Both steps are the same store
// calls the filter performed before transactions existed, so a replay over
// state written by an older collector — or over a partially applied earlier
// replay of this journal — converges to the same result.
func applyJournal(stateDir string, journal Journal) error {
	if len(journal.Quarantine) > 0 {
		if err := quarantine.New(stateDir).Append(journal.Quarantine); err != nil {
			return fmt.Errorf("quarantine skipped history: %w", err)
		}
	}
	if len(journal.Baselines) > 0 {
		if err := progress.New(stateDir).EstablishConfirmedBaseline(journal.Source, journal.Baselines); err != nil {
			return fmt.Errorf("confirm skipped history baseline: %w", err)
		}
	}
	return nil
}

func (j Journal) validate() error {
	if j.Schema != SchemaVersion {
		return fmt.Errorf("history-filter journal has unsupported schema %d, want %d", j.Schema, SchemaVersion)
	}
	if j.CreatedAt.IsZero() {
		return errors.New("history-filter journal requires createdAt")
	}
	for idx, entry := range j.Quarantine {
		if strings.TrimSpace(entry.RecordKey) == "" {
			return fmt.Errorf("history-filter journal quarantine entry %d requires a record key", idx)
		}
		if strings.TrimSpace(entry.Reason) == "" {
			return fmt.Errorf("history-filter journal quarantine entry %d requires a reason", idx)
		}
		if entry.QuarantinedAt.IsZero() {
			return fmt.Errorf("history-filter journal quarantine entry %d requires quarantinedAt", idx)
		}
	}
	for idx, update := range j.Baselines {
		if strings.TrimSpace(update.MessageID) == "" || strings.TrimSpace(update.RecordKey) == "" || update.To == nil {
			return fmt.Errorf("history-filter journal baseline %d requires message id, record key, and to-state", idx)
		}
	}
	return nil
}

func writeJournal(stateDir string, journal Journal) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	path := JournalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJournal(stateDir string) (Journal, bool, error) {
	b, err := os.ReadFile(JournalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, err
	}
	var journal Journal
	if err := json.Unmarshal(b, &journal); err != nil {
		return Journal{}, false, fmt.Errorf("corrupt %s: %w; failing closed (remove the file only if you accept abandoning the pending history-filter transaction)", JournalPath(stateDir), err)
	}
	if err := journal.validate(); err != nil {
		return Journal{}, false, fmt.Errorf("invalid %s: %w; failing closed (remove the file only if you accept abandoning the pending history-filter transaction)", JournalPath(stateDir), err)
	}
	return journal, true, nil
}

func removeJournal(stateDir string) error {
	err := os.Remove(JournalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
