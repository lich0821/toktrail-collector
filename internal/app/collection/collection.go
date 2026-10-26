// Package collection implements the periodic collection entry
// (`toktrail periodic`): export new local observations through the existing
// exportcommit WAL, then drain a bounded number of pending outbox batches
// through the existing syncclient.
//
// Guarantees:
//   - One process lock (internal/local/runlock) covers the entire run; a second
//     concurrent run fails fast with runlock.ErrBusy and performs no work.
//   - No network happens before the lock is held and the local source/input
//     grants are validated. With no enabled grants the run is a no-op that
//     never touches the network.
//   - Collection only reads inputs explicitly granted by the user
//     (internal/local/grants config); there is no default scanning.
//   - The device is never implicitly (re)bound: draining requires an
//     existing bound device, exactly like explicit `toktrail sync`, and the
//     server preflight re-checks fresh consent before every batch.
//   - No secrets appear in command arguments, output, or errors.
package collection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	synccmd "toktrail-collector/internal/syncclient"
)

// DefaultMaxSyncBatches bounds one periodic run's drain so a large backlog
// cannot make a scheduled task run unbounded; the next scheduled run
// continues where this one stopped.
const DefaultMaxSyncBatches = 5

type Options struct {
	StateDir   string
	ServerURL  string
	MaxBatches int
	HTTPClient *http.Client
	// Now is injectable for deterministic batch ids in tests.
	Now func() time.Time
}

// GrantOutcome reports what one granted source produced locally.
type GrantOutcome struct {
	Source   string
	Input    string
	Exported bool
	BatchID  string
	Records  int
	// Skipped carries a human-readable reason when this grant produced no
	// batch (no new records, disabled, or unreadable input).
	Skipped string
}

type Result struct {
	// Grants is the number of enabled grants considered.
	Grants int
	// GrantOutcomes mirrors the enabled grants in config order.
	GrantOutcomes []GrantOutcome
	// NoGrants is true when the run found no enabled grants; nothing was
	// collected and no network was used.
	NoGrants bool
	// Skipped carries the reason the run was a no-op (no grants, or lock
	// content). Empty when work was attempted.
	Skipped string

	ExportedBatches int
	ExportedRecords int

	SyncedBatches int
	SyncedRecords int
	syncedTools   map[string]bool
	// Recovered counts quarantine records re-pended during the drain.
	Recovered int
	// Quarantined counts records currently in the quarantine store after
	// the drain finished.
	Quarantined int
	// PendingRemaining counts outbox batches still pending after the
	// bounded drain.
	PendingRemaining int
	// DrainStopped is set when the drain stopped early (batch bound reached
	// or an upload failed) while batches were still pending.
	DrainStopped string
}

// Run performs one periodic collection cycle. It acquires the process lock
// for the entire run (export + drain), so the caller must not already hold
// the state lock.
func Run(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	// Lock before anything else: validation, local reads, and any network
	// all happen while this process exclusively owns the state directory.
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	res := Result{}

	// Batch payloads land in <stateDir>/batches; ensure the directory exists
	// before recovering any pending export transaction or committing new batches.
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		return res, fmt.Errorf("prepare batches dir: %w", err)
	}

	// Finish any pending export transaction left behind by an earlier crash
	// before validating grants or draining outbox, so the uncommitted batch
	// is materialized, registered as pending in outbox, and drained even if
	// all configured grants are currently idle.
	if _, err := exportcommit.Recover(stateDir); err != nil {
		return res, fmt.Errorf("recover pending export transaction: %w", err)
	}

	grantStore := grants.New(stateDir)
	// Persist legacy grants only while holding the same lock as collection.
	// Migration failures stop before scanning inputs or refreshing consent.
	if err := grantStore.MigrateLegacy(); err != nil {
		return res, fmt.Errorf("migrate source grants: %w", err)
	}
	enabledGrants, err := grantStore.Enabled()
	if err != nil {
		return res, err
	}
	res.Grants = len(enabledGrants)
	if len(enabledGrants) == 0 {
		res.NoGrants = true
		res.Skipped = "no enabled source grants; nothing to collect (sources enable requires explicit --source and --input)"
		return res, nil
	}

	now := opt.Now
	if now == nil {
		now = time.Now
	}

	var historyFrom *time.Time
	if devState, err := statedir.New(stateDir).Load(); err == nil && devState.HistoryFrom != nil && !devState.HistoryFrom.IsZero() {
		historyFrom = devState.HistoryFrom
	}

	for idx, grant := range enabledGrants {
		outcome := GrantOutcome{Source: grant.Source, Input: grant.Input}
		// Re-validate the granted input before reading it: the filesystem
		// may have changed since the grant was recorded. A missing input
		// skips that grant without failing the whole run.
		if err := grants.ValidateInput(grant.Input); err != nil {
			outcome.Skipped = fmt.Sprintf("input not accessible: %v", err)
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		batchID, err := newBatchID(now, idx)
		if err != nil {
			return res, err
		}
		output := filepath.Join(stateDir, "batches", batchID+".json")
		prepared, err := pipeline.PrepareExport(adapter.Options{
			Source:      grant.Source,
			Input:       grant.Input,
			Output:      output,
			BatchID:     batchID,
			StateDir:    stateDir,
			HistoryFrom: historyFrom,
		})
		if err != nil {
			outcome.Skipped = fmt.Sprintf("export preparation failed: %v", err)
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		if prepared.Records == 0 {
			outcome.Skipped = "no new records since the last confirmed baselines"
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		chunks, err := pipeline.SplitPreparedExport(prepared)
		if err != nil {
			outcome.Skipped = fmt.Sprintf("export split failed: %v", err)
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		for _, chunk := range chunks {
			committed, err := exportcommit.CommitExport(exportcommit.ExportOptions{
				StateDir: stateDir,
				Prepared: chunk,
				Source:   grant.Source,
				Input:    grant.Input,
			})
			if err != nil {
				return res, fmt.Errorf("commit export for source %s: %w", grant.Source, err)
			}
			outcome.Exported = true
			outcome.BatchID = committed.BatchID
			outcome.Records += committed.Records
			res.ExportedBatches++
			res.ExportedRecords += committed.Records
		}
		res.GrantOutcomes = append(res.GrantOutcomes, outcome)
	}

	if err := drain(ctx, &res, opt); err != nil {
		return res, err
	}
	// Only successful empty scans qualify. Failed reads and undrained usage
	// must not be presented as a completed empty scan.
	if res.PendingRemaining == 0 {
		statuses := []synccmd.ToolStatus{}
		seen := map[string]bool{}
		blocked := map[string]bool{}
		for _, outcome := range res.GrantOutcomes {
			if outcome.Skipped != "no new records since the last confirmed baselines" {
				blocked[toolForSource(outcome.Source)] = true
			}
		}
		for _, outcome := range res.GrantOutcomes {
			if outcome.Skipped != "no new records since the last confirmed baselines" {
				continue
			}
			tool := toolForSource(outcome.Source)
			if tool == "" || seen[tool] || blocked[tool] || res.syncedTools[tool] {
				continue
			}
			seen[tool] = true
			statuses = append(statuses, synccmd.ToolStatus{Tool: tool, Status: "no_new_records", Detail: "no new records since last confirmed baseline"})
		}
		if len(statuses) > 0 {
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient, ToolStatuses: statuses}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

func toolForSource(source string) string {
	for _, tool := range registry.SupportedTools() {
		if tool.Source == source {
			return tool.Tool
		}
	}
	return ""
}

func drain(ctx context.Context, res *Result, opt Options) error {
	stateDir := strings.TrimSpace(opt.StateDir)
	maxBatches := opt.MaxBatches
	if maxBatches <= 0 {
		maxBatches = DefaultMaxSyncBatches
	}
	ledger := outbox.New(stateDir)
	for i := 0; i < maxBatches; i++ {
		entry, ok, err := ledger.NextPending()
		if err != nil {
			return err
		}
		if !ok {
			// Nothing pending and nothing quarantined: no network at all.
			return nil
		}
		// synccmd.Run re-checks device binding and fresh server consent
		// (preflight self GET) before every upload. It never binds.
		syncResult, err := synccmd.Run(ctx, statedir.New(stateDir), synccmd.Options{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
		})
		res.Recovered += syncResult.Recovered
		res.Quarantined = syncResult.Quarantined
		if err != nil {
			if errors.Is(err, synccmd.ErrOutsideScope) {
				complete, checkErr := synccmd.ScopeReorganizationComplete(stateDir, entry.BatchID)
				if checkErr != nil {
					return checkErr
				}
				if complete {
					continue
				}
			}
			remaining, countErr := countPending(ledger)
			if countErr != nil {
				return countErr
			}
			res.PendingRemaining = remaining
			res.DrainStopped = fmt.Sprintf("upload of batch %s failed: %v", entry.BatchID, err)
			return err
		}
		if syncResult.Receipt.BatchID != "" {
			res.SyncedBatches++
			res.SyncedRecords += syncResult.Receipt.AcceptedRecords
			if tool := toolForSource(entry.Source); tool != "" && syncResult.Receipt.AcceptedRecords > 0 {
				if res.syncedTools == nil {
					res.syncedTools = map[string]bool{}
				}
				res.syncedTools[tool] = true
				if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient, ToolStatuses: []synccmd.ToolStatus{{Tool: tool, Status: "synced"}}}); err != nil {
					remaining, countErr := countPending(ledger)
					if countErr != nil {
						return countErr
					}
					res.PendingRemaining = remaining
					res.DrainStopped = fmt.Sprintf("source status report failed: %v", err)
					return err
				}
			}
		}
	}
	remaining, err := countPending(ledger)
	if err != nil {
		return err
	}
	res.PendingRemaining = remaining
	if remaining > 0 {
		res.DrainStopped = fmt.Sprintf("batch bound %d reached with %d batches still pending; the next scheduled run continues", maxBatches, remaining)
	}
	return nil
}

func countPending(ledger outbox.Store) (int, error) {
	out, err := ledger.Load()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, batch := range out.Batches {
		if batch.Status == outbox.StatusPending {
			count++
		}
	}
	return count, nil
}

// newBatchID builds a unique local batch id: timestamp plus a short random
// suffix so concurrent grants and rapid successive runs never collide. The
// exportcommit journal freezes the id before any state mutation, so crash
// recovery replays the exact same id.
func newBatchID(now func() time.Time, grantIndex int) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate batch id: %w", err)
	}
	return fmt.Sprintf("local-%s-%02d-%s", now().UTC().Format("20060102T150405Z"), grantIndex, hex.EncodeToString(buf[:])), nil
}
