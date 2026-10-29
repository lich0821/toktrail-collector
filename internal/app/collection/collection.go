// Package collection implements the periodic collection entry
// (`toktrail periodic`): export new local observations through the existing
// exportcommit WAL, then drain a bounded number of pending outbox batches
// through the existing syncclient. When the pending queue runs empty while
// the quarantine store still holds records, the drain performs one
// recovery round through the same syncclient — under its fresh-consent
// preflight and local-grant gate, never a local scope decision — so
// records the current authorization allows again are re-pended and drained
// even on a device with no new data. Quarantined records the current
// authorization still excludes stay put without failing the run.
//
// Guarantees:
//   - One process lock (internal/local/runlock) covers the entire run; a second
//     concurrent run fails fast with runlock.ErrBusy and performs no work.
//   - The server-driven grant sync runs before any local scanning, inside the
//     same lock: a bound device fetches its authoritative grant view with its
//     own credentials (so the server can pause, narrow, widen or re-enable
//     tools), applies managed default-directory grants for newly confirmed
//     tools, and fails closed when a previously active grant protocol cannot
//     be refreshed. An unbound device performs no network at all.
//   - Collection only reads inputs explicitly granted by the user or added as
//     managed built-in default-directory grants by the grant sync; there is no
//     other default scanning.
//   - The device is never implicitly (re)bound: draining requires an
//     existing bound device, exactly like explicit `toktrail sync`, and the
//     server preflight re-checks fresh consent before every batch.
//   - No secrets appear in command arguments, output, or errors.
//   - A server receipt that rejects records (partially or in full) never
//     reads as full sync success: the drain keeps every accepted record
//     counted and confirmed, counts the rejected ones explicitly, and the
//     run fails with ErrRecordsRejected instead of returning nil.
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

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
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

// ErrRecordsRejected reports a settled-but-incomplete upload: a drained
// batch's server receipt counted rejected records even though the upload
// round itself succeeded (synccmd.Run returned nil). By that point the
// syncclient has already reconciled the receipt durably — accepted records
// are confirmed with their baselines advanced and the batch is marked
// synced in the outbox — so the accepted part of the run is real and stays
// counted in Result. The rejected part means the run is NOT a full sync
// success: Run returns this sentinel (wrapped with the counts) instead of
// a nil error, and the rejected records are settled per record (they are
// never blindly resent as-is).
var ErrRecordsRejected = errors.New("records_rejected")

type Options struct {
	StateDir   string
	ServerURL  string
	MaxBatches int
	HTTPClient *http.Client
	// HomeDir overrides the user home directory used to resolve built-in
	// tool default directories during the grant sync (tests).
	HomeDir string
	// CollectorVersion is the build-injected release version. It is
	// forwarded to the grant ack only when it is a strict SemVer release
	// string; "dev" and unknown values are omitted, never faked.
	CollectorVersion string
	// Now is injectable for deterministic batch ids in tests.
	Now func() time.Time
	// Cursor, when non-nil, runs the account-level Cursor source sync
	// inside the same runlock, under the same server grant policy, after
	// the grant sync and before the local-grant collection. Nil keeps the
	// periodic behavior exactly as before. The cursor sync is independent
	// of local file grants: a cursor-only device (no enabled local
	// grants) still syncs its account source.
	Cursor *cursorsync.Options
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
	// collected and no upload was attempted (the grant-protocol self
	// fetch still happens for a bound device so the server can enable
	// tools again).
	NoGrants bool
	// Skipped carries the reason the run was a no-op (no grants, server
	// pause, or lock content). Empty when work was attempted.
	Skipped string
	// GrantSync reports the server-driven grant authorization sync that
	// ran before any local scanning.
	GrantSync GrantSync
	// Cursor reports the account-level cursor source round (zeroed when
	// the cursor wiring is absent).
	Cursor cursorsync.Result

	ExportedBatches int
	ExportedRecords int

	SyncedBatches int
	SyncedRecords int
	syncedTools   map[string]bool
	// RejectedBatches counts drained batches whose server receipt
	// reported at least one rejected record. Those batches are terminal
	// (the syncclient already reconciled the receipt: accepted records
	// confirmed, batch marked synced), so they are also counted in
	// SyncedBatches; the rejected part is carried separately here so it
	// can never silently read as accepted data.
	RejectedBatches int
	// RejectedRecords counts records the server rejected across drained
	// batches this run. Non-zero means the run is not a complete sync
	// even though every upload round itself succeeded; Run surfaces
	// ErrRecordsRejected alongside the accepted counts.
	RejectedRecords int
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

	now := opt.Now
	if now == nil {
		now = time.Now
	}

	// Server-driven grant sync: refresh the authoritative device grant view
	// with the device's own credentials BEFORE any local scanning, inside
	// the same runlock. It applies managed default-directory grants for
	// newly confirmed tools, enforces pause/narrowing for this run's reads,
	// and fails closed when a previously active grant protocol cannot be
	// refreshed. It never re-runs connect or bind and never touches device
	// identity, progress, or the outbox.
	grantSync, policy, err := syncGrants(ctx, opt, stateDir, grantStore, now)
	if err != nil {
		return res, err
	}
	res.GrantSync = grantSync

	// Report per-tool restriction states through the existing tool-status
	// channel so the server's device view can distinguish "last confirmed"
	// from "currently applied": a tool whose default directory vanished or
	// whose grant the user disabled must not silently ride an old ack.
	// Best-effort: a failure here never blocks collection.
	if len(grantSync.Pending) > 0 && !grantSync.Paused {
		if statuses := pendingToolStatuses(grantSync.Pending); len(statuses) > 0 {
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient, ToolStatuses: statuses}); err != nil {
				if !errors.Is(err, synccmd.ErrDevicePaused) && grantSync.Note == "" {
					grantSync.Note = fmt.Sprintf("restricted-tool status report failed: %v", err)
					res.GrantSync = grantSync
				}
			}
		}
	}

	if policy.Paused {
		res.Skipped = fmt.Sprintf("server reports collection paused for this device (consent revision %d); no local reading or uploads this run", grantSync.ConsentRevision)
		return res, nil
	}

	// Account-level cursor source: runs under the same lock and server
	// grant policy, independent of local file grants (a cursor-only
	// device has no local grants but still syncs). Failures are
	// non-fatal for the local tools: they are recorded and surfaced,
	// never allowed to block the device-batch collection or drain.
	if opt.Cursor != nil {
		gate := cursorsync.Gate{
			Paused:       policy.Paused,
			AllowedTools: policy.AllowedTools,
			HistoryFrom:  policy.HistoryFrom,
		}
		cursorRes, cursorErr := cursorsync.Sync(ctx, *opt.Cursor, gate)
		if cursorErr != nil {
			if cursorRes.Skipped == "" {
				cursorRes.Skipped = cursorErr.Error()
			} else {
				cursorRes.Note = cursorRes.Note + "; " + cursorErr.Error()
			}
		}
		res.Cursor = cursorRes
		// Tool-status receipt for the account-level source. A cursor-only
		// device has no local grant outcome, so without this report its
		// first successful round would never produce a "connected"
		// receipt on the server. It is sent ONLY for a fully successful,
		// fully drained round — no error, ran, nothing skipped or noted,
		// nothing pending — so failures, pauses, fence/consent stops and
		// undrained backlogs are never dressed up as success. The report
		// rides the existing tool-status channel (fresh consent preflight
		// and fixed detail vocabulary). A report failure never blocks the
		// local tools; it is surfaced as a note on the cursor round.
		if cursorErr == nil && cursorRes.Ran && cursorRes.Skipped == "" &&
			cursorRes.Note == "" && cursorRes.PendingRemaining == 0 {
			status, detail := "synced", ""
			if cursorRes.SyncedBatches == 0 {
				status, detail = "no_new_records", "no new records since last confirmed baseline"
			}
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{
				StateDir:     stateDir,
				ServerURL:    opt.ServerURL,
				HTTPClient:   opt.HTTPClient,
				ToolStatuses: []synccmd.ToolStatus{{Tool: cursorsource.ToolName, Status: status, Detail: detail}},
			}); err != nil && !errors.Is(err, synccmd.ErrDevicePaused) {
				// Note is empty on this path by construction.
				cursorRes.Note = fmt.Sprintf("cursor tool-status report failed: %v", err)
				res.Cursor = cursorRes
			}
		}
	}

	// (Re)load grants after the sync: newly confirmed tools may have gained
	// managed default-directory grants that this run must already collect.
	enabledGrants, err := grantStore.Enabled()
	if err != nil {
		return res, err
	}
	res.Grants = len(enabledGrants)
	if len(enabledGrants) == 0 {
		// A cursor-only device (no local file grants) is NOT a no-op:
		// the account-level source either ran this round or holds a
		// local permit (res.Cursor.Status is set whenever a permit
		// exists). Reporting NoGrants/"nothing to collect" there would
		// hide a successful cursor round from the caller; the cursor
		// outcome — synced records or its skip reason — lives in
		// res.Cursor.
		if opt.Cursor != nil && (res.Cursor.Ran || res.Cursor.Status != "") {
			return res, nil
		}
		res.NoGrants = true
		res.Skipped = "no enabled source grants; nothing to collect (sources enable requires explicit --source and --input)"
		return res, nil
	}

	var historyFrom *time.Time
	if policy.Active {
		// The server-confirmed effective cutoff governs (it may widen or
		// narrow); the bind-time cutoff must not permanently cap it.
		historyFrom = policy.HistoryFrom
	} else if devState, err := statedir.New(stateDir).Load(); err == nil && devState.HistoryFrom != nil && !devState.HistoryFrom.IsZero() {
		historyFrom = devState.HistoryFrom
	}

	for idx, grant := range enabledGrants {
		outcome := GrantOutcome{Source: grant.Source, Input: grant.Input}
		if !policy.SourceAllowed(grant.Source) {
			outcome.Skipped = "source not allowed by the server grant scope for this device"
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
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
				// A paused device sends no status metadata either; that is
				// a state, not a failure of the run.
				if errors.Is(err, synccmd.ErrDevicePaused) {
					return res, nil
				}
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

// drain uploads pending outbox batches up to the bound and, when the
// pending queue runs empty while the quarantine store still holds records,
// performs one recovery round through the syncclient so records that the
// current authorization allows again are re-pended and drained in the same
// run. The recovery round goes through the normal sync path — bound
// device, fresh server-consent preflight, no ingest POST — so it never
// evaluates the scope locally and never bypasses the server's
// authorization.
//
// Authorization model (the same as the pending-batch drain, plus the
// syncclient's recovery gate): local grants gate READING (which inputs the
// export phase scans), while SENDING is authorized by the server's live
// consent scope, re-checked fresh on every round and enforced again
// server-side at ingest. Quarantine recovery additionally requires an
// enabled local grant for the record's (source, input) once the device has
// a configured grant store — the syncclient enforces that on every
// recovery path, so a grant the user disabled or connect closed keeps its
// quarantined records held even when the server scope would allow them
// again. A device that never configured grants keeps the historical
// grant-agnostic recovery, matching the manual sync path.
//
// Partial receipts: synccmd.Run can succeed (nil error) with a receipt
// that rejected some or all of the batch's records — the syncclient has
// already reconciled such a receipt (accepted records confirmed, rejected
// messages settled per record, batch marked synced), so the drain neither
// retries nor rolls anything back. The accepted part stays counted; the
// rejected part is counted separately and the drain epilogue turns an
// otherwise-clean run into ErrRecordsRejected so a partial or fully
// rejected batch can never be reported as full sync success.
func drain(ctx context.Context, res *Result, opt Options) (err error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	maxBatches := opt.MaxBatches
	if maxBatches <= 0 {
		maxBatches = DefaultMaxSyncBatches
	}
	// firstRejectedBatch remembers the first batch whose receipt carried
	// rejected records, for the epilogue's diagnosis message.
	firstRejectedBatch := ""
	// Epilogue: settled rejections must never read as full sync success.
	// A receipt with rejected records arrives with a nil synccmd.Run
	// error, so without this check the drain would return nil and the
	// caller could mistake the run for a fully successful sync. Real
	// errors (upload failures, recovery failures) always win unchanged;
	// only an otherwise-clean drain is converted into the sentinel.
	defer func() {
		if err != nil || res.RejectedRecords == 0 {
			return
		}
		detail := ""
		if firstRejectedBatch != "" {
			detail = fmt.Sprintf(" (first rejected batch: %s)", firstRejectedBatch)
		}
		err = fmt.Errorf("%w: the server rejected %d record(s) across %d drained batch(es)%s; accepted records were confirmed and kept, rejected records are settled per record and are not resent as-is",
			ErrRecordsRejected, res.RejectedRecords, res.RejectedBatches, detail)
	}()
	ledger := outbox.New(stateDir)
	// uploads bounds the drain by attempted batch uploads. A quarantine
	// recovery round sends no batch and therefore never consumes an upload
	// slot: a run whose only work is recovery still drains what it
	// recovered, whatever the batch bound is.
	uploads := 0
	recoveryAttempted := false
	for uploads < maxBatches {
		entry, ok, err := ledger.NextPending()
		if err != nil {
			return err
		}
		if !ok {
			entries, qErr := quarantine.New(stateDir).Load()
			if qErr != nil {
				return qErr
			}
			// No upload is in flight, so the store's current size is the
			// authoritative post-drain quarantine count.
			res.Quarantined = len(entries)
			if len(entries) == 0 || recoveryAttempted {
				// Nothing pending and nothing (more) recoverable this run:
				// the drain is complete. With an empty quarantine store
				// this path performs no network at all.
				return nil
			}
			// Empty pending queue but quarantined records: without a round
			// here a device with no new data would never recover them —
			// recovery only runs inside the syncclient, which the drain
			// otherwise calls exclusively while a pending batch exists.
			// Attempted at most once per drain: records the fresh snapshot
			// still excludes cannot become recoverable within the same
			// run (recovery requires a strictly newer consent revision
			// and, where grants are configured, an enabled local grant).
			recoveryAttempted = true
			// synccmd.Run re-checks device binding and fetches a fresh
			// server-consent snapshot before deciding; it never binds.
			syncResult, err := synccmd.Run(ctx, statedir.New(stateDir), synccmd.Options{
				StateDir:   stateDir,
				ServerURL:  opt.ServerURL,
				HTTPClient: opt.HTTPClient,
			})
			res.Recovered += syncResult.Recovered
			if err != nil {
				// A failed round still leaves consistent recovery state
				// (replayed journals apply atomically), so reload the
				// authoritative count instead of trusting either the
				// pre-round snapshot or the zeroed error result.
				count, qErr := quarantineStoreCount(stateDir)
				if qErr != nil {
					return qErr
				}
				res.Quarantined = count
				if errors.Is(err, synccmd.ErrQuarantineHeld) {
					// Quarantined records the current authorization still
					// excludes — the live consent scope, or on a grant-
					// configured device a disabled or closed local
					// (source, input) grant — are a normal steady state,
					// not a run failure: they stay recoverable until the
					// authorization widens again.
					return nil
				}
				remaining, countErr := countPending(ledger)
				if countErr != nil {
					return countErr
				}
				res.PendingRemaining = remaining
				res.DrainStopped = fmt.Sprintf("quarantine recovery round failed: %v", err)
				return err
			}
			res.Quarantined = syncResult.Quarantined
			if syncResult.Recovered > 0 {
				// The recovered records are pending batches now; continue
				// so this run also drains them.
				continue
			}
			// Defensive: the syncclient only succeeds the recovery round
			// when something was recovered; if that ever changes, finish
			// cleanly instead of spinning.
			return nil
		}
		uploads++
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
			if errors.Is(err, synccmd.ErrDevicePaused) {
				// The server paused the device mid-run (between the grant
				// sync and this upload): stop sending, keep every pending
				// batch queued — pause is temporary, never a quarantine.
				remaining, countErr := countPending(ledger)
				if countErr != nil {
					return countErr
				}
				res.PendingRemaining = remaining
				res.DrainStopped = fmt.Sprintf("server reports collection paused; %d batch(es) stay queued for the next run", remaining)
				return nil
			}
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
			if syncResult.Receipt.RejectedRecords > 0 {
				// A partial or fully rejected receipt with a nil error:
				// the syncclient already reconciled it (accepted records
				// confirmed, batch marked synced), so the accepted part
				// stays counted above and the drain keeps going — later
				// batches must not lose their chance to upload. The
				// rejected part is recorded here and surfaced by the
				// drain epilogue, never as full sync success.
				res.RejectedBatches++
				res.RejectedRecords += syncResult.Receipt.RejectedRecords
				if firstRejectedBatch == "" {
					firstRejectedBatch = syncResult.Receipt.BatchID
				}
			}
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

// quarantineStoreCount reports how many records currently sit in the
// quarantine store.
func quarantineStoreCount(stateDir string) (int, error) {
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
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
