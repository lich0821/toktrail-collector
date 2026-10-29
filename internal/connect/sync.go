package connect

// The shared post-authorization sync orchestration. connect.Run uses it
// after its setup phases (bind, grants, scheduler install), and the
// resync CLI can drive the exact same semantics so both entry points
// agree on what a complete sync means.
//
// Phase order and why:
//  1. One normal collection round first — it refreshes the server-driven
//     authorization (grant sync), scans local sources, recovers the
//     export WAL and quarantine store, and drains a bounded number of
//     pending batches. Retransmitting history before the authorization
//     refresh would plan against a stale local grant view.
//  2. The history retransmission (internal/app/resync) of already-synced
//     outbox batches under an exclusive state lock. resync.Run never
//     locks itself, so this phase owns the runlock for it. The phase
//     always runs: on a first install the initial collection's freshly
//     synced batches are retransmitted once more, which the server
//     de-duplicates by replay — safe, and it avoids reading the outbox
//     without the lock just to detect the first-install case.
//  3. Bounded extra drain passes while batches remain pending. The
//     initial round drains at most collection.DefaultMaxSyncBatches; a
//     reconnect that accumulated a backlog must not stop there, and a
//     sync that cannot fully drain reports incomplete, never success.
//
// Locking: phases 1 and 3 go through collection.Run, which acquires and
// releases the state lock per pass; phase 2 acquires the lock with a
// bounded busy retry (a just-installed or pre-existing scheduled task may
// hold it) and holds it across resync.Run. The caller must NOT hold the
// state lock.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// DefaultMaxBacklogPasses bounds the extra collection passes after the
// initial round. Each pass drains up to collection.DefaultMaxSyncBatches
// device batches (plus the cursor source's own bounded drain), so the
// default gives a reconnect a reasonable full-drain effort (~50 device
// batches) while keeping one run finite; whatever remains is reported as
// incomplete and is continued by re-running connect, the scheduled
// collection, or the resync CLI.
const DefaultMaxBacklogPasses = 10

// ErrSyncIncomplete reports that the orchestration finished without
// covering the current authorization completely. The error message lists
// every reason; callers can distinguish it with errors.Is.
var ErrSyncIncomplete = errors.New("connect sync incomplete")

// Lock-retry budget for phases that must take the exclusive state lock
// while a scheduled collection task may legitimately hold it. Tests
// shrink both.
var (
	stateLockRetryTotal = 30 * time.Second
	stateLockRetryDelay = 250 * time.Millisecond
)

// noNewRecordsSkip is the exact GrantOutcome.Skipped wording collection
// uses for a healthy empty scan. It is the only grant skip that is normal
// (not an incompleteness); the coupling to collection's wording is
// deliberate — collection only signals this through Skipped, and connect
// must not modify that package. A wording drift degrades to an
// incompleteness report, never to a silently swallowed real failure.
const noNewRecordsSkip = "no new records since the last confirmed baselines"

// SyncOptions configures one Sync orchestration run.
type SyncOptions struct {
	// StateDir is the collector state directory (required).
	StateDir string
	// ServerURL is the server the authorization points at. Empty lets
	// resync default to the bound server (device.json).
	ServerURL string
	// HTTPClient is an optional client override (tests); it is wrapped
	// by the same safety clone connect uses.
	HTTPClient *http.Client
	// Now is an injectable clock for deterministic tests.
	Now func() time.Time
	// Out receives progress output (defaults to io.Discard).
	Out io.Writer

	// HomeDir and CollectorVersion forward to the collection rounds.
	HomeDir          string
	CollectorVersion string

	// Cursor carries the account-level Cursor wiring. Nil keeps the
	// collection behavior exactly as before (no cursor round). The first
	// collection pass forces one full-range cursor recovery round
	// (cursorsync.Options.ForceResync); backlog passes do not.
	Cursor *cursorsync.Options

	// AuthorizedTools lists the tools the driving authorization activated
	// (connect passes its activated set). It disambiguates the
	// "no enabled source grants" collection skip: with no authorized
	// local tool there is nothing to collect, which is not an
	// incompleteness.
	AuthorizedTools []string

	// AccountTools lists the account-network tools the authorization
	// named (e.g. Cursor), regardless of whether their local setup
	// succeeded. A named account tool whose round did not complete marks
	// the sync incomplete.
	AccountTools []string

	// ResyncConfirm is the caller's interactive confirmation hook (the
	// resync CLI's prompt). Sync invokes it BEFORE any collection, scan
	// or upload: it first produces a read-only offline plan and passes it
	// to the hook; returning an error aborts the whole sync with nothing
	// collected or uploaded. The pre-run plan lists the ALREADY-SYNCED
	// archive only — batches the collection phase will sync during this
	// run are not in it, and the executed retransmission re-plans after
	// collection so they join then. Nil (connect) skips interaction
	// entirely: the connect link is itself the user's authorization
	// gesture, and the executed phase prints its plan instead.
	ResyncConfirm func(resync.Plan) error
	// ResyncProgress reports each batch outcome during retransmission.
	ResyncProgress func(resync.ProgressEvent)
	// ResyncDryRun plans the retransmission offline: no collection phase,
	// no backlog drain, no state lock, no writes. The collection phase
	// mutates state and has no dry-run, and the remote consent scope is
	// NOT verified — the limitation is inherent, not incidental.
	ResyncDryRun bool
	// ResyncMaxBatches is an optional per-run retransmission upload
	// budget (0 walks the whole frozen plan).
	ResyncMaxBatches int
	// MaxBacklogPasses bounds the extra drain passes (defaults to
	// DefaultMaxBacklogPasses).
	MaxBacklogPasses int
}

// ResyncSummary is connect's compact view of one retransmission round.
// It never claims full coverage: Remaining carries exactly what a resume
// run would still retransmit, and Blocked / SkippedOutOfScopeRecords /
// ExcludedLocalGrant carry what the current authorization withholds.
type ResyncSummary struct {
	// Ran is true when the retransmission executed (a dry run counts as
	// running: it produced a plan).
	Ran bool
	// DryRun is true when only an offline plan was produced.
	DryRun bool
	// Skipped carries why the phase did not execute in a way that leaves
	// the sync incomplete (state busy, or the server paused the device).
	Skipped string
	// NotApplicable carries why the phase had nothing to retransmit under
	// the current authorization (for example: no synced batch matches a
	// currently enabled local grant because this authorization disabled
	// its sources). That is an authorization verdict, not a failure.
	NotApplicable string
	// Err is the phase's hard error, if any.
	Err string

	JobID     string
	Resumed   bool
	Completed bool
	// ConsentRevision is the live consent scope revision the
	// retransmission prefetched (or, for an empty or nothing-eligible
	// pass that never prefetches, the fresh self confirmation connect
	// performed on its behalf). Zero means unconfirmed.
	ConsentRevision int64

	Uploads         int
	UploadedRecords int
	AcceptedRecords int
	RejectedRecords int
	ReplayReceipts  int

	Blocked                  int
	SkippedOutOfScopeRecords int
	Remaining                int

	ExcludedPending     int
	ExcludedReorganized int
	ExcludedLocalGrant  int
	QuarantinedRecords  int
	Stopped             string
}

// BacklogSummary reports the extra drain passes.
type BacklogSummary struct {
	// Passes counts the collection rounds after the initial one.
	Passes int
	// Result accumulates the pass totals; its PendingRemaining (and
	// Cursor.PendingRemaining) reflect the LAST pass.
	Result collection.Result
	// PendingRemaining is the final count of pending outbox batches.
	PendingRemaining int
	// CursorPendingRemaining is the final count of pending cursor-source
	// batches.
	CursorPendingRemaining int
	// Stopped carries why draining stopped with work left (pass bound
	// reached, or a pass made no progress).
	Stopped string
	// Err is the hard error of a failed pass, if any.
	Err string
}

// SyncResult reports what one Sync orchestration did. Incomplete lists
// every reason the current authorization was not fully covered; a
// non-empty list always comes with a non-nil error (ErrSyncIncomplete)
// unless a harder phase error was returned instead.
type SyncResult struct {
	// Collection is the initial collection round.
	Collection collection.Result
	// Resync summarizes the history retransmission.
	Resync ResyncSummary
	// Backlog summarizes the extra drain passes.
	Backlog BacklogSummary
	// Incomplete lists every incompleteness reason, in phase order.
	Incomplete []string
}

// Sync performs the post-authorization sync orchestration: initial
// collection, history retransmission under an exclusive lock, then
// bounded backlog drain passes. The caller must not hold the state lock.
//
// For the resync CLI: drive it with the bound server URL, your
// interactive ResyncConfirm (Sync invokes it before ANY collection or
// upload, passing a read-only plan of the already-synced archive), and
// the ResyncMaxBatches passthrough; use ResyncDryRun for the offline
// plan (it skips collection — there is no collection dry-run — and never
// touches the lock or disk). Without ResyncConfirm there is no
// interaction: connect proceeds under its own authorization gesture.
func Sync(ctx context.Context, opt SyncOptions) (SyncResult, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return SyncResult{}, errors.New("collector state directory is required")
	}
	out := opt.Out
	if out == nil {
		out = io.Discard
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	opt.HTTPClient = newSafeHTTPClient(opt.HTTPClient)
	opt.StateDir = stateDir
	maxBacklogPasses := opt.MaxBacklogPasses
	if maxBacklogPasses <= 0 {
		maxBacklogPasses = DefaultMaxBacklogPasses
	}

	syncRes := SyncResult{}

	// Dry run: plan-only retransmission. Collection and the backlog
	// drain mutate state (export, drain, quarantine recovery) and have no
	// dry-run; the state lock is not even created.
	if opt.ResyncDryRun {
		res, err := resync.Run(ctx, resync.Options{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
			DryRun:     true,
			Now:        now,
		})
		syncRes.Resync = summarizeResync(res, true)
		if err != nil {
			syncRes.Resync.Err = err.Error()
			return syncRes, fmt.Errorf("history retransmission planning failed: %w", err)
		}
		fmt.Fprintln(out, "dry-run: offline, no files changed, remote consent scope NOT verified; execution checks consent before every upload")
		return syncRes, nil
	}

	// Pre-flight, before anything mutates state or uploads: the history
	// ownership guard, and — for callers that require interactive
	// confirmation (the resync CLI) — the user's confirmation. Both must
	// happen BEFORE the collection phase scans or uploads anything, so
	// an abort or a refusal leaves the state directory untouched.
	if err := checkHistoryOwnership(stateDir); err != nil {
		return syncRes, err
	}
	if opt.ResyncConfirm != nil {
		planRes, planErr := resync.Run(ctx, resync.Options{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
			DryRun:     true,
			Now:        now,
		})
		if planErr != nil {
			if !errResyncNothingEligible(planErr) {
				syncRes.Resync = summarizeResync(planRes, true)
				syncRes.Resync.Err = planErr.Error()
				return syncRes, fmt.Errorf("history retransmission planning failed: %w", planErr)
			}
			fmt.Fprintln(out, "plan note: no synced history is eligible under the current local grants; source scanning may still upload usage")
		} else {
			fmt.Fprintln(out, "plan note: the confirmed plan lists the already-synced archive only; batches this run's collection syncs join the executed retransmission afterwards")
		}
		if err := opt.ResyncConfirm(planRes.Plan); err != nil {
			return syncRes, fmt.Errorf("sync aborted before any collection or upload: %w", err)
		}
	}

	// Phase 1: initial collection round.
	fmt.Fprintf(out, "running initial collection...\n")
	collectOpts := collection.Options{
		StateDir:         stateDir,
		ServerURL:        opt.ServerURL,
		MaxBatches:       collection.DefaultMaxSyncBatches,
		HTTPClient:       opt.HTTPClient,
		Now:              now,
		HomeDir:          opt.HomeDir,
		CollectorVersion: opt.CollectorVersion,
		Cursor:           cursorOptionsForCollection(opt, true),
	}
	collectRes, err := runCollectionPass(ctx, collectOpts)
	syncRes.Collection = collectRes
	if err != nil {
		return syncRes, fmt.Errorf("initial collection failed: %w", err)
	}
	printCollectionRound(out, "initial collection", collectRes)

	var runErr error

	// Phase 2: history retransmission under the exclusive state lock. It
	// always runs — on a first install the freshly synced batches are
	// retransmitted once more and replay-deduplicated, which is safe and
	// avoids an unlocked outbox read just to detect the case.
	if collectRes.GrantSync.Paused {
		// Pause is a server state, not a run failure — collection treats
		// it as a skip, and so does this phase. The completeness
		// evaluation still reports it.
		syncRes.Resync.Skipped = "server reports collection paused for this device; history retransmission not attempted"
		fmt.Fprintf(out, "history retransmission: skipped (device paused)\n")
	} else {
		summary, hardErr := runResyncPhase(ctx, stateDir, opt, out, now)
		syncRes.Resync = summary
		if hardErr != nil {
			syncRes.Resync.Err = hardErr.Error()
			runErr = fmt.Errorf("history retransmission failed: %w", hardErr)
			// Keep going: the backlog drain below is independent, and
			// fresh pending data must not wait on a history failure. The
			// error is returned after the remaining phases have reported.
		}
	}

	// Phase 3: backlog drain. The initial round drains at most
	// DefaultMaxSyncBatches; a reconnect backlog needs more.
	syncRes, backlogErr := drainBacklog(ctx, syncRes, collectOpts, out, maxBacklogPasses)
	if backlogErr != nil && runErr == nil {
		runErr = backlogErr
	}

	// Completeness: an authorization that was not fully covered is
	// reported as incomplete and never as success.
	syncRes.Incomplete = evaluateIncomplete(&syncRes, opt)
	for _, reason := range syncRes.Incomplete {
		fmt.Fprintf(out, "incomplete: %s\n", reason)
	}
	if runErr != nil {
		return syncRes, runErr
	}
	if len(syncRes.Incomplete) > 0 {
		return syncRes, fmt.Errorf("%w: %s", ErrSyncIncomplete, strings.Join(syncRes.Incomplete, "; "))
	}
	return syncRes, nil
}

// checkHistoryOwnership fails closed when the synced outbox history in
// the state directory belongs to a different device than the currently
// bound one. The outbox does not record per-device attribution and
// cross-device de-duplication is not promised, so a mismatch must never
// retransmit — it would double count the history under the new device.
func checkHistoryOwnership(stateDir string) error {
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		return err
	}
	if st.DeviceID == "" {
		return nil
	}
	ownership, has, err := loadOwnership(stateDir)
	if err != nil {
		return err
	}
	if has && ownership.DeviceID != st.DeviceID {
		return fmt.Errorf("history retransmission blocked: the synced history in this state directory belongs to device %s, but this collector is bound as %s; cross-device de-duplication is not guaranteed, so connect refuses to retransmit it — use a separate state directory, or remove %s only if you accept abandoning the ownership record", ownership.DeviceID, st.DeviceID, ownershipPath(stateDir))
	}
	return nil
}

// runResyncPhase executes the retransmission under an exclusive state
// lock. A busy lock after the retry budget and a server-side pause are
// reported through ResyncSummary.Skipped (the completeness evaluation
// turns them into an incomplete result); an authorization-driven "nothing
// eligible" outcome is reported through NotApplicable; every other
// failure is a hard error returned as-is for the caller to wrap.
func runResyncPhase(ctx context.Context, stateDir string, opt SyncOptions, out io.Writer, now func() time.Time) (ResyncSummary, error) {
	summary := ResyncSummary{}

	// resync.Run never locks; this phase owns the exclusive state lock.
	// A scheduled collection task may hold it right after connect
	// installed it, hence the bounded retry.
	lock, err := acquireStateLock(ctx, stateDir)
	if err != nil {
		if errors.Is(err, runlock.ErrBusy) {
			summary.Skipped = fmt.Sprintf("the state directory stayed busy for %s (another collector process — likely the scheduled task — holds the lock); the history was NOT retransmitted", stateLockRetryTotal)
			fmt.Fprintf(out, "history retransmission: not run (%s)\n", summary.Skipped)
			return summary, nil
		}
		return summary, fmt.Errorf("acquire state lock for history retransmission: %w", err)
	}
	res, resyncErr := resync.Run(ctx, resync.Options{
		StateDir:   stateDir,
		ServerURL:  opt.ServerURL,
		HTTPClient: opt.HTTPClient,
		MaxBatches: opt.ResyncMaxBatches,
		Confirm:    confirmResyncOrDefault(opt, out),
		Progress:   progressResyncOrDefault(opt.ResyncProgress, out),
		Now:        now,
	})
	_ = lock.Close()

	summary = summarizeResync(res, true)
	// Even an empty or nothing-eligible retransmission must confirm the
	// live consent scope: an empty pass finalizes offline and a
	// nothing-eligible plan never prefetches, so without a round trip
	// here those outcomes could not observe a scope change that happened
	// after the initial collection. A failed confirmation leaves the
	// revision at zero, which the completeness evaluation reports as
	// unconfirmed — never as success.
	if summary.ConsentRevision <= 0 && (resyncErr == nil || errResyncNothingEligible(resyncErr)) {
		if self, err := syncclient.FetchDeviceSelf(ctx, statedir.New(stateDir), syncclient.Options{
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
		}); err == nil {
			summary.ConsentRevision = self.ConsentRevision
		}
	}
	if resyncErr != nil {
		if errors.Is(resyncErr, syncclient.ErrDevicePaused) {
			// Pause mirrors collection's semantics: a server state, not
			// a run failure. Nothing was sent; the job stays resumable.
			summary.Skipped = resyncErr.Error()
			fmt.Fprintf(out, "history retransmission: skipped (device paused)\n")
			return summary, nil
		}
		if errResyncNothingEligible(resyncErr) {
			// No synced batch matches the currently enabled local grants.
			// After connect applied this authorization's tool set that is
			// an authorization verdict (sources deliberately disabled or
			// narrowed), not a failure: report it, do not alarm.
			summary.NotApplicable = resyncErr.Error()
			fmt.Fprintf(out, "history retransmission: nothing eligible under the current authorization (%v)\n", resyncErr)
			return summary, nil
		}
		return summary, resyncErr
	}
	printResyncSummary(out, summary)
	return summary, nil
}

// errResyncNothingEligible matches the stable wordings resync uses when
// planning found no eligible batch because of the local grant state
// (nothing matches an enabled grant, or no grant config exists). Those
// are authorization verdicts — connect itself disables grants the
// authorization dropped — unlike a corrupt or unreadable grant store,
// which surfaces as a different error and stays a hard failure. The
// wording coupling mirrors how collection matches syncclient diagnoses;
// resync's own tests pin these strings.
func errResyncNothingEligible(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "match a currently enabled local source grant") ||
		strings.Contains(msg, "no local source grants are configured")
}

// drainBacklog runs extra collection passes while device or cursor
// batches remain pending, and records the outcome on syncRes.
//
// The passes reuse the initial round's collection wiring EXCEPT the
// forced cursor round: ForceResync is a one-round recovery semantic (a
// full-window pull that re-emits unchanged events at fresh revisions),
// and repeating it every pass would re-pull and re-emit the whole cursor
// history each time, so a large cursor backlog could never converge.
// The cursor wiring is therefore cloned with the force off on entry.
func drainBacklog(ctx context.Context, syncRes SyncResult, collectOpts collection.Options, out io.Writer, maxPasses int) (SyncResult, error) {
	if collectOpts.Cursor != nil {
		cursor := *collectOpts.Cursor
		cursor.ForceResync = false
		collectOpts.Cursor = &cursor
	}
	var passErr error
	pending := syncRes.Collection.PendingRemaining
	cursorPending := syncRes.Collection.Cursor.PendingRemaining
	for pending > 0 || cursorPending > 0 {
		if syncRes.Backlog.Passes >= maxPasses {
			syncRes.Backlog.Stopped = fmt.Sprintf("backlog pass bound (%d) reached", maxPasses)
			break
		}
		fmt.Fprintf(out, "draining backlog (pendingBatches=%d pendingCursorBatches=%d)...\n", pending, cursorPending)
		passRes, err := runCollectionPass(ctx, collectOpts)
		syncRes.Backlog.Passes++
		accumulateCollection(&syncRes.Backlog.Result, passRes)
		if err != nil {
			syncRes.Backlog.Err = err.Error()
			passErr = fmt.Errorf("backlog drain failed: %w", err)
			break
		}
		printCollectionRound(out, fmt.Sprintf("backlog pass %d", syncRes.Backlog.Passes), passRes)
		if passRes.PendingRemaining == pending && passRes.Cursor.PendingRemaining == cursorPending &&
			passRes.SyncedBatches == 0 && passRes.Cursor.SyncedBatches == 0 {
			// No batch moved and nothing was drained: paused, restricted,
			// or otherwise stuck. Stop instead of spinning; the
			// completeness evaluation reports it.
			syncRes.Backlog.Stopped = "a drain pass made no progress (paused, restricted, or nothing drainable)"
			break
		}
		pending = passRes.PendingRemaining
		cursorPending = passRes.Cursor.PendingRemaining
	}
	syncRes.Backlog.PendingRemaining = pending
	syncRes.Backlog.CursorPendingRemaining = cursorPending
	if syncRes.Backlog.Passes > 0 {
		fmt.Fprintf(out, "backlog: passes=%d syncedBatches=%d syncedRecords=%d pendingBatches=%d pendingCursorBatches=%d\n",
			syncRes.Backlog.Passes, syncRes.Backlog.Result.SyncedBatches, syncRes.Backlog.Result.SyncedRecords,
			pending, cursorPending)
		if syncRes.Backlog.Stopped != "" {
			fmt.Fprintf(out, "backlog: %s\n", syncRes.Backlog.Stopped)
		}
		if pending > 0 || cursorPending > 0 {
			fmt.Fprintf(out, "backlog: not fully drained; re-run connect or let the scheduled collection continue it\n")
		}
	}
	return syncRes, passErr
}

// evaluateIncomplete lists every reason the current authorization was not
// fully covered. It never treats a bounded drain as success, never treats
// a pause as success, and never claims full retransmission coverage.
// Authorization-driven withholding — sources this run's grants disabled,
// history outside the live consent scope — is reported in the phase
// summaries but is deliberately NOT an incompleteness.
func evaluateIncomplete(syncRes *SyncResult, opt SyncOptions) []string {
	reasons := make([]string, 0)
	seen := map[string]bool{}
	add := func(format string, args ...any) {
		reason := fmt.Sprintf(format, args...)
		if !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}

	// Source grants: every skip except a healthy empty scan is a failure
	// outcome collection reports only through GrantOutcomes.Skipped.
	outcomes := syncRes.Collection.GrantOutcomes
	outcomes = append(outcomes, syncRes.Backlog.Result.GrantOutcomes...)
	for _, o := range outcomes {
		if o.Skipped != "" && o.Skipped != noNewRecordsSkip {
			add("source %s (%s) did not complete: %s", o.Source, o.Input, o.Skipped)
		}
	}

	// Whole-run skips: pause is a server state that must not look like
	// success; a missing grant set is only normal when the authorization
	// activated no local tool.
	c := syncRes.Collection
	if c.GrantSync.Paused {
		add("collection paused by the server: %s", c.Skipped)
	} else if c.NoGrants && hasAuthorizedLocalTool(opt.AuthorizedTools) {
		add("no enabled source grants despite authorized tools: %s", c.Skipped)
	}

	// Final drain state (the last pass's numbers).
	final := c
	if syncRes.Backlog.Passes > 0 {
		final = syncRes.Backlog.Result
	}
	if final.PendingRemaining > 0 || final.Cursor.PendingRemaining > 0 {
		add("%d outbox batch(es) and %d cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them", final.PendingRemaining, final.Cursor.PendingRemaining)
	}
	if final.DrainStopped != "" {
		add("drain stopped early: %s", final.DrainStopped)
	}

	// Account sources named by the authorization must have completed a
	// round: only Skipped, Ran and the pending count judge completion —
	// a Note alone is never a failure. Callers that do not name account
	// tools explicitly (the resync CLI passes a nil list) must still not
	// swallow a failed cursor round: when a cursor permit exists locally
	// — whatever its status, since the current authorization needs the
	// data — under a grant the fresh sync allows, it joins the list. A
	// cursor the live authorization excludes — or one the device never
	// enabled or explicitly logged out — skipping normally is an
	// authorization verdict or the never-enabled steady state, never an
	// incompleteness.
	accountTools := opt.AccountTools
	if !namesTool(accountTools, cursorsource.ToolName) &&
		cursorRoundExpected(opt.StateDir, final.Cursor.Ran, final.GrantSync.AllowedTools) {
		accountTools = append(append([]string(nil), accountTools...), cursorsource.ToolName)
	}
	for _, tool := range accountTools {
		cur := final.Cursor
		switch {
		case !cur.Ran && cur.Skipped != "":
			add("account source %s did not run: %s", tool, cur.Skipped)
		case !cur.Ran:
			add("account source %s did not run this sync", tool)
		case cur.Skipped != "":
			add("account source %s failed: %s", tool, cur.Skipped)
		case cur.PendingRemaining > 0:
			add("account source %s has %d batch(es) still pending", tool, cur.PendingRemaining)
		}
	}

	// A cursor round that skipped rows without a stable upstream event id
	// left usage events uncounted: no complete success may hide that gap,
	// regardless of who named the account source. The counter is only
	// ever produced by an actual round (initial or backlog pass), so a
	// non-zero sum is direct evidence of a real run that dropped data.
	if skipped := syncRes.Collection.Cursor.SkippedNoStableID + syncRes.Backlog.Result.Cursor.SkippedNoStableID; skipped > 0 {
		add("account source %s skipped %d usage event(s) without a stable upstream id; those events are not counted", cursorsource.ToolName, skipped)
	}

	// History retransmission: incomplete only when the phase did not run
	// (busy, paused) or the job is unfinished and resumable. Batches the
	// current authorization withholds (blocked, out of scope, grant
	// disabled) and server rejections are carried by the phase summaries
	// and resync's own error semantics, not counted here.
	r := syncRes.Resync
	if r.Skipped != "" {
		add("history retransmission not completed: %s", r.Skipped)
	}
	if r.Ran && r.Remaining > 0 {
		add("%d history batch(es) remain un-retransmitted; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)", r.Remaining)
	}
	if r.Ran && !r.Completed && r.Stopped != "" {
		// A stopped job (upload failure, budget reached) is unfinished
		// even when the error path did not populate Remaining.
		add("history retransmission stopped before finishing: %s; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)", r.Stopped)
	}

	// Cross-phase scope consistency (active grant protocol only): the
	// initial collection, the history retransmission AND the backlog
	// drain passes must all have observed the same consent revision. A
	// run that straddled a server-side scope change must not report
	// success — the collection drain recovered quarantine and uploaded
	// under the old scope, so records the new scope governs (for example
	// quarantined data a widened scope would allow again) were never
	// re-covered this run. An unconfirmed retransmission revision is
	// refused the same way: unknown is never success.
	if syncRes.Collection.GrantSync.Active && r.Ran {
		collected := syncRes.Collection.GrantSync.ConsentRevision
		switch {
		case r.ConsentRevision <= 0:
			add("history retransmission could not confirm the live consent scope (collection ran under revision %d); re-run to cover the current authorization", collected)
		case r.ConsentRevision != collected:
			add("the consent scope moved between the collection (revision %d) and the history retransmission (revision %d); re-run to cover the current authorization", collected, r.ConsentRevision)
		}
		// The backlog passes re-run the grant sync; the accumulated
		// GrantSync carries the LAST pass's applied revision. A drain
		// that ran under a newer scope than the initial collection mixes
		// old-scope and new-scope uploads, and one that ran under an
		// older scope cannot cover the current authorization either.
		if syncRes.Backlog.Passes > 0 {
			if last := syncRes.Backlog.Result.GrantSync.ConsentRevision; last != collected {
				add("the consent scope moved between the collection (revision %d) and the backlog drain (revision %d); re-run to cover the current authorization", collected, last)
			}
		}
	}
	return reasons
}

// hasAuthorizedLocalTool reports whether any activated tool maps to a
// local directory grant (account-network tools do not).
func hasAuthorizedLocalTool(tools []string) bool {
	for _, name := range tools {
		if spec, ok := registry.LookupTool(name); ok && !spec.IsAccountNetwork() {
			return true
		}
	}
	return false
}

// cursorRoundExpected reports whether this sync must hold the cursor
// account source to the completion contract even though the caller did
// not name it explicitly (the resync CLI passes no account-tool list).
// Two signals identify a cursor source this run owes data for:
//
//   - the round already RAN: direct evidence the source was enabled and
//     authorized this run. A mid-round failure — even one that pauses
//     the permit afterwards (an expired login) — must never be
//     swallowed, so this short-circuits true.
//   - otherwise, a cursor permit that EXISTS locally — whatever its
//     status — under a grant the fresh sync allows for Cursor. The
//     current authorization needs the account data, so a paused or
//     login_expired permit skipping its round is an incompleteness to
//     report, never a silent success. Logout REMOVES the permit, so an
//     absent permit (never enabled, or explicitly logged out) is the
//     only local steady state that owes nothing; an unreadable permit
//     file fails toward reporting (the source exists but cannot be
//     verified).
//
// A cursor the authorization allows but the device never enabled owes
// nothing here — enabling is a local confirmation gesture, reported via
// the explicit list by the connect authorization that names Cursor.
func cursorRoundExpected(stateDir string, cursorRan bool, allowedTools []string) bool {
	if cursorRan {
		return true
	}
	if !cursorAllowedByTools(allowedTools) {
		return false
	}
	_, ok, err := cursorsource.New(stateDir).Load()
	if err != nil {
		return true
	}
	return ok
}

// cursorAllowedByTools mirrors the grant-scope semantics
// (cursorsync.Gate.cursorAllowed; managedconsent's empty-list means
// unrestricted): an empty tool list is unrestricted, a non-empty list
// must name the cursor tool.
func cursorAllowedByTools(tools []string) bool {
	return len(tools) == 0 || namesTool(tools, cursorsource.ToolName)
}

// namesTool reports whether the list names the tool (trimmed
// comparison, matching the grant-scope semantics).
func namesTool(tools []string, name string) bool {
	for _, t := range tools {
		if strings.TrimSpace(t) == name {
			return true
		}
	}
	return false
}

// runCollectionPass runs one collection round, retrying while the state
// lock is busy: a scheduled task installed moments ago (or a pre-existing
// one on a reconnect) may hold it, and a busy collection.Run performed no
// work, so the retry is safe.
func runCollectionPass(ctx context.Context, opt collection.Options) (collection.Result, error) {
	deadline := time.Now().Add(stateLockRetryTotal)
	for {
		res, err := collection.Run(ctx, opt)
		if !errors.Is(err, runlock.ErrBusy) {
			return res, err
		}
		if time.Now().After(deadline) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(stateLockRetryDelay):
		}
	}
}

// acquireStateLock acquires the exclusive state lock, retrying while
// another process (typically a scheduled collection run) holds it.
func acquireStateLock(ctx context.Context, stateDir string) (*runlock.Lock, error) {
	deadline := time.Now().Add(stateLockRetryTotal)
	for {
		lock, err := runlock.Acquire(stateDir)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, runlock.ErrBusy) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(stateLockRetryDelay):
		}
	}
}

// cursorOptionsForCollection clones the cursor wiring for a collection
// round. The first (initial) round forces one full-range recovery pull;
// backlog rounds must not force again — the forced round re-emits
// unchanged events at a fresh revision, which is a recovery semantic, not
// something to repeat every pass.
func cursorOptionsForCollection(opt SyncOptions, force bool) *cursorsync.Options {
	if opt.Cursor == nil {
		return nil
	}
	c := *opt.Cursor
	c.StateDir = opt.StateDir
	c.ServerURL = opt.ServerURL
	c.HTTPClient = opt.HTTPClient
	c.Out = opt.Out
	c.ForceResync = force
	return &c
}

// countSyncedBatches counts the outbox entries already marked synced. It
// must only be called while holding the state lock (connect's setup phase
// does) — the outbox is process-shared state.
func countSyncedBatches(stateDir string) (int, error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range out.Batches {
		if b.Status == outbox.StatusSynced {
			n++
		}
	}
	return n, nil
}

// confirmResyncOrDefault builds the confirm hook for the EXECUTED
// retransmission. The caller's interactive hook (the resync CLI) already
// confirmed this run up front, before any collection or upload; the
// executed plan may additionally contain batches this run's collection
// synced, so it is printed for transparency but not re-prompted. Without
// a caller hook (connect) there is no interaction at all: the connect
// link is itself the user's authorization gesture, and the plan is
// printed for the record.
func confirmResyncOrDefault(opt SyncOptions, out io.Writer) func(resync.Plan) error {
	return func(plan resync.Plan) error {
		printResyncPlan(out, plan)
		if opt.ResyncConfirm != nil {
			fmt.Fprintln(out, "history retransmission proceeding under the confirmation given before this run started")
		} else {
			fmt.Fprintln(out, "history retransmission confirmed by this authorization")
		}
		return nil
	}
}

func progressResyncOrDefault(progress func(resync.ProgressEvent), out io.Writer) func(resync.ProgressEvent) {
	if progress != nil {
		return progress
	}
	return func(ev resync.ProgressEvent) {
		fmt.Fprintf(out, "batch %s: %s submitted=%d accepted=%d rejected=%d skipped=%d replay=%t\n",
			ev.BatchID, ev.Outcome, ev.Uploaded, ev.Accepted, ev.Rejected, ev.Skipped, ev.Replay)
	}
}

// printResyncPlan prints the frozen plan (the same summary the resync CLI
// prints) so the user sees exactly what will be retransmitted and what
// the phase does NOT cover.
func printResyncPlan(out io.Writer, plan resync.Plan) {
	fmt.Fprintf(out, "resync target: server=%s device=%s\n", plan.ServerURL, plan.DeviceID)
	fmt.Fprintf(out, "plan: batches=%d records=%d resumed=%t alreadyDone=%d\n", len(plan.Batches), plan.PlannedRecords, plan.Resumed, plan.DoneInJob)
	fmt.Fprintf(out, "excluded: pendingBatches=%d reorganizedParents=%d localGrantBatches=%d quarantineRecords=%d\n", plan.ExcludedPending, plan.ExcludedReorganized, len(plan.ExcludedLocalGrant), plan.QuarantinedRecords)
	fmt.Fprintln(out, plan.CoverageNote)
	fmt.Fprintln(out, "De-duplication applies to the current device only; this phase never creates a device or clears progress.")
}

// summarizeResync maps a resync.Result onto the connect summary.
func summarizeResync(res resync.Result, ran bool) ResyncSummary {
	return ResyncSummary{
		Ran:                      ran,
		DryRun:                   res.DryRun,
		JobID:                    res.Plan.JobID,
		Resumed:                  res.Plan.Resumed,
		Completed:                res.Completed,
		ConsentRevision:          res.Self.ConsentRevision,
		Uploads:                  res.Uploads,
		UploadedRecords:          res.UploadedRecords,
		AcceptedRecords:          res.AcceptedRecords,
		RejectedRecords:          res.RejectedRecords,
		ReplayReceipts:           res.ReplayReceipts,
		Blocked:                  res.Blocked,
		SkippedOutOfScopeRecords: res.SkippedOutOfScopeRecords,
		Remaining:                res.Remaining,
		ExcludedPending:          res.Plan.ExcludedPending,
		ExcludedReorganized:      res.Plan.ExcludedReorganized,
		ExcludedLocalGrant:       len(res.Plan.ExcludedLocalGrant),
		QuarantinedRecords:       res.Plan.QuarantinedRecords,
		Stopped:                  res.Stopped,
	}
}

// printResyncSummary prints the round's outcome; it mirrors the resync
// CLI's report, including the explicit statements about withheld
// history, so partial coverage is never presented as a full restore.
func printResyncSummary(out io.Writer, summary ResyncSummary) {
	fmt.Fprintf(out, "history retransmission: completed=%t uploads=%d submitted=%d accepted=%d rejected=%d blocked=%d skipped=%d remaining=%d\n",
		summary.Completed, summary.Uploads, summary.UploadedRecords, summary.AcceptedRecords, summary.RejectedRecords,
		summary.Blocked, summary.SkippedOutOfScopeRecords, summary.Remaining)
	if summary.Stopped != "" {
		fmt.Fprintf(out, "history retransmission: stopped: %s\n", summary.Stopped)
	}
	if summary.Remaining > 0 {
		fmt.Fprintf(out, "history retransmission: re-run connect (or toktrail resync --all) to resume; completed batches in this job are preserved. The scheduled task does NOT continue a resync job.\n")
	}
	if summary.Blocked > 0 || summary.SkippedOutOfScopeRecords > 0 {
		fmt.Fprintf(out, "history retransmission: some history was not retransmitted because it is outside the current authorization; original archives remain unchanged.\n")
	}
}

// printCollectionRound prints one collection round's summary with the
// label the phase reports under.
func printCollectionRound(out io.Writer, label string, res collection.Result) {
	if res.NoGrants {
		fmt.Fprintf(out, "%s: no enabled source grants; skipped\n", label)
		return
	}
	fmt.Fprintf(out, "%s: exportedBatches=%d exportedRecords=%d syncedBatches=%d syncedRecords=%d\n",
		label, res.ExportedBatches, res.ExportedRecords, res.SyncedBatches, res.SyncedRecords)
	if res.Cursor.Ran {
		// The account-level cursor round is independent of the local
		// grant counts above; surface it so a cursor-only device never
		// looks like an all-zero run.
		fmt.Fprintf(out, "%s: cursor pulledEvents=%d newRecords=%d replacedRecords=%d reemittedRecords=%d uploadedRecords=%d pendingBatches=%d\n",
			label, res.Cursor.PulledEvents, res.Cursor.NewRecords,
			res.Cursor.ReplacedRecords, res.Cursor.ReemittedRecords, res.Cursor.SyncedRecords,
			res.Cursor.PendingRemaining)
	}
}

// accumulateCollection folds one drain pass into the backlog totals.
// Counters add up; state-like fields (pending counts, skip reasons,
// DrainStopped) reflect the latest pass.
func accumulateCollection(dst *collection.Result, pass collection.Result) {
	dst.ExportedBatches += pass.ExportedBatches
	dst.ExportedRecords += pass.ExportedRecords
	dst.SyncedBatches += pass.SyncedBatches
	dst.SyncedRecords += pass.SyncedRecords
	dst.Recovered += pass.Recovered
	dst.Quarantined = pass.Quarantined
	dst.PendingRemaining = pass.PendingRemaining
	dst.DrainStopped = pass.DrainStopped
	dst.NoGrants = dst.NoGrants || pass.NoGrants
	if pass.Skipped != "" {
		dst.Skipped = pass.Skipped
	}
	dst.GrantOutcomes = append(dst.GrantOutcomes, pass.GrantOutcomes...)
	dst.GrantSync = pass.GrantSync
	dst.Grants = pass.Grants

	dst.Cursor.PulledEvents += pass.Cursor.PulledEvents
	dst.Cursor.NewRecords += pass.Cursor.NewRecords
	dst.Cursor.ReplacedRecords += pass.Cursor.ReplacedRecords
	dst.Cursor.ReemittedRecords += pass.Cursor.ReemittedRecords
	dst.Cursor.SkippedUnchanged += pass.Cursor.SkippedUnchanged
	dst.Cursor.SkippedNoStableID += pass.Cursor.SkippedNoStableID
	dst.Cursor.ExportedBatches += pass.Cursor.ExportedBatches
	dst.Cursor.SyncedBatches += pass.Cursor.SyncedBatches
	dst.Cursor.SyncedRecords += pass.Cursor.SyncedRecords
	dst.Cursor.Ran = dst.Cursor.Ran || pass.Cursor.Ran
	dst.Cursor.Skipped = pass.Cursor.Skipped
	dst.Cursor.Status = pass.Cursor.Status
	dst.Cursor.Note = pass.Cursor.Note
	dst.Cursor.PendingRemaining = pass.Cursor.PendingRemaining
	dst.Cursor.FirstSyncCompleted = dst.Cursor.FirstSyncCompleted || pass.Cursor.FirstSyncCompleted
}
