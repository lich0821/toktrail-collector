// Package resync implements `toktrail resync --all`: the explicit,
// deliberate retransmission of already-synced device-outbox history to the
// currently bound server, typically after the server lost its database
// while the local outbox still records the batches as synced.
//
// Guarantees:
//   - The original outbox entries stay terminal and immutable: synced
//     batches are never re-marked pending, never re-attempted through the
//     outbox, and their files are never modified. Per-message progress,
//     cursors, the quarantine store, and the export WAL are untouched, and
//     no progress is deleted or rescanned. No Claude baselines are
//     recomputed and no record keys are rewritten.
//   - No new device is bound and no authorization is bypassed: there is no
//     force flag. Every run re-checks the live device authorization via the
//     existing syncclient preflight, and every upload goes through the
//     existing syncclient privacy gate, scope gate, and receipt
//     reconciliation.
//   - Coverage is the device ledger only (internal/local/outbox). Other
//     stores — independent account-source ledgers such as the cursor
//     account history, or recoverable quarantine records — are not part of
//     resync, and output says so explicitly instead of claiming a full
//     restore.
//   - Local authorization is strict: only batches whose (source, input)
//     currently matches an enabled local source grant are retransmitted. A
//     missing grant config denies by default, so residual archives cannot
//     bypass a withdrawn local permission.
//   - Consent-scope changes never turn stale progress into completion: an
//     incomplete job records the live consent scope its done/skip
//     decisions were made under, and every run re-verifies that baseline
//     against a fresh live snapshot after the preflight. When the
//     authorization revision or scope content changed — narrowed or
//     widened — the old decisions are not treated as completing the
//     current scope: the complete synced history is re-planned under the
//     fresh scope and saved as the new journal, the run stops before any
//     upload, and the next explicit pass executes the re-planned plan
//     (already-delivered records replay without double counting). A
//     finalize-only run (crash after the last upload, before the
//     completion write) may only complete after the same verification.
//     The same rule holds while a pass is running: every upload's
//     receipt is checked against the authorization snapshot it was
//     actually accepted under, and the completion write is preceded by
//     one final fresh scope comparison — a mid-run change (even a
//     widening that lets every upload succeed) stops the pass incomplete
//     instead of completing on stale decisions. Records withheld as
//     outside the live scope are a normal exclusion, never a failure or
//     a gap of the pass.
//   - Idempotent and resumable: an interrupted job resumes from the
//     resync-owned journal (payload hashes detect tampering), deterministic
//     child batch identities keep partial-scope retransmissions stable, and
//     the server's replay receipts keep repeated uploads from double
//     counting. A completed job is replaced by the next explicit full pass.
//   - Note: the outbox does not record which device originally synced a
//     batch, so idempotency is guaranteed for the CURRENT device identity
//     only; cross-device de-duplication on the server is not promised.
package resync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/syncclient"
)

// Options configures one resync run.
type Options struct {
	StateDir string
	// ServerURL defaults to the bound server (device.json), then to the
	// same local default the sync command uses.
	ServerURL string
	// MaxBatches is an optional per-run upload budget. Zero (the default)
	// walks the entire frozen job plan — a bounded list, never a scan. A
	// positive value stops after that many uploads and reports the
	// remainder for the next run. Negative values are rejected.
	MaxBatches int
	HTTPClient *http.Client
	// DryRun plans offline: no network access, no state changes, no journal
	// write. The remote consent scope is NOT verified in a dry run.
	DryRun bool
	// Confirm is invoked exactly once before any state change or network
	// traffic (execution only, after planning). Returning an error aborts
	// the run with zero uploads. Required for non-dry-run runs.
	Confirm func(Plan) error
	// Progress reports each batch outcome during execution (may be nil).
	Progress func(ProgressEvent)
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// PlannedBatch is one already-synced outbox batch selected for
// retransmission.
type PlannedBatch struct {
	BatchID       string
	File          string
	Source        string
	Input         string
	Records       int
	PayloadSHA256 string
	CreatedAt     time.Time
}

// Plan is the offline-plannable description of one run.
type Plan struct {
	DeviceID    string
	ServerURL   string
	StateDir    string
	JournalPath string
	JobID       string
	Resumed     bool
	// Batches are the still-to-retransmit parent batches, in order.
	Batches []PlannedBatch
	// PlannedRecords sums len(Batches[i].Records).
	PlannedRecords int
	// TotalInJob is the job's full plan size; DoneInJob counts batches the
	// resumed job already retransmitted successfully.
	TotalInJob int
	DoneInJob  int

	ExcludedReorganized int
	ExcludedPending     int
	// ExcludedLocalGrant lists batch IDs withheld because their
	// (source, input) has no currently enabled local source grant.
	ExcludedLocalGrant []string
	// QuarantinedRecords counts the recoverable quarantine store
	// (informational; quarantine is not part of resync).
	QuarantinedRecords int
	// PendingFinalize is true when the only remaining work is persisting
	// the job (nothing to upload): the previous run crashed after its last
	// upload but before the completion write, or there are no synced
	// batches at all. A dry run reports it without writing anything.
	// Execution re-verifies the live consent scope before it may claim
	// completion (an empty pass finalizes offline; a crash-recovery
	// finalize goes through the preflight and the scope gate, and
	// re-plans instead of completing when the authorization changed).
	PendingFinalize bool
	CoverageNote    string
}

// ProgressEvent reports one parent batch's outcome during execution.
type ProgressEvent struct {
	BatchID       string
	UploadBatchID string
	Outcome       string // done | blocked | failed
	Records       int    // parent batch records
	Uploaded      int    // records retransmitted for this event
	Accepted      int    // records the server accepted
	Rejected      int    // records the server rejected (not restored)
	Replay        bool
	Skipped       int    // records held back outside the live scope
	Err           string // non-empty on failed
}

// Result reports what one run did.
type Result struct {
	Plan   Plan
	DryRun bool
	// Self is the live authorization snapshot the run planned against;
	// zero for a dry run, which never contacts the server.
	Self syncclient.SelfStatus

	Uploads         int // concrete uploads (verbatim batches + derived children)
	UploadedBatches int // parent batches fully retransmitted this run
	UploadedRecords int // records retransmitted this run (submitted)
	// AcceptedRecords / RejectedRecords split this run's submitted records
	// by the server verdict. A pass with rejections is terminal (the
	// server's rejection is deterministic; retrying it would loop), but it
	// must never be reported as a full restore.
	AcceptedRecords int
	RejectedRecords int
	ReplayReceipts  int
	// SkippedOutOfScopeRecords counts records withheld under the live
	// consent scope (record keys are listed in the journal). A pass with
	// this counter above zero did NOT restore those records.
	SkippedOutOfScopeRecords int
	Blocked                  int
	Failed                   int
	Remaining                int
	Completed                bool
	// Stopped is non-empty when the run ended before finishing the plan
	// (budget reached, upload failure, an authorization stop, or a
	// consent-scope change that re-planned the job).
	Stopped     string
	JournalPath string
}

// coverageNote is the fixed scope statement every plan and report carries.
const coverageNote = "resync covers the device outbox (this collector's already-synced batches) only; independent account-source ledgers (such as cursor account history) and recoverable quarantine records are not included, and completion is not a claim of restoring anything beyond that ledger"

// Run performs one resync pass. The caller must hold the state directory
// process lock (the CLI does); Run itself never locks.
func Run(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("resync requires a state directory")
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	if opt.MaxBatches < 0 {
		return Result{}, fmt.Errorf("max-batches must be 0 (whole frozen plan) or a positive upload budget")
	}

	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; resync retransmits to the currently bound device only and never binds one itself; run toktrail bind or connect first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	ledger := outbox.New(stateDir)
	out, err := ledger.Load()
	if err != nil {
		return Result{}, err
	}

	// An incomplete job is resumed; a completed job is replaced by this
	// fresh explicit pass (server replay keeps the full re-pass from double
	// counting). A corrupt journal fails closed.
	existing, hasJob, err := loadJob(stateDir)
	if err != nil {
		return Result{}, err
	}
	resumed := false
	if hasJob && existing.completed() {
		hasJob = false
	}
	if hasJob {
		if existing.DeviceID != st.DeviceID {
			return Result{}, fmt.Errorf("the incomplete resync job %s was planned for device %q, but this collector is bound as %q; resync targets the currently bound device only — remove %s only if you accept abandoning that job", existing.JobID, existing.DeviceID, st.DeviceID, journalPath(stateDir))
		}
		if existing.ServerURL != serverURL {
			return Result{}, fmt.Errorf("the incomplete resync job %s targets server %s, but this run targets %s; re-run against the recorded server, or remove %s to abandon the job", existing.JobID, existing.ServerURL, serverURL, journalPath(stateDir))
		}
		resumed = true
	}

	plan := Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    serverURL,
		StateDir:     stateDir,
		JournalPath:  journalPath(stateDir),
		Resumed:      resumed,
		CoverageNote: coverageNote,
	}
	plan.QuarantinedRecords = quarantineCount(stateDir)

	var jb job
	// finalizeOnly marks a run whose only remaining write is persisting the
	// job (an empty new pass, or a job whose last upload landed but whose
	// completion write crashed). A dry run — and a confirmation abort —
	// must leave the disk byte-identical, so the write happens only after
	// the execution path is confirmed. An empty pass finalizes fully
	// offline; a crash-recovery finalize performs no uploads but MUST
	// re-verify the live consent scope before it may claim completion, so
	// it flows through the preflight and the scope gate like any resume
	// (its all-done batch loop then converges with zero uploads).
	var finalizeOnly bool
	if resumed {
		jb = existing
		remaining, done, err := resumePlan(stateDir, jb, out)
		if err != nil {
			return Result{}, err
		}
		if len(remaining) == 0 {
			// Crash after the last upload but before the completion write:
			// converge lazily, never inside a dry run.
			finalizeOnly = true
			plan.Batches = nil
			plan.TotalInJob = len(jb.Batches)
			plan.DoneInJob = len(jb.Batches)
			plan.JobID = jb.JobID
			fillExclusions(&plan, jb.Exclusions)
		} else {
			plan.Batches = remaining
			plan.TotalInJob = len(jb.Batches)
			plan.DoneInJob = done
			plan.JobID = jb.JobID
			fillExclusions(&plan, jb.Exclusions)
		}
	} else {
		jb, plan, err = buildNewJob(stateDir, st, serverURL, out, now, plan)
		if err != nil {
			return Result{}, err
		}
		if len(jb.Batches) == 0 {
			// Nothing synced: the empty completed job is persisted only by
			// a confirmed execution run.
			at := now().UTC()
			jb.CompletedAt = &at
			finalizeOnly = true
		}
	}
	plan.PendingFinalize = finalizeOnly

	if opt.DryRun {
		return Result{Plan: plan, DryRun: true, JournalPath: plan.JournalPath}, nil
	}

	if opt.Confirm == nil {
		return Result{Plan: plan}, errors.New("resync execution requires a confirmation callback; the CLI prompts (or passes --yes), and tests inject one")
	}
	if err := opt.Confirm(plan); err != nil {
		return Result{Plan: plan}, fmt.Errorf("resync aborted before any state change or network access: %w", err)
	}

	result := Result{Plan: plan, JournalPath: plan.JournalPath}
	// emptyFinalize is the offline completion of a pass with nothing to
	// retransmit at all (no synced batches, or an empty resumed journal):
	// there is no scope-dependent decision to re-verify, so it needs no
	// network access. Every other finalize-only case is a crash recovery
	// whose done decisions still have to clear the scope gate below.
	emptyFinalize := finalizeOnly && len(jb.Batches) == 0
	if !resumed || emptyFinalize {
		// Durable plan before any upload (a crash from here on resumes
		// instead of restarting), or the empty-pass completion write.
		// Both happen strictly after confirmation.
		if emptyFinalize && jb.CompletedAt == nil {
			if err := completeJob(stateDir, &jb, now); err != nil {
				return result, err
			}
		} else if err := saveJob(stateDir, jb); err != nil {
			return result, fmt.Errorf("cannot persist the resync job journal before any upload; nothing was retransmitted: %w", err)
		}
	}
	if emptyFinalize {
		return Result{Plan: plan, Completed: true, JournalPath: plan.JournalPath}, nil
	}

	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	// Live authorization preflight before anything is retransmitted. The
	// attempt accounting write happens first: if it fails, zero HTTP
	// traffic of any kind occurs.
	if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
		return result, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; no HTTP request was made and the job stays resumable: %w", err)
	}
	self, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
	if err != nil {
		result.Stopped = "authorization preflight failed"
		return result, fmt.Errorf("resync stopped before any upload; the job stays resumable: %w", err)
	}
	result.Self = self
	if devicePaused(self) {
		result.Stopped = "device paused"
		return result, fmt.Errorf("%w: server reports collection paused for this device; the resync job stays resumable and nothing was sent", syncclient.ErrDevicePaused)
	}
	scope, err := scopeFromSelf(self, st)
	if err != nil {
		result.Stopped = "consent scope unknown"
		return result, fmt.Errorf("resync stopped before any upload; the job stays resumable: %w", err)
	}

	// Scope gate: the job's recorded done/skip decisions are valid only
	// under the live consent scope they were made under. Verify the job's
	// baseline against this fresh snapshot; on any change (revision or
	// content, narrowed or widened) re-plan the complete synced history
	// under the fresh scope and stop before any upload — stale decisions
	// are never treated as completing the current authorization. This
	// also guards the crash-recovery finalize above: a job whose every
	// batch is done may only be marked complete under an unchanged scope.
	gate, err := reconcileJobScope(stateDir, st, serverURL, out, &jb, scope, now)
	if err != nil {
		result.Stopped = scopeGateStopped
		return result, err
	}
	if gate.replanned {
		result.Stopped = scopeGateStopped
		result.Remaining = countNotDone(gate.job)
		return result, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s); the job's earlier done/skip decisions were made under the old authorization and were NOT treated as completing the current scope. The complete synced history was re-planned as job %s (%d batch(es)) and saved to %s; re-run the same toktrail resync --all command to execute the re-planned pass — already-delivered records replay without double counting, and records outside the live scope stay withheld as a normal exclusion rather than a gap. Nothing was retransmitted in this run", jb.JobID, gate.change, gate.job.JobID, len(gate.job.Batches), journalPath(stateDir))
	}

	uploads := 0
	budget := opt.MaxBatches > 0
	for idx := range jb.Batches {
		b := &jb.Batches[idx]
		if b.Outcome == outcomeDone {
			if b.ScopeRevision == scope.revision {
				continue
			}
			// Per-batch dynamic scope check (defense in depth behind the
			// job-level gate): this done decision was recorded under a
			// consent revision other than the live one. Old done — and
			// its withheld-record list — must not count as completing the
			// current authorization, so the batch is re-opened and
			// re-evaluated from scratch below under the fresh scope. Its
			// prior receipts are dropped with it: re-derived targets
			// replay idempotently server-side, and the journal's receipt
			// accounting then reflects exactly the current evaluation.
			b.Outcome = outcomePlanned
			b.BlockedReason = ""
			b.Error = ""
			b.Skipped = nil
			b.Uploads = nil
		}
		// Tamper guard: the parent file must still hash to the payload the
		// job was planned against.
		raw, err := os.ReadFile(b.File)
		if errors.Is(err, os.ErrNotExist) {
			result.Stopped = "history file missing"
			return result, fmt.Errorf("resync stopped: batch %s history file disappeared (%s); the job stays resumable — restore the file or remove the journal to abandon it", b.BatchID, b.File)
		}
		if err != nil {
			result.Stopped = "history file unreadable"
			return result, fmt.Errorf("resync stopped: batch %s history file cannot be read: %w", b.BatchID, err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != b.PayloadSHA256 {
			result.Stopped = "history file tampered"
			return result, fmt.Errorf("resync stopped: batch %s file content changed since the job was planned (payload hash mismatch); failing closed — nothing more was retransmitted", b.BatchID)
		}
		var parent syncclient.BatchRequest
		if err := json.Unmarshal(raw, &parent); err != nil {
			result.Stopped = "history file unreadable"
			return result, fmt.Errorf("resync stopped: batch %s history file is no longer a valid batch: %w", b.BatchID, err)
		}
		// Divergence guard: the outbox must still know the batch as synced.
		entry, ok := outboxEntry(out, b.BatchID)
		if !ok || entry.Status != outbox.StatusSynced {
			result.Stopped = "outbox diverged"
			return result, fmt.Errorf("resync stopped: batch %s is no longer a synced outbox entry; local state diverged from the job plan, failing closed", b.BatchID)
		}
		// Local permission guard (also covers resume drift): the batch's
		// source must still carry an enabled local grant.
		cfg, cfgErr := grants.New(stateDir).Load()
		if cfgErr != nil {
			result.Stopped = "local grant config unreadable"
			return result, fmt.Errorf("resync stopped: batch %s cannot be checked against the local source grants: %w", b.BatchID, cfgErr)
		}
		if !grantAllowed(cfg, b.Source, b.Input) {
			markAttempt(b, now)
			b.Outcome = outcomeBlocked
			b.ScopeRevision = scope.revision
			b.BlockedReason = "local source grant is disabled or missing; re-enable it with toktrail sources enable and re-run"
			b.Uploads = nil
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.Blocked++
			emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Err: b.BlockedReason})
			continue
		}

		// Live scope evaluation: in-scope records retransmit, out-of-scope
		// records are withheld (never quarantined, never deleted — they
		// stay in the immutable original and are re-evaluated by the next
		// explicit pass).
		inScope := make([]json.RawMessage, 0, len(parent.Records))
		skipped := make([]skippedRecord, 0)
		for _, rec := range parent.Records {
			in, reason, err := scope.evaluateRecord(rec)
			if err != nil {
				result.Stopped = "record unevaluable"
				return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, err)
			}
			if !in {
				key, keyErr := recordKeyOf(rec)
				if keyErr != nil {
					result.Stopped = "record unevaluable"
					return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, keyErr)
				}
				skipped = append(skipped, skippedRecord{RecordKey: key, Reason: reason})
				continue
			}
			inScope = append(inScope, rec)
		}
		markAttempt(b, now)
		b.ScopeRevision = scope.revision
		b.Skipped = skipped

		if len(inScope) == 0 {
			b.Outcome = outcomeBlocked
			b.BlockedReason = fmt.Sprintf("all %d record(s) fall outside the live consent scope (revision %d)", len(parent.Records), scope.revision)
			b.Uploads = nil
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.Blocked++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Skipped: len(skipped), Err: b.BlockedReason})
			continue
		}

		targets, err := deriveUploads(stateDir, *b, parent, inScope, scope)
		if err != nil {
			result.Stopped = "upload derivation failed"
			return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, err)
		}
		pendingTargets := make([]jobUpload, 0, len(targets))
		doneUploads := make(map[string]bool, len(b.Uploads))
		for _, u := range b.Uploads {
			if u.ReceiptStatus != "" {
				doneUploads[u.BatchID] = true
			}
		}
		for _, t := range targets {
			if !doneUploads[t.BatchID] {
				pendingTargets = append(pendingTargets, t)
			}
		}
		if len(pendingTargets) == 0 {
			b.Outcome = outcomeDone
			b.Error = ""
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.UploadedBatches++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, progressDoneEvent(*b))
			continue
		}

		stopped := ""
		for _, t := range pendingTargets {
			if budget && uploads >= opt.MaxBatches {
				stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run toktrail resync --all to continue", opt.MaxBatches)
				break
			}
			// Account Run's internal self GET before it happens, mirroring
			// the syncclient guarantee that every authorization GET is
			// preceded by a durable attempt record.
			if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
				result.Stopped = "preflight accounting failed"
				return result, fmt.Errorf("cannot persist preflight attempt accounting before the upload of %s; the job stays resumable: %w", t.BatchID, err)
			}
			res, runErr := syncclient.Run(ctx, store, syncclient.Options{
				ServerURL:  serverURL,
				BatchFile:  t.File,
				BatchID:    t.BatchID,
				HTTPClient: client,
			})
			if runErr != nil {
				switch {
				case errors.Is(runErr, syncclient.ErrDeviceRevoked), errors.Is(runErr, syncclient.ErrSubjectDeleted):
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = "device no longer authorized"
					return result, fmt.Errorf("resync stopped; the job stays resumable and nothing further was sent: %w", runErr)
				case errors.Is(runErr, syncclient.ErrDevicePaused):
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = "device paused"
					return result, fmt.Errorf("resync stopped; the job stays resumable and nothing further was sent: %w", runErr)
				case errors.Is(runErr, syncclient.ErrScopeChanged), errors.Is(runErr, syncclient.ErrOutsideScope):
					b.Outcome = outcomeBlocked
					b.BlockedReason = "server rejected the upload under the live consent scope: " + runErr.Error()
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Blocked++
					result.Stopped = "server scope rejection"
					emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Skipped: len(skipped), Err: b.BlockedReason})
					return result, fmt.Errorf("resync stopped after a server-side scope rejection of batch %s; the local scope snapshot may be stale, the job stays resumable: %w", b.BatchID, runErr)
				default:
					b.Outcome = outcomeFailed
					b.Error = runErr.Error()
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Failed++
					result.Stopped = "upload failed"
					emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, UploadBatchID: t.BatchID, Outcome: outcomeFailed, Records: b.Records, Err: runErr.Error()})
					return result, fmt.Errorf("resync stopped after the upload of %s failed; the job stays resumable and the failed batch is retried by the next run: %w", t.BatchID, runErr)
				}
			}
			if res.Receipt.BatchID == "" {
				b.Outcome = outcomeFailed
				b.Error = "sync returned no batch receipt"
				if err := saveJob(stateDir, jb); err != nil {
					return result, err
				}
				result.Failed++
				result.Stopped = "upload failed"
				return result, fmt.Errorf("resync stopped: upload of %s returned no batch receipt; the job stays resumable", t.BatchID)
			}
			uploaded := res.Receipt.AcceptedRecords + res.Receipt.RejectedRecords
			b.Uploads = append(b.Uploads, jobUpload{
				BatchID:         t.BatchID,
				File:            t.File,
				Records:         t.Records,
				ReceiptStatus:   res.Receipt.Status,
				AcceptedRecords: res.Receipt.AcceptedRecords,
				RejectedRecords: res.Receipt.RejectedRecords,
				Replay:          res.Receipt.Replay,
				SyncedAt:        res.Receipt.ReceivedAt,
			})
			uploads++
			result.Uploads++
			result.UploadedRecords += uploaded
			result.AcceptedRecords += res.Receipt.AcceptedRecords
			result.RejectedRecords += res.Receipt.RejectedRecords
			if res.Receipt.Replay {
				result.ReplayReceipts++
			}
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			// Mid-run authorization drift: syncclient preflights every
			// upload with its own fresh self GET and echoes that snapshot's
			// consent revision on the POST, so this receipt was accepted
			// under exactly res.Self — which may be newer than the scope
			// this run derived its keep/skip decisions from (a widening
			// does not fail the upload, it succeeds). When the two diverge,
			// the remaining decisions are stale: stop before any further
			// upload and before the batch could be marked done. The
			// accepted upload stands; the job stays resumable under its
			// recorded baseline, so the next run re-plans under the live
			// scope instead of completing on the stale one.
			if drift, why := selfDrift(scope, res.Self, st); drift {
				result.Stopped = scopeGateStopped
				result.Remaining = countNotDone(jb)
				return result, fmt.Errorf("resync stopped mid-pass: the consent scope changed while retransmitting (%s); the server accepted the upload of %s under the live authorization, but this run's remaining done/skip decisions were planned under the old scope and were NOT treated as completing the current scope — re-run the same toktrail resync --all command and it re-plans the complete synced history under the live scope (already-delivered records replay without double counting)", why, t.BatchID)
			}
		}
		if stopped != "" {
			result.Stopped = stopped
			break
		}
		allDone := len(b.Uploads) >= len(targets)
		if allDone {
			b.Outcome = outcomeDone
			b.Error = ""
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.UploadedBatches++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, progressDoneEvent(*b))
		}
	}

	if result.Stopped == "" {
		// Completion gate: the job may only be marked complete under the
		// authorization it was planned against, verified FRESH at
		// completion time. The scope can move after the last upload's
		// preflight (or between the run's own preflight and a
		// finalize-only convergence), and neither the loop above nor the
		// server would necessarily notice: a widening lets every upload
		// succeed while the withheld-record decisions were made under the
		// old scope. One final self GET — preceded by the same durable
		// attempt accounting as every authorization read — closes that
		// window; on drift the job stays incomplete and the next run
		// re-plans under the live scope.
		if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
			result.Stopped = "preflight accounting failed"
			return result, fmt.Errorf("cannot persist preflight attempt accounting before the completion check; the job stays resumable and is not marked complete: %w", err)
		}
		finalSelf, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
		if err != nil {
			result.Stopped = "authorization preflight failed"
			return result, fmt.Errorf("resync stopped before the completion write; the job stays resumable and is not marked complete: %w", err)
		}
		if drift, why := selfDrift(scope, finalSelf, st); drift {
			result.Stopped = scopeGateStopped
			result.Remaining = countNotDone(jb)
			return result, fmt.Errorf("resync stopped before marking the job complete: the consent scope changed while the pass was running (%s); every accepted upload stands, but the job's done/skip decisions were planned under the old scope and were NOT treated as completing the current authorization — re-run the same toktrail resync --all command and it re-plans the complete synced history under the live scope (already-delivered records replay without double counting)", why)
		}
		if err := completeJob(stateDir, &jb, now); err != nil {
			return result, err
		}
		result.Completed = true
	} else {
		// Incomplete job: the same command resumes everything not done
		// (planned, failed, and blocked batches are all re-evaluated by
		// the resume run).
		result.Remaining = countNotDone(jb)
	}
	if result.Completed {
		// A completed pass with server-rejected records is terminal (the
		// rejection is deterministic, retrying it in place would loop), but
		// it must never be reported as a full restore.
		if rejected := countJobRejected(jb); rejected > 0 {
			return result, fmt.Errorf("the resync pass completed, but the server rejected %d record(s) (e.g. record_conflict); those records were NOT restored — the journal lists the per-batch receipts, and the record keys remain in the original batch files", rejected)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Planning helpers
// ---------------------------------------------------------------------------

func emit(fn func(ProgressEvent), ev ProgressEvent) {
	if fn != nil {
		fn(ev)
	}
}

func progressDoneEvent(b jobBatch) ProgressEvent {
	uploaded, accepted, rejected := 0, 0, 0
	replay := false
	last := ""
	for _, u := range b.Uploads {
		uploaded += u.AcceptedRecords + u.RejectedRecords
		accepted += u.AcceptedRecords
		rejected += u.RejectedRecords
		if u.Replay {
			replay = true
		}
		last = u.BatchID
	}
	return ProgressEvent{BatchID: b.BatchID, UploadBatchID: last, Outcome: outcomeDone, Records: b.Records, Uploaded: uploaded, Accepted: accepted, Rejected: rejected, Replay: replay, Skipped: len(b.Skipped)}
}
func markAttempt(b *jobBatch, now func() time.Time) {
	b.Attempts++
	at := now().UTC()
	b.LastAttemptAt = &at
}

// countNotDone counts the batches a resume run would re-evaluate.
func countNotDone(jb job) int {
	n := 0
	for _, b := range jb.Batches {
		if b.Outcome != outcomeDone {
			n++
		}
	}
	return n
}

// countJobRejected sums the server-rejected records across the job's
// recorded receipts (accepted + rejected always equals the submitted
// count per receipt).
func countJobRejected(jb job) int {
	n := 0
	for _, b := range jb.Batches {
		for _, u := range b.Uploads {
			n += u.RejectedRecords
		}
	}
	return n
}

func completeJob(stateDir string, jb *job, now func() time.Time) error {
	at := now().UTC()
	jb.CompletedAt = &at
	return saveJob(stateDir, *jb)
}

// scopeGateStopped is the Result.Stopped marker for the consent-scope
// re-plan path: the run ended before any upload because the authorization
// changed, and the journal now carries the re-planned full pass.
const scopeGateStopped = "consent scope changed"

// scopeGateOutcome reports what the scope gate decided for one run.
type scopeGateOutcome struct {
	// replanned is true when the recorded decisions were stale and the
	// complete synced history was re-planned under the fresh scope.
	replanned bool
	// job is the re-planned replacement job (replanned only): a fresh full
	// plan over the current synced outbox, baseline pinned to the fresh
	// scope, every batch planned, no carried-over outcome or receipt.
	job job
	// change describes the detected divergence for stop messages.
	change string
}

// reconcileJobScope verifies that the job's recorded done/skip decisions
// were made under the live consent scope, or re-plans the complete synced
// history under the fresh scope when they were not. It never uploads and
// never touches anything outside the resync-owned journal:
//
//   - A recorded baseline (current schema) must match the fresh scope by
//     revision and content fingerprint.
//   - A journal without a baseline (legacy schema 1, or a job that never
//     reached its preflight) derives one from the per-batch revision
//     stamps: with no live-scope decision at all the fresh scope is simply
//     adopted; with every decision attributable to the same revision as
//     the fresh snapshot the baseline is adopted (the revision is the
//     server's authoritative consent version, so an equal revision means
//     an equal scope); anything else — mixed revisions, unstamped
//     decisions, or a different revision — re-plans.
//
// Adoption only mutates the in-memory job; it persists with the first
// journal write the run performs. On re-plan the previous journal is
// replaced atomically by a fresh full plan over the CURRENT complete
// synced outbox (new job id, all batches planned, fresh scope baseline);
// the outbox, batch files, per-message progress, cursors, and quarantine
// store are untouched, and already-delivered records stay de-duplicated
// by the server's replay receipts when the re-planned pass re-sends them.
func reconcileJobScope(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, jb *job, scope liveScope, now func() time.Time) (scopeGateOutcome, error) {
	if jb.Scope != nil {
		if jb.Scope.matches(scope) {
			return scopeGateOutcome{}, nil
		}
		return replanJob(stateDir, st, serverURL, out, *jb, jb.Scope, 0, scope, now)
	}
	revision, decided, attributable := jobDecisionRevision(*jb)
	if !decided {
		// No live-scope decision exists yet (fresh plan, or an interrupted
		// run that never reached its preflight): adopt the fresh scope as
		// the baseline the upcoming decisions will be recorded under.
		jb.Scope = snapshotScope(scope)
		return scopeGateOutcome{}, nil
	}
	if attributable && revision == scope.revision {
		// Legacy migration: every recorded decision stamps this same
		// revision, so it was made under the same consent scope. Adopt
		// the full snapshot so later comparisons check content too.
		jb.Scope = snapshotScope(scope)
		return scopeGateOutcome{}, nil
	}
	if !attributable {
		revision = 0
	}
	return replanJob(stateDir, st, serverURL, out, *jb, nil, revision, scope, now)
}

// replanJob rebuilds the resync job over the complete current synced
// history under the fresh live scope and durably replaces the stale
// journal with it. oldScope is the recorded baseline (nil for a legacy
// journal whose decisions attribute to legacyRevision, or 0 when they do
// not attribute at all). A failure to build or persist leaves the
// previous journal untouched and resumable.
func replanJob(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, old job, oldScope *jobScope, legacyRevision int64, scope liveScope, now func() time.Time) (scopeGateOutcome, error) {
	change := describeScopeChange(oldScope, legacyRevision, scope)
	fresh, _, err := buildNewJob(stateDir, st, serverURL, out, now, Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    serverURL,
		StateDir:     stateDir,
		JournalPath:  journalPath(stateDir),
		CoverageNote: coverageNote,
	})
	if err != nil {
		return scopeGateOutcome{}, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s), and the complete synced history cannot be re-planned: %w; the previous journal is unchanged and the job stays resumable — resolve the reported problem, or remove %s to abandon the job, then re-run", old.JobID, change, err, journalPath(stateDir))
	}
	fresh.Scope = snapshotScope(scope)
	if err := saveJob(stateDir, fresh); err != nil {
		return scopeGateOutcome{}, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s), and the re-planned job cannot be persisted: %w; the previous journal is unchanged and the job stays resumable", old.JobID, change, err)
	}
	return scopeGateOutcome{replanned: true, job: fresh, change: change}, nil
}

func fillExclusions(plan *Plan, ex jobExclusions) {
	plan.ExcludedReorganized = ex.Reorganized
	plan.ExcludedPending = ex.Pending
	plan.ExcludedLocalGrant = append([]string(nil), ex.LocalGrant...)
}

func outboxEntry(out outbox.Outbox, batchID string) (outbox.BatchEntry, bool) {
	for _, entry := range out.Batches {
		if entry.BatchID == batchID {
			return entry, true
		}
	}
	return outbox.BatchEntry{}, false
}

// grantAllowed reports whether (source, input) currently matches an enabled
// local source grant. An empty source or input can never match, so batches
// without source identity are withheld under the same strict rule.
func grantAllowed(cfg grants.Config, source, input string) bool {
	for _, grant := range cfg.Grants {
		if grant.Source == source && grant.Input == input && grant.Enabled {
			return true
		}
	}
	return false
}

// grantsConfigExists reports whether any grant config file exists. A
// missing config denies retransmission by default (the error message tells
// the user to enable sources) so residual archives cannot bypass a
// withdrawn local permission such as a cancelled connect.
func grantsConfigExists(stateDir string) (bool, error) {
	store := grants.New(stateDir)
	for _, path := range []string{store.Path(), store.LegacyPath()} {
		if _, err := os.Stat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func quarantineCount(stateDir string) int {
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0
	}
	return len(entries)
}

// buildNewJob classifies the outbox into the job plan: synced entries are
// candidate leaves (reorganized parents are terminal — their records live
// in child batches or quarantine, which appear as their own entries, so
// skipping the parents never double counts), pending entries stay with the
// normal sync drain, and only grant-allowed, structurally valid batches
// join the plan. Every validation problem is collected and reported before
// anything is written or uploaded: a missing or tampered history file fails
// the whole run closed, because silently recovering a partial history
// would misrepresent coverage.
func buildNewJob(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, now func() time.Time, plan Plan) (job, Plan, error) {
	candidates := make([]outbox.BatchEntry, 0)
	ex := jobExclusions{}
	for _, entry := range out.Batches {
		switch entry.Status {
		case outbox.StatusSynced:
			candidates = append(candidates, entry)
		case outbox.StatusReorganized:
			ex.Reorganized++
		case outbox.StatusPending:
			ex.Pending++
		}
	}
	if len(candidates) == 0 {
		// Nothing synced: return a completed empty job so the next explicit
		// pass is again a fresh full pass. Planning is pure: the empty job
		// is persisted only by a confirmed execution run (finalizeOnly),
		// so a dry run writes nothing.
		id, err := newJobID()
		if err != nil {
			return job{}, plan, err
		}
		at := now().UTC()
		jb := job{Schema: journalSchema, JobID: id, DeviceID: st.DeviceID, ServerURL: serverURL, CreatedAt: at, CompletedAt: &at, Exclusions: ex}
		plan.JobID = id
		plan.TotalInJob = 0
		plan.DoneInJob = 0
		fillExclusions(&plan, ex)
		return jb, plan, nil
	}

	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		return job{}, plan, fmt.Errorf("cannot read the local source grants; resync refuses to retransmit without current local authorization: %w", err)
	}
	configExists, err := grantsConfigExists(stateDir)
	if err != nil {
		return job{}, plan, err
	}

	problems := make([]string, 0)
	planned := make([]PlannedBatch, 0)
	for _, entry := range candidates {
		if !grantAllowed(cfg, entry.Source, entry.Input) {
			ex.LocalGrant = append(ex.LocalGrant, entry.BatchID)
			continue
		}
		pb, err := validatePlannedBatch(entry)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		planned = append(planned, pb)
	}
	// Report integrity problems before the grant-emptiness diagnosis: a
	// run whose history files are all missing must say so, not blame the
	// grants.
	if len(problems) > 0 {
		return job{}, plan, fmt.Errorf("resync cannot plan: %d synced batch file(s) are missing or invalid; nothing was retransmitted and no job was started:\n  - %s", len(problems), strings.Join(problems, "\n  - "))
	}
	if len(planned) == 0 {
		if !configExists {
			return job{}, plan, fmt.Errorf("no local source grants are configured (grants.json is absent): resync denies retransmission by default so residual archives cannot bypass local permission; enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync")
		}
		return job{}, plan, fmt.Errorf("none of the %d synced batch(es) match a currently enabled local source grant (excluded: %s); enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync", len(candidates), strings.Join(ex.LocalGrant, ", "))
	}

	sort.Slice(planned, func(i, j int) bool {
		if !planned[i].CreatedAt.Equal(planned[j].CreatedAt) {
			return planned[i].CreatedAt.Before(planned[j].CreatedAt)
		}
		return planned[i].BatchID < planned[j].BatchID
	})

	id, err := newJobID()
	if err != nil {
		return job{}, plan, err
	}
	jb := job{Schema: journalSchema, JobID: id, DeviceID: st.DeviceID, ServerURL: serverURL, CreatedAt: now().UTC(), Exclusions: ex}
	for _, pb := range planned {
		jb.Batches = append(jb.Batches, jobBatch{
			BatchID:       pb.BatchID,
			File:          pb.File,
			Source:        pb.Source,
			Input:         pb.Input,
			Records:       pb.Records,
			PayloadSHA256: pb.PayloadSHA256,
			CreatedAt:     pb.CreatedAt,
			Outcome:       outcomePlanned,
		})
	}
	plan.Batches = planned
	plan.TotalInJob = len(planned)
	plan.DoneInJob = 0
	plan.JobID = id
	for _, pb := range planned {
		plan.PlannedRecords += pb.Records
	}
	fillExclusions(&plan, ex)
	return jb, plan, nil
}

// resumePlan revalidates the non-done batches of an incomplete job: each
// must still be a synced outbox entry and its file must still hash to the
// payload the job froze. Divergence fails closed with the batch named.
func resumePlan(stateDir string, jb job, out outbox.Outbox) ([]PlannedBatch, int, error) {
	remaining := make([]PlannedBatch, 0)
	done := 0
	problems := make([]string, 0)
	for _, b := range jb.Batches {
		if b.Outcome == outcomeDone {
			done++
			continue
		}
		entry, ok := outboxEntry(out, b.BatchID)
		if !ok || entry.Status != outbox.StatusSynced {
			problems = append(problems, fmt.Sprintf("batch %s is no longer a synced outbox entry; local state diverged from the job plan", b.BatchID))
			continue
		}
		raw, err := os.ReadFile(b.File)
		if errors.Is(err, os.ErrNotExist) {
			problems = append(problems, fmt.Sprintf("batch %s: history file is missing: %s (the outbox entry is preserved; restore the file or abandon the job)", b.BatchID, b.File))
			continue
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("batch %s: history file cannot be read: %v", b.BatchID, err))
			continue
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != b.PayloadSHA256 {
			problems = append(problems, fmt.Sprintf("batch %s: file content changed since the job was planned (payload hash mismatch); the file was tampered with or replaced", b.BatchID))
			continue
		}
		remaining = append(remaining, PlannedBatch{
			BatchID:       b.BatchID,
			File:          b.File,
			Source:        b.Source,
			Input:         b.Input,
			Records:       b.Records,
			PayloadSHA256: b.PayloadSHA256,
			CreatedAt:     b.CreatedAt,
		})
	}
	if len(problems) > 0 {
		return nil, 0, fmt.Errorf("the incomplete resync job %s can no longer be resumed safely; nothing was retransmitted:\n  - %s", jb.JobID, strings.Join(problems, "\n  - "))
	}
	return remaining, done, nil
}

// validatePlannedBatch performs the offline validation of one candidate:
// existence, parseability, identity and record-count consistency with the
// outbox entry, the upload privacy whitelist (the same adapter policy
// syncclient enforces), per-record size limits, and the scope-evaluation
// preconditions (record key, occurredAt). It also freezes the payload hash.
func validatePlannedBatch(entry outbox.BatchEntry) (PlannedBatch, error) {
	raw, err := os.ReadFile(entry.File)
	if errors.Is(err, os.ErrNotExist) {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file is missing: %s (the outbox entry is preserved; restore the file, or accept the gap and re-export from the source)", entry.BatchID, entry.File)
	}
	if err != nil {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file cannot be read: %v", entry.BatchID, err)
	}
	var batch syncclient.BatchRequest
	if err := json.Unmarshal(raw, &batch); err != nil {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file is not a valid batch: %v", entry.BatchID, err)
	}
	if strings.TrimSpace(batch.BatchID) != entry.BatchID {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file carries batch id %q; the file does not match the outbox entry", entry.BatchID, batch.BatchID)
	}
	if len(batch.Records) == 0 {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file contains no records", entry.BatchID)
	}
	if entry.RecordCount > 0 && entry.RecordCount != len(batch.Records) {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file carries %d record(s) but the outbox entry recorded %d; the file was modified after it was synced", entry.BatchID, len(batch.Records), entry.RecordCount)
	}
	for idx, rec := range batch.Records {
		if err := validatePlannedRecord(entry.BatchID, idx, rec); err != nil {
			return PlannedBatch{}, err
		}
	}
	sum := sha256.Sum256(raw)
	return PlannedBatch{
		BatchID:       entry.BatchID,
		File:          entry.File,
		Source:        strings.TrimSpace(entry.Source),
		Input:         strings.TrimSpace(entry.Input),
		Records:       len(batch.Records),
		PayloadSHA256: hex.EncodeToString(sum[:]),
		CreatedAt:     entry.CreatedAt,
	}, nil
}

// validatePlannedRecord mirrors the send-path gates that would otherwise
// only fire at upload time (syncclient requireUploadPrivacy plus the
// per-record size cap and scope preconditions), so a bad or tampered batch
// is reported clearly at planning time with zero network traffic.
func validatePlannedRecord(batchID string, idx int, rec json.RawMessage) error {
	if !utf8.Valid(rec) {
		return fmt.Errorf("batch %s: record %d contains invalid UTF-8; refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	var record adapter.Record
	if err := json.Unmarshal(rec, &record); err != nil || record == nil {
		return fmt.Errorf("batch %s: record %d is not a record object; refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	if !adapter.RecordIsUploadSafe(record) {
		return fmt.Errorf("batch %s: record %d carries extra fields or an invalid model (outside the upload whitelist); refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	compact, err := compactRecord(rec)
	if err != nil {
		return fmt.Errorf("batch %s: record %d is not valid JSON: %v", batchID, idx, err)
	}
	if len(compact) > syncclient.MaxBatchPayloadBytes {
		return fmt.Errorf("batch %s: record %d exceeds the maximum allowed size (%d bytes > %d bytes); it can never be uploaded as-is", batchID, idx, len(compact), syncclient.MaxBatchPayloadBytes)
	}
	if _, err := recordKeyOf(rec); err != nil {
		return fmt.Errorf("batch %s: record %d: %v", batchID, idx, err)
	}
	var probe struct {
		OccurredAt string `json:"occurredAt"`
	}
	if err := json.Unmarshal(rec, &probe); err != nil {
		return fmt.Errorf("batch %s: record %d is not valid JSON: %v", batchID, idx, err)
	}
	if strings.TrimSpace(probe.OccurredAt) == "" {
		return fmt.Errorf("batch %s: record %d has no occurredAt; it cannot be evaluated against the consent scope", batchID, idx)
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(probe.OccurredAt)); err != nil {
		return fmt.Errorf("batch %s: record %d has an unparseable occurredAt %q", batchID, idx, probe.OccurredAt)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Upload derivation: verbatim original vs deterministic children
// ---------------------------------------------------------------------------

// deriveUploads decides how one parent batch retransmits under the live
// scope. Fully in scope and within the server limits, the ORIGINAL file is
// retransmitted verbatim under its original batch id — the strongest
// idempotency (the server replays the identical batch). Otherwise the
// in-scope records are filtered into deterministic child batches (chunked
// to the server limits) under the resync-owned directory; child ids hash
// the parent id, live revision, scope content, and sorted kept record
// keys, so the same decision always replays to the same identity and the
// server de-duplicates it. Withheld records stay in the immutable original
// file — nothing is quarantined, modified, or deleted.
func deriveUploads(stateDir string, parent jobBatch, batch syncclient.BatchRequest, inScope []json.RawMessage, scope liveScope) ([]jobUpload, error) {
	if len(inScope) == len(batch.Records) &&
		len(batch.Records) <= syncclient.MaxBatchRecords &&
		envelopeSize(batch) <= syncclient.MaxBatchPayloadBytes {
		return []jobUpload{{BatchID: parent.BatchID, File: parent.File, Records: len(batch.Records)}}, nil
	}
	// Compact every record so chunk sizing is formatting-stable.
	compact := make([]json.RawMessage, 0, len(inScope))
	keys := make([]string, 0, len(inScope))
	for _, rec := range inScope {
		c, err := compactRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("record is not valid JSON: %w", err)
		}
		key, err := recordKeyOf(rec)
		if err != nil {
			return nil, err
		}
		compact = append(compact, c)
		keys = append(keys, key)
	}
	// Partition into chunks of <= MaxBatchRecords records and <=
	// MaxBatchPayloadBytes compact envelope, mirroring the syncclient
	// oversize split.
	const dummyOverhead = len(`{"batchId":"resync-0123456789abcdef","records":[]}`)
	var chunks [][]json.RawMessage
	var chunkKeys [][]string
	var current []json.RawMessage
	var currentKeys []string
	currentSize := dummyOverhead
	for idx, rec := range compact {
		recSize := len(rec)
		if dummyOverhead+recSize > syncclient.MaxBatchPayloadBytes {
			return nil, fmt.Errorf("record %d exceeds the per-record size cap; it can never be uploaded as-is", idx)
		}
		projected := currentSize + recSize
		if len(current) > 0 {
			projected++
		}
		if len(current) > 0 && (len(current) >= syncclient.MaxBatchRecords || projected > syncclient.MaxBatchPayloadBytes) {
			chunks = append(chunks, current)
			chunkKeys = append(chunkKeys, currentKeys)
			current = nil
			currentKeys = nil
			currentSize = dummyOverhead
			projected = dummyOverhead + recSize
		}
		current = append(current, rec)
		currentKeys = append(currentKeys, keys[idx])
		currentSize = projected
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
		chunkKeys = append(chunkKeys, currentKeys)
	}
	targets := make([]jobUpload, 0, len(chunks))
	for idx, chunk := range chunks {
		id := resyncChildBatchID(parent.BatchID, scope.revision, scope, chunkKeys[idx])
		file, err := writeChildBatch(stateDir, id, chunk)
		if err != nil {
			return nil, err
		}
		targets = append(targets, jobUpload{BatchID: id, File: file, Records: len(chunk)})
	}
	return targets, nil
}

func envelopeSize(batch syncclient.BatchRequest) int {
	b, err := json.Marshal(batch)
	if err != nil {
		return 0
	}
	return len(b)
}

// resyncChildBatchID derives the deterministic child identity:
// hash(parent batch + live revision + scope content + sorted kept record
// keys). Identical decisions replay to the identical id; a different scope
// or record set yields a different batch instead of colliding.
func resyncChildBatchID(parentBatchID string, revision int64, scope liveScope, recordKeys []string) string {
	h := sha256.New()
	h.Write([]byte(parentBatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(revision, 10)))
	h.Write([]byte{0})
	h.Write([]byte(scope.fingerprint()))
	sorted := append([]string(nil), recordKeys...)
	sort.Strings(sorted)
	for _, key := range sorted {
		h.Write([]byte{0})
		h.Write([]byte(key))
	}
	return "resync-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// writeChildBatch atomically writes one derived child batch under the
// resync-owned directory. Records are copied verbatim; an existing
// identical file is a replay no-op, a conflicting file is fatal.
func writeChildBatch(stateDir, id string, records []json.RawMessage) (string, error) {
	payload, err := json.Marshal(syncclient.BatchRequest{BatchID: id, Records: records})
	if err != nil {
		return "", err
	}
	path := childBatchPath(stateDir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if prior, err := os.ReadFile(path); err == nil {
		var priorBatch syncclient.BatchRequest
		if err := json.Unmarshal(prior, &priorBatch); err != nil || priorBatch.BatchID != id || len(priorBatch.Records) != len(records) {
			return "", fmt.Errorf("resync batch file %s already exists with different content; failing closed", path)
		}
		priorPayload, mErr := json.Marshal(priorBatch)
		if mErr != nil || !bytes.Equal(priorPayload, payload) {
			return "", fmt.Errorf("resync batch file %s already exists with different content; failing closed", path)
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func childBatchPath(stateDir, batchID string) string {
	return filepath.Join(strings.TrimSpace(stateDir), "resync", "batches", batchID+".json")
}

func compactRecord(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
