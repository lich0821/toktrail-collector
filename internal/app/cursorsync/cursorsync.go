// Package cursorsync orchestrates the account-level Cursor source:
// first-time local enable (confirmation + server enable call), periodic
// pull/normalize/upload through a dedicated cursor outbox, and logout.
//
// It reuses the bound device credentials and the server consent preflight
// (GET /v1/devices/self), but never the device-batch upload path: cursor
// records travel only to /v1/ingest/source-batches with the source fence.
//
// Identity: the account identity and the session cookie are derived ONLY
// by api.VerifySession (which validates the credential live against
// Cursor and returns the canonical "user_…" account id). Nothing here
// parses JWTs or assembles cookies itself, and auth.AccountHint (an
// unverified hint) is never used for identity or authorization.
//
// Privacy invariants: the Cursor access token, the account identity and
// the raw upstream responses exist only in memory for the duration of one
// sync; they never reach the license file, the outbox, logs, diagnostics,
// or uploads. The license stores only the pseudonymous account-match
// digest (identity.MatchAccount) and pull/upload watermarks.
package cursorsync

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/accountsource"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/sourcebatch"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/statedir"
	synccmd "toktrail-collector/internal/syncclient"
)

// PullOverlap re-pulls a bounded recent window before the watermark so
// late upstream backfill and corrections arrive (engineering parameter;
// not a correctness guarantee — upstream may correct even later).
const PullOverlap = time.Hour

// DefaultMaxBatches bounds one run's upload drain per phase.
const DefaultMaxBatches = 5

// maxNextRevision mirrors the protocol ceiling for event revisions
// (2^53-1); a license seeded above it cannot produce valid records.
const maxNextRevision = int64(1)<<53 - 1

// VerifyFunc validates one Cursor credential end to end through the
// pinned-host API client (api.Client.VerifySession) and returns the
// canonical account id plus the live session token. The CLI wires the
// real client; tests inject fakes. An expired or invalid login surfaces
// as an error wrapping api.ErrSessionExpired.
type VerifyFunc func(ctx context.Context, accessToken string) (api.VerifyResult, error)

// PullFunc fetches the collapsed usage snapshots for the fixed [from, to)
// window using the verified session token. The CLI wires the real
// internal/cursor/api client (host allowlisting, redirect refusal,
// body/page/event/duration budgets, per-response snapshot collapse);
// tests inject fakes.
type PullFunc func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error)

// ConfirmFunc asks the user for the first-time local confirmation. It
// receives the notice text and the output writer; it returns whether the
// user confirmed. The default implementation prompts on the terminal;
// tests inject fakes.
type ConfirmFunc func(notice string, out io.Writer) (bool, error)

// EnableNotice is the first-time confirmation notice (account scope,
// credential reading, and the upload boundary).
const EnableNotice = "TokTrail 将在本机读取 Cursor 桌面登录凭据，并直接向 Cursor 查询该账号的用量；仅上传脱敏后的用量记录（不包含 Cursor 登录凭据、邮箱或对话内容）。统计范围为整个 Cursor 账号（可能包含其他电脑上的使用）。"

// Options configures one sync or enable run.
type Options struct {
	StateDir   string
	ServerURL  string
	HTTPClient *http.Client
	// Auth reads the Cursor desktop login credential on demand.
	Auth auth.Provider
	// Verify validates the credential and derives the canonical account
	// identity plus session token (api.Client.VerifySession).
	Verify VerifyFunc
	// Pull fetches upstream usage events (see PullFunc).
	Pull PullFunc
	// Now overrides the clock for tests.
	Now func() time.Time
	// MaxBatches bounds the upload drain per phase (default 5).
	MaxBatches int
	// Out receives progress output; nil discards.
	Out io.Writer
}

// Gate is the effective collection policy for one run, supplied by the
// periodic grant sync (or unrestricted on direct CLI runs, where the
// live self view fetched inside Sync governs). AllowedTools nil/empty
// means unrestricted.
type Gate struct {
	Paused       bool
	AllowedTools []string
	HistoryFrom  *time.Time
}

func (g Gate) cursorAllowed() bool {
	if g.Paused {
		return false
	}
	if len(g.AllowedTools) == 0 {
		return true
	}
	for _, t := range g.AllowedTools {
		if strings.TrimSpace(t) == cursorsource.ToolName {
			return true
		}
	}
	return false
}

// Result reports one sync round.
type Result struct {
	// Ran is true when a sync attempt actually executed (permit present,
	// gates passed).
	Ran bool
	// Skipped carries the reason no attempt ran.
	Skipped string
	// Status is the resulting permit status.
	Status cursorsource.Status
	// FirstSyncCompleted is true when a pending_first_sync permit finished
	// its first complete pull this round.
	FirstSyncCompleted bool

	PulledEvents      int
	NewRecords        int
	ReplacedRecords   int
	SkippedUnchanged  int
	SkippedNoStableID int

	ExportedBatches int
	SyncedBatches   int
	SyncedRecords   int
	// PendingRemaining counts outbox batches still pending after the run.
	PendingRemaining int
	// Note carries non-fatal diagnostics.
	Note string
}

// EnableResult reports what one enable run did.
type EnableResult struct {
	// Confirmed is true when a first-time (or re-) confirmation was
	// obtained this run.
	Confirmed bool
	// ServerEnabled is true when the server enable call ran this run.
	ServerEnabled bool
	// Source is the authoritative server source metadata.
	Source protocol.Source
	// Sync is the first sync round run right after enabling (Ran=false
	// when the permit was already active and healthy).
	Sync Result
	// License is the resulting permit.
	License cursorsource.License
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return io.Discard
}

func (o Options) maxBatches() int {
	if o.MaxBatches > 0 {
		return o.MaxBatches
	}
	return DefaultMaxBatches
}

// verifiedCredential reads the desktop credential and validates it through
// Verify, returning the canonical account id and the live session token.
// An expired login maps to the login_expired permit state by the caller.
func verifiedCredential(ctx context.Context, opt Options) (cred auth.Credential, accountID, sessionToken string, err error) {
	cred, err = opt.Auth.Fetch(ctx)
	if err != nil {
		return cred, "", "", err
	}
	if !cred.HasToken() {
		return cred, "", "", errors.New("the cursor desktop credential carries no access token")
	}
	result, err := opt.Verify(ctx, cred.AccessToken)
	if err != nil {
		return cred, "", "", err
	}
	if strings.TrimSpace(result.AccountID) == "" || strings.TrimSpace(result.SessionToken) == "" {
		return cred, "", "", errors.New("credential verification returned no account identity")
	}
	return cred, result.AccountID, result.SessionToken, nil
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// Sync performs one cursor source round: refresh the server view, drain
// pending batches first, then pull the window, persist new batches, and
// drain again. Pull success means durably persisted locally; upload
// progress is tracked separately by the outbox.
func Sync(ctx context.Context, opt Options, gate Gate) (Result, error) {
	res := Result{}
	store := cursorsource.New(opt.StateDir)
	license, ok, err := store.Load()
	if err != nil {
		return res, err
	}
	if !ok {
		res.Skipped = "no local cursor permit (run toktrail connect or toktrail cursor enable)"
		return res, nil
	}
	res.Status = license.Status
	if !license.Collectable() {
		res.Skipped = skipReasonForStatus(license.Status)
		return res, nil
	}
	if !gate.cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		return res, nil
	}

	// Fresh server view: consent, account source state, fence and
	// nextRevision. This is also the upload preflight.
	self, st, err := fetchSelf(ctx, opt)
	if err != nil {
		return res, err
	}
	if self.Paused || !self.UploadAuthorized || self.Revoked {
		res.Skipped = fmt.Sprintf("device is not authorized to upload (paused=%t revoked=%t)", self.Paused, self.Revoked)
		return res, nil
	}
	// Effective scope, applied BEFORE any credential read or pull: the
	// direct CLI passes an unrestricted Gate and relies on this fresh
	// self view; the periodic run passes the grant sync's overlay of the
	// same server. Merge conservatively: a non-empty tool list (either
	// side) must include Cursor, the later history bound wins, and the
	// pull end never exceeds the server's upload window.
	effectiveGate := Gate{AllowedTools: gate.AllowedTools}
	if len(effectiveGate.AllowedTools) == 0 {
		effectiveGate.AllowedTools = self.AllowedTools
	}
	if !effectiveGate.cursorAllowed() {
		res.Skipped = "cursor is not allowed by the effective server grant scope for this device"
		return res, nil
	}
	effectiveGate.HistoryFrom = laterTime(gate.HistoryFrom, self.HistoryFrom)
	src, found := findSource(self.AccountSources, license.SourceInstanceID)
	if !found {
		res.Skipped = "the server no longer designates this device as the executor of the cursor source (reassign it on the website, then re-run toktrail cursor enable)"
		return res, nil
	}
	if skip := sourceStateSkip(src.State); skip != "" {
		res.Skipped = skip
		return res, nil
	}
	// nextRevision refresh: a new writer uses max(localNext, serverNext)
	// so a recreated source or a lost license never restarts at 1.
	if src.NextRevision > license.NextRevision {
		license.NextRevision = src.NextRevision
	}
	if license.NextRevision < 1 || license.NextRevision > maxNextRevision {
		return res, fmt.Errorf("cursor source nextRevision %d is outside the safe range 1..%d", license.NextRevision, maxNextRevision)
	}
	if src.FenceVersion < license.FenceVersion {
		return res, fmt.Errorf("server fence version %d moved backwards below the recorded %d", src.FenceVersion, license.FenceVersion)
	}
	fenceMoved := src.FenceVersion != license.FenceVersion
	license.FenceVersion = src.FenceVersion
	license.ConsentRevision = self.ConsentRevision

	res.Ran = true

	// Drain pending batches FIRST (they carry their persisted revisions;
	// retries never change them). A moved fence fences stale batches out
	// instead of re-sending them.
	ledger := cursoroutbox.New(opt.StateDir)
	if _, _, err := ledger.Recover(); err != nil {
		return res, err
	}
	if fenceMoved {
		if fenced, ferr := ledger.MarkFenced(license.FenceVersion); ferr != nil {
			return res, ferr
		} else if fenced > 0 {
			res.Note = appendNote(res.Note, fmt.Sprintf("%d pending batch(es) fenced out after the source fence moved", fenced))
		}
		// The fenced batches were never ACKed, yet the local event ledger
		// still marks their events as produced and the pull watermark as
		// covered — leaving either in place would silently lose every
		// event outside the overlap window. Reset both to the authorized
		// recovery window: this round re-produces everything from the
		// effective history start with fresh revisions, and the server
		// replaces by (subject, eventKey).
		if _, dErr := usage.DeleteCacheFile(opt.StateDir); dErr != nil {
			return res, dErr
		}
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		license.LastFullPullAt = nil
		res.Note = appendNote(res.Note, "source fence moved: local event ledger and pull watermark reset for recovery")
	}
	stopped, err := drain(ctx, opt, st, &license, &res, self)
	if err != nil {
		if sErr := store.Save(license); sErr != nil {
			return res, sErr
		}
		return res, err
	}
	if stopped {
		// The server moved (fence, consent or source state) between the
		// preflight and the upload: end the round WITHOUT pulling or
		// advancing anything — never continue under a stale authorization
		// and never report the round as fully successful.
		if pending, pErr := ledger.CountPending(); pErr == nil {
			res.PendingRemaining = pending
		}
		if sErr := store.Save(license); sErr != nil {
			return res, sErr
		}
		return res, nil
	}

	// Read the desktop credential, validate it live, and verify the
	// account still matches the confirmed one. A different account pauses
	// collection — the collector never switches accounts automatically.
	_, accountID, sessionToken, err := verifiedCredential(ctx, opt)
	if err != nil {
		if errors.Is(err, api.ErrSessionExpired) {
			return res, classifyAuthError(store, &license, err)
		}
		return res, fmt.Errorf("cursor credential verification failed: %w", err)
	}
	match := identity.MatchAccount(accountID)
	if license.AccountMatchID != "" && match != license.AccountMatchID {
		license.Status = cursorsource.StatusPausedAccountSwitch
		if sErr := store.Save(license); sErr != nil {
			return res, sErr
		}
		res.Status = license.Status
		res.Skipped = "the desktop login switched to a different Cursor account; collection paused (re-confirm with toktrail cursor enable)"
		return res, nil
	}

	// History widening: the pull watermark alone would hide newly
	// authorized older history — when the server moves the history start
	// from 7 to 30 days (or lifts it entirely), the watermark stays
	// recent and the extra history would never be fetched. Compare the
	// fresh effective cutoff against the one the last complete pull used;
	// on a widening, reset the watermark so this round re-fetches from
	// the new authorized start. The event cache stays: acknowledged
	// identities dedupe unchanged events, so only genuinely new older
	// history uploads.
	if historyWidened(&license, effectiveGate.HistoryFrom) {
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		res.Note = appendNote(res.Note, "history authorization widened: pull watermark reset to re-fetch the newly authorized window")
	}
	// Daily full reconciliation: the regular PullOverlap misses upstream
	// backfill and corrections older than the overlap. The first round of
	// each UTC day (and every round after a watermark reset) pulls the
	// whole authorized window instead; LastFullPullAt advances only after
	// a complete, durably persisted pull. The pull still runs inside the
	// authorized window and the API client's hard budgets — no unlimited
	// beyond-window backfill is promised.
	fullPull := license.PullWatermark == nil || dueFullPull(opt.now(), license.LastFullPullAt)
	// Pull window: overlap before the watermark (skipped for a full
	// pull), bounded by the effective (merged, fresh) history start; To
	// is frozen for the whole round and never exceeds the server's upload
	// window.
	from := time.Time{}
	if !fullPull && license.PullWatermark != nil {
		from = license.PullWatermark.Add(-PullOverlap)
	}
	if effectiveGate.HistoryFrom != nil && (from.IsZero() || effectiveGate.HistoryFrom.After(from)) {
		from = *effectiveGate.HistoryFrom
	}
	to := opt.now()
	if self.UploadUntil != nil && self.UploadUntil.Before(to) {
		to = *self.UploadUntil
	}
	events, err := opt.Pull(ctx, sessionToken, from, to)
	if err != nil {
		if errors.Is(err, api.ErrSessionExpired) {
			return res, classifyAuthError(store, &license, err)
		}
		// Pull failure keeps the watermark, the cache and every pending
		// batch; it is never reported as zero usage.
		return res, fmt.Errorf("cursor usage pull failed (watermark not advanced): %w", err)
	}
	res.PulledEvents = len(events)
	// Clamp to the authorized window actually queried: the upstream may
	// answer rows outside the requested range, and rows at or beyond the
	// round end — notably past the server's UploadUntil cap — must never
	// be normalized, cached or uploaded. Future events come back through
	// the next round's overlap; rows before the window start were either
	// already covered by the watermark or arrive through the daily full
	// reconciliation.
	events = clampEvents(events, from, to)

	cache, err := usage.LoadCache(opt.StateDir)
	if err != nil {
		return res, err
	}
	roundRevision := license.NextRevision
	// Normalize reads the cache read-only: staged entries are applied
	// only after the resulting batch is durable, so a failed round never
	// pollutes the live cache.
	records, staged, stats, err := usage.Normalize(events, subjectNamespace(st), accountID, roundRevision, cache)
	if err != nil {
		return res, fmt.Errorf("cursor usage normalization failed (watermark not advanced): %w", err)
	}
	res.NewRecords, res.ReplacedRecords = stats.NewRecords, stats.ReplacedRecords
	res.SkippedUnchanged, res.SkippedNoStableID = stats.SkippedUnchanged, stats.SkippedNoStableID

	if len(records) > 0 {
		for start := 0; start < len(records); start += protocol.MaxBatchRecords {
			end := start + protocol.MaxBatchRecords
			if end > len(records) {
				end = len(records)
			}
			batchID, bErr := newCursorBatchID(opt.now())
			if bErr != nil {
				return res, bErr
			}
			batch := protocol.Batch{
				BatchID:          batchID,
				SourceInstanceID: license.SourceInstanceID,
				Records:          records[start:end],
			}
			encoded, encErr := protocol.EncodeBatch(batch)
			if encErr != nil {
				return res, fmt.Errorf("encode cursor batch %s: %w", batchID, encErr)
			}
			if _, addErr := ledger.AddBatch(batch, license.FenceVersion, encoded); addErr != nil {
				return res, fmt.Errorf("persist cursor batch %s: %w", batchID, addErr)
			}
			res.ExportedBatches++
		}
	}

	// The batch is durable: apply and commit the staged cache, advance the
	// round revision and the pull watermark. Upload failures after this
	// point never change revisions — the outbox retries the immutable
	// bytes.
	cache.Apply(staged)
	maxProduced := roundRevision
	for _, r := range records {
		if r.Revision > maxProduced {
			maxProduced = r.Revision
		}
	}
	if len(records) > 0 {
		license.NextRevision = maxProduced + 1
	}
	watermark := to
	license.PullWatermark = &watermark
	// Record the effective history cutoff this complete pull used (three
	// states: none, finite, unlimited) so a later widening is detectable,
	// and stamp the daily full-reconciliation clock when this round
	// covered the whole authorized window. A failed round never reaches
	// this point, so neither stamp advances on failure.
	if effectiveGate.HistoryFrom != nil {
		cutoff := *effectiveGate.HistoryFrom
		license.PullCutoff, license.PullUnlimited = &cutoff, false
	} else {
		license.PullCutoff, license.PullUnlimited = nil, true
	}
	if fullPull {
		fullAt := opt.now()
		license.LastFullPullAt = &fullAt
	}
	if license.Status == cursorsource.StatusPendingFirstSync {
		license.Status = cursorsource.StatusActive
		res.FirstSyncCompleted = true
		res.Status = license.Status
	}
	if err := cache.Commit(); err != nil {
		return res, err
	}
	if err := store.Save(license); err != nil {
		return res, err
	}

	// Drain what this round produced (bounded). A stop here (scope, fence
	// or source state moved mid-round) ends the run with the batches
	// safely pending; the pull itself already happened under the fresh
	// preflight, so only the drain outcome is affected.
	stopped, err = drain(ctx, opt, st, &license, &res, self)
	if err != nil {
		if sErr := store.Save(license); sErr != nil {
			return res, sErr
		}
		return res, err
	}
	pending, err := ledger.CountPending()
	if err != nil {
		return res, err
	}
	res.PendingRemaining = pending
	_ = stopped
	return res, nil
}

// drain uploads pending batches up to the bound. The bound is the ROUND
// total: Sync calls drain twice (before and after the pull), and the
// budget counts batches already uploaded this round (res.SyncedBatches),
// so both calls together never exceed opt.maxBatches(). A receipt with
// rejected records is not a full acknowledgment: the batch stays pending
// and the error surfaces. Fence/consent/source-state changes STOP the
// drain without dropping anything; the returned flag tells the caller to
// end the round rather than continue under a stale authorization.
func drain(ctx context.Context, opt Options, st statedir.DeviceState, license *cursorsource.License, res *Result, self synccmd.SelfStatus) (bool, error) {
	ledger := cursoroutbox.New(opt.StateDir)
	for res.SyncedBatches < opt.maxBatches() {
		entry, ok, err := ledger.NextPending()
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		batch, err := ledger.LoadBatchBytes(entry)
		if err != nil {
			return false, err
		}
		encoded, err := protocol.EncodeBatch(batch)
		if err != nil {
			return false, err
		}
		if err := ledger.MarkAttempt(entry.BatchID, opt.now()); err != nil {
			return false, err
		}
		receipt, err := sourcebatch.PostBatch(ctx, sourcebatch.Options{
			ServerURL:        resolveServerURL(opt.ServerURL, st),
			HTTPClient:       opt.HTTPClient,
			DeviceID:         st.DeviceID,
			DeviceSecret:     st.DeviceSecret,
			SourceInstanceID: license.SourceInstanceID,
		}, encoded, license.FenceVersion, self.ConsentRevision)
		if err != nil {
			switch {
			case errors.Is(err, sourcebatch.ErrFenceStale),
				errors.Is(err, sourcebatch.ErrSourcePaused),
				errors.Is(err, sourcebatch.ErrSourceDeleted),
				errors.Is(err, sourcebatch.ErrStaleRevision),
				errors.Is(err, sourcebatch.ErrConsentStale),
				errors.Is(err, sourcebatch.ErrDeviceUnauthorized):
				res.Note = appendNote(res.Note, fmt.Sprintf("upload of batch %s stopped: %v", entry.BatchID, err))
				return true, nil
			}
			return false, fmt.Errorf("upload cursor batch %s: %w", entry.BatchID, err)
		}
		if receipt.RejectedRecords > 0 {
			// A partial receipt is never a full acknowledgment: surface
			// the sanitized per-record rejections (index plus the stable
			// reason code, never server free text) and keep the batch
			// pending for the next round.
			detail := describeRecordErrors(receipt.RecordErrors)
			if detail != "" {
				detail = ": " + detail
			}
			return false, fmt.Errorf("cursor batch %s had %d record(s) rejected by the server (batch stays pending)%s",
				entry.BatchID, receipt.RejectedRecords, detail)
		}
		if err := ledger.MarkSynced(receipt); err != nil {
			return false, err
		}
		res.SyncedBatches++
		res.SyncedRecords += receipt.AcceptedRecords
		syncedAt := receipt.ReceivedAt
		if syncedAt.IsZero() {
			syncedAt = opt.now()
		}
		license.LastSyncAt = &syncedAt
	}
	return false, nil
}

// describeRecordErrors renders a receipt's sanitized record rejections —
// the record index plus the stable reason code only (the sourcebatch
// client already whitelists the codes and drops all server free text).
// An empty list renders as an empty string.
func describeRecordErrors(errs []cursoroutbox.RecordError) string {
	if len(errs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(errs))
	for _, re := range errs {
		if re.Code == "" {
			parts = append(parts, fmt.Sprintf("record %d rejected", re.Index))
			continue
		}
		parts = append(parts, fmt.Sprintf("record %d: %s", re.Index, re.Code))
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Enable
// ---------------------------------------------------------------------------

// Enable performs the local confirmation and the server enable call, then
// runs the first sync. It never takes over an existing executor: a 409
// surfaces as ErrExecutorConflict with a clear message (reassignment is a
// website action).
//
// Order of trust: the FIRST-TIME confirmation strictly precedes any
// credential reading. An existing permit already covers reading, so
// re-enables verify first and only re-confirm when the account actually
// changed. Idempotence: an already-collectable permit for the same
// account with its source still listed and healthy on the self view is
// returned without a new confirmation.
func Enable(ctx context.Context, opt Options, confirm ConfirmFunc) (EnableResult, error) {
	out := opt.out()
	res := EnableResult{}
	store := cursorsource.New(opt.StateDir)
	statedirStore := statedir.New(opt.StateDir)
	st, err := statedirStore.Load()
	if err != nil {
		return res, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return res, errors.New("device is not bound; run toktrail connect first")
	}
	if opt.Auth == nil || opt.Verify == nil || opt.Pull == nil {
		return res, errors.New("cursor auth, verification or usage pull is not wired in this build")
	}

	self, _, err := fetchSelf(ctx, opt)
	if err != nil {
		return res, err
	}
	if self.Paused || !self.UploadAuthorized || self.Revoked {
		return res, fmt.Errorf("device is not authorized (paused=%t revoked=%t)", self.Paused, self.Revoked)
	}

	license, hasLicense, err := store.Load()
	if err != nil {
		return res, err
	}

	// First time: the local confirmation strictly precedes reading the
	// credential — an unattended run can never complete it by itself.
	if !hasLicense {
		if confirm == nil {
			confirm = DefaultConfirm
		}
		confirmed, cerr := confirm(EnableNotice, out)
		if cerr != nil {
			return res, fmt.Errorf("cursor enable needs an interactive local confirmation (run `toktrail cursor enable` in a terminal): %w", cerr)
		}
		if !confirmed {
			return res, errors.New("cursor enable declined by the user")
		}
		res.Confirmed = true
		// Server capability gate BEFORE the credential read: an old
		// server without account-source support can never store cursor
		// records, so the desktop login is not read (nor live-verified)
		// against it. A self view already listing account sources is
		// compatibility evidence and skips the extra round trip.
		if err := requireAccountSources(ctx, opt, self, st); err != nil {
			return res, fmt.Errorf("cursor enable needs a server with account-source support: %w", err)
		}
		_, accountID, _, err := verifiedCredential(ctx, opt)
		if err != nil {
			return res, fmt.Errorf("cursor credential verification failed: %w", err)
		}
		return enableServerAndSync(ctx, opt, self, st, store, cursorsource.License{}, false, identity.MatchAccount(accountID), res)
	}

	// Existing permit: reading is already covered. Verify the credential
	// to learn the current account before deciding what to do. The same
	// capability gate applies first: an old server cannot store cursor
	// records, so the login is not read against it needlessly.
	if err := requireAccountSources(ctx, opt, self, st); err != nil {
		return res, fmt.Errorf("cursor enable needs a server with account-source support: %w", err)
	}
	_, accountID, _, err := verifiedCredential(ctx, opt)
	if err != nil {
		if errors.Is(err, auth.ErrNoLogin) || errors.Is(err, api.ErrSessionExpired) {
			// The desktop login is gone: surface it, but the permit keeps
			// its state — the user re-confirms after logging back in.
			return res, fmt.Errorf("the Cursor desktop login is not currently usable; log into Cursor and re-run toktrail cursor enable: %w", err)
		}
		return res, fmt.Errorf("cursor credential verification failed: %w", err)
	}
	match := identity.MatchAccount(accountID)
	sameAccount := license.AccountMatchID == match

	// Already enabled for this account with the source still designated
	// and healthy: idempotent no-op.
	if license.Collectable() && sameAccount {
		if src, found := findSource(self.AccountSources, license.SourceInstanceID); found && sourceStateSkip(src.State) == "" {
			res.License = license
			res.Source = src
			res.Sync.Skipped = "permit already active"
			return res, nil
		}
	}

	// Re-confirmation is required only when the account actually changed
	// (switch pause). The same account reactivates without a new prompt.
	if !sameAccount {
		fmt.Fprintln(out, "检测到桌面登录切换到了另一个 Cursor 账号。")
		if confirm == nil {
			confirm = DefaultConfirm
		}
		confirmed, cerr := confirm(EnableNotice, out)
		if cerr != nil {
			return res, fmt.Errorf("cursor enable needs an interactive local confirmation (run `toktrail cursor enable` in a terminal): %w", cerr)
		}
		if !confirmed {
			return res, errors.New("cursor enable declined by the user")
		}
		res.Confirmed = true
	}
	return enableServerAndSync(ctx, opt, self, st, store, license, hasLicense, match, res)
}

// enableServerAndSync performs the server enable call, writes the permit
// and runs the first sync.
//
// State continuity: an existing permit keeps its pull watermark, recorded
// history cutoff, revision memory and event ledger ONLY when the server
// kept the same source instance, the account is unchanged and the source
// fence did not move. Otherwise the local state lies about what the
// server holds — a recreated source (deleteData + re-enable) starts empty
// server-side yet the cache would skip-unchanged its history; a different
// account derives different event keys; a moved fence invalidates the
// recorded revisions — and stale pending batches of the old source can
// never upload under the new identity and would block its drain forever.
// In every one of those cases the stale pending batches are terminally
// fenced, the event ledger and the pull-window memory are reset, and the
// first sync re-pulls from the authorized start with fresh revisions;
// the server replaces by (subject, eventKey), so nothing double-counts.
// A fresh permit (no local license) runs the same gate so leftover cache
// or outbox state from a logged-out permit cannot leak into the new one.
func enableServerAndSync(ctx context.Context, opt Options, self synccmd.SelfStatus, st statedir.DeviceState, store cursorsource.Store, license cursorsource.License, hasLicense bool, match string, res EnableResult) (EnableResult, error) {
	src, err := accountsource.Enable(ctx, accountsource.Options{
		ServerURL:       resolveServerURL(opt.ServerURL, st),
		HTTPClient:      opt.HTTPClient,
		DeviceID:        st.DeviceID,
		DeviceSecret:    st.DeviceSecret,
		ConsentRevision: self.ConsentRevision,
	}, cursorsource.SourceType)
	if err != nil {
		if errors.Is(err, accountsource.ErrExecutorConflict) {
			return res, fmt.Errorf("another device already collects this cursor account source; reassign the executor on the website first (%w)", err)
		}
		return res, err
	}
	res.ServerEnabled = true
	res.Source = src
	if src.NextRevision < 1 || src.NextRevision > maxNextRevision {
		return res, fmt.Errorf("server returned nextRevision %d outside the safe range 1..%d", src.NextRevision, maxNextRevision)
	}

	now := opt.now()
	if !hasLicense {
		license = cursorsource.License{
			SourceType:  cursorsource.SourceType,
			ConfirmedAt: now,
		}
	}
	// Continuity gate (see the function comment). The comparison runs on
	// the OLD license values, before they are overwritten below.
	if license.SourceInstanceID != src.SourceInstanceID ||
		license.AccountMatchID != match ||
		license.FenceVersion != src.FenceVersion {
		if fenced, ferr := cursoroutbox.New(opt.StateDir).MarkFencedForSource(src.SourceInstanceID, src.FenceVersion); ferr != nil {
			return res, ferr
		} else if fenced > 0 {
			fmt.Fprintf(opt.out(), "%d pending cursor batch(es) cannot upload under the changed source identity and were fenced out\n", fenced)
		}
		if _, dErr := usage.DeleteCacheFile(opt.StateDir); dErr != nil {
			return res, dErr
		}
		license.PullWatermark = nil
		license.PullCutoff, license.PullUnlimited = nil, false
		license.LastFullPullAt = nil
	}
	license.SchemaVersion = 1
	license.SourceInstanceID = src.SourceInstanceID
	license.SourceType = cursorsource.SourceType
	license.AccountMatchID = match
	license.Status = cursorsource.StatusPendingFirstSync
	license.ConfirmedAt = now
	license.ConsentRevision = self.ConsentRevision
	license.FenceVersion = src.FenceVersion
	// A new writer uses max(localNext, serverNext): a recreated source or
	// a lost license never restarts revisions at 1 (all-stale replays).
	if src.NextRevision > license.NextRevision {
		license.NextRevision = src.NextRevision
	}
	if license.NextRevision < 1 {
		license.NextRevision = 1
	}
	if err := store.Save(license); err != nil {
		return res, err
	}
	res.License = license

	// First sync round right away; failure leaves the permit at
	// pending_first_sync (the next periodic run retries).
	gate := Gate{AllowedTools: self.AllowedTools, HistoryFrom: self.HistoryFrom, Paused: self.Paused}
	syncRes, syncErr := Sync(ctx, opt, gate)
	res.Sync = syncRes
	if syncErr != nil {
		return res, fmt.Errorf("cursor enabled but the first sync failed (the permit stays pending; the next run retries): %w", syncErr)
	}
	if l, _, lErr := store.Load(); lErr == nil {
		res.License = l
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Status / Logout
// ---------------------------------------------------------------------------

// StatusResult is the local view for `toktrail cursor status`.
type StatusResult struct {
	HasLicense bool
	License    cursorsource.License
	// Source is the server's view of this device's cursor source (zero
	// when the server does not list one for this device).
	Source    protocol.Source
	HasSource bool
	// ServerReached is false when the self view could not be fetched.
	ServerReached  bool
	ServerError    error
	PendingBatches int
}

// Status collects the local permit, the server source view and the
// outbox backlog. It never reads the Cursor credential.
func Status(ctx context.Context, opt Options) (StatusResult, error) {
	res := StatusResult{}
	store := cursorsource.New(opt.StateDir)
	license, ok, err := store.Load()
	if err != nil {
		return res, err
	}
	res.HasLicense, res.License = ok, license
	st, err := statedir.New(opt.StateDir).Load()
	if err != nil {
		return res, err
	}
	if st.DeviceID != "" {
		self, _, err := fetchSelf(ctx, opt)
		if err != nil {
			res.ServerError = err
		} else {
			res.ServerReached = true
			if ok {
				if src, found := findSource(self.AccountSources, license.SourceInstanceID); found {
					res.Source, res.HasSource = src, true
				}
			}
		}
	}
	res.PendingBatches, err = cursoroutbox.New(opt.StateDir).CountPending()
	if err != nil {
		return res, err
	}
	return res, nil
}

// Logout revokes the local permit. It never deletes already-uploaded data
// (the server-side deletion flow governs that). With purge it also
// removes the local usage cache, the cursor outbox and its batch files.
func Logout(opt Options, purge bool) (removedLicense, purgedCache bool, err error) {
	store := cursorsource.New(opt.StateDir)
	removedLicense, err = store.Delete()
	if err != nil {
		return false, false, err
	}
	if !purge {
		return removedLicense, false, nil
	}
	if err := cursoroutbox.Purge(opt.StateDir); err != nil {
		return removedLicense, false, err
	}
	purgedCache, err = usage.DeleteCacheFile(opt.StateDir)
	if err != nil {
		return removedLicense, false, err
	}
	return removedLicense, purgedCache, nil
}

// DefaultConfirm prints the notice and reads a y/N answer from stdin. A
// closed or non-interactive stdin fails with a clear message so an
// unattended run can never complete the first-time confirmation by
// itself. The answer read is strictly bounded (a confirmation is a few
// bytes; anything longer is refused without echoing it) and only an
// explicit yes/y confirms.
func DefaultConfirm(notice string, out io.Writer) (bool, error) {
	fmt.Fprintln(out, notice)
	fmt.Fprint(out, "确认在本机启用 Cursor 用量采集？[y/N] ")
	line, err := readBoundedLine(os.Stdin, 64)
	if err != nil {
		return false, fmt.Errorf("no interactive input available: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// maxStdinTokenBytes bounds a manually supplied token: real Cursor tokens
// are far smaller; anything beyond this is refused without being echoed.
const maxStdinTokenBytes = 64 << 10

// readBoundedLine reads one line from r, at most max bytes (plus the
// newline). An over-long line is an error; the content read is never
// included in the error.
func readBoundedLine(r io.Reader, max int) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1))
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if len(line) > max {
		return "", fmt.Errorf("input exceeds %d bytes and was refused", max)
	}
	return line, nil
}

// stdinTokenProvider supplies a manually entered access token for one
// process only (`toktrail cursor sync --token-stdin`). The token is read
// from input with a hard length bound (never printed, never persisted,
// never written into the license, never echoed in errors); the local
// permit and server grant must already exist — this provider never
// enables anything by itself. The account identity is derived exclusively
// by the injected Verify function (api.VerifySession), never from
// unverified local hints. Interactive terminals are refused at the CLI
// layer: a token typed into a TTY would echo in cleartext.
type stdinTokenProvider struct{ r io.Reader }

// NewStdinTokenProvider returns an auth.Provider reading one access token
// (a single bounded line) from r. Callers must pass a non-interactive
// source (a pipe or file), not a terminal.
func NewStdinTokenProvider(r io.Reader) auth.Provider {
	return stdinTokenProvider{r: r}
}

func (p stdinTokenProvider) Fetch(ctx context.Context) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	line, err := readBoundedLine(p.r, maxStdinTokenBytes)
	if err != nil {
		return auth.Credential{}, fmt.Errorf("no usable token on stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return auth.Credential{}, errors.New("the token read from stdin is empty")
	}
	return auth.Credential{AccessToken: token, Source: "manual-stdin"}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func skipReasonForStatus(s cursorsource.Status) string {
	switch s {
	case cursorsource.StatusPausedAccountSwitch:
		return "permit paused: the desktop login switched to a different Cursor account; re-confirm with toktrail cursor enable"
	case cursorsource.StatusLoginExpired:
		return "permit paused: the Cursor desktop login expired; log into Cursor and re-confirm with toktrail cursor enable"
	default:
		return fmt.Sprintf("permit status %q does not collect", s)
	}
}

// sourceStateSkip maps server source states onto skip reasons; empty
// means the state collects. The accepted collecting states are "active"
// and "pending"; "paused" keeps batches queued.
func sourceStateSkip(state string) string {
	switch strings.TrimSpace(state) {
	case "active", "pending", "":
		return ""
	case "paused":
		return "the cursor source is paused server-side"
	default:
		return fmt.Sprintf("the cursor source is in server state %q", state)
	}
}

// classifyAuthError maps credential failures onto the permit status: an
// expired/rejected login marks the permit login_expired; an environment
// problem (permissions while unattended) surfaces as an actionable error
// without degrading the permit.
//
// Desktop-state readability is NOT uniform: the state database is always
// opened read-only and WAL content is immutable, but a login that exists
// only in the WAL becomes readable only after Cursor itself closes and
// checkpoints it. Already-checkpointed state reads fine at any time, so
// the messages below never claim every login state is readable.
func classifyAuthError(store cursorsource.Store, license *cursorsource.License, err error) error {
	if errors.Is(err, api.ErrSessionExpired) {
		license.Status = cursorsource.StatusLoginExpired
		if sErr := store.Save(*license); sErr != nil {
			return sErr
		}
		return fmt.Errorf("the Cursor login was rejected or expired; the permit is paused (log into Cursor, then toktrail cursor enable): %w", err)
	}
	if errors.Is(err, auth.ErrNoLogin) {
		return fmt.Errorf("no Cursor desktop login is available: %w", err)
	}
	if errors.Is(err, auth.ErrPermission) {
		return fmt.Errorf("the Cursor desktop state cannot be read with the current permissions (typical for an unattended scheduled run); re-confirm interactively or fix the local access: %w", err)
	}
	if errors.Is(err, auth.ErrUnsupportedSchema) || errors.Is(err, auth.ErrUnavailable) {
		return fmt.Errorf("the Cursor desktop state exists but cannot be read right now (a fresh login may live only in the SQLite WAL until Cursor is closed and checkpoints it; already-checkpointed state reads fine): %w", err)
	}
	return fmt.Errorf("reading or verifying the Cursor credential failed: %w", err)
}

func fetchSelf(ctx context.Context, opt Options) (synccmd.SelfStatus, statedir.DeviceState, error) {
	store := statedir.New(opt.StateDir)
	st, err := store.Load()
	if err != nil {
		return synccmd.SelfStatus{}, st, err
	}
	self, err := synccmd.FetchDeviceSelf(ctx, store, synccmd.Options{
		StateDir:   opt.StateDir,
		ServerURL:  opt.ServerURL,
		HTTPClient: opt.HTTPClient,
	})
	return self, st, err
}

func findSource(sources []protocol.Source, instanceID string) (protocol.Source, bool) {
	for _, s := range sources {
		if s.SourceInstanceID == instanceID && s.SourceType == cursorsource.SourceType {
			return s, true
		}
	}
	return protocol.Source{}, false
}

func resolveServerURL(optURL string, st statedir.DeviceState) string {
	if u := strings.TrimSpace(optURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	if u := strings.TrimSpace(st.ServerURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:3211"
}

// subjectNamespace derives the event-key subject namespace from the bound
// device state: the TokTrail application id plus the external subject id,
// canonical and length-framed (identity.SubjectNamespace). The same
// subject is stable across devices and source instances, while different
// TokTrail applications never derive identical event keys for one
// external subject id. An unbound state yields "" and fails closed in
// Normalize.
func subjectNamespace(st statedir.DeviceState) string {
	return identity.SubjectNamespace(strings.TrimSpace(st.ApplicationID), strings.TrimSpace(st.ExternalSubjectID))
}

// laterTime returns the later of two optional timestamps (nil-safe); the
// later bound is the more restrictive history cutoff.
func laterTime(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.After(*a) {
		return b
	}
	return a
}

// historyWidened reports whether the fresh effective history cutoff
// authorizes history older than the last complete pull covered. A nil
// cutoff means unrestricted, so a finite record becoming nil is a
// widening. Nothing recorded (fresh or legacy permit) never resets: an
// unknown past window is not evidence of widening, and resetting without
// evidence would re-pull everything on every upgrade. The watermark
// being nil already means the next pull starts at the authorized start,
// so there is nothing to widen then.
func historyWidened(license *cursorsource.License, fresh *time.Time) bool {
	if license.PullWatermark == nil {
		return false
	}
	if license.PullUnlimited {
		return false
	}
	if license.PullCutoff == nil {
		return false
	}
	if fresh == nil {
		return true
	}
	return fresh.Before(*license.PullCutoff)
}

// dueFullPull reports whether a full-window reconciliation pull is due:
// the first round of each UTC day (nothing recorded yet counts as due).
func dueFullPull(now time.Time, last *time.Time) bool {
	if last == nil {
		return true
	}
	a, b := now.UTC(), last.UTC()
	return a.Year() != b.Year() || a.YearDay() != b.YearDay()
}

// requireAccountSources verifies the server speaks the account-sources
// protocol before the collector reads the Cursor desktop credential: an
// old server cannot store cursor records, so reading (and live-verifying)
// the login against it would be pointless exposure. A self view that
// already lists account sources is itself compatibility evidence and
// skips the extra round trip, so the check does not repeat on every run.
func requireAccountSources(ctx context.Context, opt Options, self synccmd.SelfStatus, st statedir.DeviceState) error {
	if len(self.AccountSources) > 0 {
		return nil
	}
	return accountsource.RequireCapability(ctx, accountsource.Options{
		ServerURL:    resolveServerURL(opt.ServerURL, st),
		HTTPClient:   opt.HTTPClient,
		DeviceID:     st.DeviceID,
		DeviceSecret: st.DeviceSecret,
	})
}

// clampEvents restricts upstream rows to the authorized window actually
// queried [from, to). A divergent or hostile upstream may return rows
// outside the range it was asked for: rows at or after `to` (notably past
// the server's UploadUntil cap) must never be cached or uploaded — the
// next round's overlap picks them up once they are genuinely inside the
// window — and rows before `from` were either already covered by the
// watermark or arrive through the daily full reconciliation. A zero
// `from` (full pull from the authorized start) imposes no lower bound.
func clampEvents(events []api.UsageEvent, from, to time.Time) []api.UsageEvent {
	var out []api.UsageEvent
	for _, e := range events {
		if !from.IsZero() && e.TimestampMS < from.UnixMilli() {
			continue
		}
		if e.TimestampMS >= to.UnixMilli() {
			continue
		}
		out = append(out, e)
	}
	return out
}

func appendNote(note, add string) string {
	if note == "" {
		return add
	}
	return note + "; " + add
}

func newCursorBatchID(now time.Time) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate cursor batch id: %w", err)
	}
	return fmt.Sprintf("cursor-%s-%s", now.UTC().Format("20060102T150405Z"), hex.EncodeToString(buf[:])), nil
}
