package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
)

// Stable ingest authorization codes mirrored from the server contract. The
// collector keys off these sentinels (not the human-readable message), so
// callers can distinguish terminal stop conditions from retryable failures.
var (
	// ErrDeviceRevoked maps to the server's stable 401 device_revoked code:
	// the device binding is permanently revoked. Sending stops and the
	// collector never re-binds automatically.
	ErrDeviceRevoked = errors.New("device_revoked")
	// ErrSubjectDeleted maps to the server's stable 401 subject_deleted
	// code: the subject identity is tombstoned and can never be reused.
	// Sending stops and the collector never re-binds automatically.
	ErrSubjectDeleted = errors.New("subject_deleted")
	// ErrScopeChanged maps to the server's stable 409 scope_changed code:
	// the consent revision sent with the batch predates a consent-scope
	// change. When the batch came from the outbox (state directory present),
	// the collector automatically and persistently reorganizes it under the
	// live scope: kept records move to a new batch with a new ID, the rest
	// are quarantined recoverably, and the old batch stays immutable and
	// terminal. The error still surfaces so callers see the reorganization.
	ErrScopeChanged = errors.New("scope_changed")
	// ErrOutsideScope maps to the server's stable 403 outside_scope code:
	// record(s) fall outside the current consent scope. Outbox batches get
	// the same automatic persistent reorganization as scope_changed; all
	// out-of-scope records are quarantined recoverably and the outbox head
	// is freed instead of blocking later batches.
	ErrOutsideScope = errors.New("outside_scope")
	// ErrDeviceUnauthorized marks an authentication or identity failure on
	// GET /v1/devices/self: the server rejected the device credentials
	// (HTTP 401/403) or answered with another device's authorization.
	// Callers must stop local reading; this is never treated as a
	// transient network failure.
	ErrDeviceUnauthorized = errors.New("device_unauthorized")
	// ErrSelfProtocol marks a structurally invalid device self response
	// (undecodable body or a missing device object on HTTP 200). Callers
	// must stop local reading rather than fall back to a previous scope.
	ErrSelfProtocol = errors.New("self_protocol")
	// ErrDevicePaused maps to the grant protocol's paused state: the
	// server explicitly paused collection for this device. Callers stop
	// sending (uploads and tool-status reports) and keep pending batches
	// queued; it is a state, not a failure, and never triggers re-binding.
	ErrDevicePaused = errors.New("device_paused")
	// ErrQuarantineHeld reports the recovery-only outcome that quarantined
	// records exist but none is currently recoverable: the live consent
	// scope still excludes them (or the revision is not strictly newer),
	// or — on a device with a configured grant store — their (source,
	// input) no longer carries an enabled local grant. It is a steady
	// state, not a failure: the records stay quarantined and recoverable
	// until the authorization widens again. The periodic drain treats it
	// as a settled run; manual `toktrail sync` still surfaces the wrapped
	// diagnosis.
	ErrQuarantineHeld = errors.New("quarantine_held")
)

type Options struct {
	ServerURL    string
	StateDir     string
	BatchFile    string
	BatchID      string
	HTTPClient   *http.Client
	ToolStatuses []ToolStatus
	// ReplaceExisting must be enabled only for an explicitly authorized repair.
	ReplaceExisting bool
}

type Result struct {
	State   statedir.DeviceState
	Receipt BatchReceipt
	Status  int
	// Self is the device authorization snapshot learned from the preflight;
	// Receipt.ConsentRevision-echoed header came from Self.ConsentRevision.
	Self SelfStatus
	// Recovered counts records moved out of the quarantine store back into
	// a pending batch during this run (scope widened under a strictly newer
	// consent revision).
	Recovered int
	// Quarantined counts records currently sitting in the quarantine store
	// after this run finished.
	Quarantined int
}

type BatchRequest struct {
	BatchID         string            `json:"batchId"`
	Records         []json.RawMessage `json:"records"`
	ReplaceExisting bool              `json:"replaceExisting,omitempty"`
}

type BatchReceipt struct {
	BatchID         string        `json:"batchId"`
	Status          string        `json:"status"`
	AcceptedRecords int           `json:"acceptedRecords"`
	RejectedRecords int           `json:"rejectedRecords"`
	Replay          bool          `json:"replay"`
	ReceivedAt      time.Time     `json:"receivedAt"`
	RecordErrors    []RecordError `json:"recordErrors,omitempty"`
}

type RecordError struct {
	Index     int    `json:"index"`
	RecordKey string `json:"recordKey,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type ingestResponse struct {
	Batch BatchReceipt `json:"batch"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// SelfStatus is the device authorization snapshot returned by
// GET /v1/devices/self. ConsentRevision versions the upload authorization
// and must be echoed back as the X-Consent-Revision header on every ingest
// POST; HistoryFrom/UploadUntil/AllowedTools describe the live consent
// scope (nil/empty means unrestricted).
//
// Grant protocol: when GrantProtocolVersion is present, the server speaks
// the device grant protocol and the top-level Paused/AllowedTools/
// HistoryFrom/ConsentRevision fields are this device's effective grant
// scope (Paused is always sent as bool; a paused device reports
// AllowedTools containing the "__toktrail_paused__" sentinel). Absent
// GrantProtocolVersion means an older server: callers keep the legacy
// behavior and must not apply grant-scope changes.
type SelfStatus struct {
	DeviceID             string     `json:"deviceId"`
	ConsentRevision      int64      `json:"consentRevision"`
	HistoryFrom          *time.Time `json:"historyFrom,omitempty"`
	UploadUntil          *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools         []string   `json:"allowedTools,omitempty"`
	ProductionBound      bool       `json:"productionBound,omitempty"`
	UploadAuthorized     bool       `json:"uploadAuthorized"`
	Revoked              bool       `json:"revoked"`
	Paused               bool       `json:"paused,omitempty"`
	GrantProtocolVersion *int       `json:"grantProtocolVersion,omitempty"`
	// DeviceGrantManaged is the server's persistent explicit-authorization
	// flag for this device. Only a present-and-true flag permits the
	// collector to add built-in default-directory grants for confirmed
	// tools; false or absent means filter-only — the device never creates
	// local paths on the server's behalf.
	DeviceGrantManaged *bool `json:"deviceGrantManaged,omitempty"`
	// AccountSources lists the account-level sources this device is the
	// designated executor of (the server only returns the executing
	// device's sources). Absent/empty on servers without account sources.
	AccountSources []protocol.Source `json:"accountSources,omitempty"`
}

type selfResponse struct {
	Device *SelfStatus `json:"device,omitempty"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	if strings.TrimSpace(opt.StateDir) != "" {
		// Replay any half-applied scope reorganization or quarantine
		// recovery before anything else, so state is consistent before this
		// run selects a batch.
		if err := recoverPendingReorg(strings.TrimSpace(opt.StateDir)); err != nil {
			return Result{}, err
		}
		if err := recoverPendingSyncACK(store, strings.TrimSpace(opt.StateDir)); err != nil {
			return Result{}, err
		}
	}
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	batchFile := strings.TrimSpace(opt.BatchFile)
	ledger := outbox.New(strings.TrimSpace(opt.StateDir))
	fromOutbox := false
	var outboxEntry outbox.BatchEntry
	if batchFile == "" && strings.TrimSpace(opt.StateDir) != "" {
		entry, ok, err := ledger.NextPending()
		if err != nil {
			return Result{}, err
		}
		if !ok {
			// Empty outbox: if quarantined records exist, try to recover
			// them under the live scope. This path performs exactly one
			// self GET (preceded by durable attempt accounting) and no
			// ingest POST. A revoked or unknown scope stops with an error.
			entries, err := quarantine.New(strings.TrimSpace(opt.StateDir)).Load()
			if err != nil {
				return Result{}, err
			}
			if len(entries) == 0 {
				return Result{}, errors.New("missing batch file and no pending outbox batch")
			}
			self, recovered, err := recoverQuarantinedWithFreshSelf(ctx, client, serverURL, st, strings.TrimSpace(opt.StateDir))
			if err != nil {
				return Result{}, err
			}
			if recovered == 0 {
				return Result{}, fmt.Errorf("%w; missing batch file and no pending outbox batch; %d quarantined record(s) remain outside the consent scope and need a strictly newer consent revision before they can be recovered (or their local source grant is no longer enabled)", ErrQuarantineHeld, len(entries))
			}
			return Result{Self: self, Recovered: recovered, Quarantined: quarantineCount(strings.TrimSpace(opt.StateDir))}, nil
		}
		outboxEntry = entry
		batchFile = entry.File
		if strings.TrimSpace(opt.BatchID) == "" {
			opt.BatchID = entry.BatchID
		}
		fromOutbox = true
	}
	if opt.ReplaceExisting && fromOutbox {
		return Result{}, errors.New("replacement requires an explicitly selected batch file")
	}
	batch, err := loadBatch(batchFile, opt.BatchID)
	if err != nil {
		return Result{}, err
	}
	batch.ReplaceExisting = opt.ReplaceExisting
	// Privacy gate before any state change or HTTP traffic: a batch with
	// extra fields or malformed model identifiers must never leave the device, so
	// the upload cannot rely on the server rejecting it. The check sits
	// before MarkAttempt and the preflight journal so a rejection leaves
	// the outbox entry, attempt accounting, and batch file untouched.
	if err := requireUploadPrivacy(batch); err != nil {
		return Result{}, err
	}
	// Fail closed if any individual record exceeds MaxBatchPayloadBytes.
	for idx, raw := range batch.Records {
		compact, err := compactRawRecord(raw)
		if err != nil {
			return Result{}, fmt.Errorf("record %d invalid json: %w", idx, err)
		}
		if len(compact) > MaxBatchPayloadBytes {
			return Result{}, fmt.Errorf("record %d exceeds maximum allowed size (%d bytes > %d bytes); failing closed", idx, len(compact), MaxBatchPayloadBytes)
		}
	}

	// Oversized pending recovery: partition into <= 500 records and compact envelope <= 768 KiB.
	// Same Run uploads the first child batch.
	if isOversizedBatch(batch) {
		if !fromOutbox || strings.TrimSpace(opt.StateDir) == "" {
			return Result{}, fmt.Errorf("batch %s exceeds size limits (%d records); cannot upload oversized batch without state directory outbox", batch.BatchID, len(batch.Records))
		}
		journal, err := reorganizeOversizedBatch(strings.TrimSpace(opt.StateDir), outboxEntry, batch)
		if err != nil {
			return Result{}, fmt.Errorf("reorganize oversized batch %s: %w", batch.BatchID, err)
		}
		if len(journal.NewBatches) == 0 {
			return Result{}, fmt.Errorf("oversize split of batch %s produced no child batches", batch.BatchID)
		}
		firstChild := journal.NewBatches[0]
		opt.BatchID = firstChild.BatchID
		batchFile = batchFilePath(strings.TrimSpace(opt.StateDir), firstChild.BatchID)
		batch, err = loadBatch(batchFile, opt.BatchID)
		if err != nil {
			return Result{}, fmt.Errorf("load split child batch %s: %w", firstChild.BatchID, err)
		}
		outboxEntry = outbox.BatchEntry{
			BatchID:               firstChild.BatchID,
			File:                  batchFile,
			Source:                firstChild.Source,
			Input:                 firstChild.Input,
			Status:                outbox.StatusPending,
			RecordCount:           len(firstChild.Records),
			OriginConsentRevision: journal.ConsentRevision,
		}
	}
	if fromOutbox {
		// MarkAttempt stays batch-bound: only a known pending outbox entry
		// can be marked, never an arbitrary --file batch.
		if err := ledger.MarkAttempt(batch.BatchID, time.Now().UTC()); err != nil {
			return Result{}, err
		}
	}
	if strings.TrimSpace(opt.StateDir) != "" {
		// Durable authorization-attempt accounting for the self GET too:
		// every GET — including the explicit --file path with a state
		// directory — is preceded by a persisted attempt record, mirroring
		// the guarantee MarkAttempt gives the ingest POST. If this write
		// fails, zero HTTP traffic of any kind happens. Only the fully
		// stateless mode (no state directory) is exempt: there is nothing
		// to journal into.
		if _, err := ledger.RecordPreflightAttempt(time.Now().UTC()); err != nil {
			if fromOutbox {
				return Result{}, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; the batch stays pending and no HTTP request was made: %w", err)
			}
			return Result{}, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; the batch file was not uploaded and no HTTP request was made: %w", err)
		}
	}
	// Preflight: refresh the live device authorization snapshot before any
	// upload. The MarkAttempt journal above is already durable at this
	// point, so the existing guarantee holds: a failure before or during
	// this check still performs zero ingest POSTs while attempt accounting
	// survives. A revoked or deleted device stops here, before the POST.
	selfStatus, err := preflightSelf(ctx, client, serverURL, st)
	if err != nil {
		return Result{}, err
	}
	// A server that speaks the grant protocol and reports the device
	// paused stops all sending here: the batch stays pending (never
	// quarantined — pause is temporary) and no ingest POST happens. The
	// server's record-level scope enforcement remains the final defense
	// for everything uploaded before the pause.
	if err := checkNotPaused(selfStatus); err != nil {
		return Result{Self: selfStatus}, err
	}
	// Local scope gate BEFORE any POST: narrowed-away data must never
	// leave the device for the server to reject. Every record is checked
	// against the fresh preflight scope (allowed tools and time range).
	// Out-of-scope records in an outbox batch are split off through the
	// durable WAL/quarantine path — quarantined locally, never submitted —
	// while the in-scope remainder uploads normally; a --file batch with
	// out-of-scope records is refused outright with zero network traffic.
	//
	// Race boundary (deliberately not over-promised): a consent change the
	// user makes between this preflight GET and the ingest POST cannot be
	// recalled from the wire — bytes already sent are sent. What the gate
	// guarantees is that the server never PERSISTS such data: the POST
	// still carries X-Consent-Revision and the server validates it, so a
	// racing narrowing rejects the batch server-side exactly as before.
	// No absolute instantaneous revocation of in-flight requests is
	// claimed.
	if err := gateBatchAgainstScope(&batch, &outboxEntry, &opt, ledger, fromOutbox, selfStatus, strings.TrimSpace(opt.StateDir)); err != nil {
		return Result{Self: selfStatus}, err
	}
	// With the live scope in hand, recover any quarantined records that are
	// back inside it (requires a strictly newer consent revision). A
	// recovery failure fails closed: the batch stays pending and no POST
	// happens, because proceeding with an unrecoverable quarantine state
	// could silently strand records.
	recovered, err := recoverQuarantinedWithScope(strings.TrimSpace(opt.StateDir), selfStatus)
	if err != nil {
		return Result{}, err
	}
	endpoint, err := joinURL(serverURL, "/v1/ingest/batches")
	if err != nil {
		return Result{}, err
	}
	batch.ReplaceExisting = opt.ReplaceExisting
	payload, err := json.Marshal(batch)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	// The production control plane requires the consent revision the
	// snapshot was taken under; the batch body wire format is unchanged.
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(selfStatus.ConsentRevision, 10))
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	var body ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Result{}, err
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		code, message := "", ""
		if body.Error != nil {
			code, message = body.Error.Code, body.Error.Message
		}
		err := classifyIngestError(resp.StatusCode, code, message)
		// Scope rejections of an outbox batch trigger a persistent, crash-safe
		// reorganization under the live scope: kept records get a new batch
		// with a new deterministic ID, out-of-scope records are quarantined
		// recoverably, and the old batch becomes terminal — the outbox head
		// can never stay blocked on a stale scope. Batches passed via --file
		// (no outbox) keep the diagnosis-only behavior.
		if fromOutbox && strings.TrimSpace(opt.StateDir) != "" &&
			(errors.Is(err, ErrScopeChanged) || errors.Is(err, ErrOutsideScope)) {
			journal, reorgErr := reorganizeBatchAfterScopeError(ctx, client, serverURL, st, strings.TrimSpace(opt.StateDir), outboxEntry, batch)
			if reorgErr != nil {
				return Result{}, fmt.Errorf("%w; automatic scope reorganization failed, the batch stays pending and no records were moved: %v", err, reorgErr)
			}
			return Result{}, fmt.Errorf("%w; %s", err, reorgSummary(journal))
		}
		return Result{}, err
	}
	if body.Batch.BatchID == "" {
		return Result{}, errors.New("sync response missing batch receipt")
	}
	if body.Batch.BatchID != batch.BatchID {
		return Result{}, fmt.Errorf("sync response batch receipt %q does not match submitted batch %q; keeping batch pending", body.Batch.BatchID, batch.BatchID)
	}
	// Reconcile the receipt against the submitted batch BEFORE any state
	// change: an inconsistent receipt (wrong counts or indexes that do not
	// match the submitted records) must leave the outbox pending, the
	// per-message progress untouched, and no ACK journal behind, rather than
	// guess which records succeeded.
	rejectedKeys, err := reconcileReceipt(body.Batch, batch)
	if err != nil {
		return Result{}, err
	}
	st.ServerURL = strings.TrimRight(serverURL, "/")
	st.LastSyncBatchID = body.Batch.BatchID
	st.LastSyncStatus = body.Batch.Status
	st.LastSyncAcceptedRecords = body.Batch.AcceptedRecords
	st.LastSyncRejectedRecords = body.Batch.RejectedRecords
	st.LastSyncedAt = body.Batch.ReceivedAt
	if st.LastSyncedAt.IsZero() {
		st.LastSyncedAt = time.Now().UTC()
	}
	receipt := outbox.Receipt{
		BatchID:         body.Batch.BatchID,
		Status:          body.Batch.Status,
		AcceptedRecords: body.Batch.AcceptedRecords,
		RejectedRecords: body.Batch.RejectedRecords,
		ReceivedAt:      st.LastSyncedAt,
	}
	var cursorConfirm *progress.ConfirmOptions
	var messageConfirm *progress.MessageBatchConfirm
	if fromOutbox && strings.TrimSpace(outboxEntry.Source) != "" && strings.TrimSpace(outboxEntry.Input) != "" {
		cursorConfirm = &progress.ConfirmOptions{
			Source:      outboxEntry.Source,
			Input:       outboxEntry.Input,
			BatchID:     body.Batch.BatchID,
			RecordCount: outboxEntry.RecordCount,
			Status:      body.Batch.Status,
			ConfirmedAt: st.LastSyncedAt,
		}
		// Per-message partial ACK: accepted messages advance to their pending
		// to-state, rejected ones unfreeze but keep their baseline and never
		// auto-resend the same interval key. Rejected messages never block
		// accepted ones.
		messageConfirm = &progress.MessageBatchConfirm{
			BatchID:      body.Batch.BatchID,
			RejectedKeys: rejectedKeys,
		}
	}
	if err := commitSyncACK(store, strings.TrimSpace(opt.StateDir), syncACKJournal{
		State:          st,
		FromOutbox:     fromOutbox,
		Receipt:        receipt,
		CursorConfirm:  cursorConfirm,
		MessageConfirm: messageConfirm,
	}); err != nil {
		return Result{}, err
	}
	return Result{State: st, Receipt: body.Batch, Status: resp.StatusCode, Self: selfStatus, Recovered: recovered, Quarantined: quarantineCount(strings.TrimSpace(opt.StateDir))}, nil
}

// FetchDeviceSelf fetches the device's live authorization snapshot via
// GET /v1/devices/self using the device's own credentials, WITHOUT the
// upload-preflight history adjustment: the returned HistoryFrom and
// AllowedTools are the raw server-effective grant scope, so grant-sync
// callers can honor server-side widenings. Revoked or unauthorized devices
// fail like the upload preflight. This never binds or re-binds.
func FetchDeviceSelf(ctx context.Context, store statedir.Store, opt Options) (SelfStatus, error) {
	st, err := store.Load()
	if err != nil {
		return SelfStatus{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return SelfStatus{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return fetchSelf(ctx, client, serverURL, st)
}

// fetchSelf performs the authenticated GET and applies the shared
// terminal-condition checks. The returned snapshot is raw (no local
// history adjustment).
func fetchSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState) (SelfStatus, error) {
	endpoint, err := joinURL(serverURL, "/v1/devices/self")
	if err != nil {
		return SelfStatus{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SelfStatus{}, err
	}
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	resp, err := client.Do(req)
	if err != nil {
		return SelfStatus{}, fmt.Errorf("device self check failed: %w", err)
	}
	defer resp.Body.Close()
	var body selfResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return SelfStatus{}, fmt.Errorf("%w: device self check returned an undecodable body (status %d): %v", ErrSelfProtocol, resp.StatusCode, err)
	}
	if resp.StatusCode == http.StatusOK {
		if body.Device == nil {
			return SelfStatus{}, fmt.Errorf("%w: device self check response missing device status", ErrSelfProtocol)
		}
		if body.Device.Revoked || !body.Device.UploadAuthorized {
			return SelfStatus{}, fmt.Errorf("%w: server reports device %s is no longer authorized to upload; sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, body.Device.DeviceID)
		}
		// The snapshot must describe THIS device: applying another device's
		// authorization (or a server that cannot name the authenticated
		// device) fails closed.
		if body.Device.DeviceID != st.DeviceID {
			return SelfStatus{}, fmt.Errorf("%w: device self check returned authorization for device %q, but this collector is bound as %q; refusing to apply another device's authorization", ErrDeviceUnauthorized, body.Device.DeviceID, st.DeviceID)
		}
		return *body.Device, nil
	}
	code, message := "", ""
	if body.Error != nil {
		code, message = body.Error.Code, body.Error.Message
	}
	switch code {
	case "device_revoked":
		return SelfStatus{}, fmt.Errorf("%w: %s; sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, message)
	case "subject_deleted":
		return SelfStatus{}, fmt.Errorf("%w: %s; sending stopped and the collector never re-binds automatically", ErrSubjectDeleted, message)
	}
	// Authentication failures are terminal for reading, never a transient
	// network condition.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return SelfStatus{}, fmt.Errorf("%w: device self check rejected the device credentials (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	}
	if code != "" || message != "" {
		return SelfStatus{}, fmt.Errorf("device self check failed: status %d: %s: %s", resp.StatusCode, code, message)
	}
	return SelfStatus{}, fmt.Errorf("device self check failed: status %d", resp.StatusCode)
}

// preflightSelf refreshes the device's live authorization snapshot via
// GET /v1/devices/self before any upload. It returns the snapshot whose
// ConsentRevision must be echoed on the ingest POST. Terminal conditions
// (device revoked, subject deleted) return wrapped ErrDeviceRevoked /
// ErrSubjectDeleted so callers stop sending; the collector never re-binds
// automatically. Any other failure is a plain error: the batch stays
// pending and the next sync run retries after a fresh preflight.
// gateBatchAgainstScope enforces the fresh consent scope locally before
// any ingest POST. It mutates batch/outboxEntry to the in-scope child when
// a split happened, so the caller uploads exactly the scoped-down batch.
func gateBatchAgainstScope(batch *BatchRequest, entry *outbox.BatchEntry, opt *Options, ledger outbox.Store, fromOutbox bool, self SelfStatus, stateDir string) error {
	scope, err := liveScopeFromSelf(self)
	if err != nil {
		return err
	}
	outOfScope := 0
	for _, raw := range batch.Records {
		inScope, _, err := scope.evaluateRecord(raw)
		if err != nil {
			return fmt.Errorf("batch %s stays pending and was not uploaded: %w", batch.BatchID, err)
		}
		if !inScope {
			outOfScope++
		}
	}
	if outOfScope == 0 {
		return nil
	}
	if !fromOutbox || stateDir == "" {
		return fmt.Errorf("batch %s contains %d of %d record(s) outside the current consent scope; refusing to upload a --file batch without sending anything (drain the outbox instead, which quarantines out-of-scope records locally)",
			batch.BatchID, outOfScope, len(batch.Records))
	}
	journal, err := splitBatchUnderScope(stateDir, *entry, *batch, scope, "pre-post-scope")
	if err != nil {
		return err
	}
	if len(journal.NewBatches) == 0 {
		// Everything was out of scope: the old batch is terminal and its
		// records are quarantined locally; nothing is uploaded.
		return fmt.Errorf("%w; batch %s fully quarantined locally under revision %d without any upload", ErrOutsideScope, batch.BatchID, scope.revision)
	}
	child := journal.NewBatches[0]
	childFile := batchFilePath(stateDir, child.BatchID)
	childBatch, err := loadBatch(childFile, child.BatchID)
	if err != nil {
		return fmt.Errorf("load scoped child batch %s: %w", child.BatchID, err)
	}
	childEntry := outbox.BatchEntry{
		BatchID:               child.BatchID,
		File:                  childFile,
		Source:                child.Source,
		Input:                 child.Input,
		Status:                outbox.StatusPending,
		RecordCount:           len(child.Records),
		OriginConsentRevision: journal.ConsentRevision,
	}
	if err := ledger.MarkAttempt(child.BatchID, time.Now().UTC()); err != nil {
		return err
	}
	*batch = childBatch
	*entry = childEntry
	if strings.TrimSpace(opt.BatchID) != "" {
		opt.BatchID = child.BatchID
	}
	return nil
}

// checkNotPaused reports ErrDevicePaused when the fetched snapshot speaks
// the grant protocol and the device is paused (explicit flag or the
// allowedTools sentinel). Old-protocol snapshots never pause.
func checkNotPaused(self SelfStatus) error {
	if self.GrantProtocolVersion == nil {
		return nil
	}
	paused := self.Paused
	for _, tool := range self.AllowedTools {
		if strings.TrimSpace(tool) == pausedToolSentinel {
			paused = true
		}
	}
	if paused {
		return fmt.Errorf("%w: server reports collection paused for this device; pending batches stay queued and nothing is sent", ErrDevicePaused)
	}
	return nil
}

// pausedToolSentinel is the marker the server places in allowedTools when
// the device is paused.
const pausedToolSentinel = "__toktrail_paused__"

func preflightSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState) (SelfStatus, error) {
	dev, err := fetchSelf(ctx, client, serverURL, st)
	if err != nil {
		return SelfStatus{}, err
	}
	// Under the grant protocol the server-confirmed effective cutoff is
	// authoritative and may legitimately widen beyond the bind-time cutoff,
	// so it is used as-is. Only old-protocol servers keep the legacy
	// never-widen behavior (max with the bind-time cutoff).
	if dev.GrantProtocolVersion == nil {
		if st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
			if dev.HistoryFrom == nil || dev.HistoryFrom.Before(*st.HistoryFrom) {
				hf := *st.HistoryFrom
				dev.HistoryFrom = &hf
			}
		}
	}
	return dev, nil
}

// classifyIngestError maps a non-2xx ingest response onto a typed error.
// Terminal codes (device_revoked, subject_deleted) stop sending entirely;
// scope codes (scope_changed, outside_scope) are handled by the caller with
// a persistent reorganization when the batch came from the outbox, so the
// messages here describe that follow-up rather than demanding manual
// re-export.
func classifyIngestError(status int, code string, message string) error {
	switch code {
	case "device_revoked":
		return fmt.Errorf("%w: %s (HTTP %d); sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, message, status)
	case "subject_deleted":
		return fmt.Errorf("%w: %s (HTTP %d); sending stopped and the collector never re-binds automatically", ErrSubjectDeleted, message, status)
	case "scope_changed":
		return fmt.Errorf("%w: %s (HTTP %d); the batch is reorganized under the live consent scope when it came from the outbox", ErrScopeChanged, message, status)
	case "outside_scope":
		return fmt.Errorf("%w: %s (HTTP %d); out-of-scope records are quarantined recoverably when the batch came from the outbox", ErrOutsideScope, message, status)
	}
	if code != "" || message != "" {
		return fmt.Errorf("sync failed: %s: %s", code, message)
	}
	return fmt.Errorf("sync failed: status %d", status)
}

// batchRecordKey extracts the recordKey of one raw submitted record.
func batchRecordKey(raw json.RawMessage) (string, error) {
	var probe struct {
		RecordKey string `json:"recordKey"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("submitted record is not valid JSON: %w", err)
	}
	return probe.RecordKey, nil
}

// reconcileReceipt checks the server receipt against the submitted batch:
//   - accepted + rejected must equal the submitted record count;
//   - len(recordErrors) must equal the rejected count;
//   - every error index must address a submitted record, and a non-empty
//     recordKey must match the record at that index.
//
// On success it returns the rejected record keys with their error codes for
// per-message confirmation. On inconsistency it returns an error and the
// caller must not change any state.
func reconcileReceipt(receipt BatchReceipt, batch BatchRequest) (map[string]string, error) {
	if receipt.AcceptedRecords+receipt.RejectedRecords != len(batch.Records) {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: %d accepted + %d rejected != %d submitted records; keeping batch pending",
			receipt.BatchID, receipt.AcceptedRecords, receipt.RejectedRecords, len(batch.Records))
	}
	if len(receipt.RecordErrors) != receipt.RejectedRecords {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: %d record errors != %d rejected records; keeping batch pending",
			receipt.BatchID, len(receipt.RecordErrors), receipt.RejectedRecords)
	}
	keys := make([]string, len(batch.Records))
	for idx, raw := range batch.Records {
		key, err := batchRecordKey(raw)
		if err != nil {
			return nil, fmt.Errorf("batch %s record %d: %w", receipt.BatchID, idx, err)
		}
		if key == "" {
			return nil, fmt.Errorf("batch %s record %d has no recordKey", receipt.BatchID, idx)
		}
		keys[idx] = key
	}
	rejectedKeys := make(map[string]string, len(receipt.RecordErrors))
	for _, recordErr := range receipt.RecordErrors {
		if recordErr.Index < 0 || recordErr.Index >= len(keys) {
			return nil, fmt.Errorf("receipt inconsistent with batch %s: record error index %d out of range for %d submitted records; keeping batch pending",
				receipt.BatchID, recordErr.Index, len(keys))
		}
		key := recordErr.RecordKey
		if key == "" {
			key = keys[recordErr.Index]
		} else if key != keys[recordErr.Index] {
			return nil, fmt.Errorf("receipt inconsistent with batch %s: record error index %d references recordKey %q but the submitted record at that index is %q; keeping batch pending",
				receipt.BatchID, recordErr.Index, recordErr.RecordKey, keys[recordErr.Index])
		}
		rejectedKeys[key] = recordErr.Code
	}
	return rejectedKeys, nil
}

const syncACKJournalFileName = "sync-ack-transaction.json"

type syncACKJournal struct {
	State          statedir.DeviceState          `json:"state"`
	FromOutbox     bool                          `json:"fromOutbox"`
	Receipt        outbox.Receipt                `json:"receipt"`
	CursorConfirm  *progress.ConfirmOptions      `json:"cursorConfirm,omitempty"`
	MessageConfirm *progress.MessageBatchConfirm `json:"messageConfirm,omitempty"`
}

func syncACKJournalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), syncACKJournalFileName)
}

func recoverPendingSyncACK(store statedir.Store, stateDir string) error {
	path := syncACKJournalPath(stateDir)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal syncACKJournal
	if err := json.Unmarshal(b, &journal); err != nil {
		return err
	}
	if err := applySyncACK(store, strings.TrimSpace(stateDir), journal); err != nil {
		return err
	}
	return os.Remove(path)
}

func commitSyncACK(store statedir.Store, stateDir string, journal syncACKJournal) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return applySyncACK(store, stateDir, journal)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	path := syncACKJournalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := applySyncACK(store, stateDir, journal); err != nil {
		return err
	}
	return os.Remove(path)
}

func applySyncACK(store statedir.Store, stateDir string, journal syncACKJournal) error {
	if err := store.Save(journal.State); err != nil {
		return err
	}
	if journal.FromOutbox {
		if err := outbox.New(stateDir).MarkSynced(journal.Receipt); err != nil {
			return err
		}
	}
	if journal.CursorConfirm != nil {
		if _, err := progress.New(stateDir).Confirm(*journal.CursorConfirm); err != nil {
			return err
		}
	}
	// Per-message progress only exists under a state directory.
	if journal.MessageConfirm != nil && strings.TrimSpace(stateDir) != "" {
		if _, err := progress.New(stateDir).ConfirmMessageBatch(*journal.MessageConfirm); err != nil {
			return err
		}
	}
	return nil
}

func loadBatch(path string, overrideBatchID string) (BatchRequest, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return BatchRequest{}, errors.New("missing batch file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return BatchRequest{}, err
	}
	var batch BatchRequest
	if err := json.Unmarshal(b, &batch); err != nil {
		return BatchRequest{}, err
	}
	if strings.TrimSpace(overrideBatchID) != "" {
		batch.BatchID = strings.TrimSpace(overrideBatchID)
	}
	batch.BatchID = strings.TrimSpace(batch.BatchID)
	if batch.BatchID == "" {
		return BatchRequest{}, errors.New("batch file missing batchId; pass --batch or include batchId")
	}
	if len(batch.Records) == 0 {
		return BatchRequest{}, errors.New("batch file must contain at least one record")
	}
	return batch, nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid server URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
