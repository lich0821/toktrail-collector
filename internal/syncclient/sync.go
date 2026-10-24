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
)

type Options struct {
	ServerURL  string
	StateDir   string
	BatchFile  string
	BatchID    string
	HTTPClient *http.Client
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
	BatchID string            `json:"batchId"`
	Records []json.RawMessage `json:"records"`
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
type SelfStatus struct {
	DeviceID         string     `json:"deviceId"`
	ConsentRevision  int64      `json:"consentRevision"`
	HistoryFrom      *time.Time `json:"historyFrom,omitempty"`
	UploadUntil      *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools     []string   `json:"allowedTools,omitempty"`
	ProductionBound  bool       `json:"productionBound,omitempty"`
	UploadAuthorized bool       `json:"uploadAuthorized"`
	Revoked          bool       `json:"revoked"`
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
				return Result{}, fmt.Errorf("missing batch file and no pending outbox batch; %d quarantined record(s) remain outside the consent scope and need a strictly newer consent revision before they can be recovered", len(entries))
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
	batch, err := loadBatch(batchFile, opt.BatchID)
	if err != nil {
		return Result{}, err
	}
	// Privacy gate before any state change or HTTP traffic: a pre-fix
	// batch (extra fields, private model) must never leave the device, so
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

// preflightSelf refreshes the device's live authorization snapshot via
// GET /v1/devices/self before any upload. It returns the snapshot whose
// ConsentRevision must be echoed on the ingest POST. Terminal conditions
// (device revoked, subject deleted) return wrapped ErrDeviceRevoked /
// ErrSubjectDeleted so callers stop sending; the collector never re-binds
// automatically. Any other failure is a plain error: the batch stays
// pending and the next sync run retries after a fresh preflight.
func preflightSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState) (SelfStatus, error) {
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
		return SelfStatus{}, fmt.Errorf("device self check failed: status %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode == http.StatusOK {
		if body.Device == nil {
			return SelfStatus{}, errors.New("device self check response missing device status")
		}
		if body.Device.Revoked || !body.Device.UploadAuthorized {
			return SelfStatus{}, fmt.Errorf("%w: server reports device %s is no longer authorized to upload; sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, body.Device.DeviceID)
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
	if code != "" || message != "" {
		return SelfStatus{}, fmt.Errorf("device self check failed: status %d: %s: %s", resp.StatusCode, code, message)
	}
	return SelfStatus{}, fmt.Errorf("device self check failed: status %d", resp.StatusCode)
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
