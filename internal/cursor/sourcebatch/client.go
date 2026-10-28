// Package sourcebatch uploads account-level cursor source batches to the
// TokTrail server ingest endpoint. It is deliberately separate from the
// device-batch syncclient: cursor records never travel to
// /v1/ingest/batches, and every request carries the source fence
// (X-Source-Fence) alongside the device authorization and the live
// consent revision.
//
// Security properties:
//
//   - the HTTP client never follows redirects (a cloned client with a
//     refusing CheckRedirect), so the device Authorization header can
//     never leak to another host;
//   - receipts are strictly validated (batch id match, the server's
//     accepted/rejected/partial_error status enum — which the server
//     derives from the record counts, so a status that disagrees with
//     the counts is invalid — non-negative counts covering every record,
//     non-zero receivedAt, in-range record error indexes) before they
//     are treated as an acknowledgment — a rejected or partial_error
//     receipt carries its indexed record errors and is NEVER a full
//     acknowledgment;
//   - error messages never echo server-provided message text (untrusted
//     data); only stable codes and HTTP statuses travel.
package sourcebatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
)

// Sentinel errors for actionable sync behavior (server wire codes:
// source_fence_changed, scope_changed, source_paused, source_deleted —
// plus the defensive aliases consent_revision_stale and stale_revision).
var (
	// ErrFenceStale: the server moved the source fence; the caller must
	// stop sending and re-fetch the self view (old pending batches are
	// fenced out, never re-sent).
	ErrFenceStale = errors.New("cursor source fence changed")
	// ErrConsentStale: the consent revision advanced; re-fetch and retry.
	ErrConsentStale = errors.New("consent revision is stale")
	// ErrSourcePaused: the server paused the account source; batches stay
	// pending and the next run re-checks the source state.
	ErrSourcePaused = errors.New("cursor source is paused server-side")
	// ErrSourceDeleted: the server deleted the account source; the next
	// self refresh will no longer list it.
	ErrSourceDeleted = errors.New("cursor source was deleted server-side")
	// ErrStaleRevision: the batch carries event revisions at or below the
	// facts the server already stores (obsolete replay). The batch is not
	// re-sent as-is; recovery is a nextRevision refresh followed by new
	// rounds.
	ErrStaleRevision = errors.New("cursor batch revisions are stale")
	// ErrDeviceUnauthorized: the device credentials were rejected.
	ErrDeviceUnauthorized = errors.New("device authorization rejected")
	// ErrInvalidReceipt: the server answered 2xx with a receipt that does
	// not strictly validate; never treated as success.
	ErrInvalidReceipt = errors.New("invalid source-batch receipt")
)

const maxResponseBytes = 1 << 20

// RecordError is one server-rejected record with its index in the batch.
// The reason code is a stable server code; the server's free-text detail
// and recordKey fields are deliberately not modeled, so untrusted text
// never enters the collector.
type RecordError struct {
	Index int    `json:"index"`
	Code  string `json:"code,omitempty"`
}

// Receipt mirrors the device-batch ingest receipt shape
// (internal/syncclient.BatchReceipt) so the server can reuse the format,
// extended with indexed record errors for partial acknowledgments. The
// status is exactly the server's accepted / rejected / partial_error enum
// (the server derives it from the counts); a re-sent duplicate keeps its
// original status and sets Replay.
type Receipt struct {
	BatchID         string        `json:"batchId"`
	Status          string        `json:"status"`
	AcceptedRecords int           `json:"acceptedRecords"`
	RejectedRecords int           `json:"rejectedRecords"`
	Replay          bool          `json:"replay"`
	ReceivedAt      time.Time     `json:"receivedAt"`
	RecordErrors    []RecordError `json:"recordErrors,omitempty"`
}

// Options configures one request set.
type Options struct {
	ServerURL  string
	HTTPClient *http.Client
	// DeviceID/DeviceSecret are the existing bound-device credentials;
	// account sources ride the device authentication.
	DeviceID, DeviceSecret string
	SourceInstanceID       string
}

type response struct {
	Batch *struct {
		BatchID         string        `json:"batchId"`
		Status          string        `json:"status"`
		AcceptedRecords int           `json:"acceptedRecords"`
		RejectedRecords int           `json:"rejectedRecords"`
		Replay          bool          `json:"replay"`
		ReceivedAt      time.Time     `json:"receivedAt"`
		RecordErrors    []RecordError `json:"recordErrors,omitempty"`
	} `json:"batch,omitempty"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// expectedReceiptStatus mirrors the server's usage.ReceiptStatus
// derivation: no rejections → accepted, every record rejected →
// rejected, some of each → partial_error. A receipt whose status
// disagrees with what its counts imply is invalid.
func expectedReceiptStatus(accepted, rejected int) string {
	switch {
	case rejected == 0:
		return "accepted"
	case accepted == 0:
		return "rejected"
	default:
		return "partial_error"
	}
}

// validateReceipt strictly checks a 2xx receipt against the uploaded
// batch: the batch id must match, the status must be one of the server's
// accepted/rejected/partial_error enum and consistent with the record
// counts, counts must be non-negative, and receivedAt must be present.
// For a POST (recordCount >= 0) the counts must cover every record and
// every record error index must fall inside the batch; a GET receipt
// (recordCount < 0 — the server replays the stored receipt without the
// batch) skips only those two coverage checks. Receipts with rejected
// records (rejected / partial_error) validate and carry their indexed
// record errors: they are NEVER a full acknowledgment, and the caller
// must keep the batch pending (cursoroutbox.MarkSynced refuses them).
func validateReceipt(r *Receipt, batchID string, recordCount int) error {
	if r.BatchID != batchID {
		return fmt.Errorf("%w: receipt names batch %q, uploaded %q", ErrInvalidReceipt, r.BatchID, batchID)
	}
	if r.AcceptedRecords < 0 || r.RejectedRecords < 0 {
		return fmt.Errorf("%w: negative record counts", ErrInvalidReceipt)
	}
	switch r.Status {
	case "accepted", "rejected", "partial_error":
		if want := expectedReceiptStatus(r.AcceptedRecords, r.RejectedRecords); r.Status != want {
			return fmt.Errorf("%w: receipt status %q disagrees with accepted %d / rejected %d records", ErrInvalidReceipt, r.Status, r.AcceptedRecords, r.RejectedRecords)
		}
	default:
		return fmt.Errorf("%w: unknown receipt status %q", ErrInvalidReceipt, r.Status)
	}
	if recordCount >= 0 {
		if r.AcceptedRecords+r.RejectedRecords != recordCount {
			return fmt.Errorf("%w: accepted %d + rejected %d != %d records", ErrInvalidReceipt, r.AcceptedRecords, r.RejectedRecords, recordCount)
		}
		for _, re := range r.RecordErrors {
			if re.Index < 0 || re.Index >= recordCount {
				return fmt.Errorf("%w: record error index %d out of range", ErrInvalidReceipt, re.Index)
			}
		}
	} else {
		// GET: the record count is unknown, so only the index sign is
		// checkable; coverage cannot be re-verified.
		for _, re := range r.RecordErrors {
			if re.Index < 0 {
				return fmt.Errorf("%w: record error index %d out of range", ErrInvalidReceipt, re.Index)
			}
		}
	}
	if r.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: missing receivedAt", ErrInvalidReceipt)
	}
	return nil
}

// PostBatch uploads one validated batch. fenceVersion is the current
// source fence from the live self view; consentRevision is the live
// device consent revision. The body is the exact immutable outbox bytes
// (already protocol-encoded), re-validated here before transmission.
func PostBatch(ctx context.Context, opt Options, encoded []byte, fenceVersion, consentRevision int64) (cursoroutbox.Receipt, error) {
	batch, err := protocol.DecodeBatch(encoded)
	if err != nil {
		return cursoroutbox.Receipt{}, fmt.Errorf("refusing to upload unvalidated cursor batch: %w", err)
	}
	if batch.SourceInstanceID != opt.SourceInstanceID {
		return cursoroutbox.Receipt{}, fmt.Errorf("cursor batch %s belongs to source %s, not %s", batch.BatchID, batch.SourceInstanceID, opt.SourceInstanceID)
	}
	endpoint, err := joinURL(opt.ServerURL, "/v1/ingest/source-batches")
	if err != nil {
		return cursoroutbox.Receipt{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return cursoroutbox.Receipt{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Source-Fence", strconv.FormatInt(fenceVersion, 10))
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(consentRevision, 10))
	resp, err := client(opt).Do(req)
	if err != nil {
		return cursoroutbox.Receipt{}, err
	}
	defer resp.Body.Close()
	receipt, err := decodeReceipt(resp, batch.BatchID, len(batch.Records))
	if err != nil {
		return cursoroutbox.Receipt{}, err
	}
	return toStoreReceipt(receipt), nil
}

// GetBatch fetches the server-side receipt of one previously uploaded
// batch, carrying the current consent revision and source fence like the
// POST. It reports whether the server knows the batch.
func GetBatch(ctx context.Context, opt Options, batchID string, fenceVersion, consentRevision int64) (cursoroutbox.Receipt, bool, error) {
	endpoint, err := joinURL(opt.ServerURL, "/v1/ingest/source-batches/"+url.PathEscape(batchID))
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Source-Fence", strconv.FormatInt(fenceVersion, 10))
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(consentRevision, 10))
	q := req.URL.Query()
	q.Set("sourceInstanceId", opt.SourceInstanceID)
	req.URL.RawQuery = q.Encode()
	resp, err := client(opt).Do(req)
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return cursoroutbox.Receipt{}, false, nil
	}
	// A GET receipt is validated against the batch identity only: the
	// server replays the stored receipt (with its real counts and record
	// errors) but not the batch, so count coverage and the record error
	// index upper bound cannot be re-checked.
	receipt, err := decodeReceipt(resp, batchID, -1)
	if err != nil {
		return cursoroutbox.Receipt{}, false, err
	}
	return toStoreReceipt(receipt), true, nil
}

// sanitizeRecordErrors keeps the index and the stable reason code of
// each server-rejected record, but only for codes on the server's known
// safe list (stale_revision, record_conflict and the invalid_* family);
// every other code collapses to the generic record_rejected so untrusted
// server text can never ride into store receipts or diagnostics. The
// server's free-text message is never parsed at all.
func sanitizeRecordErrors(errs []RecordError) []cursoroutbox.RecordError {
	if len(errs) == 0 {
		return nil
	}
	out := make([]cursoroutbox.RecordError, 0, len(errs))
	for _, re := range errs {
		code := "record_rejected"
		switch re.Code {
		case "stale_revision", "record_conflict", "invalid_event_key", "invalid_revision", "invalid_kind", "invalid_time", "invalid_tool", "invalid_adapter_version", "invalid_source_type", "invalid_model", "invalid_decimal":
			code = re.Code
		}
		out = append(out, cursoroutbox.RecordError{Index: re.Index, Code: code})
	}
	return out
}

func toStoreReceipt(r Receipt) cursoroutbox.Receipt {
	return cursoroutbox.Receipt{
		BatchID:         r.BatchID,
		Status:          r.Status,
		AcceptedRecords: r.AcceptedRecords,
		RejectedRecords: r.RejectedRecords,
		Replay:          r.Replay,
		ReceivedAt:      r.ReceivedAt,
		RecordErrors:    sanitizeRecordErrors(r.RecordErrors),
	}
}

func decodeReceipt(resp *http.Response, batchID string, recordCount int) (Receipt, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Receipt{}, err
	}
	if len(body) > maxResponseBytes {
		return Receipt{}, errors.New("source-batch response exceeds 1 MB limit")
	}
	var r response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		if err := json.Unmarshal(body, &r); err != nil || r.Batch == nil {
			return Receipt{}, fmt.Errorf("%w: HTTP %d carries no receipt", ErrInvalidReceipt, resp.StatusCode)
		}
		receipt := Receipt{
			BatchID:         r.Batch.BatchID,
			Status:          r.Batch.Status,
			AcceptedRecords: r.Batch.AcceptedRecords,
			RejectedRecords: r.Batch.RejectedRecords,
			Replay:          r.Batch.Replay,
			ReceivedAt:      r.Batch.ReceivedAt,
			RecordErrors:    r.Batch.RecordErrors,
		}
		if err := validateReceipt(&receipt, batchID, recordCount); err != nil {
			return Receipt{}, err
		}
		return receipt, nil
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Receipt{}, fmt.Errorf("source-batch request failed: HTTP %d", resp.StatusCode)
	}
	code := ""
	if r.Error != nil {
		code = r.Error.Code
	}
	switch {
	case code == "stale_revision":
		return Receipt{}, ErrStaleRevision
	case code == "source_fence_changed":
		return Receipt{}, ErrFenceStale
	case code == "source_paused":
		return Receipt{}, ErrSourcePaused
	case code == "source_deleted":
		return Receipt{}, ErrSourceDeleted
	case code == "scope_changed":
		// The server's actual wire code for a stale consent revision
		// (it carries the authoritative currentConsentRevision).
		return Receipt{}, ErrConsentStale
	case code == "consent_revision_stale":
		// Defensive alias kept for forward compatibility.
		return Receipt{}, ErrConsentStale
	case resp.StatusCode == http.StatusUnauthorized:
		return Receipt{}, fmt.Errorf("%w (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden:
		return Receipt{}, fmt.Errorf("%w (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	}
	// The server's free-text message is untrusted echo data and is
	// deliberately not included in the error.
	return Receipt{}, fmt.Errorf("source-batch request failed: HTTP %d code=%q", resp.StatusCode, code)
}

// client clones the configured client into one that never follows
// redirects, so the Authorization header cannot leak to another host.
func client(opt Options) *http.Client {
	base := &http.Client{}
	if opt.HTTPClient != nil {
		*base = *opt.HTTPClient
	}
	if base.Timeout <= 0 || base.Timeout > 60*time.Second {
		base.Timeout = 15 * time.Second
	}
	base.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return base
}

func joinURL(base, path string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "", errors.New("server URL is required")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path, nil
}
