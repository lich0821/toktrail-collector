package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

// Grant-ack protocol (server-confirmed):
//
//	POST /v1/devices/grant-ack   (device bearer credentials)
//	  {"consentRevision": N, "collectorVersion": "vX.Y.Z[-pre]"?}
//	  -> {"grantAck": {"consentRevision": N, "currentConsentRevision": M,
//	                   "collectorVersion"?: string, "ackedAt": time}}
//
// The ack is the device's "actually applied" receipt for a consent
// revision. Callers must only send it after the revision's grant scope has
// been fully applied locally, and must treat an echo mismatch as a failed
// ack. currentConsentRevision greater than the acked revision means the
// server has moved on; the caller should re-fetch and re-apply instead of
// reading under the stale revision.

// GrantAckRequest is the grant-ack POST body. ApplyState reports whether
// the revision is fully applied ("applied", the default when omitted) or
// applied with restrictions ("pending": an allowed tool is unknown, its
// default directory is missing, or its grant is manually disabled). The
// server uses it to keep the device UI honest about the CURRENT state
// instead of an earlier full ack. CollectorVersion is optional and only
// included when it is a strict SemVer string (the build-injected "dev" or
// unknown values are omitted, never faked). The body never contains local
// paths or any other sensitive information.
type GrantAckRequest struct {
	ConsentRevision  int64  `json:"consentRevision"`
	ApplyState       string `json:"applyState,omitempty"`
	CollectorVersion string `json:"collectorVersion,omitempty"`
}

// GrantAck is the server's receipt for one acknowledged revision.
type GrantAck struct {
	ConsentRevision        int64 `json:"consentRevision"`
	CurrentConsentRevision int64 `json:"currentConsentRevision"`
	// AckedState is the server's echo of the acknowledged state under the
	// receipt field name "ackedState" (the REQUEST field is applyState).
	// An absent field is backward-compatible with "applied" only; a
	// pending request never counts as confirmed by an absent echo.
	AckedState       string    `json:"ackedState,omitempty"`
	CollectorVersion string    `json:"collectorVersion,omitempty"`
	AckedAt          time.Time `json:"ackedAt"`
}

type grantAckResponse struct {
	GrantAck *GrantAck `json:"grantAck,omitempty"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Ack error sentinels. ErrAckRevisionAdvanced means the server moved past
// the acked revision (409 scope_changed or a future-revision echo): the
// applied view may be stale and callers must re-fetch instead of reading
// under it. ErrAckEchoMismatch means the server confirmed an unexpected
// revision or state: the ack bookkeeping is unclear and callers should
// conservatively stop. Transport-level failures carry neither sentinel —
// the freshly fetched view remains this run's authorization and only the
// receipt is missing.
var (
	ErrAckRevisionAdvanced = errors.New("grant_ack_revision_advanced")
	ErrAckEchoMismatch     = errors.New("grant_ack_echo_mismatch")
)

// maxCollectorVersionLen bounds the optional collector version echo.
const maxCollectorVersionLen = 64

// strictSemVerRegex matches exactly vX.Y.Z with an optional SemVer
// prerelease; "dev", empty, and other non-release identifiers are rejected
// so the ack never claims a release version the build cannot prove.
var strictSemVerRegex = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// ValidCollectorVersion reports whether v is a strict SemVer release string
// suitable for the optional ack field.
func ValidCollectorVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && len(v) <= maxCollectorVersionLen && strictSemVerRegex.MatchString(v)
}

// ReportGrantAck acknowledges that the device applied the given consent
// revision. The server must echo the same revision in grantAck.consentRevision;
// anything else is a failed ack (an old revision's ack must never stand in
// for a newer one). A nil GrantAck result with a nil error never happens:
// either the ack is confirmed or an error explains why it was not.
func ReportGrantAck(ctx context.Context, store statedir.Store, opt Options, req GrantAckRequest) (GrantAck, error) {
	if req.ConsentRevision <= 0 {
		return GrantAck{}, fmt.Errorf("grant ack requires a positive consentRevision, got %d", req.ConsentRevision)
	}
	switch req.ApplyState {
	case "", "applied", "pending":
	default:
		return GrantAck{}, fmt.Errorf("grant ack applyState must be \"applied\" or \"pending\", got %q", req.ApplyState)
	}
	if req.CollectorVersion != "" && !ValidCollectorVersion(req.CollectorVersion) {
		return GrantAck{}, errors.New("grant ack collectorVersion must be a strict semver release string or omitted")
	}
	st, err := store.Load()
	if err != nil {
		return GrantAck{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return GrantAck{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		return GrantAck{}, errors.New("server URL is required")
	}
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	endpoint, err := joinURL(serverURL, "/v1/devices/grant-ack")
	if err != nil {
		return GrantAck{}, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return GrantAck{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return GrantAck{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	resp, err := client.Do(httpReq)
	if err != nil {
		return GrantAck{}, fmt.Errorf("grant ack failed: %w", err)
	}
	defer resp.Body.Close()
	var body grantAckResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return GrantAck{}, fmt.Errorf("grant ack failed: status %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return GrantAck{}, fmt.Errorf("grant ack endpoint not available (HTTP %d); the ack will be retried on the next run", resp.StatusCode)
		}
		code, message := "", ""
		if body.Error != nil {
			code, message = body.Error.Code, body.Error.Message
		}
		if resp.StatusCode == http.StatusConflict && code == "scope_changed" {
			return GrantAck{}, fmt.Errorf("%w: the server's consent revision moved past %d before the ack; the applied view may be stale", ErrAckRevisionAdvanced, req.ConsentRevision)
		}
		return GrantAck{}, classifyIngestError(resp.StatusCode, code, message)
	}
	if body.GrantAck == nil {
		return GrantAck{}, errors.New("grant ack response missing grantAck")
	}
	if body.GrantAck.ConsentRevision > req.ConsentRevision {
		return GrantAck{}, fmt.Errorf("%w: the server confirmed revision %d while %d was acked; the applied view may be stale", ErrAckRevisionAdvanced, body.GrantAck.ConsentRevision, req.ConsentRevision)
	}
	if body.GrantAck.ConsentRevision != req.ConsentRevision {
		return GrantAck{}, fmt.Errorf("%w: acked %d but server confirmed %d; the ack is not recorded and the revision state is unclear", ErrAckEchoMismatch, req.ConsentRevision, body.GrantAck.ConsentRevision)
	}
	requested := req.ApplyState
	if requested == "" {
		requested = "applied"
	}
	echoed := body.GrantAck.AckedState
	if echoed == "" {
		echoed = "applied"
	}
	if echoed != requested {
		return GrantAck{}, fmt.Errorf("%w: requested state %q but server confirmed %q; the ack is not recorded and the state is unclear", ErrAckEchoMismatch, requested, echoed)
	}
	return *body.GrantAck, nil
}
