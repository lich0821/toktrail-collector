// Package accountsource talks to the TokTrail server account-source
// control endpoint: the old-server capability gate (RequireCapability —
// CLI enable must detect unsupported servers itself, not rely on website
// gating) and the device-authenticated enable call that creates the
// cursor source instance and CAS-binds this device as its executor (the
// server only binds when the executor slot is empty — it never takes
// over an existing executor, and neither does the collector).
package accountsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
)

// ErrExecutorConflict: another device already collects this account source.
// Resolution is a website-side reassignment; the collector never claims a
// taken executor slot.
var ErrExecutorConflict = errors.New("another device is the executor of this cursor account source")

const maxResponseBytes = 1 << 20

// Options configures the enable request.
type Options struct {
	ServerURL  string
	HTTPClient *http.Client
	// DeviceID/DeviceSecret are the existing bound-device credentials.
	DeviceID, DeviceSecret string
	// ConsentRevision is the live device consent revision echoed as
	// X-Consent-Revision.
	ConsentRevision int64
}

type enableResponse struct {
	Source *protocol.Source `json:"source,omitempty"`
	// Error.Message is parsed for shape compatibility only: it is
	// untrusted server free text and is never echoed into errors.
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Enable asks the server to create (or CAS-bind, executor slot empty) the
// account source of sourceType for the authenticated device. The response
// carries the authoritative source metadata: sourceInstanceId, state,
// fenceVersion and nextRevision (subject+sourceType MAX alive revision +
// 1, continued across source recreation, reset to 1 only by deleteData).
func Enable(ctx context.Context, opt Options, sourceType string) (protocol.Source, error) {
	endpoint, err := joinURL(opt.ServerURL, "/v1/account-sources/enable")
	if err != nil {
		return protocol.Source{}, err
	}
	payload, err := json.Marshal(struct {
		SourceType string `json:"sourceType"`
	}{SourceType: sourceType})
	if err != nil {
		return protocol.Source{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return protocol.Source{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(opt.ConsentRevision, 10))
	resp, err := client(opt).Do(req)
	if err != nil {
		return protocol.Source{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return protocol.Source{}, err
	}
	if len(body) > maxResponseBytes {
		return protocol.Source{}, errors.New("account-source response exceeds 1 MB limit")
	}
	var r enableResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return protocol.Source{}, fmt.Errorf("invalid account-source response HTTP %d", resp.StatusCode)
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		if r.Source == nil || strings.TrimSpace(r.Source.SourceInstanceID) == "" {
			return protocol.Source{}, fmt.Errorf("account-source response HTTP %d carries no source", resp.StatusCode)
		}
		return *r.Source, nil
	case resp.StatusCode == http.StatusConflict:
		return protocol.Source{}, ErrExecutorConflict
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return protocol.Source{}, fmt.Errorf("account-source enable rejected: HTTP %d code=%q", resp.StatusCode, errorCode(r))
	}
	// The server's free-text message is untrusted echo data and is
	// deliberately not included in the error.
	return protocol.Source{}, fmt.Errorf("account-source enable failed: HTTP %d code=%q", resp.StatusCode, errorCode(r))
}

func errorCode(r enableResponse) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// CapabilityAccountSources is the server capability feature gating the
// account-level source protocol (enable + source-batch ingest).
const CapabilityAccountSources = "account-sources"

// maxCapabilityBytes bounds the capabilities document: it is a small
// feature list, never a data payload.
const maxCapabilityBytes = 64 << 10

// RequireCapability verifies the server speaks the account-sources
// protocol BEFORE the collector reads the Cursor desktop credential: GET
// /v1/capabilities must answer 200 with a features list containing
// "account-sources". Old servers answer 404 or omit the feature and can
// never store cursor records, so callers stop instead of pointlessly
// reading (and live-verifying) the desktop login against them. The probe
// is fail-closed on every unverifiable outcome (non-200, malformed or
// oversized document, transport error, timeout), never follows redirects
// (the Authorization header cannot leak to another host), and attaches no
// Cursor credential — only the device credentials, when present.
func RequireCapability(ctx context.Context, opt Options) error {
	endpoint, err := joinURL(opt.ServerURL, "/v1/capabilities")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if opt.DeviceID != "" && opt.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+opt.DeviceID+"."+opt.DeviceSecret)
	}
	resp, err := client(opt).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCapabilityBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxCapabilityBytes {
		return errors.New("account-source capabilities response exceeds size limit")
	}
	var caps struct {
		Features []string `json:"features"`
		Error    *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &caps); err != nil {
		return fmt.Errorf("invalid account-source capabilities response HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		code := ""
		if caps.Error != nil {
			code = caps.Error.Code
		}
		return fmt.Errorf("account-source capabilities check failed: HTTP %d code=%q", resp.StatusCode, code)
	}
	for _, f := range caps.Features {
		if strings.TrimSpace(f) == CapabilityAccountSources {
			return nil
		}
	}
	return fmt.Errorf("server does not support %s (feature missing from /v1/capabilities)", CapabilityAccountSources)
}

// client clones the configured client into one that never follows
// redirects and always carries a bounded timeout, so the device
// Authorization header cannot leak to another host and a hung server
// cannot stall an enable or capability probe.
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
