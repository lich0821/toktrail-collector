package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// accountIDPattern is the TokTrail policy for a real high-entropy Cursor
// account id: "user_" followed by at least eight alphanumeric/underscore
// characters. The reference accepts any non-empty suffix; TokTrail rejects
// trivially weak ids rather than guess an account.
var accountIDPattern = regexp.MustCompile(`^user_[A-Za-z0-9_]{8,}$`)

// VerifyResult is the outcome of VerifySession.
type VerifyResult struct {
	// AccountID is the stable account id ("user_…") derived from the
	// credential's JWT sub claim. It is stable across token rotation: a
	// refreshed token with the same sub maps to the same account.
	AccountID string `json:"accountID"`
	// SessionToken is the normalized WorkosCursorSessionToken cookie value
	// ("{user_id}%3A%3A{jwt}") that Cursor accepted live. It is a
	// credential: it never serializes to JSON and renders redacted.
	SessionToken string `json:"-"`
	// Summary is the billing-window proof that Cursor accepted the session.
	Summary *UsageSummary `json:"summary,omitempty"`
}

// String renders the result with the session token redacted.
func (r VerifyResult) String() string {
	token := "[REDACTED]"
	if r.SessionToken == "" {
		token = ""
	}
	return fmt.Sprintf("api.VerifyResult{AccountID:%s SessionToken:%s}", r.AccountID, token)
}

// GoString renders the result with the session token redacted.
func (r VerifyResult) GoString() string {
	return r.String()
}

// VerifySession validates one Cursor credential end to end and returns the
// stable account id it belongs to.
//
// The credential may be a full session cookie value
// ("{user_id}%3A%3A{jwt}", "%3A%3A" being URL-encoded "::"; a literal "::"
// is tolerated) or a bare desktop access token JWT (state.vscdb
// cursorAuth/accessToken), mirroring tokscale's extract_user_id_from_session_token
// and user_id_from_access_token_jwt.
//
// Flow, with the trust boundary of each step:
//
//  1. The stable account id is derived locally from the JWT sub claim
//     (format "auth0|user_…"). The JWT payload is decoded, NOT
//     signature-verified — no Cursor public key is available to the
//     reference implementation either. This step binds the cookie prefix to
//     the token payload: a cookie whose prefix differs from the id its own
//     JWT carries is rejected before any network call.
//  2. The session is proven live: GET /api/usage-summary with the
//     assembled cookie must return 200 with a billingCycleStart /
//     billingCycleEnd window (tokscale's validate_cursor_session rule).
//     401/403 maps to ErrSessionExpired.
//
// Trust boundary: Cursor verifies that the session token works, but no
// user-identity endpoint exists in the reference protocol and the summary
// response carries no identity fields, so the AccountID is a locally
// derived stable identifier — NOT a Cursor-attested proof of user
// identity. Callers must not present it as one.
//
// Token rotation keeps the account: a different session token with the
// same sub verifies to the same AccountID.
func (c *Client) VerifySession(ctx context.Context, credential string) (VerifyResult, error) {
	var result VerifyResult
	trimmed := strings.TrimSpace(credential)
	if trimmed == "" {
		return result, errors.New("cursor api: credential is empty")
	}

	prefix, jwt, hasPrefix := splitCredential(trimmed)
	accountID, err := accountIDFromJWT(jwt)
	if err != nil {
		return result, err
	}
	if hasPrefix && prefix != accountID {
		// The cookie claims a different account than its own token does;
		// reject before anything leaves the machine.
		return result, errors.New("cursor api: credential cookie prefix does not match its token subject")
	}
	sessionToken := accountID + "%3A%3A" + jwt

	summary, err := c.FetchUsageSummary(ctx, Session{Token: sessionToken})
	if err != nil {
		if errors.Is(err, ErrSessionExpired) {
			return result, fmt.Errorf("cursor api: credential was rejected by Cursor: %w", err)
		}
		return result, fmt.Errorf("cursor api: could not verify credential with Cursor: %w", err)
	}
	result.AccountID = accountID
	result.SessionToken = sessionToken
	result.Summary = summary
	return result, nil
}

// splitCredential splits a cookie-form credential into its user-id prefix
// and JWT. A bare JWT yields hasPrefix=false.
func splitCredential(credential string) (prefix, jwt string, hasPrefix bool) {
	if idx := strings.Index(credential, "%3A%3A"); idx > 0 {
		return strings.TrimSpace(credential[:idx]), strings.TrimSpace(credential[idx+len("%3A%3A"):]), true
	}
	if idx := strings.Index(credential, "::"); idx > 0 {
		return strings.TrimSpace(credential[:idx]), strings.TrimSpace(credential[idx+2:]), true
	}
	return "", credential, false
}

// accountIDFromJWT decodes the JWT payload (base64url, padding tolerated)
// and extracts the "user_…" id from the sub claim, mirroring the
// reference's user_id_from_access_token_jwt extraction. Error messages
// never echo the credential.
func accountIDFromJWT(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return "", errors.New("cursor api: credential is not a valid JWT")
	}
	payload := parts[1]
	bytes, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		bytes, err = base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			return "", errors.New("cursor api: credential JWT payload is not valid base64url")
		}
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &claims); err != nil || claims == nil {
		return "", errors.New("cursor api: credential JWT payload is not a JSON object")
	}
	sub, err := strictString("sub", claims["sub"])
	if err != nil || sub == "" {
		return "", errors.New("cursor api: credential JWT has no sub claim")
	}
	// Take the "user_…" run inside the sub (e.g. "auth0|user_abc"), stopping
	// at the first character that cannot be part of the id.
	idx := strings.Index(sub, "user_")
	if idx < 0 {
		return "", errors.New("cursor api: cannot derive a user id from the credential JWT sub claim")
	}
	run := sub[idx:]
	end := len(run)
	for i := 0; i < len(run); i++ {
		c := run[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			end = i
			break
		}
	}
	id := run[:end]
	if !accountIDPattern.MatchString(id) {
		return "", errors.New("cursor api: credential user id is not a real high-entropy account id")
	}
	return id, nil
}
