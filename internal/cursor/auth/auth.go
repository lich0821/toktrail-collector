// Package auth reads Cursor authentication credentials from local desktop
// state.
//
// Scope (current): read-only extraction of the Cursor desktop access token
// from the standard SQLite state database (state.vscdb), ItemTable keys
// "cursorAuth" and "cursorAuth/accessToken". The package:
//
//   - never reads chat, workspace, or other state tables; only the two
//     credential keys of ItemTable are queried;
//   - never copies the state database;
//   - never writes the state database, its journal files, or anything
//     else in the Cursor data directory — the database is opened through a
//     read-only SQLite URI (mode=ro) and reads fail rather than fall back
//     to a writable open. WAL-mode databases are header-sniffed and always
//     opened immutable, so SQLite cannot create -shm/-wal sidecars even
//     when a writer exits mid-read; the freshness this costs is documented
//     on sqliteReadOnlyDSN.
//
// Security properties:
//
//   - Credential secret fields (AccessToken, AccountID, AccountHint) are
//     tagged json:"-" so accidental serialization cannot leak them, and
//     Credential implements redacted String/GoString so default fmt verbs
//     (%v, %+v, %#v) and error wrapping cannot leak them either; secrets
//     exist only in memory.
//   - Every error returned by this package is redacted: messages never
//     contain filesystem paths, DSNs, SQL text, or token material, so they
//     are safe to log verbatim. Classify failures with errors.Is against
//     the Err* sentinels below, or errors.As on *ReadError.
//   - AccountHint is extracted from the unverified JWT payload of the
//     access token. Parsing a JWT payload proves nothing about identity;
//     the authoritative account id must come from the server identity
//     endpoint (a future HTTP step) and belongs in Credential.AccountID.
//
// macOS Keychain storage is not implemented yet; the Provider interface
// leaves room for a keychain-backed implementation later. This package
// performs no HTTP calls and no shell-outs (SQLite access is pure Go via
// modernc.org/sqlite).
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Credential is a Cursor authentication credential.
//
// Secret fields are in-memory only and excluded from JSON serialization.
type Credential struct {
	// AccessToken is the bearer token used to call Cursor APIs. In-memory
	// only; never serialized (json:"-").
	AccessToken string `json:"-"`
	// AccountID is the server-verified Cursor account identifier. The
	// desktop reader always leaves it empty: it must be filled in by the
	// identity-verification step (HTTP identity endpoint), never from
	// unverified local data. In-memory only; never serialized (json:"-").
	AccountID string `json:"-"`
	// AccountHint is the unverified subject claim ("sub") extracted from
	// the access token's JWT payload. It is a local disambiguation hint,
	// NOT proof of identity. In-memory only; never serialized (json:"-").
	AccountHint string `json:"-"`
	// Source identifies where the credential was read from (see the
	// Source* constants). It contains no paths or secrets.
	Source string `json:"source,omitempty"`
	// ExpiresAt is the expiry recorded in the access token's unverified
	// JWT payload. Advisory only until the token is validated server-side.
	// The zero time means "unknown".
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// HasToken reports whether the credential carries a non-blank access token.
func (c Credential) HasToken() bool {
	return strings.TrimSpace(c.AccessToken) != ""
}

// String returns a redacted, log-safe representation of the credential. It
// never contains the access token or account identifiers, only their
// presence, so fmt verbs and error wrapping cannot leak secrets.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{Source:%q HasToken:%t HasAccountID:%t HasAccountHint:%t ExpiresAt:%s}",
		c.Source, c.HasToken(), c.AccountID != "", c.AccountHint != "", c.ExpiresAt.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer so %#v is redacted exactly like
// String.
func (c Credential) GoString() string { return c.String() }

// Provider reads a Cursor credential from a storage backend.
type Provider interface {
	// Fetch returns the current credential. Implementations must return
	// redacted errors (see ReadError) and must never leak token material.
	Fetch(ctx context.Context) (Credential, error)
}

// Credential source identifiers.
const (
	// SourceDesktopSQLite identifies a credential read from the Cursor
	// desktop SQLite state database (state.vscdb).
	SourceDesktopSQLite = "cursor-desktop-sqlite"
)

// ErrorCode classifies credential read failures.
type ErrorCode string

const (
	// CodeNoLogin: no Cursor login is available — the desktop state is
	// missing, or it holds no credential (the user is not logged in).
	CodeNoLogin ErrorCode = "no_login"
	// CodePermission: the desktop state exists but cannot be read with the
	// current process permissions.
	CodePermission ErrorCode = "permission"
	// CodeUnsupportedSchema: the desktop state exists but its schema is not
	// recognized (not a SQLite database, missing ItemTable, or an auth
	// entry this package cannot interpret).
	CodeUnsupportedSchema ErrorCode = "unsupported_schema"
	// CodeUnsupportedOS: the target GOOS has no known Cursor desktop
	// layout.
	CodeUnsupportedOS ErrorCode = "unsupported_os"
	// CodeUnavailable: the desktop state could not be read for another
	// reason (I/O error, database locked in a read-only-incompatible
	// state, options missing required inputs, ...).
	CodeUnavailable ErrorCode = "unavailable"
)

// Sentinel errors for errors.Is matching. They carry no paths or secrets.
var (
	ErrNoLogin           = errors.New("cursor/auth: no cursor login")
	ErrPermission        = errors.New("cursor/auth: cursor state not readable: permission denied")
	ErrUnsupportedSchema = errors.New("cursor/auth: cursor state schema not supported")
	ErrUnsupportedOS     = errors.New("cursor/auth: unsupported operating system")
	ErrUnavailable       = errors.New("cursor/auth: cursor state unavailable")
)

// ReadError is a redacted credential-read failure. Error() output never
// contains filesystem paths, DSNs, SQL statements, or token material, so it
// is safe to log verbatim.
type ReadError struct {
	// Code classifies the failure.
	Code ErrorCode
	// Op names the failing operation (e.g. "stat", "open", "query"). It
	// never contains paths or secrets.
	Op string
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("cursor/auth: %s: %s", e.Op, e.Code)
}

// Unwrap returns the sentinel error for e.Code so callers can match with
// errors.Is(err, auth.ErrNoLogin) and friends. Underlying OS and SQLite
// errors are deliberately dropped at classification time and never exposed.
func (e *ReadError) Unwrap() error {
	switch e.Code {
	case CodeNoLogin:
		return ErrNoLogin
	case CodePermission:
		return ErrPermission
	case CodeUnsupportedSchema:
		return ErrUnsupportedSchema
	case CodeUnsupportedOS:
		return ErrUnsupportedOS
	default:
		return ErrUnavailable
	}
}
