package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver; no cgo, no shell sqlite3
)

// ItemTable keys holding the desktop credential. Only these keys are ever
// queried; chat and workspace tables are never touched.
const (
	// itemKeyCursorAuthDirect stores the access token as a plain string.
	itemKeyCursorAuthDirect = "cursorAuth/accessToken"
	// itemKeyCursorAuth stores a JSON auth object whose accessToken field
	// holds the token. It is read only when the direct key does not
	// suffice, so the wider object is not pulled when it is not needed.
	//
	// Compatibility: Cursor's ItemTable has been observed in the wild in
	// both shapes — a dedicated "cursorAuth/accessToken" string and a
	// "cursorAuth" JSON object with an accessToken field (the object also
	// carries provider and subscription fields this package ignores). The
	// fallback keeps both readable; drop it once the protocol reference
	// confirms only one shape ships.
	itemKeyCursorAuth = "cursorAuth"
)

// SQLite file header facts used to open databases without side effects.
const (
	// sqliteHeaderLen is the size of the SQLite database file header.
	sqliteHeaderLen = 100
	// File format version bytes 18 (write) and 19 (read): 1 selects a
	// rollback journal, 2 selects WAL.
	sqliteFormatVersionOffset = 18
	sqliteFormatRollback      = 1
	sqliteFormatWAL           = 2
)

var sqliteMagic = []byte("SQLite format 3\x00")

// testHookAfterDSN is a test-only seam (not concurrency-safe). When set it
// runs inside readStateDBToken after the read-only DSN has been fixed but
// before SQLite has opened any file, letting tests reproduce the race where
// the state database's sidecar files vanish between the DSN decision and
// the actual open. It is nil in production.
var testHookAfterDSN func()

// sniffJournalMode inspects a SQLite file header and reports whether the
// database is in WAL mode. Read errors are classified, never rendered.
func sniffJournalMode(header []byte) (bool, error) {
	if !bytes.Equal(header[:16], sqliteMagic) {
		return false, &ReadError{Code: CodeUnsupportedSchema, Op: "sniff"}
	}
	switch header[sqliteFormatVersionOffset] {
	case sqliteFormatRollback:
		return false, nil
	case sqliteFormatWAL:
		return true, nil
	default:
		return false, &ReadError{Code: CodeUnsupportedSchema, Op: "sniff"}
	}
}

// readStateDBToken opens the state database read-only and extracts the
// access token. It returns "" (with nil error) when no credential exists.
// walMode is the journal mode sniffed from the file header.
func readStateDBToken(ctx context.Context, path, goos string, walMode bool) (string, error) {
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path, goos, walMode))
	if err != nil {
		return "", &ReadError{Code: CodeUnavailable, Op: "open-db"}
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if testHookAfterDSN != nil {
		// Test seam only (not concurrency-safe): runs after the DSN is
		// fixed but before SQLite has opened any file, letting tests
		// shrink the DSN-decision-versus-open TOCTOU window.
		testHookAfterDSN()
	}
	// Primary path: the dedicated cursorAuth/accessToken key. Only this key
	// is read; the cursorAuth object is not touched when it suffices.
	direct, err := queryItemValue(ctx, db, itemKeyCursorAuthDirect)
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(string(direct)); token != "" {
		return token, nil
	}
	// The direct key is absent or blank; fall back to reading the
	// cursorAuth JSON object only now.
	blob, err := queryItemValue(ctx, db, itemKeyCursorAuth)
	if err != nil {
		return "", err
	}
	if len(blob) == 0 {
		return "", nil
	}
	token, err := accessTokenFromAuthBlob(blob)
	if err != nil {
		return "", &ReadError{Code: CodeUnsupportedSchema, Op: "parse"}
	}
	return token, nil
}

// queryItemValue returns the raw value stored under key in ItemTable, or nil
// when the key is absent. Values are returned as bytes regardless of the
// column affinity Cursor stored them with.
func queryItemValue(ctx context.Context, db *sql.DB, key string) ([]byte, error) {
	row := db.QueryRowContext(ctx, "SELECT value FROM ItemTable WHERE key = ?", key)
	var value any
	if err := row.Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, classifyQueryError(err)
	}
	return valueBytes(value), nil
}

func valueBytes(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case string:
		return []byte(t)
	default:
		return nil
	}
}

// accessTokenFromAuthBlob extracts the access token from the JSON value
// stored under the cursorAuth ItemTable key.
func accessTokenFromAuthBlob(blob []byte) (string, error) {
	var parsed struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(blob, &parsed); err != nil {
		return "", err
	}
	return strings.TrimSpace(parsed.AccessToken), nil
}

// classifyQueryError maps SQLite/database/sql failures onto redacted
// ReadErrors. The underlying message is inspected for classification only
// and is never included in the returned error.
func classifyQueryError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err // context errors carry no secrets
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such table"):
		// Not a Cursor state database schema.
		return &ReadError{Code: CodeUnsupportedSchema, Op: "query"}
	case strings.Contains(msg, "file is not a database"),
		strings.Contains(msg, "database disk image is malformed"),
		strings.Contains(msg, "malformed database"):
		return &ReadError{Code: CodeUnsupportedSchema, Op: "query"}
	default:
		// Includes "unable to open database file" (e.g. a live WAL
		// database whose read-only open SQLite cannot support), busy
		// locks, and anything unrecognized.
		return &ReadError{Code: CodeUnavailable, Op: "query"}
	}
}

// sqliteReadOnlyDSN builds a read-only SQLite URI DSN for the state
// database at path. walMode is the journal mode sniffed from the file
// header.
//
// mode=ro makes SQLite fail rather than create or write the database file.
// WAL-mode databases additionally get immutable=1, unconditionally:
//
//   - Strictness: with a writable directory, a plain mode=ro open of a
//     WAL database makes SQLite create -shm/-wal sidecar files. That can
//     even happen when sidecars already exist at DSN-build time, because
//     the writer may exit and delete them before SQLite actually opens
//     the files (sql.Open is lazy) — re-checking existence cannot close
//     that race. immutable=1 never locks, maps, or creates anything, so
//     the Cursor directory is never written, by construction.
//   - Freshness limitation: immutable reads only the main database file.
//     A WAL-mode database whose writer is running keeps recent commits in
//     the un-checkpointed -wal, invisible here. A credential written
//     since the last checkpoint therefore reads as missing until Cursor
//     closes and checkpoints — typically fixed by the next collection
//     run. A crash-leftover -wal is likewise ignored, and a concurrent
//     write during the read can surface as a redacted
//     unsupported_schema/unavailable error instead of stale success.
//
// Rollback-journal databases keep plain mode=ro: reads never journal and
// committed data is always in the main file.
//
// URI characters that would corrupt parsing are percent-encoded; on
// windows, native separators are normalized to "/" (SQLite converts them
// back to the platform separator).
func sqliteReadOnlyDSN(path, goos string, walMode bool) string {
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case goos == "windows" && c == '\\':
			b.WriteByte('/')
		case c == '%' || c == '?' || c == '#' || c == ' ':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("?mode=ro")
	if walMode {
		b.WriteString("&immutable=1")
	}
	return b.String()
}
