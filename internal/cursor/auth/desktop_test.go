package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// syntheticOptions builds hermetic Options for the HOST goos: every base
// directory is pinned inside home, so no host environment variable or real
// Cursor data is ever consulted.
func syntheticOptions(home string) Options {
	return Options{
		HomeDir:       home,
		GOOS:          runtime.GOOS,
		AppData:       filepath.Join(home, "AppData", "Roaming"),
		XDGConfigHome: filepath.Join(home, ".config"),
	}
}

// newSyntheticState creates a synthetic Cursor home directory containing a
// state.vscdb whose ItemTable holds rows. Everything lives under
// t.TempDir(); no real Cursor data is ever touched.
func newSyntheticState(t *testing.T, rows map[string]any) (Options, string) {
	t.Helper()
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	createSyntheticStateDB(t, path, rows)
	return opts, path
}

// createSyntheticStateDB creates a synthetic state.vscdb (read-write, on a
// file the test owns) with the VS Code ItemTable schema.
func createSyntheticStateDB(t *testing.T, path string, rows map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	for key, value := range rows {
		if _, err := db.Exec(`INSERT INTO ItemTable (key, value) VALUES (?, ?)`, key, value); err != nil {
			t.Fatal(err)
		}
	}
}

func fileSum(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestFetchDirectKey(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-direct-token"),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-direct-token" || !cred.HasToken() {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if cred.Source != SourceDesktopSQLite {
		t.Fatalf("unexpected source: %q", cred.Source)
	}
}

func TestFetchDirectKeyStoredAsText(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: "synthetic-text-token",
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-text-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
}

func TestFetchBlobFallback(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuth: []byte(`{"accessToken":"synthetic-blob-token","lastProvider":"auth0","subscriptionStatus":{}}`),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-blob-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
}

func TestFetchPrefersDirectKeyOverBlob(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-direct-token"),
		itemKeyCursorAuth:       []byte(`{"accessToken":"synthetic-blob-token"}`),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-direct-token" {
		t.Fatalf("expected direct key to win, got: %s", cred)
	}
}

func TestFetchBlobFallbackWhenDirectBlank(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("   "),
		itemKeyCursorAuth:       []byte(`{"accessToken":"synthetic-blob-token"}`),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-blob-token" {
		t.Fatalf("expected blob fallback, got: %s", cred)
	}
}

func TestFetchUnverifiedHintFromJWT(t *testing.T) {
	token := syntheticJWT(t, `{"sub":"user_synthetic123","exp":1893456000}`)
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte(token),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != token {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if cred.AccountHint != "user_synthetic123" {
		t.Fatalf("unexpected account hint: %q", cred.AccountHint)
	}
	if cred.AccountID != "" {
		t.Fatal("AccountID must stay empty until the server identity endpoint verifies it")
	}
	if cred.ExpiresAt.Unix() != 1893456000 {
		t.Fatalf("unexpected expiry: %v", cred.ExpiresAt)
	}
}

func TestFetchNonJWTTokenHasNoHint(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-opaque-token"),
	})
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccountHint != "" || !cred.ExpiresAt.IsZero() {
		t.Fatalf("expected no unverified hint, got: %s", cred)
	}
}

func TestFetchNoLoginWhenStateEmpty(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		"workbench.panel.size": []byte("300"),
	})
	_, err := DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrNoLogin) {
		t.Fatalf("want ErrNoLogin, got %v", err)
	}
	var re *ReadError
	if !errors.As(err, &re) || re.Code != CodeNoLogin {
		t.Fatalf("want ReadError{no_login}, got %v", err)
	}
}

func TestFetchNoLoginWhenBlobLoggedOut(t *testing.T) {
	for name, value := range map[string]any{
		"empty object": []byte(`{}`),
		"blank token":  []byte(`{"accessToken":""}`),
		"null value":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			opts, _ := newSyntheticState(t, map[string]any{itemKeyCursorAuth: value})
			_, err := DesktopProvider(opts).Fetch(context.Background())
			if !errors.Is(err, ErrNoLogin) {
				t.Fatalf("want ErrNoLogin, got %v", err)
			}
		})
	}
}

func TestFetchNoLoginWhenDBMissing(t *testing.T) {
	opts := syntheticOptions(t.TempDir())
	_, err := DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrNoLogin) {
		t.Fatalf("want ErrNoLogin, got %v", err)
	}
}

func TestFetchUnsupportedSchemaWhenNotADatabase(t *testing.T) {
	opts := syntheticOptions(t.TempDir())
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("definitely not a sqlite database (synthetic)"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
}

func TestFetchUnsupportedSchemaWhenItemTableMissing(t *testing.T) {
	opts := syntheticOptions(t.TempDir())
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE synthetic_other (key TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
}

func TestFetchUnsupportedSchemaWhenBlobMalformed(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuth: []byte(`not-json`),
	})
	_, err := DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
}

func TestFetchPermissionDeniedIsRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not enforced on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits are not enforced")
	}
	opts, path := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-secret-token"),
	})
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	_, err := DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("want ErrPermission, got %v", err)
	}
	var re *ReadError
	if !errors.As(err, &re) || re.Code != CodePermission {
		t.Fatalf("want ReadError{permission}, got %v", err)
	}
	// The rendered error (including through wrapping) must not leak the
	// token, the home directory, or the database file name.
	rendered := fmt.Sprintf("outer: %v", err)
	for _, secret := range []string{"synthetic-secret-token", opts.HomeDir, "state.vscdb"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("error leaks %q: %s", secret, rendered)
		}
	}
}

func TestFetchDoesNotModifyStateDB(t *testing.T) {
	opts, path := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-direct-token"),
		itemKeyCursorAuth:       []byte(`{"accessToken":"synthetic-blob-token"}`),
	})
	beforeSum := fileSum(t, path)
	beforeEntries := dirEntries(t, filepath.Dir(path))
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-direct-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	afterEntries := dirEntries(t, filepath.Dir(path))
	if !reflect.DeepEqual(beforeEntries, afterEntries) {
		t.Fatalf("files appeared next to the state database: %v", afterEntries)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		for _, name := range afterEntries {
			if strings.HasSuffix(name, suffix) {
				t.Fatalf("journal file %q created next to the state database", name)
			}
		}
	}
}

func TestFetchContextCanceled(t *testing.T) {
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-direct-token"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DesktopProvider(opts).Fetch(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestFetchUnsupportedGOOS(t *testing.T) {
	_, err := DesktopProvider(Options{HomeDir: "/synthetic-home", GOOS: "plan9"}).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedOS) {
		t.Fatalf("want ErrUnsupportedOS, got %v", err)
	}
}

func TestReadDesktopConvenience(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("APPDATA", "")
	opts, _ := newSyntheticState(t, map[string]any{
		itemKeyCursorAuthDirect: []byte("synthetic-direct-token"),
	})
	cred, err := ReadDesktop(context.Background(), opts.HomeDir, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "synthetic-direct-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
}

// createWALStateDB creates a synthetic WAL-mode state database. When keepOpen
// is true the writing connection stays open, leaving live -wal/-shm sidecar
// files behind, mimicking a running Cursor holding the database.
func createWALStateDB(t *testing.T, path string, keepOpen bool) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Register before any SQL or skip/fatal path. TempDir cleanup runs
	// after this callback, so Windows never has to remove an open mapping.
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`PRAGMA journal_mode=wal`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO ItemTable (key, value) VALUES (?, ?)`, itemKeyCursorAuthDirect, []byte("synthetic-wal-token")); err != nil {
		t.Fatal(err)
	}
	if !keepOpen {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	return db
}

func TestWALFixtureClosesOnEarlySkip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.vscdb")
	var writer *sql.DB
	t.Run("early-skip", func(t *testing.T) {
		writer = createWALStateDB(t, path, true)
		t.Skip("exercise fixture cleanup before the caller can register a defer")
	})
	if writer == nil || writer.Stats().OpenConnections != 0 {
		t.Fatal("synthetic WAL writer leaked across skipped subtest cleanup")
	}
	// This also exercises Windows' rule against removing an open DB file.
	if err := os.Remove(path); err != nil {
		t.Fatalf("database is still held after subtest cleanup: %v", err)
	}
}

// TestFetchWALModeDBCreatesNoSidecarFiles verifies the read-only contract on
// an existing database whose header selects WAL mode but whose -wal/-shm
// files are gone (a cleanly closed writer): a mode=ro read must not create
// -wal/-shm/-journal files and must not modify the database bytes.
func TestFetchWALModeDBCreatesNoSidecarFiles(t *testing.T) {
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	createWALStateDB(t, path, false)
	pre := dirEntries(t, filepath.Dir(path))
	if len(pre) != 1 || pre[0] != "state.vscdb" {
		t.Fatalf("precondition: expected only state.vscdb after clean close, got %v", pre)
	}
	beforeSum := fileSum(t, path)
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatalf("read of WAL-mode database without sidecar files failed: %v", err)
	}
	if cred.AccessToken != "synthetic-wal-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	post := dirEntries(t, filepath.Dir(path))
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("mode=ro created sidecar files: %v", post)
	}
}

// TestFetchWALModeDBWithLiveWriterCheckPointed: Cursor is running (writer
// holds -wal/-shm) and the credential was already checkpointed into the
// main file — the common case for a long-lived login. immutable reads the
// main file without touching the live sidecars.
func TestFetchWALModeDBWithLiveWriterCheckPointed(t *testing.T) {
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	writer := createWALStateDB(t, path, true)
	defer func() { _ = writer.Close() }()
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	beforeSum := fileSum(t, path)
	pre := dirEntries(t, filepath.Dir(path))
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatalf("checkpointed credential must be readable while the writer runs: %v", err)
	}
	if cred.AccessToken != "synthetic-wal-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	if post := dirEntries(t, filepath.Dir(path)); !reflect.DeepEqual(pre, post) {
		t.Fatalf("read touched files next to the database: before=%v after=%v", pre, post)
	}
}

// TestFetchWALModeDBWithLiveWriterUncheckpointed: Cursor is running and the
// credential exists only in the un-checkpointed -wal. immutable cannot see
// it, so the read fails closed with a redacted error instead of writing to
// the Cursor directory to share the live WAL-index. This is the documented
// freshness limitation of the strict no-write guarantee.
func TestFetchWALModeDBWithLiveWriterUncheckpointed(t *testing.T) {
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	writer := createWALStateDB(t, path, true)
	defer func() { _ = writer.Close() }()
	beforeSum := fileSum(t, path)
	pre := dirEntries(t, filepath.Dir(path))
	_, err = DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema when the credential is WAL-only, got %v", err)
	}
	if rendered := err.Error(); strings.Contains(rendered, opts.HomeDir) || strings.Contains(rendered, "synthetic-wal-token") {
		t.Fatalf("error leaks sensitive data: %s", rendered)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	if post := dirEntries(t, filepath.Dir(path)); !reflect.DeepEqual(pre, post) {
		t.Fatalf("read touched files next to the database: before=%v after=%v", pre, post)
	}
}

// TestFetchWALSidecarsVanishMidRead reproduces review finding F2: the
// -wal/-shm sidecars exist when the read-only DSN is decided but are
// deleted (Cursor exits) before SQLite opens any file. The read must not
// recreate them. This test fails against a DSN strategy that trusts
// sidecar existence: such an open would recreate -shm/-wal in the writable
// directory.
func TestFetchWALSidecarsVanishMidRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot unlink files an open connection maps")
	}
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	writer := createWALStateDB(t, path, true)
	defer func() { _ = writer.Close() }()
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	beforeSum := fileSum(t, path)
	testHookAfterDSN = func() {
		if err := os.Remove(path + "-wal"); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path + "-shm"); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { testHookAfterDSN = nil }()
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatalf("checkpointed credential must be readable when sidecars vanish mid-read: %v", err)
	}
	if cred.AccessToken != "synthetic-wal-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	post := dirEntries(t, filepath.Dir(path))
	if len(post) != 1 || post[0] != "state.vscdb" {
		t.Fatalf("sidecars were recreated after vanishing mid-read: %v", post)
	}
}

// TestSQLiteReadOnlyDSNImmutablePolicy pins the DSN policy by construction:
// WAL-mode databases always carry immutable=1 regardless of any sidecar
// state (existence is not even consulted), so no open-decision/open race
// can produce a sidecar-creating DSN. Rollback-journal databases never do.
func TestSQLiteReadOnlyDSNImmutablePolicy(t *testing.T) {
	rollback := sqliteReadOnlyDSN("/tmp/synthetic state.vscdb", "linux", false)
	if want := "file:/tmp/synthetic%20state.vscdb?mode=ro"; rollback != want {
		t.Fatalf("rollback DSN: got %q, want %q", rollback, want)
	}
	wal := sqliteReadOnlyDSN("/tmp/synthetic state.vscdb", "linux", true)
	if want := "file:/tmp/synthetic%20state.vscdb?mode=ro&immutable=1"; wal != want {
		t.Fatalf("wal DSN: got %q, want %q", wal, want)
	}
	windowsWAL := sqliteReadOnlyDSN(`C:\Users\synthetic\state.vscdb`, "windows", true)
	if want := "file:C:/Users/synthetic/state.vscdb?mode=ro&immutable=1"; windowsWAL != want {
		t.Fatalf("windows wal DSN: got %q, want %q", windowsWAL, want)
	}
}

// orphanWAL snapshots only this test's synthetic files, then closes the writer
// before restoring them without an SHM index. Closing first is necessary on
// Windows, where an open SQLite mapping prevents unlinking its files. Capturing
// before Close preserves the pre-checkpoint state for the crash simulation.
func orphanWAL(t *testing.T, writer *sql.DB, path string) {
	t.Helper()
	main, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wal, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close synthetic writer before restoring orphaned WAL: %v", err)
	}
	if err := os.WriteFile(path, main, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-wal", wal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// TestFetchOrphanedWALAfterCheckpoint: a crash-leftover -wal whose content
// was already checkpointed into the main file. immutable reads the main
// file, finds the token, and creates nothing.
func TestFetchOrphanedWALAfterCheckpoint(t *testing.T) {
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	writer := createWALStateDB(t, path, true)
	if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	orphanWAL(t, writer, path)
	beforeSum := fileSum(t, path)
	pre := dirEntries(t, filepath.Dir(path))
	cred, err := DesktopProvider(opts).Fetch(context.Background())
	if err != nil {
		t.Fatalf("expected the checkpointed main file to be readable: %v", err)
	}
	if cred.AccessToken != "synthetic-wal-token" {
		t.Fatalf("unexpected credential: %s", cred)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	if post := dirEntries(t, filepath.Dir(path)); !reflect.DeepEqual(pre, post) {
		t.Fatalf("immutable read created or removed files: before=%v after=%v", pre, post)
	}
}

// TestFetchOrphanedWALUncheckpointed: a crash-leftover -wal holding content
// that never reached the main file. immutable ignores the orphaned -wal, so
// the read fails closed (schema not found in the main file) without ever
// recovering the WAL, which would require writing.
func TestFetchOrphanedWALUncheckpointed(t *testing.T) {
	home := t.TempDir()
	opts := syntheticOptions(home)
	path, err := stateDBPath(opts, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	writer := createWALStateDB(t, path, true)
	orphanWAL(t, writer, path)
	beforeSum := fileSum(t, path)
	pre := dirEntries(t, filepath.Dir(path))
	_, err = DesktopProvider(opts).Fetch(context.Background())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema from the stale main file, got %v", err)
	}
	if rendered := err.Error(); strings.Contains(rendered, opts.HomeDir) || strings.Contains(rendered, "synthetic-wal-token") {
		t.Fatalf("error leaks sensitive data: %s", rendered)
	}
	if after := fileSum(t, path); !bytes.Equal(beforeSum, after) {
		t.Fatal("state database content changed during read")
	}
	if post := dirEntries(t, filepath.Dir(path)); !reflect.DeepEqual(pre, post) {
		t.Fatalf("immutable read created or removed files: before=%v after=%v", pre, post)
	}
}
