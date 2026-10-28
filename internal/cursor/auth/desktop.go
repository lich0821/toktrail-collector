package auth

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
)

// Options configures DesktopProvider. Every input is injectable: nothing is
// read from the host environment unless a field is left empty, so embedders
// and tests stay hermetic by filling the fields explicitly.
type Options struct {
	// HomeDir is the user home directory. Empty: os.UserHomeDir().
	HomeDir string
	// GOOS selects the Cursor desktop path layout: "darwin", "linux", or
	// "windows". Empty: runtime.GOOS.
	GOOS string
	// AppData overrides the Windows roaming AppData base directory.
	// Precedence: AppData option > APPDATA env > HomeDir\AppData\Roaming.
	// Only consulted when GOOS is "windows".
	AppData string
	// XDGConfigHome overrides the XDG configuration base directory.
	// Precedence: XDGConfigHome option > XDG_CONFIG_HOME env >
	// HomeDir/.config. Only consulted when GOOS is "linux".
	XDGConfigHome string
}

// DesktopProvider returns a Provider that reads the Cursor desktop
// credential from the standard state database (state.vscdb) for the layout
// selected by opts.
func DesktopProvider(opts Options) Provider {
	return desktopProvider{opts: opts}
}

// ReadDesktop reads the Cursor desktop credential using the standard layout
// for home and goos. It is a convenience wrapper around DesktopProvider.
func ReadDesktop(ctx context.Context, home, goos string) (Credential, error) {
	return DesktopProvider(Options{HomeDir: home, GOOS: goos}).Fetch(ctx)
}

var _ Provider = desktopProvider{}

type desktopProvider struct{ opts Options }

// Fetch reads the Cursor desktop credential. It stats the state database,
// probes read access, then opens the database read-only and queries only the
// two credential keys of ItemTable.
func (p desktopProvider) Fetch(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	goos, err := p.targetGOOS()
	if err != nil {
		return Credential{}, err
	}
	path, err := stateDBPath(p.opts, goos)
	if err != nil {
		return Credential{}, err
	}
	if _, err := os.Stat(path); err != nil {
		return Credential{}, classifyStatError(err)
	}
	// Read-only probe: surfaces permission failures (including Windows
	// ACLs) before the SQLite layer, and reads the file header so a
	// side-effect-free read-only DSN can be chosen.
	probe, err := os.Open(path)
	if err != nil {
		return Credential{}, classifyOpenError(err)
	}
	header := make([]byte, sqliteHeaderLen)
	_, readErr := io.ReadFull(probe, header)
	_ = probe.Close()
	if readErr != nil {
		// Every valid SQLite database is much larger than its 100-byte
		// header, so a short read means this is not one.
		return Credential{}, &ReadError{Code: CodeUnsupportedSchema, Op: "sniff"}
	}
	walMode, err := sniffJournalMode(header)
	if err != nil {
		return Credential{}, err
	}
	token, err := readStateDBToken(ctx, path, goos, walMode)
	if err != nil {
		return Credential{}, err
	}
	if strings.TrimSpace(token) == "" {
		return Credential{}, &ReadError{Code: CodeNoLogin, Op: "query"}
	}
	cred := Credential{AccessToken: token, Source: SourceDesktopSQLite}
	if sub, exp, ok := unverifiedTokenHint(token); ok {
		cred.AccountHint = sub
		cred.ExpiresAt = exp
	}
	// AccountID stays empty: the desktop reader never asserts a verified
	// account identity. It is reserved for the server identity endpoint.
	return cred, nil
}

func (p desktopProvider) targetGOOS() (string, error) {
	goos := strings.TrimSpace(p.opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "darwin", "linux", "windows":
		return goos, nil
	default:
		return "", &ReadError{Code: CodeUnsupportedOS, Op: "resolve-goos"}
	}
}

// stateDBPath resolves the Cursor desktop state database path for goos.
//
// Layouts (Cursor is a VS Code fork and keeps the VS Code globalStorage
// location):
//
//	darwin:  <home>/Library/Application Support/Cursor/User/globalStorage/state.vscdb
//	linux:   <xdg-config>/Cursor/User/globalStorage/state.vscdb
//	windows: <appdata>\Cursor\User\globalStorage\state.vscdb
func stateDBPath(opts Options, goos string) (string, error) {
	switch goos {
	case "darwin":
		home, err := homeDir(opts)
		if err != nil {
			return "", err
		}
		return joinPath(goos, home, "Library", "Application Support", "Cursor", "User", "globalStorage", "state.vscdb"), nil
	case "linux":
		base, err := linuxConfigBase(opts)
		if err != nil {
			return "", err
		}
		return joinPath(goos, base, "Cursor", "User", "globalStorage", "state.vscdb"), nil
	case "windows":
		base, err := windowsAppDataBase(opts)
		if err != nil {
			return "", err
		}
		return joinPath(goos, base, "Cursor", "User", "globalStorage", "state.vscdb"), nil
	default:
		return "", &ReadError{Code: CodeUnsupportedOS, Op: "resolve-path"}
	}
}

func homeDir(opts Options) (string, error) {
	if v := strings.TrimSpace(opts.HomeDir); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", &ReadError{Code: CodeUnavailable, Op: "resolve-home"}
	}
	return home, nil
}

func linuxConfigBase(opts Options) (string, error) {
	if v := strings.TrimSpace(opts.XDGConfigHome); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); v != "" {
		return v, nil
	}
	home, err := homeDir(opts)
	if err != nil {
		return "", err
	}
	return joinPath("linux", home, ".config"), nil
}

func windowsAppDataBase(opts Options) (string, error) {
	if v := strings.TrimSpace(opts.AppData); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("APPDATA")); v != "" {
		return v, nil
	}
	home, err := homeDir(opts)
	if err != nil {
		return "", err
	}
	return joinPath("windows", home, "AppData", "Roaming"), nil
}

// joinPath joins path elements with the separator of the TARGET goos, not
// the host, so callers can build foreign layouts as plain strings.
func joinPath(goos string, base string, elems ...string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	parts := make([]string, 0, len(elems)+1)
	parts = append(parts, base)
	parts = append(parts, elems...)
	return strings.Join(parts, sep)
}

func classifyStatError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &ReadError{Code: CodeNoLogin, Op: "stat"}
	case errors.Is(err, fs.ErrPermission):
		return &ReadError{Code: CodePermission, Op: "stat"}
	default:
		return &ReadError{Code: CodeUnavailable, Op: "stat"}
	}
}

func classifyOpenError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &ReadError{Code: CodeNoLogin, Op: "open"}
	case errors.Is(err, fs.ErrPermission):
		return &ReadError{Code: CodePermission, Op: "open"}
	default:
		return &ReadError{Code: CodeUnavailable, Op: "open"}
	}
}
