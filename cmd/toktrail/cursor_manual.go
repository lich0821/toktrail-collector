package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/local/statedir"
)

// Manual enable is an explicit fallback when the desktop state cannot be read.
// Permission and the token use separate channels: an affirmative CLI flag and
// protected stdin. Tokens are never command arguments or persistent settings.
func parseCursorEnableArgs(args []string) (dir, server string, manual bool, err error) {
	fs := flag.NewFlagSet("cursor enable", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	tokenStdin := fs.Bool("token-stdin", false, "use one manual access token from protected stdin for this process only")
	confirm := fs.Bool("confirm-local", false, "explicitly consent to local Cursor account collection when using --token-stdin")
	if err = fs.Parse(args); err != nil {
		return
	}
	if fs.NArg() != 0 {
		err = errors.New("unexpected positional arguments; supply credentials only through protected stdin")
		return
	}
	if *tokenStdin != *confirm {
		err = errors.New("manual enable requires both --token-stdin and --confirm-local; the token must come from a protected pipe or file")
		return
	}
	dir, server, manual = *stateDir, *serverURL, *tokenStdin
	if dir == "" {
		dir, err = statedir.DefaultDir()
	}
	return
}

// Enable verifies, then synchronizes immediately, so the same in-memory manual
// credential must be available for both calls without reading stdin twice.
type manualCredentialProvider struct {
	provider   auth.Provider
	once       sync.Once
	credential auth.Credential
	err        error
}

func (p *manualCredentialProvider) Fetch(ctx context.Context) (auth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return auth.Credential{}, err
	}
	p.once.Do(func() { p.credential, p.err = p.provider.Fetch(ctx) })
	return p.credential, p.err
}
func (*manualCredentialProvider) String() string   { return "manual credential provider [redacted]" }
func (*manualCredentialProvider) GoString() string { return "manual credential provider [redacted]" }

func protectedManualProvider(input *os.File) (auth.Provider, error) {
	if input == nil {
		return nil, errors.New("manual credential input is unavailable")
	}
	info, err := input.Stat()
	if err != nil {
		return nil, errors.New("manual credential input is unavailable")
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return nil, errors.New("--token-stdin requires a protected pipe or file; interactive terminal input is refused to avoid echoing the token")
	}
	return &manualCredentialProvider{provider: cursorsync.NewStdinTokenProvider(input)}, nil
}

func manualEnableConfirmation(notice string, out io.Writer) (bool, error) {
	_, err := fmt.Fprintln(out, notice)
	return err == nil, err
}
