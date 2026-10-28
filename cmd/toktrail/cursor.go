package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

// cursorSyncOptions wires the real cursor providers: the desktop SQLite
// auth reader, the pinned-host Cursor API client (credential verification
// with canonical account derivation, snapshots collapsed per response).
// Everything stays injectable through cursorsync.Options for tests; this
// is the production wiring only.
func cursorSyncOptions(stateDir, serverURL string, httpClient *http.Client) (*cursorsync.Options, error) {
	apiClient, err := api.New(api.Options{HTTPClient: httpClient})
	if err != nil {
		return nil, err
	}
	verify := func(ctx context.Context, accessToken string) (api.VerifyResult, error) {
		return apiClient.VerifySession(ctx, accessToken)
	}
	pull := func(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
		var startMS *int64
		if !from.IsZero() {
			ms := from.UnixMilli()
			if ms > 0 {
				startMS = &ms
			}
		}
		res, err := apiClient.FetchUsageEvents(ctx, api.Session{Token: sessionToken}, api.FetchOptions{
			StartDateMS: startMS,
			EndDateMS:   to.UnixMilli(),
		})
		if err != nil {
			return nil, err
		}
		return api.CollapseSnapshots(res.Events).Events, nil
	}
	return &cursorsync.Options{
		StateDir:   stateDir,
		ServerURL:  serverURL,
		HTTPClient: httpClient,
		Auth:       auth.DesktopProvider(auth.Options{}),
		Verify:     verify,
		Pull:       pull,
		Out:        os.Stdout,
	}, nil
}

func runCursor(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail cursor <enable|status|sync|logout> [flags]")
		return flag.ErrHelp
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "enable":
		return runCursorEnable(rest)
	case "status":
		return runCursorStatus(rest)
	case "sync":
		return runCursorSync(rest)
	case "logout":
		return runCursorLogout(rest)
	}
	fmt.Fprintf(os.Stderr, "unknown cursor subcommand %q; try enable|status|sync|logout\n", sub)
	os.Exit(2)
	return nil
}

func cursorStateDir(args []string) (string, *string, error) {
	fs := flag.NewFlagSet("cursor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return "", nil, err
		}
	}
	return dir, serverURL, nil
}

func runCursorEnable(args []string) error {
	dir, serverURL, manual, err := parseCursorEnableArgs(args)
	if err != nil {
		return err
	}
	opts, err := cursorSyncOptions(dir, serverURL, nil)
	if err != nil {
		return err
	}
	var confirm cursorsync.ConfirmFunc
	if manual {
		opts.Auth, err = protectedManualProvider(os.Stdin)
		if err != nil {
			return err
		}
		confirm = manualEnableConfirmation
	}
	lock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := cursorsync.Enable(ctx, *opts, confirm)
	if err != nil {
		return err
	}
	fmt.Printf("cursor source enabled: sourceInstanceId=%s state=%s fenceVersion=%d nextRevision=%d\n",
		res.Source.SourceInstanceID, res.Source.State, res.Source.FenceVersion, res.Source.NextRevision)
	if res.Sync.Ran {
		printCursorSyncResult(res.Sync)
	} else if res.Sync.Skipped != "" {
		fmt.Printf("first sync: %s\n", res.Sync.Skipped)
	}
	fmt.Printf("state=%s\n", statedir.New(dir).Path())
	return nil
}

func runCursorStatus(args []string) error {
	dir, serverURL, err := cursorStateDir(args)
	if err != nil {
		return err
	}
	opts := cursorsync.Options{StateDir: dir, ServerURL: *serverURL}
	lock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := cursorsync.Status(ctx, opts)
	if err != nil {
		return err
	}
	if !res.HasLicense {
		fmt.Printf("cursor: no local permit (enable with toktrail connect or toktrail cursor enable)\n")
	} else {
		fmt.Printf("permit: status=%s confirmedAt=%s\n", res.License.Status, res.License.ConfirmedAt.Format(time.RFC3339))
		fmt.Printf("source: sourceInstanceId=%s fenceVersion=%d nextRevision=%d\n", res.License.SourceInstanceID, res.License.FenceVersion, res.License.NextRevision)
		if res.License.PullWatermark != nil {
			fmt.Printf("pullWatermark=%s\n", res.License.PullWatermark.Format(time.RFC3339))
		}
		if res.License.LastSyncAt != nil {
			fmt.Printf("lastSyncAt=%s\n", res.License.LastSyncAt.Format(time.RFC3339))
		}
	}
	if res.ServerReached {
		if res.HasSource {
			fmt.Printf("server source: state=%s fenceVersion=%d nextRevision=%d\n", res.Source.State, res.Source.FenceVersion, res.Source.NextRevision)
		} else {
			fmt.Printf("server source: this device is not the executor of any cursor source\n")
		}
	} else if res.ServerError != nil {
		fmt.Printf("server source: unavailable (%v)\n", res.ServerError)
	}
	fmt.Printf("pendingBatches=%d\n", res.PendingBatches)
	fmt.Printf("state=%s\n", statedir.New(dir).Path())
	return nil
}

func runCursorSync(args []string) error {
	fs := flag.NewFlagSet("cursor sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	tokenStdin := fs.Bool("token-stdin", false, "read a manual access token from stdin for THIS process only (never stored; the local permit and server grant must already exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	opts, err := cursorSyncOptions(dir, *serverURL, nil)
	if err != nil {
		return err
	}
	if *tokenStdin {
		// Only the credential is process-local; ordinary usage metadata
		// still follows the normal durable queue and existing permission.
		opts.Auth, err = protectedManualProvider(os.Stdin)
		if err != nil {
			return err
		}
	}
	lock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// An unrestricted gate: the direct CLI sync applies the live server
	// view fetched inside Sync (allowed tools, history window, source
	// state) rather than the periodic grant-sync overlay.
	res, err := cursorsync.Sync(ctx, *opts, cursorsync.Gate{})
	if err != nil {
		if res.Ran || res.Skipped == "" {
			return err
		}
		fmt.Printf("cursor: %s\n", res.Skipped)
		return err
	}
	if !res.Ran {
		fmt.Printf("cursor: %s\n", res.Skipped)
		return nil
	}
	printCursorSyncResult(res)
	return nil
}

func printCursorSyncResult(res cursorsync.Result) {
	fmt.Printf("cursor sync: pulledEvents=%d new=%d replaced=%d unchanged=%d noStableId=%d\n",
		res.PulledEvents, res.NewRecords, res.ReplacedRecords, res.SkippedUnchanged, res.SkippedNoStableID)
	fmt.Printf("cursor sync: exportedBatches=%d syncedBatches=%d syncedRecords=%d pendingRemaining=%d\n",
		res.ExportedBatches, res.SyncedBatches, res.SyncedRecords, res.PendingRemaining)
	if res.FirstSyncCompleted {
		fmt.Printf("cursor sync: first usage pull persisted; local permit active (upload confirmation is shown in syncedRecords/pendingRemaining)\n")
	}
	if res.Note != "" {
		fmt.Printf("cursor sync: note=%s\n", res.Note)
	}
}

func runCursorLogout(args []string) error {
	fs := flag.NewFlagSet("cursor logout", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	purge := fs.Bool("purge-cache", false, "also delete the local cursor usage cache, outbox and batch files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	lock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	removedLicense, purgedCache, err := cursorsync.Logout(cursorsync.Options{StateDir: dir}, *purge)
	if err != nil {
		return err
	}
	if !removedLicense {
		fmt.Printf("cursor: no local permit to remove\n")
		return nil
	}
	fmt.Printf("cursor: local permit removed (uploaded data is governed by the server-side deletion flow)\n")
	if *purge {
		fmt.Printf("cursor: local cache purged=%t\n", purgedCache)
	}
	return nil
}
