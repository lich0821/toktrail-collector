package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/diagnostic"
	statuscmd "toktrail-collector/internal/app/status"
	bindcmd "toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	synccmd "toktrail-collector/internal/syncclient"
)

var version = "dev"

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "version":
		fmt.Println("toktrail", version)
	case "connect":
		if err := runConnect(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
			os.Exit(1)
		}
	case "bind":
		if err := runBind(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bind failed: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := runStatus(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "status failed: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(1)
		}
	case "preview":
		if err := runPreview(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "preview failed: %v\n", err)
			os.Exit(1)
		}
	case "export":
		if err := runExport(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "export failed: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := runSync(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sync failed: %v\n", err)
			os.Exit(1)
		}
	case "periodic":
		if err := runPeriodic(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "periodic failed: %v\n", err)
			os.Exit(1)
		}
	case "sources":
		if err := runSources(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sources failed: %v\n", err)
			os.Exit(1)
		}
	case "plugins":
		if err := runPlugins(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "plugins failed: %v\n", err)
			os.Exit(1)
		}
	case "service":
		if err := runService(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "service failed: %v\n", err)
			os.Exit(1)
		}
	case "privacy":
		if err := runPrivacy(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "privacy failed: %v\n", err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "doctor failed: %v\n", err)
			os.Exit(1)
		}
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; try help\n", cmd)
		os.Exit(2)
	}
}

func runBind(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", "http://127.0.0.1:3211"), "toktrail-server base URL")
	ticket := fs.String("ticket", env("TOKTRAIL_BIND_TICKET", ""), "one-time bind ticket")
	applicationID := fs.String("application", env("TOKTRAIL_APPLICATION_ID", "leaderboard-local"), "server application id")
	subjectID := fs.String("subject", env("TOKTRAIL_SUBJECT_ID", ""), "external subject id from leaderboard/account flow")
	deviceName := fs.String("device-name", env("TOKTRAIL_DEVICE_NAME", "toktrail-collector"), "local device name")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := bindcmd.Run(ctx, statedir.New(dir), bindcmd.Options{
		ServerURL:         *serverURL,
		Ticket:            *ticket,
		ApplicationID:     *applicationID,
		ExternalSubjectID: *subjectID,
		DeviceName:        *deviceName,
	})
	if err != nil {
		return err
	}
	replay := "new"
	if result.Replay {
		replay = "replay"
	}
	fmt.Printf("bound device %s (%s), consentRevision=%d, state=%s\n", result.State.DeviceID, replay, result.State.ConsentRevision, statedir.New(dir).Path())
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := statuscmd.Run(ctx, statedir.New(dir), statuscmd.Options{ServerURL: *serverURL})
	if err != nil {
		return err
	}
	fmt.Printf("device %s\n", result.State.DeviceID)
	fmt.Printf("uploadAuthorized=%t publicAuthorized=%t revoked=%t consentRevision=%d\n", result.State.UploadAuthorized, result.State.PublicAuthorized, result.State.Revoked, result.State.ConsentRevision)
	fmt.Printf("checkedAt=%s state=%s\n", result.State.LastCheckedAt.Format(time.RFC3339), statedir.New(dir).Path())
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory; interval sources use it to load confirmed baselines")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	// Finish any pending export transaction first so interval baselines
	// are consistent before the claude-code-jsonl progress state is read.
	if _, err := exportcommit.Recover(dir); err != nil {
		return err
	}
	res, err := pipeline.Scan(adapter.Options{Source: *source, Input: *input, StateDir: dir})
	if err != nil {
		return err
	}
	fmt.Printf("source=%s records=%d valid=%d invalid=%d\n", res.Source, res.RecordCount, res.ValidRecords, res.InvalidRecords)
	fmt.Printf("knownIncludeRecords=%d tokensInclude=%s knownExcludeRecords=%d tokensExclude=%s\n", res.KnownIncludeRecords, formatOptionalUint(res.TokensInclude), res.KnownExcludeRecords, formatOptionalUint(res.TokensExclude))
	if res.EarliestOccurredAt != nil && res.LatestOccurredAt != nil {
		fmt.Printf("range=%s..%s\n", res.EarliestOccurredAt.Format(time.RFC3339), res.LatestOccurredAt.Format(time.RFC3339))
	}
	for _, tool := range adapter.SortedTools(res.Tools) {
		fmt.Printf("tool[%s]=%d\n", tool, res.Tools[tool])
	}
	if res.Quarantined > 0 {
		fmt.Printf("quarantined=%d\n", res.Quarantined)
		if remaining := res.Quarantined - len(res.Issues); remaining > 0 {
			fmt.Printf("quarantineNote=%d more quarantined lines not listed\n", remaining)
		}
	}
	if len(res.Issues) > 0 {
		// Line quarantines and message-level interval diagnostics share the
		// issue list; report even when nothing was quarantined.
		for _, issue := range res.Issues {
			fmt.Printf("issue[%s:%d]=%s\n", issue.File, issue.Line, issue.Reason)
		}
	}
	return nil
}

func runPreview(args []string) error {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	limit := fs.Int("limit", 10, "max records to preview")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory; interval sources use it to load confirmed baselines")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	if _, err := exportcommit.Recover(dir); err != nil {
		return err
	}
	rows, err := pipeline.Preview(adapter.Options{Source: *source, Input: *input, Limit: *limit, StateDir: dir})
	if err != nil {
		return err
	}
	for _, row := range rows {
		status := "ok"
		if !row.Valid {
			status = "invalid:" + row.Error
		}
		fmt.Printf("%d %s tool=%s kind=%s occurredAt=%s include=%s exclude=%s %s\n", row.Index, row.RecordKey, row.Tool, row.Kind, row.Occurred, formatOptionalUint(row.Include), formatOptionalUint(row.Exclude), status)
	}
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	output := fs.String("out", "", "output batch JSON file")
	batchID := fs.String("batch", "", "batch id; generated when omitted")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory for outbox")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	prepared, err := pipeline.PrepareExport(adapter.Options{Source: *source, Input: *input, Output: *output, BatchID: *batchID, StateDir: dir})
	if err != nil {
		return err
	}
	if prepared.Records == 0 {
		// Nothing new since the last confirmed baselines (e.g. all messages
		// frozen or unchanged); committing an empty batch would only churn
		// the outbox and cursor.
		fmt.Printf("no new records for source=%s\n", *source)
		return nil
	}
	chunks, err := pipeline.SplitPreparedExport(prepared)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		res, err := exportcommit.CommitExport(exportcommit.ExportOptions{
			StateDir: dir,
			Prepared: chunk,
			Source:   *source,
			Input:    *input,
		})
		if err != nil {
			return err
		}
		fmt.Printf("exported batch %s records=%d file=%s\n", res.BatchID, res.Records, res.Output)
		fmt.Printf("outbox=%s status=pending\n", res.OutboxPath)
		fmt.Printf("cursor=%s batch=%s\n", res.CursorPath, res.BatchID)
	}
	return nil
}

func runSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	batchFile := fs.String("file", "", "usage batch JSON file to upload")
	batchID := fs.String("batch", "", "override or provide batch id")
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
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := synccmd.Run(ctx, statedir.New(dir), synccmd.Options{
		ServerURL: *serverURL,
		StateDir:  dir,
		BatchFile: *batchFile,
		BatchID:   *batchID,
	})
	if err != nil {
		return err
	}
	replay := "new"
	if result.Receipt.Replay {
		replay = "replay"
	}
	if result.Receipt.BatchID == "" {
		// Recovery-only run: no batch was uploaded, quarantined records were
		// re-pended under the live consent scope. The recovered/quarantined
		// line below carries the outcome.
	} else {
		fmt.Printf("synced batch %s (%s), status=%s accepted=%d rejected=%d\n", result.Receipt.BatchID, replay, result.Receipt.Status, result.Receipt.AcceptedRecords, result.Receipt.RejectedRecords)
	}
	fmt.Printf("device=%s consentRevision=%d uploadAuthorized=%t\n", result.Self.DeviceID, result.Self.ConsentRevision, result.Self.UploadAuthorized)
	fmt.Printf("recovered=%d quarantined=%d\n", result.Recovered, result.Quarantined)
	if result.Receipt.BatchID == "" {
		fmt.Printf("state=%s\n", statedir.New(dir).Path())
		return nil
	}
	fmt.Printf("receivedAt=%s state=%s\n", result.Receipt.ReceivedAt.Format(time.RFC3339), statedir.New(dir).Path())
	return nil
}

func formatOptionalUint(v *uint64) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v)
}

// ---------------------------------------------------------------------------
// periodic: the complete-exit scheduled entry. It collects only the
// explicitly granted sources (grants.json), exports with the existing
// exportcommit WAL, and drains a bounded number of pending batches with the
// existing syncclient (server fresh-consent preflight preserved). One
// process lock covers the entire run; overlapping runs fail fast.
// ---------------------------------------------------------------------------

func runPeriodic(args []string) error {
	fs := flag.NewFlagSet("periodic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	maxBatches := fs.Int("max-batches", collection.DefaultMaxSyncBatches, "max pending outbox batches to upload per run")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := collection.Run(ctx, collection.Options{
		StateDir:   dir,
		ServerURL:  *serverURL,
		MaxBatches: *maxBatches,
	})
	if err != nil {
		return err
	}
	if result.NoGrants {
		fmt.Printf("no enabled source grants; nothing collected (enable with: toktrail sources enable --source <s> --input <path>)\n")
		return nil
	}
	for _, outcome := range result.GrantOutcomes {
		switch {
		case outcome.Skipped != "":
			fmt.Printf("grant %s %s: skipped (%s)\n", outcome.Source, outcome.Input, outcome.Skipped)
		case !outcome.Exported:
			fmt.Printf("grant %s %s: no new records\n", outcome.Source, outcome.Input)
		default:
			fmt.Printf("grant %s %s: exported batch %s records=%d\n", outcome.Source, outcome.Input, outcome.BatchID, outcome.Records)
		}
	}
	fmt.Printf("exportedBatches=%d exportedRecords=%d\n", result.ExportedBatches, result.ExportedRecords)
	fmt.Printf("syncedBatches=%d syncedRecords=%d\n", result.SyncedBatches, result.SyncedRecords)
	if result.PendingRemaining > 0 {
		fmt.Printf("pendingRemaining=%d (drain stops at %d batch(es) per run; the next run continues)\n", result.PendingRemaining, *maxBatches)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sources / plugins: adapter visibility and enablement for scheduled
// collection. Manual scan/preview/export keep their explicit
// --source/--input semantics and are unaffected by this config.
// ---------------------------------------------------------------------------

func runSources(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail sources <list|enable|disable>")
		return flag.ErrHelp
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		return runSourcesList(rest)
	case "enable":
		return runSourcesEnable(rest)
	case "disable":
		return runSourcesDisable(rest)
	}
	fmt.Fprintf(os.Stderr, "unknown sources subcommand %q; try help\n", sub)
	os.Exit(2)
	return nil
}

func runSourcesList(args []string) error {
	fs := flag.NewFlagSet("sources list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
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
	store := grants.New(dir)
	config, err := store.Load()
	if err != nil {
		return err
	}
	enabled := make(map[string]bool)
	for _, grant := range config.Grants {
		if grant.Enabled {
			enabled[grant.Source+"\x00"+grant.Input] = true
		}
	}
	for _, source := range grants.KnownSources() {
		fmt.Printf("source %s\n", source)
	}
	for _, grant := range config.Grants {
		status := "disabled"
		if grant.Enabled {
			status = "enabled"
		}
		fmt.Printf("grant %s %s %s\n", grant.Source, grant.Input, status)
	}
	fmt.Printf("state=%s\n", store.Path())
	_ = enabled
	return nil
}

func runSourcesEnable(args []string) error {
	fs := flag.NewFlagSet("sources enable", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "adapter source (usage-json, codex-jsonl, claude-code-jsonl)")
	input := fs.String("input", "", "absolute local input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *input == "" {
		return fmt.Errorf("sources enable requires explicit --source and --input (no default scanning)")
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	grant, err := grants.New(dir).Enable(*source, *input)
	if err != nil {
		return err
	}
	fmt.Printf("enabled grant %s %s\n", grant.Source, grant.Input)
	fmt.Printf("state=%s\n", grants.New(dir).Path())
	return nil
}

func runSourcesDisable(args []string) error {
	fs := flag.NewFlagSet("sources disable", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "adapter source")
	input := fs.String("input", "", "local input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *input == "" {
		return fmt.Errorf("sources disable requires explicit --source and --input")
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	grant, found, err := grants.New(dir).Disable(*source, *input)
	if err != nil {
		return err
	}
	if !found {
		fmt.Printf("no grant for %s %s\n", *source, *input)
		return nil
	}
	fmt.Printf("disabled grant %s %s\n", grant.Source, grant.Input)
	fmt.Printf("state=%s\n", grants.New(dir).Path())
	return nil
}

func runPlugins(args []string) error {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail plugins")
		return flag.ErrHelp
	}
	// Plugins are compiled into the binary (no runtime plugin loading, no
	// unvetted code paths); this lists the built-in adapters and their
	// inputs so users can see what exists before granting anything.
	for _, plugin := range registry.All() {
		fmt.Printf("plugin %s %s\n", plugin.Source, plugin.Description)
	}
	fmt.Printf("note=plugins are compiled in; enable a grant with: toktrail sources enable --source <s> --input <path>\n")
	return nil
}

// ---------------------------------------------------------------------------
// service: install/uninstall the per-user scheduled collection task.
// Installing never binds a device, never scans, and never runs a
// collection; only the grants given explicitly with --grant are stored.
// ---------------------------------------------------------------------------

func runService(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail service <install|uninstall> [flags]")
		return flag.ErrHelp
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "install":
		return runServiceInstall(rest)
	case "uninstall":
		return runServiceUninstall(rest)
	}
	fmt.Fprintf(os.Stderr, "unknown service subcommand %q; try help\n", sub)
	os.Exit(2)
	return nil
}

func parseGrant(arg string) (source, input string, err error) {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid grant %q; expected --grant <source>=<absolute-input-path>", arg)
	}
	return parts[0], parts[1], nil
}

func runServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	dryRun := fs.Bool("dry-run", false, "print the rendered scheduler plan without changing anything")
	interval := fs.Duration("interval", scheduler.DefaultInterval, "scheduling interval (minimum 1m)")
	grantSpecs := multiFlag{}
	fs.Var(&grantSpecs, "grant", "explicit source grant for scheduled collection: <source>=<absolute-input-path>; repeatable")
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
	if len(grantSpecs) == 0 {
		return fmt.Errorf("service install requires at least one explicit --grant <source>=<input>; scheduled collection never scans by default")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Validate and persist grants BEFORE touching any scheduler file, so
	// a bad grant cannot leave a half-configured task behind. The state
	// process lock serializes this against concurrent commands.
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	store := grants.New(dir)
	for _, grantArg := range grantSpecs {
		source, input, err := parseGrant(grantArg)
		if err != nil {
			return err
		}
		if _, err := store.Enable(source, input); err != nil {
			return err
		}
	}
	plan, err := scheduler.Install(scheduler.InstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: dir,
			Binary:   binary,
			Interval: *interval,
			HomeDir:  home,
		},
		DryRun: *dryRun,
		Out:    os.Stdout,
	})
	if err != nil {
		return err
	}
	identity, _ := scheduler.TaskIdentity(dir)
	fmt.Printf("service=%s interval=%s\n", identity, *interval)
	fmt.Printf("scheduled command: %s periodic --state-dir %s\n", binary, plan.Marker)
	fmt.Printf("note=installing the service does not bind, scan, or collect; the first run happens after the first interval elapses\n")
	return nil
}

func runServiceUninstall(args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	dryRun := fs.Bool("dry-run", false, "print the uninstall plan without changing anything")
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
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Uninstall does not execute the binary, but the shared task-config
	// validation requires an absolute path so the rendered identity is
	// unambiguous; resolve the current executable like install does.
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	if _, err := scheduler.Uninstall(scheduler.UninstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: dir,
			Binary:   binary,
			Interval: scheduler.DefaultInterval,
			HomeDir:  home,
		},
		DryRun: *dryRun,
		Out:    os.Stdout,
	}); err != nil {
		return err
	}
	identity, _ := scheduler.TaskIdentity(dir)
	fmt.Printf("service=%s removed\n", identity)
	fmt.Printf("note=source grants and local state are kept; remove them manually if desired\n")
	return nil
}

// multiFlag collects repeatable string flags (--grant a=b --grant c=d).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// ---------------------------------------------------------------------------
// privacy / doctor
// ---------------------------------------------------------------------------

func runPrivacy(args []string) error {
	fs := flag.NewFlagSet("privacy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	source := fs.String("source", "", "narrow the report to one adapter source (with --input)")
	input := fs.String("input", "", "narrow the report to one input path (with --source)")
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
	reports, err := diagnostic.Privacy(diagnostic.PrivacyOptions{
		StateDir: dir,
		Source:   *source,
		Input:    *input,
	})
	if err != nil {
		return err
	}
	if len(reports) == 0 {
		fmt.Printf("no enabled source grants; nothing scanned (privacy performs no network access)\n")
		return nil
	}
	for _, report := range reports {
		fmt.Printf("source=%s input=%s\n", report.Source, report.Input)
		fmt.Printf("records=%d valid=%d invalid=%d quarantined=%d\n", report.RecordCount, report.ValidRecords, report.InvalidRecords, report.Quarantined)
		fmt.Printf("uploadSafeRecords=%d tokensInclude=%s tokensExclude=%s\n", report.UploadSafeRecords, formatOptionalUint(report.TokensInclude), formatOptionalUint(report.TokensExclude))
		if report.Earliest != nil && report.Latest != nil {
			fmt.Printf("range=%s..%s\n", report.Earliest.Format(time.RFC3339), report.Latest.Format(time.RFC3339))
		}
		for _, tool := range adapter.SortedTools(report.Tools) {
			fmt.Printf("tool[%s]=%d\n", tool, report.Tools[tool])
		}
		fmt.Printf("outboxPending=%d outboxPendingRecords=%d\n", report.OutboxPending, report.OutboxPendingRecords)
	}
	fmt.Printf("note=privacy is local-only; no network access was performed\n")
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	checkServer := fs.Bool("check-server", false, "also check the server device status (the only networked check)")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
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
	binary := ""
	if executable, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(executable); err == nil {
			binary = abs
		}
	}
	home := ""
	if h, err := os.UserHomeDir(); err == nil {
		home = h
	}
	report, err := diagnostic.Doctor(diagnostic.DoctorOptions{
		StateDir:    dir,
		CheckServer: *checkServer,
		ServerURL:   *serverURL,
		Binary:      binary,
		HomeDir:     home,
	})
	if err != nil {
		return err
	}
	for _, check := range report.Checks {
		fmt.Printf("%s %s %s\n", check.Status, check.Name, check.Detail)
	}
	if report.Failed() {
		return fmt.Errorf("doctor found failing checks (see above)")
	}
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printHelp() {
	fmt.Println(`toktrail collector scaffold

Commands:
  version                    print collector version
  connect '<URL>'            one-step device setup via connect URL/ticket: fetches
                             server configuration, binds device, probes local tools,
                             configures source grants, installs scheduled service,
                             and runs initial collection
  bind                       bind this device to toktrail-server using explicit upload authorization
  status                     check bound device authorization from toktrail-server
  scan [--source usage-json|codex-jsonl|claude-code-jsonl] --input <path>
                              locally scan usage records without network/account access
  preview [--source usage-json|codex-jsonl|claude-code-jsonl] --input <path>
                              preview local usage records
  export [--source usage-json|codex-jsonl|claude-code-jsonl] --input <path> --out <batch.json>
                              export local records and add a pending outbox batch
  sync [--file <batch.json>]  preflight device authorization, then upload a local batch
                              (or the oldest pending outbox batch) with the current
                              consent revision; revoked/deleted devices stop sending

Planned by the approved architecture:
  sources / plugins            adapter visibility and enablement
  service install|uninstall    platform scheduled sync
  privacy / doctor             consent and diagnostics

Scheduling and diagnostics (implemented):
  periodic [--state-dir <dir>] [--max-batches <n>]
                               complete-exit scheduled run: collect the
                               enabled source grants only (no default
                               scanning), export via the WAL, then drain a
                               bounded number of pending batches with the
                               existing server-consent preflight; one
                               process lock covers the whole run
  sources list                 show built-in sources and enabled grants
  sources enable --source <s> --input <path>
                               grant scheduled collection an explicit
                               source+input (manual scan/export semantics
                               are unchanged)
  sources disable --source <s> --input <path>
                               revoke that grant
  plugins                      list the compiled-in adapters
  service install --grant <source>=<input> [--interval 30m] [--dry-run]
                               install the per-user scheduled task
                               (launchd / user systemd timer / Task
                               Scheduler); user scope only; does NOT bind,
                               scan, or collect
  service uninstall            remove the per-user scheduled task (keeps
                               local state and grants)
  privacy [--source <s> --input <path>]
                               local-only report of what would be uploaded;
                               never touches the network
  doctor [--check-server]      local health checks; the server check is the
                               only networked one and is opt-in

Implementation migrates one tool adapter first, then expands coverage.`)
}
