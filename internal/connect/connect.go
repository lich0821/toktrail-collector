package connect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// Run coordinates the full connect orchestration:
// 1. Fetching server configuration via one-time ticket over HTTPS / loopback HTTP.
// 2. Binding device credentials (or skipping if already bound for this ticket/url receipt).
//  3. Probing locally available sources based on server-specified tool list and local disk existence.
//  4. Configuring local source grants (disabling previously active grants not in the new set).
//  5. Installing the scheduled background service.
//  6. Reporting probe-only tool statuses to the server (unsupported tools, missing default
//     directories); activated tools are reported by the collection flow (synced / no_new_records).
//  7. Performing an initial collection run (without nested state locks).
func Run(ctx context.Context, opt Options) (Result, error) {
	out := opt.Out
	if out == nil {
		out = io.Discard
	}

	nowFn := opt.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()

	homeDir := opt.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return Result{}, fmt.Errorf("user home directory: %w", err)
		}
	}

	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("state directory is required")
	}

	binary := opt.BinaryPath
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("executable path: %w", err)
		}
		binary, err = filepath.Abs(binary)
		if err != nil {
			return Result{}, fmt.Errorf("absolute executable path: %w", err)
		}
	}

	interval := opt.Interval
	if interval == 0 {
		interval = scheduler.DefaultInterval
	}
	opt.HTTPClient = newSafeHTTPClient(opt.HTTPClient)

	// 1. Parse connect URL and ticket
	strippedURL, ticket, err := parseAndValidateConnectURL(opt.URL)
	if err != nil {
		return Result{}, err
	}

	// 2. Fetch server configuration via ticket
	cfg, err := fetchConnectConfig(ctx, opt.HTTPClient, strippedURL, ticket, now)
	if err != nil {
		return Result{}, err
	}
	fmt.Fprintf(out, "connected to %s (applicationId=%s, subjectId=%s)\n", strippedURL, cfg.ApplicationID, cfg.SubjectID)

	// Compute deterministic receipt fingerprint (SHA-256 of ticket and canonical URL).
	fingerprint := computeReceiptFingerprint(ticket, strippedURL)

	// 3-5. Perform state-locked setup operations
	var (
		deviceID        string
		consentRev      int64
		skippedBind     bool
		authorizedTools []string
		serviceIdentity string
	)

	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}

	lockedWork := func() error {
		store := statedir.New(stateDir)
		st, err := store.Load()
		if err != nil {
			return err
		}

		deviceName := opt.DeviceName
		if deviceName == "" {
			deviceName = "toktrail-collector"
		}
		platform := runtime.GOOS + "-" + runtime.GOARCH
		bindFp := bind.Fingerprint(cfg.ServerURL, ticket, cfg.ApplicationID, cfg.SubjectID, deviceName, platform)

		var cutoff *time.Time
		historyDays := 0
		if cfg.Days != nil {
			historyDays = *cfg.Days
			t := nowFn().UTC().AddDate(0, 0, -historyDays)
			cutoff = &t
		}

		if shouldSkipBind(st, fingerprint, bindFp, cfg) {
			skippedBind = true
			deviceID = st.DeviceID
			consentRev = st.ConsentRevision
			needSave := false
			isNewReceipt := st.ConnectReceiptHash != fingerprint
			if isNewReceipt {
				st.ConnectReceiptHash = fingerprint
				st.PendingConnectReceiptHash = ""
				needSave = true
			}
			if isNewReceipt || cfg.Days == nil || st.HistoryFrom == nil || st.HistoryFrom.IsZero() {
				applyHistoryCutoff(&st, cutoff, historyDays)
				needSave = true
			}
			if needSave {
				if err := store.Save(st); err != nil {
					return fmt.Errorf("save state: %w", err)
				}
			}
			fmt.Fprintf(out, "device %s already bound; skipping bind\n", deviceID)
		} else {
			skippedBind = false
			st.PendingConnectReceiptHash = fingerprint
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save pending state: %w", err)
			}

			bindRes, err := bind.Run(ctx, store, bind.Options{
				ServerURL:         cfg.ServerURL,
				Ticket:            ticket,
				ApplicationID:     cfg.ApplicationID,
				ExternalSubjectID: cfg.SubjectID,
				DeviceName:        opt.DeviceName,
				HTTPClient:        opt.HTTPClient,
				Now:               nowFn,
			})
			if err != nil {
				return fmt.Errorf("device bind failed: %w", sanitizeError(err, ticket))
			}
			deviceID = bindRes.State.DeviceID
			consentRev = bindRes.State.ConsentRevision

			st, err = store.Load()
			if err != nil {
				return err
			}
			st.ConnectReceiptHash = fingerprint
			st.PendingConnectReceiptHash = ""
			applyHistoryCutoff(&st, cutoff, historyDays)
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save bound state: %w", err)
			}
			fmt.Fprintf(out, "bound device %s (consentRevision=%d)\n", deviceID, consentRev)
		}

		// Tool probing. Tools that could not be activated are reported to
		// the server with probe-only statuses (unsupported /
		// not_detected); activated tools are reported by the collection
		// flow with synced / no_new_records and are intentionally absent
		// here. Duplicate entries in cfg.Tools are collapsed by tool name
		// so the report stays within the tool-status contract.
		var grantsToApply []grants.Grant
		var probeStatuses []syncclient.ToolStatus
		reportedProbe := map[string]bool{}
		for _, toolName := range cfg.Tools {
			spec, ok := registry.LookupTool(toolName)
			if !ok {
				fmt.Fprintf(out, "tool %q: unsupported tool; skipped\n", toolName)
				if !reportedProbe[toolName] {
					reportedProbe[toolName] = true
					probeStatuses = append(probeStatuses, syncclient.ToolStatus{
						Tool:   toolName,
						Status: "unsupported",
						Detail: "unsupported tool",
					})
				}
				continue
			}
			if spec.IsAccountNetwork() {
				// Account-network tools never map to a local directory
				// grant. The first-time local confirmation (integrated
				// enable) runs here, inside the state lock, because the
				// server-side enable and the license write are state
				// mutations; an existing permit defers to the initial
				// collection. A confirmation failure is a clear skip — it
				// never fails the whole connect run (the other tools keep
				// their setup) and never reports a fabricated tool status.
				if opt.Cursor == nil {
					fmt.Fprintf(out, "tool %q: account source; this build has no cursor wiring, skipped\n", spec.Tool)
					continue
				}
				license, hasLicense, lErr := cursorsource.New(stateDir).Load()
				if lErr != nil {
					return lErr
				}
				if hasLicense && license.Collectable() {
					fmt.Fprintf(out, "tool %q: local permit already active; the initial collection continues it\n", spec.Tool)
					authorizedTools = append(authorizedTools, spec.Tool)
					continue
				}
				enableOpts := *opt.Cursor
				enableOpts.StateDir = stateDir
				enableOpts.ServerURL = cfg.ServerURL
				enableOpts.HTTPClient = opt.HTTPClient
				enableOpts.Out = out
				enableRes, enableErr := cursorsync.Enable(ctx, enableOpts, opt.CursorConfirm)
				if enableErr != nil {
					fmt.Fprintf(out, "tool %q: %v\n", spec.Tool, enableErr)
					fmt.Fprintf(out, "tool %q: not enabled; run `toktrail cursor enable` in a terminal to confirm locally\n", spec.Tool)
					continue
				}
				fmt.Fprintf(out, "tool %q: enabled (sourceInstanceId=%s, state=%s)\n", spec.Tool, enableRes.Source.SourceInstanceID, enableRes.Source.State)
				if enableRes.Sync.Ran {
					fmt.Fprintf(out, "tool %q: first sync pulled=%d new=%d replaced=%d uploaded=%d pending=%d\n",
						spec.Tool, enableRes.Sync.PulledEvents, enableRes.Sync.NewRecords, enableRes.Sync.ReplacedRecords, enableRes.Sync.SyncedRecords, enableRes.Sync.PendingRemaining)
				}
				authorizedTools = append(authorizedTools, spec.Tool)
				continue
			}
			targetDir := spec.ResolveDefaultInput(homeDir)
			stat, err := os.Stat(targetDir)
			if err != nil || !stat.IsDir() {
				fmt.Fprintf(out, "tool %q: directory %s not found; skipped\n", spec.Tool, targetDir)
				if !reportedProbe[spec.Tool] {
					reportedProbe[spec.Tool] = true
					probeStatuses = append(probeStatuses, syncclient.ToolStatus{
						Tool:   spec.Tool,
						Status: "not_detected",
						Detail: "default directory not found",
					})
				}
				continue
			}
			fmt.Fprintf(out, "tool %q: detected directory %s; authorized\n", spec.Tool, targetDir)
			authorizedTools = append(authorizedTools, spec.Tool)
			grantsToApply = append(grantsToApply, grants.Grant{
				Source: spec.Source,
				Input:  targetDir,
			})
		}

		grantStore := grants.New(stateDir)
		enabledGrants, err := grantStore.ApplyConnectGrants(grantsToApply)
		if err != nil {
			return fmt.Errorf("apply grants: %w", err)
		}
		if len(enabledGrants) == 0 && len(authorizedTools) == 0 {
			// Account-network tools (Cursor) never create local grants;
			// a run that enabled one is not "no sources active".
			fmt.Fprintf(out, "warning: no tool directories detected locally; no sources active\n")
		}

		// Scheduler installation
		plan, err := scheduler.Install(scheduler.InstallOptions{
			Config: scheduler.TaskConfig{
				Platform: runtime.GOOS,
				StateDir: stateDir,
				Binary:   binary,
				Interval: interval,
				HomeDir:  homeDir,
			},
			Runner: opt.SchedulerRunner,
			DryRun: opt.DryRun,
			Out:    out,
		})
		if err != nil {
			return fmt.Errorf("install service failed: %w", err)
		}
		serviceIdentity = plan.TaskName
		fmt.Fprintf(out, "installed service %s (interval=%s)\n", plan.TaskName, interval)

		// 6. Report probe-only tool statuses to the server. Older servers
		// that have not deployed the tool-status endpoint answer 404/405,
		// which ReportToolStatuses tolerates. Any other failure surfaces:
		// the connect run fails rather than silently dropping the report.
		if len(probeStatuses) > 0 {
			_, err := syncclient.ReportToolStatuses(ctx, store, syncclient.Options{
				StateDir:     stateDir,
				ServerURL:    cfg.ServerURL,
				HTTPClient:   opt.HTTPClient,
				ToolStatuses: probeStatuses,
			})
			if err != nil {
				return fmt.Errorf("report tool statuses failed: %w", sanitizeError(err, ticket))
			}
		}
		return nil
	}

	err = lockedWork()
	_ = lock.Close()
	if err != nil {
		return Result{}, err
	}

	// 7. Initial collection run (collection.Run acquires its own state lock)
	fmt.Fprintf(out, "running initial collection...\n")
	cursorOpts := opt.Cursor
	if cursorOpts != nil {
		c := *cursorOpts
		c.StateDir = stateDir
		c.ServerURL = cfg.ServerURL
		c.HTTPClient = opt.HTTPClient
		c.Out = out
		cursorOpts = &c
	}
	periodicResult, err := collection.Run(ctx, collection.Options{
		StateDir:   stateDir,
		ServerURL:  cfg.ServerURL,
		MaxBatches: collection.DefaultMaxSyncBatches,
		HTTPClient: opt.HTTPClient,
		Now:        nowFn,
		Cursor:     cursorOpts,
	})
	if err != nil {
		return Result{
			DeviceID:         deviceID,
			ServerURL:        cfg.ServerURL,
			ApplicationID:    cfg.ApplicationID,
			SubjectID:        cfg.SubjectID,
			ConsentRevision:  consentRev,
			SkippedBind:      skippedBind,
			AuthorizedTools:  authorizedTools,
			InstalledService: serviceIdentity,
		}, fmt.Errorf("initial collection failed: %w", err)
	}

	if periodicResult.NoGrants {
		fmt.Fprintf(out, "initial collection: no enabled source grants; skipped\n")
	} else {
		fmt.Fprintf(out, "initial collection: exportedBatches=%d exportedRecords=%d syncedBatches=%d syncedRecords=%d\n",
			periodicResult.ExportedBatches, periodicResult.ExportedRecords,
			periodicResult.SyncedBatches, periodicResult.SyncedRecords)
	}
	if periodicResult.Cursor.Ran {
		// The account-level cursor round is independent of the local
		// grant counts above; surface it so a cursor-only device never
		// looks like an all-zero run.
		fmt.Fprintf(out, "initial collection: cursor pulledEvents=%d newRecords=%d replacedRecords=%d uploadedRecords=%d pendingBatches=%d\n",
			periodicResult.Cursor.PulledEvents, periodicResult.Cursor.NewRecords,
			periodicResult.Cursor.ReplacedRecords, periodicResult.Cursor.SyncedRecords,
			periodicResult.Cursor.PendingRemaining)
	}

	return Result{
		DeviceID:         deviceID,
		ServerURL:        cfg.ServerURL,
		ApplicationID:    cfg.ApplicationID,
		SubjectID:        cfg.SubjectID,
		ConsentRevision:  consentRev,
		SkippedBind:      skippedBind,
		AuthorizedTools:  authorizedTools,
		InstalledService: serviceIdentity,
		PeriodicResult:   periodicResult,
	}, nil
}

// applyHistoryCutoff pins the consented history window without ever
// shrinking it. Bind and rebind must not orphan records an earlier consent
// already authorized: narrowing HistoryFrom would move already-collected
// records before the cutoff, where the pipeline quarantines them as
// before_history_from. A cutoff is applied only when it widens the window
// (no current cutoff, or an earlier date); HistoryDays keeps the widest
// window ever granted. A nil cutoff means unlimited history — the widest
// window — so it clears any pinned cutoff. Baselines, the outbox, and
// collection progress live in separate stores and are never rewritten by
// bind or rebind.
func applyHistoryCutoff(st *statedir.DeviceState, cutoff *time.Time, days int) {
	if cutoff == nil {
		st.HistoryFrom = nil
		st.HistoryDays = 0
		return
	}
	if st.HistoryFrom == nil || st.HistoryFrom.IsZero() || cutoff.Before(*st.HistoryFrom) {
		st.HistoryFrom = cutoff
		st.HistoryDays = days
		return
	}
	if days > st.HistoryDays {
		st.HistoryDays = days
	}
}
