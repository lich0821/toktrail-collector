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
	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/registry"
)

// Run coordinates the full connect orchestration:
// 1. Fetching server configuration via one-time ticket over HTTPS / loopback HTTP.
// 2. Binding device credentials (or skipping if already bound for this ticket/url receipt).
// 3. Probing locally available sources based on server-specified tool list and local disk existence.
// 4. Configuring local source grants (disabling previously active grants not in the new set).
// 5. Installing the scheduled background service.
// 6. Performing an initial collection run (without nested state locks).
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
		if cfg.Days > 0 {
			t := nowFn().UTC().AddDate(0, 0, -cfg.Days)
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
			if isNewReceipt || st.HistoryFrom == nil {
				if cutoff != nil {
					st.HistoryFrom = cutoff
					st.HistoryDays = cfg.Days
				} else {
					st.HistoryFrom = nil
					st.HistoryDays = 0
				}
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
			if cutoff != nil {
				st.HistoryFrom = cutoff
				st.HistoryDays = cfg.Days
			} else {
				st.HistoryFrom = nil
				st.HistoryDays = 0
			}
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save bound state: %w", err)
			}
			fmt.Fprintf(out, "bound device %s (consentRevision=%d)\n", deviceID, consentRev)
		}

		// Tool probing
		var grantsToApply []grants.Grant
		for _, toolName := range cfg.Tools {
			spec, ok := registry.LookupTool(toolName)
			if !ok {
				fmt.Fprintf(out, "tool %q: unsupported tool; skipped\n", toolName)
				continue
			}
			targetDir := spec.ResolveDefaultInput(homeDir)
			stat, err := os.Stat(targetDir)
			if err != nil || !stat.IsDir() {
				fmt.Fprintf(out, "tool %q: directory %s not found; skipped\n", spec.Tool, targetDir)
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
		if len(enabledGrants) == 0 {
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
		return nil
	}

	err = lockedWork()
	_ = lock.Close()
	if err != nil {
		return Result{}, err
	}

	// 6. Initial collection run (collection.Run acquires its own state lock)
	fmt.Fprintf(out, "running initial collection...\n")
	periodicResult, err := collection.Run(ctx, collection.Options{
		StateDir:   stateDir,
		ServerURL:  cfg.ServerURL,
		MaxBatches: collection.DefaultMaxSyncBatches,
		HTTPClient: opt.HTTPClient,
		Now:        nowFn,
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
