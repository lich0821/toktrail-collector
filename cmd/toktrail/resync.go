package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	resynccmd "toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

func runResync(args []string) error {
	return runResyncWithIO(args, os.Stdin, os.Stdout)
}

func runResyncWithIO(args []string, input io.Reader, output io.Writer) error {
	fs := flag.NewFlagSet("resync", flag.ContinueOnError)
	fs.SetOutput(output)
	all := fs.Bool("all", false, "resynchronize usage within the current authorization")
	dryRun := fs.Bool("dry-run", false, "offline read-only plan; remote scope is not verified")
	yes := fs.Bool("yes", false, "confirm retransmission without an interactive prompt")
	replaceExisting := fs.Bool("replace-existing", false, "override mode: scan the CURRENT Codex and DeepSeek Harness sources and replace same-key server records with the current scanned record (explicit confirmation required)")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "server base URL; defaults to bound server")
	maxBatches := fs.Int("max-batches", 0, "upload budget; 0 processes the entire frozen plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*all {
		return errors.New("resync requires --all; use --all --dry-run to inspect the plan first")
	}
	if fs.NArg() != 0 {
		return errors.New("resync accepts flags only, no positional arguments")
	}
	if *maxBatches < 0 {
		return errors.New("--max-batches must be zero or a positive integer")
	}
	if *dryRun && *yes {
		return errors.New("--dry-run and --yes cannot be combined: dry-run never uploads")
	}
	dir := strings.TrimSpace(*stateDir)
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	if !*dryRun {
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return err
		}
		if err := lock.Close(); err != nil {
			return err
		}
	}
	printPlan := func(plan resynccmd.Plan) {
		fmt.Fprintf(output, "resync target: server=%s device=%s\n", plan.ServerURL, plan.DeviceID)
		fmt.Fprintf(output, "plan: batches=%d records=%d resumed=%t alreadyDone=%d\n", len(plan.Batches), plan.PlannedRecords, plan.Resumed, plan.DoneInJob)
		fmt.Fprintf(output, "excluded: pendingBatches=%d reorganizedParents=%d localGrantBatches=%d quarantineRecords=%d\n", plan.ExcludedPending, plan.ExcludedReorganized, len(plan.ExcludedLocalGrant), plan.QuarantinedRecords)
		fmt.Fprintln(output, plan.CoverageNote)
		fmt.Fprintln(output, "De-duplication applies to the current device only; this command never creates a device or clears progress.")
	}
	printOverridePlan := func(plan resynccmd.OverridePlan) {
		fmt.Fprintf(output, "override target: server=%s device=%s\n", plan.ServerURL, plan.DeviceID)
		fmt.Fprintf(output, "override plan (current source scans only):\n")
		for _, sp := range plan.Sources {
			fmt.Fprintf(output, "  %s %s: scanned=%d drifted=%d new=%d frozenAttempts=%d alreadyCurrent=%d invalid=%d scanIssues=%d scanQuarantined=%d\n",
				sp.Source, sp.Input, sp.Scanned, sp.Drifted, sp.NewRecords, sp.FrozenAttempts, sp.AlreadyCurrent, sp.InvalidRecords, sp.ScanIssues, sp.ScanQuarantined)
			if len(sp.InvalidKeys) > 0 {
				fmt.Fprintf(output, "    invalid keys (first %d): %s\n", len(sp.InvalidKeys), strings.Join(sp.InvalidKeys, ", "))
			}
		}
		if len(plan.ExcludedSources) > 0 {
			fmt.Fprintf(output, "excluded sources (not part of the override): %s\n", strings.Join(plan.ExcludedSources, "; "))
		}
		if plan.WithheldNoGrant > 0 {
			fmt.Fprintf(output, "pending override attempts with no enabled grant (stay pending): %d\n", plan.WithheldNoGrant)
		}
		fmt.Fprintf(output, "totals: replace=%d insert=%d\n", plan.TotalReplace, plan.TotalNew)
		fmt.Fprintln(output, plan.Warning)
		fmt.Fprintln(output, "De-duplication applies to the current device only; this command never creates a device or clears progress.")
	}
	confirm := func(plan resynccmd.Plan) error {
		printPlan(plan)
		if *yes {
			return nil
		}
		fmt.Fprint(output, "Resynchronize usage under the live server consent? [y/N] ")
		scanner := bufio.NewScanner(input)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return errors.New("confirmation not provided; use --yes only after reviewing the plan")
		}
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if answer != "y" && answer != "yes" {
			return errors.New("cancelled")
		}
		return nil
	}
	confirmOverride := func(plan resynccmd.OverridePlan) error {
		printOverridePlan(plan)
		if plan.TotalReplace == 0 && plan.TotalNew == 0 {
			fmt.Fprintln(output, "nothing to override: the current scans already match the effective baselines")
		}
		if *yes {
			return nil
		}
		fmt.Fprint(output, "Replace server records that conflict with the CURRENT scan of the granted Codex/DeepSeek Harness sources? [y/N] ")
		scanner := bufio.NewScanner(input)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return errors.New("confirmation not provided; use --yes only after reviewing the plan")
		}
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if answer != "y" && answer != "yes" {
			return errors.New("cancelled")
		}
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *replaceExisting {
		if *dryRun {
			result, err := resynccmd.RunOverride(ctx, resynccmd.OverrideOptions{StateDir: dir, ServerURL: *serverURL, DryRun: true})
			if err == nil {
				printOverridePlan(result.Plan)
				fmt.Fprintln(output, "dry-run: offline plan only; the remote consent scope, the server's replace-existing capability, and scope withholding are not evaluated")
			}
			return err
		}
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return err
		}
		if err := lock.Close(); err != nil {
			return err
		}
		cursorOpts, err := cursorSyncOptions(dir, *serverURL, nil)
		if err != nil {
			return err
		}
		cursorOpts.Out = output
		result, err := connect.Sync(ctx, connect.SyncOptions{
			StateDir: dir, ServerURL: *serverURL, Cursor: cursorOpts, Out: output,
			ResyncReplaceExisting: true,
			ResyncMaxBatches:      *maxBatches,
			ResyncOverrideConfirm: confirmOverride,
			ResyncOverrideProgress: func(event resynccmd.OverrideProgressEvent) {
				fmt.Fprintf(output, "override batch %s: %s records=%d accepted=%d rejected=%d replay=%t\n", event.BatchID, event.Outcome, event.Records, event.Accepted, event.Rejected, event.Replay)
			},
		})
		_ = result
		if err != nil {
			return err
		}
		if !result.Resync.Completed {
			fmt.Fprintln(output, "Run the same resync --all --replace-existing command again to resume the override pass.")
		}
		return nil
	}
	if *dryRun {
		result, err := resynccmd.Run(ctx, resynccmd.Options{StateDir: dir, ServerURL: *serverURL, DryRun: true})
		if err == nil {
			printPlan(result.Plan)
			fmt.Fprintln(output, "dry-run: archive plan only; source scanning, quarantine recovery and remote consent are not evaluated")
		}
		return err
	}
	cursorOpts, err := cursorSyncOptions(dir, *serverURL, nil)
	if err != nil {
		return err
	}
	cursorOpts.Out = output
	result, err := connect.Sync(ctx, connect.SyncOptions{
		StateDir: dir, ServerURL: *serverURL, Cursor: cursorOpts, Out: output,
		ResyncDryRun: *dryRun, ResyncMaxBatches: *maxBatches, ResyncConfirm: confirm,
		ResyncProgress: func(event resynccmd.ProgressEvent) {
			fmt.Fprintf(output, "batch %s: %s submitted=%d accepted=%d rejected=%d skipped=%d replay=%t\n", event.BatchID, event.Outcome, event.Uploaded, event.Accepted, event.Rejected, event.Skipped, event.Replay)
		},
	})
	if result.Resync.Remaining > 0 {
		fmt.Fprintln(output, "Run the same resync --all command again to resume.")
	}
	return err
}
