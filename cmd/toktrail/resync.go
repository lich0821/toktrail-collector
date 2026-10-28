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
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
)

func runResync(args []string) error {
	return runResyncWithIO(args, os.Stdin, os.Stdout)
}

func runResyncWithIO(args []string, input io.Reader, output io.Writer) error {
	fs := flag.NewFlagSet("resync", flag.ContinueOnError)
	fs.SetOutput(output)
	all := fs.Bool("all", false, "retransmit all eligible already-synced device batches")
	dryRun := fs.Bool("dry-run", false, "offline read-only plan; remote scope is not verified")
	yes := fs.Bool("yes", false, "confirm retransmission without an interactive prompt")
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
	// A dry run must not even create the process lock file. Its plan is a
	// read-only snapshot; execution takes the same lock as periodic collection.
	if !*dryRun {
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	printPlan := func(plan resynccmd.Plan) {
		fmt.Fprintf(output, "resync target: server=%s device=%s\n", plan.ServerURL, plan.DeviceID)
		fmt.Fprintf(output, "plan: batches=%d records=%d resumed=%t alreadyDone=%d\n", len(plan.Batches), plan.PlannedRecords, plan.Resumed, plan.DoneInJob)
		fmt.Fprintf(output, "excluded: pendingBatches=%d reorganizedParents=%d localGrantBatches=%d quarantineRecords=%d\n", plan.ExcludedPending, plan.ExcludedReorganized, len(plan.ExcludedLocalGrant), plan.QuarantinedRecords)
		fmt.Fprintln(output, plan.CoverageNote)
		fmt.Fprintln(output, "De-duplication applies to the current device only; this command never creates a device or clears progress.")
	}
	confirm := func(plan resynccmd.Plan) error {
		printPlan(plan)
		if *yes {
			return nil
		}
		fmt.Fprint(output, "Retransmit this history under the live server consent? [y/N] ")
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
	result, err := resynccmd.Run(ctx, resynccmd.Options{
		StateDir: dir, ServerURL: *serverURL, DryRun: *dryRun, MaxBatches: *maxBatches, Confirm: confirm,
		Progress: func(event resynccmd.ProgressEvent) {
			fmt.Fprintf(output, "batch %s: %s submitted=%d accepted=%d rejected=%d skipped=%d replay=%t\n", event.BatchID, event.Outcome, event.Uploaded, event.Accepted, event.Rejected, event.Skipped, event.Replay)
		},
	})
	if result.DryRun {
		printPlan(result.Plan)
		fmt.Fprintln(output, "dry-run: offline, no files changed, remote consent scope NOT verified; execution checks consent before every upload")
		return err
	}
	if result.JournalPath != "" {
		fmt.Fprintf(output, "resync: completed=%t uploads=%d submitted=%d accepted=%d rejected=%d blocked=%d skipped=%d remaining=%d\n", result.Completed, result.Uploads, result.UploadedRecords, result.AcceptedRecords, result.RejectedRecords, result.Blocked, result.SkippedOutOfScopeRecords, result.Remaining)
		if result.Stopped != "" {
			fmt.Fprintln(output, result.Stopped)
		}
		if result.Remaining > 0 {
			fmt.Fprintln(output, "Run the same resync --all command again to resume; completed batches in this job are preserved.")
		}
		if result.Blocked > 0 || result.SkippedOutOfScopeRecords > 0 {
			fmt.Fprintln(output, "Some history was not restored because it is outside current authorization; original archives remain unchanged.")
		}
	}
	return err
}
