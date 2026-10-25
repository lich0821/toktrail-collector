package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
)

var connectSchedulerRunner scheduler.Runner // injectable for tests

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	deviceName := fs.String("device-name", "", "optional device name override")
	interval := fs.Duration("interval", scheduler.DefaultInterval, "scheduled collection interval (minimum 1m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: toktrail connect [flags] '<URL>'")
	}
	connectURL := rest[0]
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
	_, err := connect.Run(ctx, connect.Options{
		URL:             connectURL,
		StateDir:        dir,
		DeviceName:      *deviceName,
		Interval:        *interval,
		SchedulerRunner: connectSchedulerRunner,
		Out:             os.Stdout,
	})
	return err
}
