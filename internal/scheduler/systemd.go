package scheduler

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// systemdUnitPath returns the user unit file path for a suffix
// (".service" or ".timer").
func systemdUnitPath(cfg TaskConfig, identity, suffix string) string {
	return filepath.Join(cfg.HomeDir, ".config", "systemd", "user", identity+suffix)
}

// renderSystemdInstall renders a user-level systemd oneshot service plus a
// timer that runs it every interval. The timer is the enabled unit; the
// service is a complete-exit Type=oneshot job.
func renderSystemdInstall(cfg TaskConfig, plan Plan) (Plan, error) {
	servicePath := systemdUnitPath(cfg, plan.TaskName, ".service")
	timerPath := systemdUnitPath(cfg, plan.TaskName, ".timer")
	plan.EnsureDirs = []string{filepath.Dir(servicePath)}
	plan.Files = []FileWrite{
		{
			Path:    servicePath,
			Mode:    0o644,
			Content: renderSystemdService(plan.TaskName, cfg.Binary, plan.Marker, cfg.Interval),
		},
		{
			Path:    timerPath,
			Mode:    0o644,
			Content: renderSystemdTimer(plan.TaskName, cfg.StateDir, cfg.Interval),
		},
	}
	plan.Commands = []Command{
		{
			Name:    "systemctl",
			Args:    []string{"--user", "daemon-reload"},
			Purpose: "reload user systemd units",
		},
		{
			Name:    "systemctl",
			Args:    []string{"--user", "enable", "--now", plan.TaskName + ".timer"},
			Purpose: "enable and start the collection timer",
		},
	}
	plan.UndoCommands = []Command{
		{
			Name:       "systemctl",
			Args:       []string{"--user", "disable", "--now", plan.TaskName + ".timer"},
			Purpose:    "disable the partially installed timer",
			BestEffort: true,
		},
		{
			Name:       "systemctl",
			Args:       []string{"--user", "daemon-reload"},
			Purpose:    "reload user systemd units after rollback",
			BestEffort: true,
		},
	}
	plan.UninstallCommands = []Command{
		{
			Name:       "systemctl",
			Args:       []string{"--user", "disable", "--now", plan.TaskName + ".timer"},
			Purpose:    "stop and disable the collection timer",
			BestEffort: true,
		},
	}
	plan.PostRemoveCommands = []Command{
		{
			Name:       "systemctl",
			Args:       []string{"--user", "daemon-reload"},
			Purpose:    "drop the removed units from the user manager",
			BestEffort: true,
		},
	}
	plan.RemoveFiles = []string{servicePath, timerPath}
	return plan, nil
}

func renderSystemdUninstall(cfg TaskConfig, plan Plan) (Plan, error) {
	servicePath := systemdUnitPath(cfg, plan.TaskName, ".service")
	timerPath := systemdUnitPath(cfg, plan.TaskName, ".timer")
	plan.UninstallCommands = []Command{
		{
			Name:       "systemctl",
			Args:       []string{"--user", "disable", "--now", plan.TaskName + ".timer"},
			Purpose:    "stop and disable the collection timer",
			BestEffort: true,
		},
	}
	plan.PostRemoveCommands = []Command{
		{
			Name:       "systemctl",
			Args:       []string{"--user", "daemon-reload"},
			Purpose:    "drop the removed units from the user manager",
			BestEffort: true,
		},
	}
	plan.RemoveFiles = []string{servicePath, timerPath}
	return plan, nil
}

// renderSystemdService writes the oneshot service unit. ExecStart uses
// systemd argument quoting (no shell is involved).
func renderSystemdService(identity, binary, stateDir string, interval time.Duration) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=TokTrail collector scheduled collection (user, complete-exit)\n")
	fmt.Fprintf(&b, "Documentation=file:%s\n", stateDir)
	fmt.Fprintf(&b, "X-TokTrail-Task=%s\n", identity)
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=oneshot\n")
	execArgs := []string{systemdEscapeArg(binary), "periodic", "--state-dir", systemdEscapeArg(stateDir)}
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(execArgs, " "))
	// The periodic entry holds the state process lock for the whole run;
	// an overlapping start fails fast with the lock error instead of
	// racing, so no extra systemd-level serialization is needed.
	b.WriteString("# overlapping runs are refused by the collector's process lock\n")
	return b.String()
}

// renderSystemdTimer writes the timer unit.
func renderSystemdTimer(identity, stateDir string, interval time.Duration) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=TokTrail collector scheduled collection timer\n")
	// The timer must carry the identity and state-dir marker too so
	// uninstall's owned-file validation covers both owned units.
	fmt.Fprintf(&b, "Documentation=file:%s\n", stateDir)
	fmt.Fprintf(&b, "X-TokTrail-Task=%s\n\n", identity)
	b.WriteString("[Timer]\n")
	fmt.Fprintf(&b, "Unit=%s.service\n", identity)
	fmt.Fprintf(&b, "OnBootSec=2m\n")
	fmt.Fprintf(&b, "OnUnitActiveSec=%s\n", formatSystemdDuration(interval))
	b.WriteString("AccuracySec=30s\n")
	b.WriteString("Persistent=false\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=timers.target\n")
	return b.String()
}

// formatSystemdDuration renders a time.Duration as a systemd duration
// (seconds precision is enough for scheduling intervals).
func formatSystemdDuration(d time.Duration) string {
	secs := int64(d / time.Second)
	if secs%60 == 0 {
		return fmt.Sprintf("%dm", secs/60)
	}
	return fmt.Sprintf("%ds", secs)
}
