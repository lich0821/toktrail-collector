package scheduler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// launchdPath returns the LaunchAgent plist path for this task identity.
func launchdPath(cfg TaskConfig, identity string) string {
	return filepath.Join(cfg.HomeDir, "Library", "LaunchAgents", identity+".plist")
}

// renderLaunchdInstall renders a per-user LaunchAgent: StartInterval runs
// the complete-exit periodic command every interval. ProgramArguments is a
// real argument array in a plist, so paths with spaces or XML
// metacharacters need only XML escaping, never shell quoting.
func renderLaunchdInstall(cfg TaskConfig, plan Plan) (Plan, error) {
	plist := launchdPath(cfg, plan.TaskName)
	uid := os.Getuid()
	guiTarget := fmt.Sprintf("gui/%d", uid)
	label := plan.TaskName
	logOut := filepath.Join(plan.Marker, "scheduler", "periodic.log")
	logErr := filepath.Join(plan.Marker, "scheduler", "periodic.err.log")
	// launchd does not create log directories; ensure they exist so the
	// job can always write its (secret-free, counts-only) output.
	plan.EnsureDirs = []string{filepath.Join(plan.Marker, "scheduler")}
	plan.Files = []FileWrite{{
		Path:    plist,
		Mode:    0o644,
		Content: renderLaunchdPlist(label, cfg.Binary, plan.Marker, cfg.Interval, logOut, logErr),
	}}
	// bootstrap is idempotent-safe because the bootout below first unloads
	// any previous registration of the same label; it is best effort so a
	// first install (nothing loaded yet) does not fail.
	plan.Commands = []Command{
		{
			Name:       "launchctl",
			Args:       []string{"bootout", guiTarget + "/" + label},
			Purpose:    "unload any previous registration of this task",
			BestEffort: true,
		},
		{
			Name:    "launchctl",
			Args:    []string{"bootstrap", guiTarget, plist},
			Purpose: "register the LaunchAgent for the current user",
		},
		{
			Name:    "launchctl",
			Args:    []string{"enable", guiTarget + "/" + label},
			Purpose: "enable the LaunchAgent",
		},
	}
	plan.UndoCommands = []Command{
		{
			Name:       "launchctl",
			Args:       []string{"bootout", guiTarget + "/" + label},
			Purpose:    "unload the partially installed task",
			BestEffort: true,
		},
	}
	plan.UninstallCommands = []Command{
		{
			Name:       "launchctl",
			Args:       []string{"bootout", guiTarget + "/" + label},
			Purpose:    "unload the LaunchAgent",
			BestEffort: true,
		},
	}
	plan.RemoveFiles = []string{plist}
	return plan, nil
}

func renderLaunchdUninstall(cfg TaskConfig, plan Plan) (Plan, error) {
	plist := launchdPath(cfg, plan.TaskName)
	uid := os.Getuid()
	guiTarget := fmt.Sprintf("gui/%d", uid)
	// bootout requires "gui/<uid>/<label>" as a single service-target;
	// after a separate domain-target, launchctl treats the label as a plist path.
	plan.UninstallCommands = []Command{
		{
			Name:       "launchctl",
			Args:       []string{"bootout", guiTarget + "/" + plan.TaskName},
			Purpose:    "unload the LaunchAgent",
			BestEffort: true,
		},
	}
	plan.RemoveFiles = []string{plist}
	return plan, nil
}

// renderLaunchdPlist writes the plist with XML-escaped values. LaunchAgent
// plists must be readable by the user; 0644 matches Apple's convention.
func renderLaunchdPlist(label, binary, stateDir string, interval time.Duration, logOut, logErr string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	writePlistKey(&b, "Label")
	writePlistString(&b, label)
	writePlistKey(&b, "ProgramArguments")
	b.WriteString("<array>\n")
	for _, arg := range []string{binary, "periodic", "--state-dir", stateDir} {
		writePlistString(&b, arg)
	}
	b.WriteString("</array>\n")
	writePlistKey(&b, "StartInterval")
	fmt.Fprintf(&b, "<integer>%d</integer>\n", int(interval.Seconds()))
	writePlistKey(&b, "RunAtLoad")
	b.WriteString("<false/>\n")
	writePlistKey(&b, "ProcessType")
	writePlistString(&b, "Background")
	writePlistKey(&b, "StandardOutPath")
	writePlistString(&b, logOut)
	writePlistKey(&b, "StandardErrorPath")
	writePlistString(&b, logErr)
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func writePlistKey(b *strings.Builder, key string) {
	b.WriteString("\t<key>")
	b.WriteString(xmlEscape(key))
	b.WriteString("</key>\n")
}

func writePlistString(b *strings.Builder, value string) {
	b.WriteString("\t<string>")
	b.WriteString(xmlEscape(value))
	b.WriteString("</string>\n")
}
