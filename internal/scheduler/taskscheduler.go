package scheduler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// windowsTaskName returns the schtasks task name for this identity. The
// leading backslash places it in the task root folder.
func windowsTaskName(identity string) string {
	return "\\" + "TokTrailCollector-" + strings.TrimPrefix(identity, "toktrail-collector-")
}

// renderTaskSchedulerInstall renders a schtasks-based per-user task. The
// task definition is written as XML (properly escaped) to a scratch file
// and registered with `schtasks /Create /F /XML <file> /TN <name>` using
// an argument array — no shell, no string concatenation into a command
// line, so paths with spaces and metacharacters are safe.
func renderTaskSchedulerInstall(cfg TaskConfig, plan Plan) (Plan, error) {
	taskName := windowsTaskName(plan.TaskName)
	xmlPath := filepath.Join(os.TempDir(), plan.TaskName+".task.xml")
	plan.Files = []FileWrite{{
		Path:    xmlPath,
		Mode:    0o600,
		Temp:    true,
		Content: renderWindowsTaskXML(taskName, cfg.Binary, plan.Marker, cfg.Interval),
	}}
	plan.Commands = []Command{
		{
			Name:    "schtasks",
			Args:    []string{"/Create", "/F", "/XML", xmlPath, "/TN", taskName},
			Purpose: "register the Task Scheduler task for the current user",
		},
	}
	plan.UndoCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the partially registered task",
			BestEffort: true,
		},
	}
	plan.UninstallCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the Task Scheduler task",
			BestEffort: true,
		},
	}
	// The task itself lives in the OS task store, not in files we own, so
	// there is nothing to remove from disk.
	plan.RemoveFiles = nil
	return plan, nil
}

func renderTaskSchedulerUninstall(cfg TaskConfig, plan Plan) (Plan, error) {
	taskName := windowsTaskName(plan.TaskName)
	plan.UninstallCommands = []Command{
		{
			Name:       "schtasks",
			Args:       []string{"/Delete", "/F", "/TN", taskName},
			Purpose:    "delete the Task Scheduler task",
			BestEffort: true,
		},
	}
	return plan, nil
}

// renderWindowsTaskXML writes the Task Scheduler 1.2 definition. The task
// runs the complete-exit `periodic` command for the current interactive
// user (LeastPrivilege), repeats every interval, and lets the collector's
// own process lock refuse overlapping instances (IgnoreNew policy).
func renderWindowsTaskXML(taskName, binary, stateDir string, interval time.Duration) string {
	arguments := strings.Join([]string{
		"periodic",
		"--state-dir",
		windowsQuoteArg(stateDir),
	}, " ")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	b.WriteString("  <RegistrationInfo>\n")
	b.WriteString("    <Description>")
	b.WriteString(xmlEscape("TokTrail collector scheduled collection (user, complete-exit) for state directory " + stateDir))
	b.WriteString("</Description>\n")
	b.WriteString("    <URI>")
	b.WriteString(xmlEscape(taskName))
	b.WriteString("</URI>\n")
	b.WriteString("    <Author>TokTrail collector</Author>\n")
	b.WriteString("  </RegistrationInfo>\n")
	b.WriteString("  <Triggers>\n")
	b.WriteString("    <TimeTrigger>\n")
	b.WriteString("      <Repetition>\n")
	b.WriteString("        <Interval>")
	b.WriteString(xmlEscape(formatWindowsInterval(interval)))
	b.WriteString("</Interval>\n")
	b.WriteString("        <StopAtDurationEnd>false</StopAtDurationEnd>\n")
	b.WriteString("      </Repetition>\n")
	b.WriteString("      <StartBoundary>2020-01-01T00:00:00</StartBoundary>\n")
	b.WriteString("      <Enabled>true</Enabled>\n")
	b.WriteString("    </TimeTrigger>\n")
	b.WriteString("  </Triggers>\n")
	b.WriteString("  <Principals>\n")
	b.WriteString("    <Principal id=\"Author\">\n")
	b.WriteString("      <UserId></UserId>\n")
	b.WriteString("      <LogonType>InteractiveToken</LogonType>\n")
	b.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\n")
	b.WriteString("    </Principal>\n")
	b.WriteString("  </Principals>\n")
	b.WriteString("  <Settings>\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\n")
	b.WriteString("    <StartWhenAvailable>false</StartWhenAvailable>\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\n")
	b.WriteString("    <Enabled>true</Enabled>\n")
	b.WriteString("    <Hidden>false</Hidden>\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\n")
	b.WriteString("    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n")
	b.WriteString("    <Priority>7</Priority>\n")
	b.WriteString("  </Settings>\n")
	b.WriteString("  <Actions Context=\"Author\">\n")
	b.WriteString("    <Exec>\n")
	b.WriteString("      <Command>")
	b.WriteString(xmlEscape(binary))
	b.WriteString("</Command>\n")
	b.WriteString("      <Arguments>")
	b.WriteString(xmlEscape(arguments))
	b.WriteString("</Arguments>\n")
	b.WriteString("    </Exec>\n")
	b.WriteString("  </Actions>\n")
	b.WriteString("</Task>\n")
	return b.String()
}

// formatWindowsInterval renders an interval as an ISO 8601 duration for
// the Task Scheduler Repetition/Interval element (minutes granularity).
func formatWindowsInterval(d time.Duration) string {
	minutes := int64(d / time.Minute)
	return fmt.Sprintf("PT%dm", minutes)
}
