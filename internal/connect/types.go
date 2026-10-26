package connect

import (
	"io"
	"net/http"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/scheduler"
)

// Options controls a connect orchestration run.
type Options struct {
	URL             string           // Raw connect URL: http(s)://<host>/api/collector/connect#<64-hex ticket>
	StateDir        string           // Local TokTrail state directory
	DeviceName      string           // Optional device name
	Interval        time.Duration    // Scheduling interval (defaults to scheduler.DefaultInterval)
	HomeDir         string           // Optional home directory override (defaults to os.UserHomeDir)
	BinaryPath      string           // Optional binary executable path override (defaults to os.Executable)
	HTTPClient      *http.Client     // Optional HTTP client override for testing
	SchedulerRunner scheduler.Runner // Optional scheduler runner override for testing
	DryRun          bool             // Optional dry run for scheduler installation
	Now             func() time.Time // Injectable clock for deterministic tests
	Out             io.Writer        // Destination for progress output (defaults to io.Discard)
}

// Result summarizes a completed connect orchestration.
type Result struct {
	DeviceID         string            `json:"deviceId"`
	ServerURL        string            `json:"serverUrl"`
	ApplicationID    string            `json:"applicationId"`
	SubjectID        string            `json:"subjectId"`
	ConsentRevision  int64             `json:"consentRevision"`
	SkippedBind      bool              `json:"skippedBind"`
	AuthorizedTools  []string          `json:"authorizedTools"`
	InstalledService string            `json:"installedService"`
	PeriodicResult   collection.Result `json:"periodicResult"`
}

// Config is the server-provided configuration payload fetched from the connect endpoint.
type Config struct {
	SchemaVersion int      `json:"schemaVersion"`
	ServerURL     string   `json:"serverUrl"`
	ApplicationID string   `json:"applicationId"`
	SubjectID     string   `json:"subjectId"`
	Tools         []string `json:"tools"`
	Days          int      `json:"days"`
	ExpiresAt     string   `json:"expiresAt"`
}
