// Package managedconsent stores the server-confirmed device grant scope
// (the grant protocol's effective view) and computes the local reading
// policy from it.
//
// The overlay file records the last successfully fetched and applied view.
// Its existence is also the "this device has spoken the grant protocol"
// marker used for fail-closed behavior: once the protocol has been seen, a
// failed refresh, a server without the protocol fields (downgrade), or an
// unsupported protocol version stops local reading instead of falling back
// to the previous scope. The cached overlay authorizes nothing by itself —
// reading only ever proceeds under a view fetched and applied in the same
// run; the cache is for display and ack bookkeeping.
//
// The package never touches device identity, progress, the outbox, or
// user-authored grant entries. Server tool names are mapped through the
// compiled-in adapter registry only; the server can never introduce a
// local path.
package managedconsent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/source/registry"
)

// PausedToolSentinel is the marker the server places in allowedTools when
// the device is paused. A paused device reads nothing.
const PausedToolSentinel = "__toktrail_paused__"

const (
	overlayFileName = "managed-consent.json"
	// SchemaVersion is the only overlay schema this code accepts.
	SchemaVersion = 1
	// MaxAllowedTools bounds the accepted tool list.
	MaxAllowedTools = 64
	// MaxToolNameLen bounds one accepted tool name.
	MaxToolNameLen = 64
)

// Overlay is the durable record of the last applied server grant view.
type Overlay struct {
	SchemaVersion   int        `json:"schemaVersion"`
	ConsentRevision int64      `json:"consentRevision"`
	Paused          bool       `json:"paused"`
	AllowedTools    []string   `json:"allowedTools"`
	HistoryFrom     *time.Time `json:"historyFrom,omitempty"`
	AppliedAt       time.Time  `json:"appliedAt"`
	// DeviceGrantManaged records the applied managed flag.
	DeviceGrantManaged bool `json:"deviceGrantManaged"`
	// DeviceID and ServerURL bind the overlay to the device identity it
	// was applied for. A different bound device never reuses the recorded
	// ack or the managed grants.
	DeviceID  string `json:"deviceId"`
	ServerURL string `json:"serverUrl,omitempty"`
	// Pending maps an allowed tool name to the reason it could not be
	// fully applied locally (unknown adapter, missing default directory,
	// manually disabled grant). While Pending is non-empty the revision is
	// not acknowledged: the server UI must not be told "applied".
	Pending map[string]string `json:"pending,omitempty"`
	// AckedRevision is the revision the server confirmed via grant-ack, and
	// AckedCollectorVersion the collector release version that was acked
	// with it ("" when none was sent). A collector upgrade re-acks the same
	// revision so the server learns the new version; a restricted
	// (pending) application never carries a previous ack forward.
	AckedRevision         int64      `json:"ackedRevision,omitempty"`
	AckedApplyState       string     `json:"ackedApplyState,omitempty"`
	AckedCollectorVersion string     `json:"ackedCollectorVersion,omitempty"`
	AckedAt               *time.Time `json:"ackedAt,omitempty"`
}

// View is a validated server grant view to apply. The caller has already
// confirmed the grant protocol marker on the fetched snapshot.
type View struct {
	ConsentRevision int64
	Paused          bool
	AllowedTools    []string
	HistoryFrom     *time.Time
	// DeviceGrantManaged is the server's persistent explicit-authorization
	// flag for this device. Only when true may the sync add built-in
	// default-directory grants for confirmed tools; false means
	// filter-only and never creates local paths.
	DeviceGrantManaged bool
}

// ValidateView checks a server view before it is applied. It fails closed
// on a non-positive revision (nothing could be acknowledged) and malformed
// tool entries.
func ValidateView(v View) error {
	if v.ConsentRevision <= 0 {
		return fmt.Errorf("grant view has non-positive consentRevision %d", v.ConsentRevision)
	}
	if len(v.AllowedTools) > MaxAllowedTools {
		return fmt.Errorf("grant view lists %d tools, exceeds limit %d", len(v.AllowedTools), MaxAllowedTools)
	}
	seen := make(map[string]bool, len(v.AllowedTools))
	for i, tool := range v.AllowedTools {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			return fmt.Errorf("grant view tool %d is empty", i)
		}
		if len(tool) > MaxToolNameLen {
			return fmt.Errorf("grant view tool %d exceeds %d characters", i, MaxToolNameLen)
		}
		if seen[tool] {
			return fmt.Errorf("grant view lists tool %q more than once", tool)
		}
		seen[tool] = true
	}
	return nil
}

// Store reads and writes the overlay under a state directory.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, overlayFileName) }

// Load returns the overlay and whether one exists. A corrupt overlay is an
// error: fail closed rather than silently dropping a previously applied
// (possibly narrowing) scope.
func (s Store) Load() (Overlay, bool, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Overlay{}, false, nil
	}
	if err != nil {
		return Overlay{}, false, err
	}
	var o Overlay
	if err := json.Unmarshal(b, &o); err != nil {
		return Overlay{}, false, fmt.Errorf("corrupt %s: %w", s.Path(), err)
	}
	if o.SchemaVersion != SchemaVersion {
		return Overlay{}, false, fmt.Errorf("unsupported %s schema version %d, want %d", s.Path(), o.SchemaVersion, SchemaVersion)
	}
	if o.ConsentRevision <= 0 {
		return Overlay{}, false, fmt.Errorf("corrupt %s: non-positive consentRevision", s.Path())
	}
	return o, true, nil
}

// Save atomically persists the overlay (0600, temp file plus rename).
func (s Store) Save(o Overlay) error {
	if err := ValidateView(View{ConsentRevision: o.ConsentRevision, Paused: o.Paused, AllowedTools: o.AllowedTools, HistoryFrom: o.HistoryFrom}); err != nil {
		return err
	}
	if o.SchemaVersion == 0 {
		o.SchemaVersion = SchemaVersion
	}
	if o.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported overlay schema version %d", o.SchemaVersion)
	}
	if o.AppliedAt.IsZero() {
		return errors.New("overlay requires appliedAt")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, "managed-consent.*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return err
	}
	tmpName = ""
	return nil
}

// Policy is the effective local reading policy derived from an overlay.
// It is computed only from a view applied in the current run.
type Policy struct {
	// Active is true when the grant protocol governs this run.
	Active bool
	// Paused stops all local reading for the run.
	Paused bool
	// allowedSources maps adapter source ids that may be read; nil means
	// unrestricted (legacy empty-list semantics).
	allowedSources map[string]bool
	// HistoryFrom is the server-effective cutoff for new exports; nil
	// means no cutoff. It replaces (does not max with) the bind-time
	// cutoff so server-side widenings take effect.
	HistoryFrom *time.Time
	// AllowedTools mirrors the applied raw server list (display/acks).
	AllowedTools []string
}

// Policy computes the effective policy. Paused is honored from the flag or
// the sentinel. An empty tool list (without the sentinel) keeps the legacy
// "unrestricted" meaning. Unknown tool names match no source and can never
// expand reading.
func (o Overlay) Policy() Policy {
	p := Policy{Active: true, AllowedTools: o.AllowedTools, HistoryFrom: o.HistoryFrom}
	p.Paused = o.Paused
	for _, tool := range o.AllowedTools {
		if strings.TrimSpace(tool) == PausedToolSentinel {
			p.Paused = true
		}
	}
	if p.Paused {
		return p
	}
	if len(o.AllowedTools) == 0 {
		return p // unrestricted
	}
	p.allowedSources = make(map[string]bool, len(o.AllowedTools))
	for _, tool := range o.AllowedTools {
		if spec, ok := registry.LookupTool(tool); ok {
			p.allowedSources[spec.Source] = true
		}
	}
	return p
}

// FilterGrants returns the granted sources this policy allows to be read.
// A paused policy reads nothing. An unrestricted policy keeps everything.
func (p Policy) FilterGrants(enabled []grants.Grant) []grants.Grant {
	if !p.Active || p.Paused {
		return nil
	}
	if p.allowedSources == nil {
		return enabled
	}
	var out []grants.Grant
	for _, g := range enabled {
		if p.allowedSources[g.Source] {
			out = append(out, g)
		}
	}
	return out
}

// SourceAllowed reports whether the adapter source may be read.
func (p Policy) SourceAllowed(source string) bool {
	if !p.Active {
		return true
	}
	if p.Paused {
		return false
	}
	if p.allowedSources == nil {
		return true
	}
	return p.allowedSources[source]
}
