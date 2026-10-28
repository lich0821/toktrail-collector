// Package cursorsource stores the local permit for the account-level
// Cursor source: the user's explicit local confirmation that this device
// may read the Cursor desktop login credential and query the Cursor usage
// API on the user's behalf.
//
// The permit deliberately does NOT live in grants.json: grants are
// (source, input) pairs over local files with absolute paths, while the
// Cursor source is collected over the network from a locally confirmed
// account. The license never stores Cursor credentials, emails, or raw
// account ids — only the pseudonymous account-match digest from
// internal/cursor/identity.
package cursorsource

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/source/adapter"
)

const (
	// ToolName is the canonical tool display name.
	ToolName = "Cursor"
	// SourceType is the source id of the account-level cursor source.
	SourceType = adapter.CursorDashboardAPISource

	licenseFileName = "cursor-source.json"
	schemaVersion   = 1
)

// Status is the local permit state machine. StatusPendingFirstSync is set
// by the first local confirmation and becomes StatusActive after the first
// successfully completed pull; paused statuses keep the permit but stop
// collection until the user acts (re-confirm or re-login). There is no
// persisted "disabled": logout removes the license entirely.
type Status string

const (
	StatusPendingFirstSync    Status = "pending_first_sync"
	StatusActive              Status = "active"
	StatusPausedAccountSwitch Status = "paused_account_switch"
	StatusLoginExpired        Status = "login_expired"
)

func (s Status) valid() bool {
	switch s {
	case StatusPendingFirstSync, StatusActive, StatusPausedAccountSwitch, StatusLoginExpired:
		return true
	}
	return false
}

// License is the durable local permit record.
type License struct {
	SchemaVersion    int    `json:"schemaVersion"`
	SourceInstanceID string `json:"sourceInstanceId"`
	SourceType       string `json:"sourceType"`
	// CredentialSource records where the credential is read from
	// ("desktop"); the token itself is never stored.
	CredentialSource string `json:"credentialSource"`
	// AccountMatchID is the local-only account-switch digest
	// (identity.MatchAccount). It never leaves this file.
	AccountMatchID string    `json:"accountMatchId"`
	Status         Status    `json:"status"`
	ConfirmedAt    time.Time `json:"confirmedAt"`
	// ConsentRevision and FenceVersion snapshot the server authorization
	// the permit was confirmed under; every sync refreshes both from the
	// live self view.
	ConsentRevision int64 `json:"consentRevision"`
	FenceVersion    int64 `json:"fenceVersion"`
	// NextRevision is the next round revision to assign to produced
	// records. It is seeded from the server (source.nextRevision,
	// subject+sourceType MAX alive revision + 1) and refreshed from
	// self.accountSources[].nextRevision; a new writer uses
	// max(localNext, serverNext). It advances only when a batch is
	// durably persisted — never on upload success or failure.
	NextRevision int64 `json:"nextRevision"`
	// PullWatermark is the exclusive end of the last fully paginated
	// pull. It advances only after complete pagination; upload progress
	// lives in the cursor outbox, not here.
	PullWatermark *time.Time `json:"pullWatermark,omitempty"`
	// PullCutoff records the effective history cutoff the last complete
	// pull was bounded by, so a later server-side widening (an earlier
	// cutoff, or lifting it entirely) is detectable and the newly
	// authorized history actually gets fetched. Three states: nil with
	// PullUnlimited false means nothing recorded yet (fresh or legacy
	// permit); a non-nil value is the finite bound; nil with
	// PullUnlimited true means the last pull ran with no cutoff.
	// Local window metadata only — never an account identifier.
	PullCutoff    *time.Time `json:"pullCutoff,omitempty"`
	PullUnlimited bool       `json:"pullUnlimited,omitempty"`
	// LastFullPullAt records when a pull last covered the whole
	// authorized window (first pull, post-reset recovery, or the
	// once-daily reconciliation). The first round of each UTC day
	// re-pulls the full window so upstream backfill and corrections
	// older than the regular overlap still arrive. Local metadata only,
	// no PII.
	LastFullPullAt *time.Time `json:"lastFullPullAt,omitempty"`
	// LastSyncAt records the last acknowledged source-batch upload.
	LastSyncAt *time.Time `json:"lastSyncAt,omitempty"`
	UpdatedAt  time.Time  `json:"updatedAt,omitempty"`
}

// Collectable reports whether the sync may run under this permit.
func (l License) Collectable() bool {
	return l.Status == StatusPendingFirstSync || l.Status == StatusActive
}

// Store reads and writes the license under a state directory.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, licenseFileName) }

// Load returns the license and whether one exists. A corrupt license is
// an error (fail closed): a half-readable permit must never silently
// degrade into "no permit" or a fresh one.
func (s Store) Load() (License, bool, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return License{}, false, nil
	}
	if err != nil {
		return License{}, false, err
	}
	var l License
	if err := json.Unmarshal(b, &l); err != nil {
		return License{}, false, fmt.Errorf("corrupt %s: %w", s.Path(), err)
	}
	if l.SchemaVersion != schemaVersion {
		return License{}, false, fmt.Errorf("unsupported %s schema version %d, want %d", s.Path(), l.SchemaVersion, schemaVersion)
	}
	if strings.TrimSpace(l.SourceInstanceID) == "" {
		return License{}, false, fmt.Errorf("corrupt %s: missing sourceInstanceId", s.Path())
	}
	if l.SourceType != SourceType {
		return License{}, false, fmt.Errorf("corrupt %s: sourceType %q, want %q", s.Path(), l.SourceType, SourceType)
	}
	if !l.Status.valid() {
		return License{}, false, fmt.Errorf("corrupt %s: unknown status %q", s.Path(), l.Status)
	}
	if l.NextRevision < 1 {
		return License{}, false, fmt.Errorf("corrupt %s: nextRevision %d must be positive", s.Path(), l.NextRevision)
	}
	return l, true, nil
}

// Save atomically persists the license (0600, temp file plus rename).
func (s Store) Save(l License) error {
	if strings.TrimSpace(l.SourceInstanceID) == "" {
		return errors.New("license requires sourceInstanceId")
	}
	if l.SourceType == "" {
		l.SourceType = SourceType
	}
	if l.SourceType != SourceType {
		return fmt.Errorf("license sourceType %q does not match %q", l.SourceType, SourceType)
	}
	if !l.Status.valid() {
		return fmt.Errorf("unknown license status %q", l.Status)
	}
	if l.NextRevision < 1 {
		return errors.New("license nextRevision must be positive")
	}
	if l.ConfirmedAt.IsZero() {
		return errors.New("license requires confirmedAt")
	}
	l.SchemaVersion = schemaVersion
	l.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, "cursor-source.*.tmp")
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

// Delete removes the license (logout). It reports whether a file was
// removed. Deleting the permit never deletes already-uploaded data; the
// existing server-side deletion flow governs that.
func (s Store) Delete() (bool, error) {
	err := os.Remove(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
