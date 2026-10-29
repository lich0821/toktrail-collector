package connect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The outbox ledger does not record which device (or subject) originally
// synced a batch, and the server does not promise cross-device
// de-duplication. Before connect lets a run retransmit local history, it
// therefore records — under the state lock, in its own connect-owned file
// — which device identity owns the synced history in a state directory,
// and fails closed whenever that ownership no longer matches the bound
// device. This file is the only writer; nothing else in the collector
// reads or writes it.

const ownershipSchema = 1

// historyOwnership is the durable record of the device identity that owns
// the synced outbox history in a state directory.
type historyOwnership struct {
	Schema     int    `json:"schema"`
	DeviceID   string `json:"deviceId"`
	RecordedAt string `json:"recordedAt"`
}

// ownershipPath is the connect-owned ownership guard location.
func ownershipPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), "connect", "ownership.json")
}

// loadOwnership reads the ownership guard. A missing file is (zero, false,
// nil). A present-but-invalid file fails closed: connect never guesses
// ownership, because a wrong guess would upload one device's archives
// under another account.
func loadOwnership(stateDir string) (historyOwnership, bool, error) {
	raw, err := os.ReadFile(ownershipPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return historyOwnership{}, false, nil
	}
	if err != nil {
		return historyOwnership{}, false, fmt.Errorf("read history ownership guard: %w", err)
	}
	var own historyOwnership
	if err := json.Unmarshal(raw, &own); err != nil {
		return historyOwnership{}, true, fmt.Errorf("corrupt %s: %w; failing closed — remove the file only if you accept abandoning the ownership record", ownershipPath(stateDir), err)
	}
	if own.Schema != ownershipSchema || strings.TrimSpace(own.DeviceID) == "" {
		return historyOwnership{}, true, fmt.Errorf("corrupt %s: unsupported schema or missing device id; failing closed — remove the file only if you accept abandoning the ownership record", ownershipPath(stateDir))
	}
	return own, true, nil
}

// saveOwnership records the owning device identity. It is write-once per
// state directory: connect only writes the guard when none exists (a
// matching existing guard is never rewritten, and a mismatching one fails
// closed before this is ever reached), so the rename below never targets
// an existing file and stays portable.
func saveOwnership(stateDir, deviceID string, now time.Time) error {
	path := ownershipPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create history ownership guard directory: %w", err)
	}
	own := historyOwnership{
		Schema:     ownershipSchema,
		DeviceID:   strings.TrimSpace(deviceID),
		RecordedAt: now.UTC().Format(time.RFC3339),
	}
	raw, err := json.Marshal(own)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write history ownership guard: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("persist history ownership guard: %w", err)
	}
	return nil
}
