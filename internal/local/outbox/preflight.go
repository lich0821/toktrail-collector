package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// preflight-attempts.json is the durable authorization-attempt log. Every
// sync path that is about to issue a GET /v1/devices/self without a
// batch-bound MarkAttempt (the explicit --file path with a state directory,
// the quarantine-recovery-only path, and the fresh scope re-fetch after a
// scope error) must first persist an attempt here.
// If this write fails, the run stops with zero HTTP traffic of any kind —
// the same guarantee MarkAttempt gives the ingest POST. The log is pure
// accounting: it is monotonic, needs no replay step, and a crash between the
// write and the GET can only over-count attempts, never under-count them or
// duplicate server traffic.
const preflightAttemptsFileName = "preflight-attempts.json"

// PreflightAttempts is the persisted authorization-attempt accounting.
type PreflightAttempts struct {
	Count   int       `json:"count"`
	FirstAt time.Time `json:"firstAt,omitempty"`
	LastAt  time.Time `json:"lastAt"`
}

func (s Store) PreflightAttemptsPath() string {
	return filepath.Join(s.dir, preflightAttemptsFileName)
}

// LoadPreflightAttempts returns the accounting; a missing file is a zero
// value, a corrupt file is an error (never silently reset accounting).
// A file that exists must describe a well-formed accounting: count strictly
// positive, both timestamps present and non-zero. Anything else — null, an
// empty object, a zero or negative count, missing timestamps — is treated
// as corruption and fails closed rather than being read as a fresh zero
// state (which would silently reset attempt accounting and break the
// monotonic guarantee). A last timestamp earlier than the first is NOT
// corruption: clock skew can legitimately produce that ordering, and the
// accounting is order-agnostic.
func (s Store) LoadPreflightAttempts() (PreflightAttempts, error) {
	b, err := os.ReadFile(s.PreflightAttemptsPath())
	if errors.Is(err, os.ErrNotExist) {
		return PreflightAttempts{}, nil
	}
	if err != nil {
		return PreflightAttempts{}, err
	}
	var attempts PreflightAttempts
	if err := json.Unmarshal(b, &attempts); err != nil {
		return PreflightAttempts{}, fmt.Errorf("corrupt %s: %w", s.PreflightAttemptsPath(), err)
	}
	if attempts.Count <= 0 {
		return PreflightAttempts{}, fmt.Errorf("corrupt %s: attempt count must be strictly positive, got %d", s.PreflightAttemptsPath(), attempts.Count)
	}
	if attempts.FirstAt.IsZero() {
		return PreflightAttempts{}, fmt.Errorf("corrupt %s: first attempt timestamp is missing or zero", s.PreflightAttemptsPath())
	}
	if attempts.LastAt.IsZero() {
		return PreflightAttempts{}, fmt.Errorf("corrupt %s: last attempt timestamp is missing or zero", s.PreflightAttemptsPath())
	}
	return attempts, nil
}

// RecordPreflightAttempt appends one attempt atomically (tmp + rename). The
// write is durable before the caller performs any HTTP request. The count
// is a non-negative int; incrementing past the maximum fails closed instead
// of wrapping to a negative (which the strict load would then reject as
// corruption on every later run).
func (s Store) RecordPreflightAttempt(at time.Time) (PreflightAttempts, error) {
	attempts, err := s.LoadPreflightAttempts()
	if err != nil {
		return PreflightAttempts{}, err
	}
	if attempts.Count == math.MaxInt {
		return PreflightAttempts{}, fmt.Errorf("preflight attempt accounting is exhausted at %d attempts; refusing to wrap the counter", attempts.Count)
	}
	attempts.Count++
	if attempts.FirstAt.IsZero() {
		attempts.FirstAt = at.UTC()
	}
	attempts.LastAt = at.UTC()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return PreflightAttempts{}, err
	}
	b, err := json.MarshalIndent(attempts, "", "  ")
	if err != nil {
		return PreflightAttempts{}, err
	}
	tmp := s.PreflightAttemptsPath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return PreflightAttempts{}, err
	}
	if err := os.Rename(tmp, s.PreflightAttemptsPath()); err != nil {
		return PreflightAttempts{}, err
	}
	return attempts, nil
}
