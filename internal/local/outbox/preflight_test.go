package outbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func preflightTime(minute int) time.Time {
	return time.Date(2026, 10, 20, 10, minute, 0, 0, time.UTC)
}

func TestPreflightAttemptsPathLayout(t *testing.T) {
	dir := t.TempDir()
	if got, want := New(dir).PreflightAttemptsPath(), filepath.Join(dir, "preflight-attempts.json"); got != want {
		t.Fatalf("preflight attempts path = %q, want %q", got, want)
	}
}

func TestPreflightAttemptsMissingFileIsZero(t *testing.T) {
	dir := t.TempDir()
	attempts, err := New(dir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Count != 0 || !attempts.FirstAt.IsZero() || !attempts.LastAt.IsZero() {
		t.Fatalf("expected a zero accounting for a missing file, got %#v", attempts)
	}
}

func TestRecordPreflightAttemptIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	first, err := store.RecordPreflightAttempt(preflightTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if first.Count != 1 || !first.FirstAt.Equal(preflightTime(0)) || !first.LastAt.Equal(preflightTime(0)) {
		t.Fatalf("first attempt = %#v", first)
	}

	second, err := New(dir).RecordPreflightAttempt(preflightTime(5))
	if err != nil {
		t.Fatal(err)
	}
	if second.Count != 2 || !second.FirstAt.Equal(preflightTime(0)) || !second.LastAt.Equal(preflightTime(5)) {
		t.Fatalf("second attempt must keep FirstAt and advance LastAt: %#v", second)
	}

	third, err := New(dir).RecordPreflightAttempt(preflightTime(9))
	if err != nil {
		t.Fatal(err)
	}
	if third.Count != 3 || !third.FirstAt.Equal(preflightTime(0)) || !third.LastAt.Equal(preflightTime(9)) {
		t.Fatalf("third attempt = %#v", third)
	}

	// A fresh store handle sees the same accounting (durability).
	persisted, err := New(dir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Count != 3 || !persisted.FirstAt.Equal(preflightTime(0)) || !persisted.LastAt.Equal(preflightTime(9)) {
		t.Fatalf("persisted accounting = %#v", persisted)
	}
}

func TestRecordPreflightAttemptNoTempResidue(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir).RecordPreflightAttempt(preflightTime(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "preflight-attempts.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("expected the atomic write to leave no temp file behind: %v", err)
	}
}

func TestLoadPreflightAttemptsCorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if err := os.WriteFile(store.PreflightAttemptsPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).LoadPreflightAttempts(); err == nil {
		t.Fatal("expected a corrupt accounting file to fail closed")
	}
	// Recording on top of a corrupt file must also fail, never reset it.
	if _, err := New(dir).RecordPreflightAttempt(preflightTime(0)); err == nil {
		t.Fatal("expected RecordPreflightAttempt to fail on a corrupt accounting file")
	}
	// The corrupt content is untouched.
	b, readErr := os.ReadFile(store.PreflightAttemptsPath())
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(b), "{not json") {
		t.Fatalf("expected the corrupt accounting to be left untouched, got %s", b)
	}
}

// writePreflightFile writes a raw accounting fixture so tests can exercise
// structurally broken but syntactically valid files.
func writePreflightFile(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(New(dir).PreflightAttemptsPath(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPreflightAttemptsRejectsStructurallyBrokenFiles(t *testing.T) {
	valid := `{"count":3,"firstAt":"2026-10-20T10:00:00Z","lastAt":"2026-10-20T10:09:00Z"}`
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"null", `null`, "strictly positive"},
		{"empty object", `{}`, "strictly positive"},
		{"zero count with timestamps", `{"count":0,"firstAt":"2026-10-20T10:00:00Z","lastAt":"2026-10-20T10:00:00Z"}`, "strictly positive"},
		{"negative count", `{"count":-2,"firstAt":"2026-10-20T10:00:00Z","lastAt":"2026-10-20T10:00:00Z"}`, "strictly positive"},
		{"missing timestamps", `{"count":2}`, "first attempt timestamp"},
		{"zero first timestamp", `{"count":2,"firstAt":"0001-01-01T00:00:00Z","lastAt":"2026-10-20T10:00:00Z"}`, "first attempt timestamp"},
		{"missing last timestamp", `{"count":2,"firstAt":"2026-10-20T10:00:00Z"}`, "last attempt timestamp"},
		{"zero last timestamp", `{"count":2,"firstAt":"2026-10-20T10:00:00Z","lastAt":"0001-01-01T00:00:00Z"}`, "last attempt timestamp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePreflightFile(t, dir, tc.content)
			if _, err := New(dir).LoadPreflightAttempts(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected Load to reject %s with %q, got %v", tc.name, tc.want, err)
			}
			// Recording on top of the broken file must also fail, never
			// treat it as a fresh zero state and silently reset accounting.
			if _, err := New(dir).RecordPreflightAttempt(preflightTime(0)); err == nil {
				t.Fatalf("expected RecordPreflightAttempt to reject %s", tc.name)
			}
		})
	}

	// Sanity: the valid fixture itself still loads.
	dir := t.TempDir()
	writePreflightFile(t, dir, valid)
	attempts, err := New(dir).LoadPreflightAttempts()
	if err != nil || attempts.Count != 3 {
		t.Fatalf("expected the valid accounting to load, got %#v err=%v", attempts, err)
	}
}

// TestLoadPreflightAttemptsAllowsClockSkew: a last timestamp earlier than
// the first is a legitimate clock-skew artifact, not corruption.
func TestLoadPreflightAttemptsAllowsClockSkew(t *testing.T) {
	dir := t.TempDir()
	writePreflightFile(t, dir, `{"count":4,"firstAt":"2026-10-20T10:09:00Z","lastAt":"2026-10-20T10:00:00Z"}`)
	attempts, err := New(dir).LoadPreflightAttempts()
	if err != nil {
		t.Fatalf("clock-skewed accounting must load, got %v", err)
	}
	if attempts.Count != 4 {
		t.Fatalf("expected count 4, got %#v", attempts)
	}
	// Recording still advances the count without rewriting the first
	// timestamp or complaining about the ordering.
	next, err := New(dir).RecordPreflightAttempt(preflightTime(3))
	if err != nil || next.Count != 5 {
		t.Fatalf("expected recording to keep working on clock-skewed accounting: %#v err=%v", next, err)
	}
	if !next.FirstAt.Equal(time.Date(2026, 10, 20, 10, 9, 0, 0, time.UTC)) {
		t.Fatalf("expected FirstAt preserved under clock skew: %#v", next)
	}
}

// TestRecordPreflightAttemptRefusesCounterOverflow: a counter already at
// the maximum int must fail closed instead of wrapping to a negative value
// (which every later load would then reject as corruption, permanently
// bricking the journal with no recovery path).
func TestRecordPreflightAttemptRefusesCounterOverflow(t *testing.T) {
	dir := t.TempDir()
	writePreflightFile(t, dir, `{"count":9223372036854775807,"firstAt":"2026-10-20T10:00:00Z","lastAt":"2026-10-20T10:00:00Z"}`)
	if _, err := New(dir).RecordPreflightAttempt(preflightTime(1)); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("expected overflow to fail closed, got %v", err)
	}
	// The file is left untouched: the maxed-out accounting still loads.
	attempts, err := New(dir).LoadPreflightAttempts()
	if err != nil || attempts.Count != 9223372036854775807 {
		t.Fatalf("expected the maxed accounting to be preserved, got %#v err=%v", attempts, err)
	}
}
