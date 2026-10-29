package overrides

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

func mustCanonical(t *testing.T, rec map[string]any) json.RawMessage {
	t.Helper()
	b, err := CanonicalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func record(key, tokens string) json.RawMessage {
	// Intentionally build via a map to force canonical marshal ordering.
	b, _ := json.Marshal(map[string]any{
		"recordKey":  key,
		"kind":       "delta",
		"tool":       "Codex",
		"model":      "gpt-5.4",
		"occurredAt": "2026-10-01T00:00:00Z",
		"input":      tokens,
		"output":     "1",
		"cacheRead":  "0",
		"cacheWrite": "0",
		"adapterVersion": "synthetic",
		"sourceType":     "fixture",
	})
	return b
}

func boundState(t *testing.T, dir, device, server string) {
	t.Helper()
	if err := statedir.New(dir).Save(statedir.DeviceState{
		DeviceID:     device,
		DeviceSecret: strings.Repeat("a", 64),
		ServerURL:    server,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRoundTripAndValidation(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)
	if _, has, err := store.Load(); err != nil || has {
		t.Fatalf("missing ledger must be empty: %v %v", has, err)
	}
	at := time.Now().UTC()
	ledger := Ledger{
		Schema:    Schema,
		DeviceID:  "device-a",
		ServerURL: "http://127.0.0.1:3211",
		Entries: map[string]Entry{
			"codex:k1": {
				RecordKey: "codex:k1",
				Source:    CodexSource,
				Input:     "/input",
				Record:    record("codex:k1", "10"),
				AttemptID: "oa-1",
				Status:    StatusConfirmed,
				UpdatedAt: at,
			},
		},
	}
	if err := store.Save(ledger); err != nil {
		t.Fatal(err)
	}
	loaded, has, err := store.Load()
	if err != nil || !has {
		t.Fatalf("load: %v %v", has, err)
	}
	if got := loaded.Entries["codex:k1"]; got.Status != StatusConfirmed || got.AttemptID != "oa-1" {
		t.Fatalf("round trip lost fields: %#v", got)
	}
	// Pending entry keeps the previous confirmed record and its own
	// attempt id.
	loaded.Entries["codex:k1"] = Entry{
		RecordKey:        "codex:k1",
		Source:           CodexSource,
		Input:            "/input",
		Record:           record("codex:k1", "10"),
		AttemptID:        "oa-1",
		Status:           StatusPending,
		PendingRecord:    record("codex:k1", "11"),
		PendingAttemptID: "oa-2",
		PendingSince:     &at,
		UpdatedAt:        at,
	}
	if err := store.Save(loaded); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); err != nil {
		t.Fatalf("pending entry must validate: %v", err)
	}
}

func TestStoreValidationFailsClosed(t *testing.T) {
	at := time.Now().UTC()
	cases := map[string]Ledger{
		"foreign schema": {Schema: 99, Entries: map[string]Entry{}},
		"entries without binding": {Schema: Schema, Entries: map[string]Entry{
			"codex:k": {RecordKey: "codex:k", Source: CodexSource, Record: record("codex:k", "1"), AttemptID: "oa-1", Status: StatusConfirmed, UpdatedAt: at},
		}},
		"unsupported source": {Schema: Schema, DeviceID: "d", ServerURL: "http://s", Entries: map[string]Entry{
			"claude:k": {RecordKey: "claude:k", Source: "claude-code-jsonl", Record: record("claude:k", "1"), AttemptID: "oa-1", Status: StatusConfirmed, UpdatedAt: at},
		}},
		"pending without attempt id": {Schema: Schema, DeviceID: "d", ServerURL: "http://s", Entries: map[string]Entry{
			"codex:k": {RecordKey: "codex:k", Source: CodexSource, PendingRecord: record("codex:k", "1"), Status: StatusPending, PendingSince: &at, UpdatedAt: at},
		}},
		"confirmed without attempt id": {Schema: Schema, DeviceID: "d", ServerURL: "http://s", Entries: map[string]Entry{
			"codex:k": {RecordKey: "codex:k", Source: CodexSource, Record: record("codex:k", "1"), Status: StatusConfirmed, UpdatedAt: at},
		}},
		"key mismatch": {Schema: Schema, DeviceID: "d", ServerURL: "http://s", Entries: map[string]Entry{
			"codex:k": {RecordKey: "codex:other", Source: CodexSource, Record: record("codex:other", "1"), AttemptID: "oa-1", Status: StatusConfirmed, UpdatedAt: at},
		}},
	}
	for name, ledger := range cases {
		if err := ledger.Validate(); err == nil {
			t.Fatalf("%s: expected validation failure", name)
		}
	}
}

func TestApplyToBaseline(t *testing.T) {
	dir := t.TempDir()
	boundState(t, dir, "device-a", "http://srv")
	store := New(dir)
	at := time.Now().UTC()

	// No ledger: no-op.
	known := map[string][]byte{"codex:k1": record("codex:k1", "10")}
	if err := ApplyToBaseline(dir, CodexSource, known); err != nil {
		t.Fatal(err)
	}

	// Confirmed entry supersedes the stored payload.
	ledger := Ledger{Schema: Schema, DeviceID: "device-a", ServerURL: "http://srv", Entries: map[string]Entry{
		"codex:k1": {RecordKey: "codex:k1", Source: CodexSource, Record: record("codex:k1", "99"), AttemptID: "oa-1", Status: StatusConfirmed, UpdatedAt: at},
	}}
	if err := store.Save(ledger); err != nil {
		t.Fatal(err)
	}
	known = map[string][]byte{"codex:k1": record("codex:k1", "10")}
	if err := ApplyToBaseline(dir, CodexSource, known); err != nil {
		t.Fatal(err)
	}
	if string(known["codex:k1"]) != string(record("codex:k1", "99")) {
		t.Fatalf("confirmed override must supersede the stored payload, got %s", known["codex:k1"])
	}

	// Pending entry blocks the source fail-closed.
	pending := ledger.Entries["codex:k1"]
	pending.Status = StatusPending
	pending.PendingRecord = record("codex:k1", "100")
	pending.PendingAttemptID = "oa-2"
	pending.PendingSince = &at
	ledger.Entries["codex:k1"] = pending
	if err := store.Save(ledger); err != nil {
		t.Fatal(err)
	}
	err := ApplyToBaseline(dir, CodexSource, known)
	if err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("pending override must block the scan, got %v", err)
	}

	// Another source's pending entries do not block this source.
	confirmed := ledger.Entries["codex:k1"]
	confirmed.Status = StatusConfirmed
	confirmed.PendingRecord = nil
	confirmed.PendingAttemptID = ""
	confirmed.PendingSince = nil
	ledger.Entries["codex:k1"] = confirmed
	ledger.Entries["dsh:k"] = Entry{RecordKey: "dsh:k", Source: DeepSeekSource, PendingRecord: record("dsh:k", "1"), PendingAttemptID: "oa-3", Status: StatusPending, PendingSince: &at, UpdatedAt: at}
	if err := store.Save(ledger); err != nil {
		t.Fatal(err)
	}
	if err := ApplyToBaseline(dir, CodexSource, known); err != nil {
		t.Fatalf("a pending dsh entry must not block the codex scan: %v", err)
	}
	if err := ApplyToBaseline(dir, DeepSeekSource, map[string][]byte{}); err == nil {
		t.Fatal("a pending dsh entry must block the dsh scan")
	}
}

func TestBindingError(t *testing.T) {
	dir := t.TempDir()
	at := time.Now().UTC()
	ledger := Ledger{Schema: Schema, DeviceID: "device-a", ServerURL: "http://srv", Entries: map[string]Entry{
		"codex:k1": {RecordKey: "codex:k1", Source: CodexSource, Record: record("codex:k1", "10"), AttemptID: "oa-1", Status: StatusConfirmed, UpdatedAt: at},
	}}
	// Unbound state dir: fail closed.
	if err := ledger.BindingError(dir); err == nil {
		t.Fatal("unbound collector must not apply the ledger")
	}
	// Different device: fail closed.
	boundState(t, dir, "device-b", "http://srv")
	if err := ledger.BindingError(dir); err == nil || !strings.Contains(err.Error(), "device-a") {
		t.Fatalf("device mismatch must fail closed, got %v", err)
	}
	// Different bound server: fail closed.
	boundState(t, dir, "device-a", "http://other")
	if err := ledger.BindingError(dir); err == nil || !strings.Contains(err.Error(), "http://srv") {
		t.Fatalf("server mismatch must fail closed, got %v", err)
	}
	// Matching binding: ok.
	boundState(t, dir, "device-a", "http://srv")
	if err := ledger.BindingError(dir); err != nil {
		t.Fatal(err)
	}
	// Empty ledger never binds.
	if err := (Ledger{}).BindingError(dir); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalIsStableAcrossShapes(t *testing.T) {
	raw := json.RawMessage(`{"b":1,"a":2}`)
	c1, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Canonical(c1)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Fatalf("canonical form must round-trip: %s vs %s", c1, c2)
	}
	if _, err := Canonical(nil); err == nil {
		t.Fatal("empty record must fail")
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "unused"), nil, 0600); err != nil {
		t.Fatal(err)
	}
}
