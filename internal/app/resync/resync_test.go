package resync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

type fakeRemote struct {
	mu                                    sync.Mutex
	calls                                 int
	posts                                 int
	seen                                  map[string]bool
	receipts                              map[string]syncclient.BatchReceipt
	paused, revoked, reject, wrongReceipt bool
	failBatch                             string
	allowed                               []string
	from                                  *time.Time
}

func newRemote(t *testing.T) (*fakeRemote, *httptest.Server) {
	t.Helper()
	s := &fakeRemote{seen: map[string]bool{}, receipts: map[string]syncclient.BatchReceipt{}, allowed: []string{"Codex"}}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/devices/self" {
			v := 1
			json.NewEncoder(w).Encode(map[string]any{"device": syncclient.SelfStatus{DeviceID: "device-resync", ConsentRevision: 1, UploadAuthorized: !s.revoked, Revoked: s.revoked, Paused: s.paused, GrantProtocolVersion: &v, AllowedTools: s.allowed, HistoryFrom: s.from}})
			return
		}
		if r.URL.Path != "/v1/ingest/batches" {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("X-Consent-Revision") != "1" {
			t.Error("missing live consent revision")
		}
		s.posts++
		var batch syncclient.BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if batch.BatchID == s.failBatch {
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":{"code":"temporarily_unavailable","message":"synthetic failure"}}`)
			return
		}
		receipt, ok := s.receipts[batch.BatchID]
		if ok {
			receipt.Replay = true
		} else {
			receipt = syncclient.BatchReceipt{BatchID: batch.BatchID, Status: "accepted", AcceptedRecords: len(batch.Records), ReceivedAt: time.Now().UTC()}
			for idx, raw := range batch.Records {
				var rec map[string]any
				json.Unmarshal(raw, &rec)
				key := rec["recordKey"].(string)
				if s.reject {
					receipt.AcceptedRecords--
					receipt.RejectedRecords++
					receipt.Status = "partial"
					receipt.RecordErrors = append(receipt.RecordErrors, syncclient.RecordError{Index: idx, RecordKey: key, Code: "record_conflict", Message: "synthetic conflict"})
				} else {
					s.seen[key] = true
				}
			}
			s.receipts[batch.BatchID] = receipt
		}
		if s.wrongReceipt {
			receipt.BatchID = "another-batch"
		}
		json.NewEncoder(w).Encode(map[string]any{"batch": receipt})
	}))
	t.Cleanup(h.Close)
	return s, h
}
func record(key, occurred string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"recordKey": key, "kind": "delta", "tool": "Codex", "model": "gpt-5.4", "occurredAt": occurred, "input": "100", "output": "50", "cacheRead": "20", "cacheWrite": "5", "adapterVersion": "synthetic", "sourceType": "fixture"})
	return b
}
func fixture(t *testing.T, url string, batches ...[]json.RawMessage) string {
	t.Helper()
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DeviceID: "device-resync", DeviceSecret: strings.Repeat("a", 64), ApplicationID: "synthetic-app", ExternalSubjectID: "synthetic-user", ServerURL: url, UploadAuthorized: true, ConsentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	grant := map[string]any{"version": 1, "grants": []map[string]any{{"source": "codex-jsonl", "input": "/synthetic/codex", "enabled": true}}}
	writeJSON(t, filepath.Join(dir, "grants.json"), grant)
	var entries []outbox.BatchEntry
	for idx, records := range batches {
		id := fmt.Sprintf("batch-%02d", idx)
		file := filepath.Join(dir, id+".json")
		writeJSON(t, file, syncclient.BatchRequest{BatchID: id, Records: records})
		entries = append(entries, outbox.BatchEntry{BatchID: id, File: file, Source: "codex-jsonl", Input: "/synthetic/codex", Status: outbox.StatusSynced, RecordCount: len(records), CreatedAt: time.Now().UTC()})
	}
	if err := outbox.New(dir).Save(outbox.Outbox{Batches: entries}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"message-progress.json", "adapter-cursors.json", "scope-quarantine.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		m[strings.TrimPrefix(path, dir)] = string(b)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return m
}
func options(dir string) Options {
	return Options{StateDir: dir, Confirm: func(Plan) error { return nil }}
}
func assertOriginals(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	for path, value := range before {
		if path == "/device.json" {
			continue
		}
		b, err := os.ReadFile(dir + path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != value {
			t.Fatalf("original file changed: %s", path)
		}
	}
}
func TestDryRunIsOfflineAndReadOnly(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint(empty), func(t *testing.T) {
			remote, server := newRemote(t)
			var batches [][]json.RawMessage
			if !empty {
				batches = append(batches, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
			}
			dir := fixture(t, server.URL, batches...)
			before := snapshot(t, dir)
			opt := options(dir)
			opt.DryRun = true
			result, err := Run(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			if !result.DryRun || remote.calls != 0 {
				t.Fatalf("dry-run made requests: %+v", result)
			}
			if !reflect.DeepEqual(before, snapshot(t, dir)) {
				t.Fatal("dry-run changed disk")
			}
		})
	}
}
func TestRestoreReplayAndPreserveOriginalProgress(t *testing.T) {
	remote, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
	before := snapshot(t, dir)
	first, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Completed || first.AcceptedRecords != 2 || len(remote.seen) != 2 {
		t.Fatalf("restore: %+v", first)
	}
	assertOriginals(t, dir, before)
	again, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Completed || again.ReplayReceipts != 2 || len(remote.seen) != 2 || remote.posts != 4 {
		t.Fatalf("explicit second pass must replay without duplicates: %+v", again)
	}
	assertOriginals(t, dir, before)
}
func TestBudgetAndFailureResume(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
			opt := options(dir)
			if failure {
				remote.failBatch = "batch-01"
			} else {
				opt.MaxBatches = 1
			}
			first, err := Run(context.Background(), opt)
			if failure && err == nil {
				t.Fatal("expected transient failure")
			}
			if !failure && err != nil {
				t.Fatal(err)
			}
			if first.Completed {
				t.Fatal("premature completion")
			}
			remote.failBatch = ""
			resumed, err := Run(context.Background(), options(dir))
			if err != nil {
				t.Fatal(err)
			}
			if !resumed.Completed || !resumed.Plan.Resumed || resumed.Uploads != 1 || len(remote.seen) != 2 {
				t.Fatalf("resume: %+v", resumed)
			}
		})
	}
}
func TestScopeFiltersWithoutChangingArchives(t *testing.T) {
	remote, server := newRemote(t)
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	remote.from = &cutoff
	dir := fixture(t, server.URL, []json.RawMessage{record("old", "2025-01-01T00:00:00Z"), record("new", "2026-10-28T00:00:00Z")})
	before := snapshot(t, dir)
	result, err := Run(context.Background(), options(dir))
	if err != nil {
		t.Fatal(err)
	}
	if result.AcceptedRecords != 1 || result.SkippedOutOfScopeRecords != 1 || remote.seen["old"] || !remote.seen["new"] {
		t.Fatalf("scope: %+v", result)
	}
	assertOriginals(t, dir, before)
}
func TestAuthorizationStopsResync(t *testing.T) {
	for _, kind := range []string{"paused", "revoked", "local-disabled", "local-missing"} {
		t.Run(kind, func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
			switch kind {
			case "paused":
				remote.paused = true
			case "revoked":
				remote.revoked = true
			case "local-disabled":
				writeJSON(t, filepath.Join(dir, "grants.json"), map[string]any{"version": 1, "grants": []map[string]any{{"source": "codex-jsonl", "input": "/synthetic/codex", "enabled": false}}})
			case "local-missing":
				if err := os.Remove(filepath.Join(dir, "grants.json")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Run(context.Background(), options(dir)); err == nil {
				t.Fatal("expected authorization refusal")
			}
			if remote.posts != 0 {
				t.Fatal("uploaded without authorization")
			}
		})
	}
}
func TestResumeRejectsTamperingAndMissingArchive(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			remote, server := newRemote(t)
			dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")}, []json.RawMessage{record("b", "2026-10-27T00:00:00Z")})
			opt := options(dir)
			opt.MaxBatches = 1
			if _, err := Run(context.Background(), opt); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "batch-01.json")
			if missing {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			previous := remote.posts
			if _, err := Run(context.Background(), options(dir)); err == nil {
				t.Fatal("expected changed archive refusal")
			}
			if remote.posts != previous {
				t.Fatal("uploaded after archive divergence")
			}
		})
	}
}
func TestDryRunDoesNotFinalizeInterruptedJob(t *testing.T) {
	_, server := newRemote(t)
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	if _, err := Run(context.Background(), options(dir)); err != nil {
		t.Fatal(err)
	}
	jb, _, err := loadJob(dir)
	if err != nil {
		t.Fatal(err)
	}
	jb.CompletedAt = nil
	if err := saveJob(dir, jb); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	opt := options(dir)
	opt.DryRun = true
	result, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Plan.PendingFinalize || !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("dry-run finalized a job")
	}
	opt.DryRun = false
	opt.Confirm = func(Plan) error { return errors.New("cancelled") }
	if _, err := Run(context.Background(), opt); err == nil {
		t.Fatal("expected cancelled finalize")
	}
	if !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("cancelled confirmation wrote state")
	}
}
func TestWrongBatchReceiptRemainsResumable(t *testing.T) {
	remote, server := newRemote(t)
	remote.wrongReceipt = true
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.Completed || !strings.Contains(err.Error(), "does not match submitted batch") {
		t.Fatalf("wrong receipt accepted: %+v err=%v", result, err)
	}
	job, exists, err := loadJob(dir)
	if err != nil || !exists || job.CompletedAt != nil || job.Batches[0].Outcome == outcomeDone {
		t.Fatalf("wrong receipt marked completed: %+v err=%v", job, err)
	}
	remote.wrongReceipt = false
	result, err = Run(context.Background(), options(dir))
	if err != nil || !result.Completed || !result.Plan.Resumed {
		t.Fatalf("valid receipt could not resume: %+v err=%v", result, err)
	}
}

func TestRejectedReceiptIsNotReportedAsSuccessfulRestore(t *testing.T) {
	remote, server := newRemote(t)
	remote.reject = true
	dir := fixture(t, server.URL, []json.RawMessage{record("a", "2026-10-28T00:00:00Z")})
	result, err := Run(context.Background(), options(dir))
	if err == nil || result.RejectedRecords != 1 || result.AcceptedRecords != 0 || len(remote.seen) != 0 {
		t.Fatalf("rejection hidden: %+v err=%v", result, err)
	}
}
