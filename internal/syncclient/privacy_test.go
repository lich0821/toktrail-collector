package syncclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

// TestRunSyncUploadsWhitelistedUsageJSONRecords runs the real pipeline end
// to end — free-form usage-json input → PrepareExport → CommitExport (outbox)
// → Run — and asserts the records that actually leave the machine carry only
// the ingest whitelist: malicious extra fields (sessionId, path, prompt,
// nested objects) are dropped before the batch file is ever written, and a
// private model route collapses to "unknown".
func TestRunSyncUploadsWhitelistedUsageJSONRecords(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	inputDir := t.TempDir()
	input := filepath.Join(inputDir, "usage.json")
	raw := map[string]any{"records": []map[string]any{{
		"recordKey":      "privacy-1",
		"kind":           "delta",
		"occurredAt":     "2026-10-20T10:00:00Z",
		"tool":           "usage-json",
		"model":          "company-private-finetune-42",
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
		"sessionId":      "sess-secret-123",
		"path":           "/Users/example/secret/project",
		"prompt":         "draft the acquisition memo",
		"nested":         map[string]any{"deep": "leak"},
	}}}
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(inputDir, "batch-privacy.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{
		Input:   input,
		Output:  out,
		BatchID: "batch-privacy-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exportcommit.CommitExport(exportcommit.ExportOptions{
		StateDir:    stateDir,
		Prepared:    prepared,
		Source:      adapter.UsageJSONSource,
		Input:       input,
		CommittedAt: time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	// The committed batch file must already be clean: sync uploads it
	// verbatim, so sanitizing at upload time would come too late.
	batchBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"sess-secret-123", "secret/project", "acquisition memo", "company-private-finetune-42", "deep"} {
		if strings.Contains(string(batchBytes), leak) {
			t.Fatalf("batch file leaked private input content %q: %s", leak, batchBytes)
		}
	}

	var uploaded []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 1) {
			return
		}
		var batch BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Fatal(err)
		}
		for _, record := range batch.Records {
			var decoded map[string]any
			if err := json.Unmarshal(record, &decoded); err != nil {
				t.Fatal(err)
			}
			uploaded = append(uploaded, decoded)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         batch.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(batch.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-21T04:01:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Status != "accepted" {
		t.Fatalf("unexpected sync result: %#v", res)
	}
	if len(uploaded) != 1 {
		t.Fatalf("expected 1 uploaded record, got %d", len(uploaded))
	}
	allowed := map[string]bool{
		"recordKey": true, "groupKey": true, "resetKey": true, "kind": true,
		"occurredAt": true, "tool": true, "model": true, "input": true,
		"cacheRead": true, "cacheWrite": true, "output": true,
		"adapterVersion": true, "sourceType": true, "mutationType": true,
	}
	for field := range uploaded[0] {
		if !allowed[field] {
			t.Errorf("uploaded record leaked non-whitelisted field %q: %#v", field, uploaded[0][field])
		}
	}
	if uploaded[0]["model"] != "unknown" {
		t.Errorf("uploaded record must not carry a private model route, got %#v", uploaded[0]["model"])
	}
	if uploaded[0]["recordKey"] != "privacy-1" {
		t.Errorf("uploaded recordKey changed: %#v", uploaded[0]["recordKey"])
	}
}

// legacyLeakyBatchFile simulates a batch frozen before the export-side
// privacy fix: one clean record and one carrying free-form extras and a
// private model route. Such a batch must never be uploaded verbatim again.
func legacyLeakyBatchFile(t *testing.T, batchID string) string {
	t.Helper()
	return writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey":      "legacy-clean",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:30:00Z",
				"tool":           "usage-json",
				"input":          "10",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "5",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
			},
			{
				"recordKey":      "legacy-leak",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:40:00Z",
				"tool":           "usage-json",
				"model":          "company-private-finetune-42",
				"input":          "7",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "2",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
				"sessionId":      "sess-secret-123",
				"prompt":         "draft the acquisition memo",
			},
		},
	})
}

// TestRunSyncRefusesLegacyOutboxBatchBeforeAnyRequest covers the automatic
// outbox entry: a pre-fix pending batch is refused by the local privacy
// gate before any state change — zero HTTP requests (not even the preflight
// self GET), zero attempt accounting, the batch file untouched, the outbox
// entry still pending, and the per-message ACK state unchanged.
func TestRunSyncRefusesLegacyOutboxBatchBeforeAnyRequest(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-legacy-outbox-1"
	batchFile := legacyLeakyBatchFile(t, batchID)
	before, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2,
	}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-clean", RecordKey: "legacy-clean", To: &progress.MessageUsageState{Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(5)}},
		{MessageID: "msg-leak", RecordKey: "legacy-leak", To: &progress.MessageUsageState{Input: u64ptr(7), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(2)}},
	}); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("no HTTP request must happen for a legacy batch, got %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "outside the upload whitelist") || !strings.Contains(err.Error(), "no HTTP request was made") {
		t.Fatalf("expected the static privacy gate error, got %v", err)
	}
	if strings.Contains(err.Error(), "sess-secret-123") || strings.Contains(err.Error(), "acquisition memo") || strings.Contains(err.Error(), "company-private-finetune-42") {
		t.Fatalf("privacy gate error must not echo record contents: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expected zero HTTP requests, got %d", requests.Load())
	}
	after, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("batch file must stay untouched:\n%s\n%s", before, after)
	}
	entry, ok, err := outbox.New(stateDir).NextPending()
	if err != nil || !ok {
		t.Fatalf("expected the batch to stay pending: %v %v", ok, err)
	}
	if entry.BatchID != batchID || entry.File != batchFile || entry.Status != "pending" || !entry.LastAttemptAt.IsZero() {
		t.Fatalf("outbox entry must be unchanged with no attempt accounting: %#v", entry)
	}
	progress, _, err := progress.New(stateDir).MessageProgressFor(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"msg-clean", "msg-leak"} {
		p, ok := progress[msg]
		if !ok || p.Pending == nil || p.Pending.BatchID != batchID || p.Confirmed != nil {
			t.Fatalf("per-message ACK state must stay unchanged for %s: %#v", msg, p)
		}
	}
}

// TestRunSyncRefusesLegacyExplicitFileBatch covers the explicit --file
// entry, with and without a state directory: the gate is a property of the
// payload, not of the outbox.
func TestRunSyncRefusesLegacyExplicitFileBatch(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	batchFile := legacyLeakyBatchFile(t, "batch-legacy-file-1")
	before, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("no HTTP request must happen for a legacy batch, got %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, BatchFile: batchFile, BatchID: "batch-legacy-file-1"})
	if err == nil || !strings.Contains(err.Error(), "outside the upload whitelist") || !strings.Contains(err.Error(), "no HTTP request was made") {
		t.Fatalf("expected the static privacy gate error (stateful --file), got %v", err)
	}
	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile, BatchID: "batch-legacy-file-1"})
	if err == nil || !strings.Contains(err.Error(), "outside the upload whitelist") || !strings.Contains(err.Error(), "no HTTP request was made") {
		t.Fatalf("expected the static privacy gate error (stateless --file), got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expected zero HTTP requests, got %d", requests.Load())
	}
	after, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("batch file must stay untouched:\n%s\n%s", before, after)
	}
}

// TestRunSyncReorganizedLegacyBatchStaysGated covers batches re-created by
// a scope reorganization before the privacy fix: the reorganized batch is a
// fresh outbox head, and the gate refuses it the same way — the recovery
// and reorg machinery never becomes a bypass.
func TestRunSyncReorganizedLegacyBatchStaysGated(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-legacy-reorg-1"
	historyFrom := mustParseTime(t, "2026-10-20T10:00:00Z")
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				// In scope, but a pre-fix record with free-form extras:
				// the reorg keeps it verbatim, so the new batch inherits
				// the leak and must be gated.
				"recordKey":      "record-keep",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:30:00Z",
				"tool":           "usage-json",
				"input":          "10",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "5",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
				"sessionId":      "sess-secret-123",
			},
			{
				"recordKey":      "record-drop",
				"kind":           "delta",
				"occurredAt":     "2026-10-20T10:40:00Z",
				"tool":           "other-tool",
				"input":          "7",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "2",
				"adapterVersion": "test-adapter-1",
				"sourceType":     "fixture",
			},
		},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2,
	}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-keep", RecordKey: "record-keep", To: &progress.MessageUsageState{Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(5)}},
		{MessageID: "msg-drop", RecordKey: "record-drop", To: &progress.MessageUsageState{Input: u64ptr(7), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(2)}},
	}); err != nil {
		t.Fatal(err)
	}
	entry, ok, err := outbox.New(stateDir).NextPending()
	if err != nil || !ok {
		t.Fatalf("expected a pending batch: %v %v", ok, err)
	}

	// Scoped server for the reorg's own self GET; a POST here would mean
	// the reorg path itself uploads, which it must not.
	scoped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			serveSelfScoped(w, r, 8, []string{"usage-json"}, &historyFrom, nil)
			return
		}
		t.Errorf("unexpected %s %s during reorganization", r.Method, r.URL.Path)
	}))
	defer scoped.Close()
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := loadBatch(batchFile, "")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := reorganizeBatchAfterScopeError(t.Context(), &http.Client{}, scoped.URL, st, stateDir, entry, batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.NewBatches) != 1 || len(journal.NewBatches[0].Records) != 1 {
		t.Fatalf("expected one kept record in the reorganized batch: %#v", journal.NewBatches)
	}
	reorgID := journal.NewBatches[0].BatchID

	// The reorganized batch is the outbox head; sending it must be gated.
	var requests atomic.Int32
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("no HTTP request must happen for the reorganized legacy batch, got %s %s", r.Method, r.URL.Path)
	}))
	defer counting.Close()
	_, err = Run(t.Context(), store, Options{ServerURL: counting.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "outside the upload whitelist") || !strings.Contains(err.Error(), "no HTTP request was made") {
		t.Fatalf("expected the static privacy gate error for the reorganized batch, got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expected zero HTTP requests, got %d", requests.Load())
	}
	next, ok, err := outbox.New(stateDir).NextPending()
	if err != nil || !ok {
		t.Fatalf("expected the reorganized batch to stay pending: %v %v", ok, err)
	}
	if next.BatchID != reorgID {
		t.Fatalf("expected the reorganized batch %s at the outbox head, got %#v", reorgID, next)
	}
}

// TestRunSyncUploadsFrozenLegitimateBatchByteIdentical proves the gate is
// inert for conforming batches: a frozen legitimate batch leaves the device
// byte-for-byte and hash-identical to the on-disk file.
func TestRunSyncUploadsFrozenLegitimateBatchByteIdentical(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const batchID = "batch-frozen-1"
	batch := BatchRequest{BatchID: batchID, Records: []json.RawMessage{
		[]byte(`{"recordKey":"frozen-1","kind":"delta","occurredAt":"2026-10-20T10:30:00Z","tool":"Codex","model":"gpt-4o","input":"10","cacheRead":"0","cacheWrite":"0","output":"5","adapterVersion":"test-adapter-1","sourceType":"fixture"}`),
		[]byte(`{"recordKey":"frozen-2","kind":"delta","occurredAt":"2026-10-20T10:40:00Z","tool":"Claude Code","model":"unknown","input":"7","cacheRead":"0","cacheWrite":"0","output":"2","adapterVersion":"test-adapter-1","sourceType":"fixture"}`),
	}}
	fileBytes, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	batchFile := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(batchFile, fileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: batchFile, RecordCount: 2,
	}); err != nil {
		t.Fatal(err)
	}

	var postBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 1) {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		postBody = body
		var received BatchRequest
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         received.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(received.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-21T04:01:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Status != "accepted" {
		t.Fatalf("unexpected sync result: %#v", res)
	}
	if !bytes.Equal(postBody, fileBytes) {
		t.Fatalf("frozen legitimate batch must upload byte-identical:\n%s\n%s", postBody, fileBytes)
	}
	if sha256.Sum256(postBody) != sha256.Sum256(fileBytes) {
		t.Fatal("frozen legitimate batch must upload hash-identical")
	}
	if _, ok, err := outbox.New(stateDir).NextPending(); err != nil || ok {
		t.Fatalf("expected an empty outbox after the accepted upload: %v %v", ok, err)
	}
}
