package syncclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
)

// serveSelfScoped mirrors serveSelf but renders a concrete consent scope:
// allowed tools, historyFrom and uploadUntil follow the server semantics
// (non-empty tools = exact membership; historyFrom inclusive, uploadUntil
// exclusive; all nil = unrestricted).
func serveSelfScoped(w http.ResponseWriter, r *http.Request, revision int64, allowedTools []string, historyFrom, uploadUntil *time.Time) {
	device := map[string]any{
		"deviceId":         "dev-1",
		"consentRevision":  revision,
		"uploadAuthorized": true,
		"revoked":          false,
	}
	if len(allowedTools) > 0 {
		device["allowedTools"] = allowedTools
	}
	if historyFrom != nil {
		device["historyFrom"] = historyFrom.Format(time.RFC3339Nano)
	}
	if uploadUntil != nil {
		device["uploadUntil"] = uploadUntil.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// outboxEntryOf returns the outbox entry with the given batch ID.
func outboxEntryOf(t *testing.T, stateDir, batchID string) *outbox.BatchEntry {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Batches {
		if out.Batches[i].BatchID == batchID {
			return &out.Batches[i]
		}
	}
	t.Fatalf("outbox has no batch %s: %#v", batchID, out.Batches)
	return nil
}

// TestRunSyncOutsideScopeQuarantinesAndFreesHeadOfLine covers the full mixed
// lifecycle: a batch whose records split between in-scope, tool-rejected, and
// time-window-rejected under one scope; the kept record is re-batched, the
// rejected ones are quarantined recoverably with their per-message intervals;
// the kept batch syncs; a later, strictly newer and wider revision recovers
// the quarantined records into a fresh recovery batch that syncs verbatim.
func TestRunSyncOutsideScopeQuarantinesAndFreesHeadOfLine(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-mixed-1"
	historyFrom := mustParseTime(t, "2026-10-20T10:00:00Z")
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey": "record-a", "kind": "delta",
				"occurredAt": "2026-10-20T10:30:00Z", "tool": "usage-json",
				"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
			{
				"recordKey": "record-b", "kind": "delta",
				"occurredAt": "2026-10-20T10:40:00Z", "tool": "other-tool",
				"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
			{
				"recordKey": "record-c", "kind": "delta",
				"occurredAt": "2026-10-20T09:30:00Z", "tool": "usage-json",
				"input": "4", "cacheRead": "0", "cacheWrite": "0", "output": "3",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
		},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 3}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 3}); err != nil {
		t.Fatal(err)
	}
	msgTo := map[string]*progress.MessageUsageState{
		"msg-a": {Input: u64ptr(10), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(5)},
		"msg-b": {Input: u64ptr(7), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(2)},
		"msg-c": {Input: u64ptr(4), CacheRead: u64ptr(0), CacheWrite: u64ptr(0), Output: u64ptr(3)},
	}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-a", RecordKey: "record-a", To: msgTo["msg-a"]},
		{MessageID: "msg-b", RecordKey: "record-b", To: msgTo["msg-b"]},
		{MessageID: "msg-c", RecordKey: "record-c", To: msgTo["msg-c"]},
	}); err != nil {
		t.Fatal(err)
	}
	// Deterministic reorganized batch ID: old batch + revision 8 + the
	// revision-8 scope content + the kept key.
	narrowScope := liveScope{revision: 8, historyFrom: &historyFrom, allowedTools: map[string]struct{}{"usage-json": {}}}
	keptID := reorgBatchID(batchID, 8, narrowScope, []string{"record-a"})
	recoveryID := recoveryBatchID(source, 9, []string{"record-b", "record-c"})

	var gets, posts atomic.Int32
	var revision atomic.Int64
	var restrict, reject atomic.Bool
	revision.Store(8)
	restrict.Store(true)
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			var tools []string
			var from *time.Time
			if restrict.Load() {
				tools = []string{"usage-json"}
				from = &historyFrom
			}
			serveSelfScoped(w, r, revision.Load(), tools, from, nil)
			return
		}
		posts.Add(1)
		if reject.Load() {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
				"code":          "outside_scope",
				"message":       "records fall outside the consent scope",
				"recordIndexes": []int{1, 2},
			}})
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(got.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	// Run 1: 403 outside_scope. The batch is durably reorganized: record-a
	// kept in a new pending batch, record-b (tool) and record-c (window)
	// quarantined, message intervals migrated or released, head freed.
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrOutsideScope) {
		t.Fatalf("expected ErrOutsideScope, got %v", err)
	}
	if !strings.Contains(err.Error(), "1 record(s) kept") || !strings.Contains(err.Error(), "2 record(s) quarantined recoverably") {
		t.Fatalf("expected the reorganization summary in the error, got: %v", err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("expected 2 GET / 1 POST in the reorganization run, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	if entry := outboxEntryOf(t, stateDir, batchID); entry.Status != outbox.StatusReorganized || entry.ReorganizedInto != keptID || entry.ReorganizedRevision != 8 {
		t.Fatalf("expected old batch terminally reorganized into %s: %#v", keptID, entry)
	}
	if entry := outboxEntryOf(t, stateDir, keptID); entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 8 || entry.RecordCount != 1 {
		t.Fatalf("expected kept batch pending under revision 8: %#v", entry)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 2 {
		t.Fatalf("expected two quarantined records, err=%v entries=%#v", qErr, qEntries)
	}
	qBy := map[string]quarantine.Entry{}
	for _, entry := range qEntries {
		qBy[entry.RecordKey] = entry
	}
	if q := qBy["record-b"]; q.Reason != quarantine.ReasonToolNotAllowed || q.ConsentRevision != 8 || q.OriginBatchID != batchID || q.MessageID != "msg-b" || q.Source != source || !q.ToState.Equal(msgTo["msg-b"]) || q.FromState != nil {
		t.Fatalf("unexpected quarantine entry for record-b: %#v", q)
	}
	if q := qBy["record-c"]; q.Reason != quarantine.ReasonBeforeHistoryFrom || q.ConsentRevision != 8 || q.MessageID != "msg-c" || !q.ToState.Equal(msgTo["msg-c"]) {
		t.Fatalf("unexpected quarantine entry for record-c: %#v", q)
	}
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if msgs["msg-a"].Pending == nil || msgs["msg-a"].Pending.BatchID != keptID || msgs["msg-a"].Pending.RecordKey != "record-a" || !msgs["msg-a"].Pending.To.Equal(msgTo["msg-a"]) {
		t.Fatalf("expected msg-a interval migrated to the kept batch: %#v", msgs["msg-a"])
	}
	for _, id := range []string{"msg-b", "msg-c"} {
		if msgs[id].Pending != nil || msgs[id].QuarantinedKey == "" || msgs[id].QuarantinedRevision != 8 || msgs[id].Confirmed != nil {
			t.Fatalf("expected %s released and quarantined without baseline damage: %#v", id, msgs[id])
		}
	}
	if msgs["msg-b"].QuarantinedReason != quarantine.ReasonToolNotAllowed || msgs["msg-c"].QuarantinedReason != quarantine.ReasonBeforeHistoryFrom {
		t.Fatalf("expected quarantine reasons in message progress: %#v %#v", msgs["msg-b"], msgs["msg-c"])
	}
	cursorLedger, loadErr := cursors.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(cursorLedger.Cursors) != 1 || cursorLedger.Cursors[0].BatchID != keptID || cursorLedger.Cursors[0].ConfirmedBatchID != "" {
		t.Fatalf("expected cursor pending on the kept batch: %#v", cursorLedger)
	}

	// Run 2: the kept batch syncs normally (no re-post of old content).
	reject.Store(false)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 3 || posts.Load() != 2 {
		t.Fatalf("expected one GET and one POST for the kept batch, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	if entry := outboxEntryOf(t, stateDir, keptID); entry.Status != outbox.StatusSynced || entry.ReceiptStatus != "accepted" {
		t.Fatalf("expected kept batch synced: %#v", entry)
	}
	msgs, _, msgErr = cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if !msgs["msg-a"].Confirmed.Equal(msgTo["msg-a"]) || msgs["msg-a"].Pending != nil {
		t.Fatalf("expected msg-a confirmed: %#v", msgs["msg-a"])
	}
	if msgs["msg-b"].Pending != nil || msgs["msg-c"].Pending != nil {
		t.Fatalf("expected quarantined messages untouched by the kept-batch ACK")
	}

	// Run 3: empty outbox, quarantine non-empty, scope widened under a
	// strictly newer revision — exactly one GET, no POST, records re-pended.
	revision.Store(9)
	restrict.Store(false)
	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 2 || result.Quarantined != 0 || result.Receipt.BatchID != "" {
		t.Fatalf("expected a recovery-only run of 2 records: %#v", result)
	}
	if gets.Load() != 4 || posts.Load() != 2 {
		t.Fatalf("expected one GET and zero POST in the recovery-only run, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	if entry := outboxEntryOf(t, stateDir, recoveryID); entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 9 || entry.RecordCount != 2 {
		t.Fatalf("expected recovery batch pending under revision 9: %#v", entry)
	}
	msgs, _, msgErr = cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	for _, id := range []string{"msg-b", "msg-c"} {
		if msgs[id].Pending == nil || msgs[id].Pending.BatchID != recoveryID || msgs[id].QuarantinedKey != "" {
			t.Fatalf("expected %s re-pended under the recovery batch: %#v", id, msgs[id])
		}
	}
	if msgs["msg-b"].Pending.RecordKey != "record-b" || !msgs["msg-b"].Pending.To.Equal(msgTo["msg-b"]) || msgs["msg-b"].Confirmed != nil {
		t.Fatalf("expected original interval and baseline restored for msg-b: %#v", msgs["msg-b"])
	}

	// Run 4: the recovery batch syncs under the new revision, confirming the
	// recovered messages against their original endpoints.
	reject.Store(false)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 5 || posts.Load() != 3 {
		t.Fatalf("expected one GET and one POST for the recovery batch, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	if entry := outboxEntryOf(t, stateDir, recoveryID); entry.Status != outbox.StatusSynced || entry.ReceiptStatus != "accepted" {
		t.Fatalf("expected recovery batch synced: %#v", entry)
	}
	msgs, _, msgErr = cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	for _, id := range []string{"msg-b", "msg-c"} {
		if msgs[id].Pending != nil || !msgs[id].Confirmed.Equal(msgTo[id]) {
			t.Fatalf("expected %s confirmed at its original endpoint: %#v", id, msgs[id])
		}
	}
	qEntries, qErr = quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected quarantine drained, err=%v entries=%#v", qErr, qEntries)
	}
}

// TestRunSyncAllOutOfScopeFreesHeadOfLine: when every record of the head
// batch is outside the scope, no new batch is created, everything is
// quarantined, and the outbox head is still freed — later batches are never
// blocked by a fully out-of-scope batch.
func TestRunSyncAllOutOfScopeFreesHeadOfLine(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-out-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-x", "kind": "delta",
			"occurredAt": "2026-10-20T11:00:00Z", "tool": "usage-json",
			"input": "6", "cacheRead": "0", "cacheWrite": "0", "output": "1",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{{MessageID: "msg-x", RecordKey: "record-x", To: &progress.MessageUsageState{Input: u64ptr(6)}}}); err != nil {
		t.Fatal(err)
	}
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			uploadUntil := mustParseTime(t, "2026-10-20T10:00:00Z")
			serveSelfScoped(w, r, 6, nil, nil, &uploadUntil)
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
			"code": "outside_scope", "message": "records fall outside the consent scope", "recordIndexes": []int{0},
		}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrOutsideScope) {
		t.Fatalf("expected ErrOutsideScope, got %v", err)
	}
	if !strings.Contains(err.Error(), "no new batch") || !strings.Contains(err.Error(), "after_upload_until") {
		t.Fatalf("expected a no-new-batch summary with the upload-until reason, got: %v", err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("expected 2 GET / 1 POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	// Old batch terminal with no successor; outbox is drained.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusReorganized || out.Batches[0].ReorganizedInto != "" {
		t.Fatalf("expected the old batch terminal without a successor: %#v", out)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 1 || qEntries[0].Reason != quarantine.ReasonAfterUploadUntil {
		t.Fatalf("expected record-x quarantined after_upload_until, err=%v: %#v", qErr, qEntries)
	}
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if msgs["msg-x"].Pending != nil || msgs["msg-x"].QuarantinedKey != "record-x" {
		t.Fatalf("expected msg-x released and quarantined: %#v", msgs["msg-x"])
	}
	// The next run has an empty outbox: it must not loop on the quarantined
	// head — it reports the strictly-newer-revision requirement instead.
	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "need a strictly newer consent revision") {
		t.Fatalf("expected the quarantine diagnosis on the next run, got %v", err)
	}
	if gets.Load() != 3 || posts.Load() != 1 {
		t.Fatalf("expected one more GET and no further POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
}

// TestRunSyncSameRevisionReorgFailsClosed: a batch that was already
// reorganized under revision R must not be silently re-reorganized at the
// same revision — the scope content changed without a revision bump, which
// fails closed with the batch pending and nothing moved.
func TestRunSyncSameRevisionReorgFailsClosed(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "reorg-already-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1, OriginConsentRevision: 8}); err != nil {
		t.Fatal(err)
	}
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			serveSelfScoped(w, r, 8, nil, nil, nil)
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "scope_changed", "message": "consent revision moved",
		}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected ErrScopeChanged, got %v", err)
	}
	if !strings.Contains(err.Error(), "without a revision bump") {
		t.Fatalf("expected the same-revision fail-closed diagnosis, got: %v", err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("expected 2 GET / 1 POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("expected the batch to stay exactly as it was: %#v", out)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected nothing quarantined, err=%v: %#v", qErr, qEntries)
	}
}

// TestRunSyncChainedScopeChangesKeepHashIDsBounded: a reorganized batch that
// is rejected again under another revision is reorganized again; batch IDs
// stay fixed-length hashes of their inputs, so repeated scope changes can
// never grow the IDs.
func TestRunSyncChainedScopeChangesKeepHashIDsBounded(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-chain-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	firstID := reorgBatchID(batchID, 7, liveScope{revision: 7}, []string{"record-1"})
	secondID := reorgBatchID(firstID, 8, liveScope{revision: 8}, []string{"record-1"})

	var revision atomic.Int64
	var reject atomic.Bool
	var lastPosted atomic.Value
	revision.Store(7)
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			serveSelfScoped(w, r, revision.Load(), nil, nil, nil)
			return
		}
		if reject.Load() {
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
				"code": "scope_changed", "message": "consent revision moved",
			}})
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		lastPosted.Store(got.BatchID)
		if r.Header.Get("X-Consent-Revision") != "9" {
			t.Errorf("expected the fresh revision echoed, got %q", r.Header.Get("X-Consent-Revision"))
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted",
			"acceptedRecords": len(got.Records), "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected ErrScopeChanged on the first rejection, got %v", err)
	}
	revision.Store(8)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected ErrScopeChanged on the second rejection, got %v", err)
	}
	if secondID == firstID {
		t.Fatal("expected distinct batch IDs across revisions")
	}
	for _, id := range []string{firstID, secondID} {
		if len(id) != len("reorg-")+16 || !strings.HasPrefix(id, "reorg-") {
			t.Fatalf("expected a fixed-length hash batch ID, got %q", id)
		}
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 3 {
		t.Fatalf("expected three outbox entries after two reorganizations: %#v", out)
	}
	if entry := outboxEntryOf(t, stateDir, batchID); entry.Status != outbox.StatusReorganized || entry.ReorganizedInto != firstID {
		t.Fatalf("expected the origin batch terminal into %s: %#v", firstID, entry)
	}
	if entry := outboxEntryOf(t, stateDir, firstID); entry.Status != outbox.StatusReorganized || entry.ReorganizedInto != secondID || entry.ReorganizedRevision != 8 {
		t.Fatalf("expected the first reorg batch terminal into %s: %#v", secondID, entry)
	}
	if entry := outboxEntryOf(t, stateDir, secondID); entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 8 {
		t.Fatalf("expected the second reorg batch pending: %#v", entry)
	}
	// The third run uploads the latest reorganized batch, not the old ones.
	revision.Store(9)
	reject.Store(false)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if lastPosted.Load() != secondID {
		t.Fatalf("expected the second reorg batch to be posted, got %v", lastPosted.Load())
	}
}

// TestRunSyncReorgUnknownRevisionFailsClosed: a self snapshot without a
// usable consent revision during the reorganization means the scope is
// unknown; nothing is moved or quarantined and the batch stays pending.
func TestRunSyncReorgUnknownRevisionFailsClosed(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-unknown-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			// The re-fetch reports revision 0: unknown, not unrestricted.
			serveSelfScoped(w, r, 0, nil, nil, nil)
			return
		}
		posts.Add(1)
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "scope_changed", "message": "consent revision moved",
		}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrScopeChanged) {
		t.Fatalf("expected ErrScopeChanged, got %v", err)
	}
	if !strings.Contains(err.Error(), "does not report a valid consent revision") {
		t.Fatalf("expected the unknown-scope fail-closed diagnosis, got: %v", err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("expected 2 GET / 1 POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusPending {
		t.Fatalf("expected the batch untouched: %#v", out)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected nothing quarantined, err=%v: %#v", qErr, qEntries)
	}
}

// quarantineFixture seeds one quarantined record so recovery paths have
// something to work on.
func quarantineFixture(t *testing.T, stateDir, source, batchID string, revision int64, messageID string, from, to *progress.MessageUsageState) quarantine.Entry {
	t.Helper()
	record := json.RawMessage(`{"recordKey":"record-q","kind":"delta","occurredAt":"2026-10-20T10:00:00Z","tool":"usage-json","input":"9","cacheRead":"0","cacheWrite":"0","output":"1","adapterVersion":"test-adapter-1","sourceType":"fixture"}`)
	entry := quarantine.Entry{
		Source: source, Input: "/tmp/usage.jsonl", RecordKey: "record-q", Record: record,
		OriginBatchID: batchID, Reason: quarantine.ReasonToolNotAllowed,
		ConsentRevision: revision, QuarantinedAt: mustParseTime(t, "2026-10-20T10:05:00Z"),
		MessageID: messageID, FromState: from, ToState: to,
	}
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{entry}); err != nil {
		t.Fatal(err)
	}
	return entry
}

// blockPreflightJournal prevents the preflight attempt journal write by
// occupying its tmp path with a directory, simulating a durable-write
// failure.
func blockPreflightJournal(t *testing.T, stateDir string) {
	t.Helper()
	if err := os.Mkdir(outbox.New(stateDir).PreflightAttemptsPath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestRunSyncPreflightJournalFailureZeroHTTPRecoveryOnly: when the durable
// preflight attempt accounting cannot be written, the recovery-only path
// performs zero HTTP requests of any kind.
func TestRunSyncPreflightJournalFailureZeroHTTPRecoveryOnly(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	quarantineFixture(t, stateDir, "usage-json", "batch-q-1", 8, "", nil, nil)
	blockPreflightJournal(t, stateDir)
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		} else {
			posts.Add(1)
		}
		t.Errorf("no HTTP request was expected, got %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": "internal", "message": "unreachable"}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "cannot persist preflight attempt accounting before the authorization check") {
		t.Fatalf("expected the preflight journal failure diagnosis, got %v", err)
	}
	if gets.Load() != 0 || posts.Load() != 0 {
		t.Fatalf("expected zero HTTP traffic, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 1 {
		t.Fatalf("expected the quarantine store untouched, err=%v: %#v", qErr, qEntries)
	}
}

// TestRunSyncPreflightJournalFailureZeroHTTPBatchPath: same guarantee on the
// batch path — the outbox attempt survives durably, but neither the
// authorization GET nor the ingest POST is issued.
func TestRunSyncPreflightJournalFailureZeroHTTPBatchPath(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-pf-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 1}); err != nil {
		t.Fatal(err)
	}
	blockPreflightJournal(t, stateDir)
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		} else {
			posts.Add(1)
		}
		t.Errorf("no HTTP request was expected, got %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": "internal", "message": "unreachable"}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "cannot persist preflight attempt accounting") {
		t.Fatalf("expected the preflight journal failure diagnosis, got %v", err)
	}
	if gets.Load() != 0 || posts.Load() != 0 {
		t.Fatalf("expected zero HTTP traffic, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	// The outbox attempt itself was persisted before the blocked write.
	if entry := outboxEntryOf(t, stateDir, batchID); entry.LastAttemptAt.IsZero() {
		t.Fatalf("expected the durable outbox attempt to survive: %#v", entry)
	}
}

// TestRunSyncRecoverySameRevisionDoesNotRecover: a quarantine recorded under
// revision R is never auto-recovered at revision R, even when the scope
// content would now allow the record — only a strictly newer revision
// re-authorizes it.
func TestRunSyncRecoverySameRevisionDoesNotRecover(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	quarantineFixture(t, stateDir, "usage-json", "batch-q-1", 8, "", nil, nil)
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			serveSelfScoped(w, r, 8, nil, nil, nil)
			return
		}
		posts.Add(1)
		t.Errorf("no POST was expected, got %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "1 quarantined record(s) remain outside the consent scope and need a strictly newer consent revision") {
		t.Fatalf("expected the same-revision recovery refusal, got %v", err)
	}
	if gets.Load() != 1 || posts.Load() != 0 {
		t.Fatalf("expected one GET and zero POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 1 {
		t.Fatalf("expected the quarantine store untouched, err=%v: %#v", qErr, qEntries)
	}
}

// TestRunSyncRecoveryStaleBaselineFailsClosed: a quarantine entry whose
// recorded pre-quarantine baseline no longer matches the live message
// progress is inconsistent; recovery fails closed and everything stays
// quarantined instead of guessing.
func TestRunSyncRecoveryStaleBaselineFailsClosed(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	// Message progress: msg-q confirmed at input 5 and quarantined for
	// record-q (the release the quarantine store would have performed).
	cursors := progress.New(stateDir)
	messageProgress := progress.MessageProgress{
		Confirmed:           &progress.MessageUsageState{Input: u64ptr(5)},
		QuarantinedKey:      "record-q",
		QuarantinedReason:   quarantine.ReasonToolNotAllowed,
		QuarantinedRevision: 8,
		UpdatedAt:           mustParseTime(t, "2026-10-20T10:05:00Z"),
	}
	// Seed the progress file directly with the same on-disk layout the
	// cursor store uses (the public API only mutates progress through batch
	// transactions, and this test wants a drifted pre-quarantine baseline).
	progressFile := map[string]any{
		"version":  "1",
		"messages": map[string]progress.MessageProgress{source + "\x00msg-q": messageProgress},
	}
	progressBytes, marshalErr := json.MarshalIndent(progressFile, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if err := os.WriteFile(cursors.MessageProgressPath(), progressBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// The quarantine store claims the baseline was input 4 — drifted.
	quarantineFixture(t, stateDir, source, "batch-q-1", 8, "msg-q",
		&progress.MessageUsageState{Input: u64ptr(4)},
		&progress.MessageUsageState{Input: u64ptr(9)})
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			serveSelfScoped(w, r, 9, nil, nil, nil)
			return
		}
		posts.Add(1)
		t.Errorf("no POST was expected, got %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "confirmed baseline of message msg-q changed since it was quarantined") {
		t.Fatalf("expected the stale-baseline fail-closed diagnosis, got %v", err)
	}
	if gets.Load() != 1 || posts.Load() != 0 {
		t.Fatalf("expected one GET and zero POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 1 {
		t.Fatalf("expected everything to stay quarantined, err=%v: %#v", qErr, qEntries)
	}
}

// TestReorgJournalReplayCoversCrashPhases: the reorg journal is written
// before any state changes and applied idempotently, so a crash between the
// write, the apply, and the removal converges on the same final state no
// matter which phase the replay starts from.
func TestReorgJournalReplayCoversCrashPhases(t *testing.T) {
	for _, phase := range []string{"written-not-applied", "applied-not-removed", "double-applied"} {
		t.Run(phase, func(t *testing.T) {
			stateDir, _, _ := setupBoundState(t)
			const source = "usage-json"
			const oldBatchID = "batch-journal-1"
			batchFile := writeBatchFile(t, map[string]any{
				"batchId": oldBatchID,
				"records": []map[string]any{
					{
						"recordKey": "record-k", "kind": "delta",
						"occurredAt": "2026-10-20T10:30:00Z", "tool": "usage-json",
						"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
						"adapterVersion": "test-adapter-1", "sourceType": "fixture",
					},
					{
						"recordKey": "record-q", "kind": "delta",
						"occurredAt": "2026-10-20T10:40:00Z", "tool": "other-tool",
						"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
						"adapterVersion": "test-adapter-1", "sourceType": "fixture",
					},
				},
			})
			if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: oldBatchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2}); err != nil {
				t.Fatal(err)
			}
			cursors := progress.New(stateDir)
			if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: oldBatchID, RecordCount: 2}); err != nil {
				t.Fatal(err)
			}
			if err := cursors.ApplyMessagePending(source, oldBatchID, []progress.MessagePendingUpdate{
				{MessageID: "msg-k", RecordKey: "record-k", To: &progress.MessageUsageState{Input: u64ptr(10)}},
				{MessageID: "msg-q", RecordKey: "record-q", To: &progress.MessageUsageState{Input: u64ptr(7)}},
			}); err != nil {
				t.Fatal(err)
			}
			keptRaw := json.RawMessage(`{"adapterVersion":"test-adapter-1","cacheRead":"0","cacheWrite":"0","input":"10","kind":"delta","occurredAt":"2026-10-20T10:30:00Z","output":"5","recordKey":"record-k","sourceType":"fixture","tool":"usage-json"}`)
			quarantinedRaw := json.RawMessage(`{"adapterVersion":"test-adapter-1","cacheRead":"0","cacheWrite":"0","input":"7","kind":"delta","occurredAt":"2026-10-20T10:40:00Z","output":"2","recordKey":"record-q","sourceType":"fixture","tool":"other-tool"}`)
			newID := "reorg-journaltest1"
			journal := reorgJournal{
				Kind: "scope-error", OldBatchID: oldBatchID, OldSource: source,
				ConsentRevision: 8, CreatedAt: mustParseTime(t, "2026-10-20T10:06:00Z"),
				NewBatches: []reorgBatchPlan{{
					BatchID: newID, Source: source, Input: batchFile,
					Records: []json.RawMessage{keptRaw},
				}},
				Quarantine: []quarantine.Entry{{
					Source: source, Input: batchFile, RecordKey: "record-q", Record: quarantinedRaw,
					OriginBatchID: oldBatchID, Reason: quarantine.ReasonToolNotAllowed,
					ConsentRevision: 8, QuarantinedAt: mustParseTime(t, "2026-10-20T10:06:00Z"),
					MessageID: "msg-q", ToState: &progress.MessageUsageState{Input: u64ptr(7)},
				}},
			}
			switch phase {
			case "written-not-applied":
				// Crash right after the journal hit disk.
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			case "applied-not-removed":
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			case "double-applied":
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			}
			// The next run replays the journal to completion.
			if err := recoverPendingReorg(stateDir); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(reorgJournalPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected the journal removed after replay, err=%v", err)
			}
			// Exactly one terminal old batch, one pending new batch.
			out, loadErr := outbox.New(stateDir).Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if len(out.Batches) != 2 {
				t.Fatalf("expected two outbox entries after replay: %#v", out)
			}
			if entry := outboxEntryOf(t, stateDir, oldBatchID); entry.Status != outbox.StatusReorganized || entry.ReorganizedInto != newID {
				t.Fatalf("expected the old batch terminal: %#v", entry)
			}
			if entry := outboxEntryOf(t, stateDir, newID); entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 8 || entry.RecordCount != 1 {
				t.Fatalf("expected the new batch pending exactly once: %#v", entry)
			}
			qEntries, qErr := quarantine.New(stateDir).Load()
			if qErr != nil || len(qEntries) != 1 || qEntries[0].RecordKey != "record-q" {
				t.Fatalf("expected exactly one quarantined record, err=%v: %#v", qErr, qEntries)
			}
			msgs, _, msgErr := cursors.MessageProgressFor(source)
			if msgErr != nil {
				t.Fatal(msgErr)
			}
			if msgs["msg-k"].Pending == nil || msgs["msg-k"].Pending.BatchID != newID {
				t.Fatalf("expected msg-k migrated exactly once: %#v", msgs["msg-k"])
			}
			if msgs["msg-q"].Pending != nil || msgs["msg-q"].QuarantinedKey != "record-q" {
				t.Fatalf("expected msg-q quarantined exactly once: %#v", msgs["msg-q"])
			}
		})
	}
}

// TestLoadReorgJournalCorruptFailsClosed: a corrupt journal is never
// partially applied — the run refuses to continue.
func TestLoadReorgJournalCorruptFailsClosed(t *testing.T) {
	stateDir, _, _ := setupBoundState(t)
	if err := os.WriteFile(reorgJournalPath(stateDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadReorgJournal(stateDir); err == nil || !strings.Contains(err.Error(), "failing closed") {
		t.Fatalf("expected the corrupt-journal diagnosis, got %v", err)
	}
	if err := recoverPendingReorg(stateDir); err == nil {
		t.Fatal("expected recoverPendingReorg to refuse a corrupt journal")
	}
	// A structurally valid journal without kind/revision fails closed too.
	if err := os.WriteFile(reorgJournalPath(stateDir), []byte(`{"createdAt":"2026-10-20T10:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadReorgJournal(stateDir); err == nil || !strings.Contains(err.Error(), "failing closed") {
		t.Fatalf("expected the missing-revision diagnosis, got %v", err)
	}
}

// TestPreflightAttemptsPathLayout pins the on-disk layout of the preflight
// attempt journal: a single JSON file inside the state directory.
func TestPreflightAttemptsPathLayout(t *testing.T) {
	stateDir, _, _ := setupBoundState(t)
	if got, want := outbox.New(stateDir).PreflightAttemptsPath(), filepath.Join(stateDir, "preflight-attempts.json"); got != want {
		t.Fatalf("preflight attempts path = %q, want %q", got, want)
	}
}

// TestRunSyncExplicitFileWithStateDirJournalsPreflight: the explicit --file
// path with a state directory performs the self GET, and that GET is covered
// by the durable preflight attempt journal even though the batch is not an
// outbox entry (MarkAttempt must never fire for an unknown batch).
func TestRunSyncExplicitFileWithStateDirJournalsPreflight(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const batchID = "batch-file-pf-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 8) {
			gets.Add(1)
			return
		}
		if r.URL.Path != "/v1/ingest/batches" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unreachable"}})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": batchID, "status": "accepted", "acceptedRecords": 1,
			"rejectedRecords": 0, "replay": false, "receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, BatchFile: batchFile})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusAccepted || gets.Load() != 1 {
		t.Fatalf("expected one self GET and an accepted upload: %#v (GETs: %d)", res, gets.Load())
	}
	attempts, err := outbox.New(stateDir).LoadPreflightAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Count != 1 || attempts.FirstAt.IsZero() || attempts.LastAt.IsZero() {
		t.Fatalf("expected the explicit-file GET to be journaled, got %#v", attempts)
	}
	// MarkAttempt never fires for a batch that is not an outbox entry.
	if _, ok, err := outbox.New(stateDir).NextPending(); err != nil || ok {
		t.Fatalf("expected no outbox entry to be created or marked, ok=%v err=%v", ok, err)
	}
}

// TestRunSyncPreflightJournalFailureZeroHTTPExplicitFile: same zero-HTTP
// guarantee on the explicit --file path — when the durable preflight attempt
// accounting cannot be written, neither the authorization GET nor the ingest
// POST is issued.
func TestRunSyncPreflightJournalFailureZeroHTTPExplicitFile(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "batch-file-pf-2",
		"records": []map[string]any{{
			"recordKey": "record-1", "kind": "delta",
			"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
			"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
			"adapterVersion": "test-adapter-1", "sourceType": "fixture",
		}},
	})
	blockPreflightJournal(t, stateDir)
	var gets, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		} else {
			posts.Add(1)
		}
		t.Errorf("no HTTP request was expected, got %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": "internal", "message": "unreachable"}})
	}))
	defer server.Close()

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, BatchFile: batchFile})
	if err == nil || !strings.Contains(err.Error(), "cannot persist preflight attempt accounting") || !strings.Contains(err.Error(), "the batch file was not uploaded") {
		t.Fatalf("expected the explicit-file preflight journal failure diagnosis, got %v", err)
	}
	if gets.Load() != 0 || posts.Load() != 0 {
		t.Fatalf("expected zero HTTP traffic, got %d GET / %d POST", gets.Load(), posts.Load())
	}
}

// TestRunSyncGenericRecoveryAcrossLifecycle: the full lifecycle for a
// generic (usage-json/Codex-style) batch with NO message progress at all —
// no MessageID on any record. The batch falls outside the scope, both
// records are quarantined, the head is freed; a strictly newer revision
// recovers them into a pending recovery batch; the next run ACKs it; the
// run after that must find an empty quarantine, an empty outbox and must
// neither rebuild the recovery batch nor hit the already-synced refusal.
func TestRunSyncGenericRecoveryAcrossLifecycle(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-generic-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey": "record-gen-a", "kind": "delta",
				"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
				"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
			{
				"recordKey": "record-gen-b", "kind": "delta",
				"occurredAt": "2026-10-20T10:05:00Z", "tool": "other-tool",
				"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
		},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	// No ApplyMessagePending: these records carry no message provenance,
	// which is exactly the generic usage-json / Codex shape.
	recoveryID := recoveryBatchID(source, 9, []string{"record-gen-a", "record-gen-b"})

	var gets, posts atomic.Int32
	var revision atomic.Int64
	var restrict, reject atomic.Bool
	var postedMu sync.Mutex
	var postedKeys []string
	revision.Store(8)
	restrict.Store(true)
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			gets.Add(1)
			var tools []string
			if restrict.Load() {
				tools = []string{"codex"}
			}
			serveSelfScoped(w, r, revision.Load(), tools, nil, nil)
			return
		}
		posts.Add(1)
		if reject.Load() {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
				"code":          "outside_scope",
				"message":       "records fall outside the consent scope",
				"recordIndexes": []int{0, 1},
			}})
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		postedMu.Lock()
		postedKeys = postedKeys[:0]
		for _, raw := range got.Records {
			key, err := recordKeyOf(raw)
			if err != nil {
				t.Error(err)
			} else {
				postedKeys = append(postedKeys, key)
			}
		}
		postedMu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         got.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(got.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	// Run 1: 403 outside_scope under revision 8 with a scope that admits
	// neither record's tool. No record fits a new batch, so both are
	// quarantined (without any MessageID) and the head is freed.
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrOutsideScope) {
		t.Fatalf("expected ErrOutsideScope, got %v", err)
	}
	if !strings.Contains(err.Error(), "no new batch") || !strings.Contains(err.Error(), "2 record(s) quarantined recoverably") {
		t.Fatalf("expected the no-new-batch reorganization summary, got: %v", err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("expected 2 GET / 1 POST in the reorganization run, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 2 {
		t.Fatalf("expected two quarantined records, err=%v: %#v", qErr, qEntries)
	}
	for _, entry := range qEntries {
		if entry.MessageID != "" {
			t.Fatalf("expected generic quarantine entries without a MessageID, got %#v", entry)
		}
		if entry.ConsentRevision != 8 {
			t.Fatalf("expected the quarantine recorded under revision 8, got %#v", entry)
		}
	}
	// Run 2: revision 9 with an unrestricted scope. The outbox is empty, so
	// the recovery-only path runs: both generic records are re-batched and
	// — the regression this pins — actually REMOVED from quarantine even
	// though they carry no MessageID.
	revision.Store(9)
	restrict.Store(false)
	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 2 || result.Quarantined != 0 {
		t.Fatalf("expected 2 recovered and 0 quarantined, got %#v", result)
	}
	qEntries, qErr = quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected the quarantine store drained, err=%v: %#v", qErr, qEntries)
	}
	if gets.Load() != 3 || posts.Load() != 1 {
		t.Fatalf("expected one recovery GET and no POST, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	entry := outboxEntryOf(t, stateDir, recoveryID)
	if entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 9 || entry.RecordCount != 2 {
		t.Fatalf("expected the recovery batch pending under revision 9: %#v", entry)
	}
	// Run 3: the recovery batch syncs. The posted records keep their
	// original keys and payload count.
	reject.Store(false)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	postedMu.Lock()
	keys := append([]string(nil), postedKeys...)
	postedMu.Unlock()
	if len(keys) != 2 || keys[0] != "record-gen-a" || keys[1] != "record-gen-b" {
		t.Fatalf("expected the original record keys posted unchanged, got %#v", keys)
	}
	if entry := outboxEntryOf(t, stateDir, recoveryID); entry.Status != outbox.StatusSynced || entry.ReceiptStatus != "accepted" {
		t.Fatalf("expected the recovery batch synced: %#v", entry)
	}
	if gets.Load() != 4 || posts.Load() != 2 {
		t.Fatalf("expected one GET and one POST for the recovery batch, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	// Run 4: nothing pending, nothing quarantined. The run must report the
	// missing batch, not rebuild the recovery batch and not trip over the
	// already-synced reorg refusal or requeue the same records.
	_, err = Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "missing batch file and no pending outbox batch") {
		t.Fatalf("expected the missing-batch diagnosis on the drained run, got %v", err)
	}
	if strings.Contains(err.Error(), "already synced") || strings.Contains(err.Error(), "strictly newer consent revision") {
		t.Fatalf("the drained run must not re-recover or refuse the synced batch, got %v", err)
	}
	if gets.Load() != 4 || posts.Load() != 2 {
		t.Fatalf("expected no further HTTP traffic, got %d GET / %d POST", gets.Load(), posts.Load())
	}
	qEntries, qErr = quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected the quarantine still empty after ACK, err=%v: %#v", qErr, qEntries)
	}
}

// TestRunSyncMixedGenericAndMessageBackedRecovery: one batch holds a
// generic record (no message provenance) and a message-backed record
// (Claude-style interval). Both are quarantined by the same scope error and
// both are recovered under a strictly newer revision — the generic one via
// its empty-MessageID Recover item, the message-backed one with its pending
// interval restored under the recovery batch.
func TestRunSyncMixedGenericAndMessageBackedRecovery(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-mixed-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey": "record-gen", "kind": "delta",
				"occurredAt": "2026-10-20T10:00:00Z", "tool": "usage-json",
				"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
			{
				"recordKey": "record-msg", "kind": "delta",
				"occurredAt": "2026-10-20T10:05:00Z", "tool": "usage-json",
				"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
				"adapterVersion": "test-adapter-1", "sourceType": "fixture",
			},
		},
	})
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{BatchID: batchID, File: batchFile, Source: source, Input: batchFile, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	cursors := progress.New(stateDir)
	if _, err := cursors.Advance(progress.AdvanceOptions{Source: source, Input: batchFile, BatchID: batchID, RecordCount: 2}); err != nil {
		t.Fatal(err)
	}
	msgTo := &progress.MessageUsageState{Input: u64ptr(7), Output: u64ptr(2)}
	if err := cursors.ApplyMessagePending(source, batchID, []progress.MessagePendingUpdate{
		{MessageID: "msg-m", RecordKey: "record-msg", To: msgTo},
	}); err != nil {
		t.Fatal(err)
	}
	recoveryID := recoveryBatchID(source, 9, []string{"record-gen", "record-msg"})

	var revision atomic.Int64
	var restrict, reject atomic.Bool
	revision.Store(8)
	restrict.Store(true)
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			var tools []string
			if restrict.Load() {
				tools = []string{"codex"}
			}
			serveSelfScoped(w, r, revision.Load(), tools, nil, nil)
			return
		}
		if reject.Load() {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
				"code": "outside_scope", "message": "records fall outside the consent scope", "recordIndexes": []int{0, 1},
			}})
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted", "acceptedRecords": len(got.Records),
			"rejectedRecords": 0, "replay": false, "receivedAt": "2026-10-20T10:12:00Z",
		}})
	}))
	defer server.Close()

	// Run 1: both records quarantined, head freed.
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrOutsideScope) {
		t.Fatalf("expected ErrOutsideScope, got %v", err)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 2 {
		t.Fatalf("expected two quarantined records, err=%v: %#v", qErr, qEntries)
	}
	byKey := map[string]quarantine.Entry{}
	for _, entry := range qEntries {
		byKey[entry.RecordKey] = entry
	}
	if byKey["record-gen"].MessageID != "" {
		t.Fatalf("expected the generic entry without a MessageID, got %#v", byKey["record-gen"])
	}
	if byKey["record-msg"].MessageID != "msg-m" || byKey["record-msg"].ToState == nil {
		t.Fatalf("expected the message-backed entry with provenance, got %#v", byKey["record-msg"])
	}

	// Run 2: strict newer revision with an unrestricted scope recovers both
	// into one recovery batch.
	revision.Store(9)
	restrict.Store(false)
	result, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 2 || result.Quarantined != 0 {
		t.Fatalf("expected both records recovered, got %#v", result)
	}
	qEntries, qErr = quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("expected the quarantine drained, err=%v: %#v", qErr, qEntries)
	}
	if entry := outboxEntryOf(t, stateDir, recoveryID); entry.Status != outbox.StatusPending || entry.RecordCount != 2 {
		t.Fatalf("expected the mixed recovery batch pending: %#v", entry)
	}
	// The message-backed record is re-pended under the recovery batch; the
	// generic record contributes no message progress at all.
	msgs, _, msgErr := cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if msgs["msg-m"].Pending == nil || msgs["msg-m"].Pending.BatchID != recoveryID || msgs["msg-m"].Pending.RecordKey != "record-msg" || !msgs["msg-m"].Pending.To.Equal(msgTo) {
		t.Fatalf("expected msg-m restored under the recovery batch: %#v", msgs["msg-m"])
	}
	if msgs["msg-m"].QuarantinedKey != "" {
		t.Fatalf("expected the quarantine marker cleared for msg-m: %#v", msgs["msg-m"])
	}

	// Run 3: the recovery batch syncs and the message confirms at its
	// original endpoint.
	reject.Store(false)
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if entry := outboxEntryOf(t, stateDir, recoveryID); entry.Status != outbox.StatusSynced {
		t.Fatalf("expected the recovery batch synced: %#v", entry)
	}
	msgs, _, msgErr = cursors.MessageProgressFor(source)
	if msgErr != nil {
		t.Fatal(msgErr)
	}
	if msgs["msg-m"].Pending != nil || msgs["msg-m"].Confirmed == nil || !msgs["msg-m"].Confirmed.Equal(msgTo) {
		t.Fatalf("expected msg-m confirmed at its endpoint after ACK: %#v", msgs["msg-m"])
	}
}

// TestRecoveryJournalReplayCoversCrashPhasesGeneric: crash-phase idempotency
// of a quarantine-recovery journal whose Recover items carry NO MessageID —
// the generic usage-json / Codex shape. Whatever the phase, replay converges
// on an empty quarantine and a single pending recovery batch.
func TestRecoveryJournalReplayCoversCrashPhasesGeneric(t *testing.T) {
	for _, phase := range []string{"written-not-applied", "applied-not-removed", "double-applied"} {
		t.Run(phase, func(t *testing.T) {
			stateDir, _, _ := setupBoundState(t)
			const source = "usage-json"
			recordRaw := json.RawMessage(`{"recordKey":"record-gen","kind":"delta","occurredAt":"2026-10-20T10:40:00Z","tool":"usage-json","input":"7","cacheRead":"0","cacheWrite":"0","output":"2","adapterVersion":"t","sourceType":"fixture"}`)
			// A generic quarantined record: no MessageID, no state pair.
			seeded := quarantine.Entry{
				Source: source, Input: "/tmp/usage.jsonl", RecordKey: "record-gen", Record: recordRaw,
				OriginBatchID: "batch-q-1", Reason: quarantine.ReasonToolNotAllowed,
				ConsentRevision: 8, QuarantinedAt: mustParseTime(t, "2026-10-20T10:05:00Z"),
			}
			if err := quarantine.New(stateDir).Append([]quarantine.Entry{seeded}); err != nil {
				t.Fatal(err)
			}
			recoveryID := recoveryBatchID(source, 9, []string{"record-gen"})
			journal := reorgJournal{
				Kind: "quarantine-recovery", ConsentRevision: 9,
				CreatedAt: mustParseTime(t, "2026-10-20T10:06:00Z"),
				NewBatches: []reorgBatchPlan{{
					BatchID: recoveryID, Source: source, Input: "/tmp/usage.jsonl",
					Records: []json.RawMessage{recordRaw},
				}},
				Recover: []reorgRecoveryItem{{
					Source: source, RecordKey: "record-gen", BatchID: recoveryID,
				}},
			}
			switch phase {
			case "written-not-applied":
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			case "applied-not-removed":
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			case "double-applied":
				if err := writeReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
				if err := applyReorgJournal(stateDir, journal); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverPendingReorg(stateDir); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(reorgJournalPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected the journal removed after replay, err=%v", err)
			}
			// The regression this pins: the generic entry actually leaves
			// the quarantine store on replay.
			qEntries, qErr := quarantine.New(stateDir).Load()
			if qErr != nil || len(qEntries) != 0 {
				t.Fatalf("expected an empty quarantine store after replay, err=%v: %#v", qErr, qEntries)
			}
			// Exactly one pending recovery batch, born under revision 9,
			// with the original record verbatim.
			entry := outboxEntryOf(t, stateDir, recoveryID)
			if entry.Status != outbox.StatusPending || entry.OriginConsentRevision != 9 || entry.RecordCount != 1 {
				t.Fatalf("expected the recovery batch pending exactly once: %#v", entry)
			}
			recovered, readErr := os.ReadFile(batchFilePath(stateDir, recoveryID))
			if readErr != nil {
				t.Fatal(readErr)
			}
			var recoveredBatch struct {
				Records []json.RawMessage `json:"records"`
			}
			if err := json.Unmarshal(recovered, &recoveredBatch); err != nil {
				t.Fatal(err)
			}
			if len(recoveredBatch.Records) != 1 {
				t.Fatalf("expected one record in the recovery batch file: %s", recovered)
			}
			if key, err := recordKeyOf(recoveredBatch.Records[0]); err != nil || key != "record-gen" {
				t.Fatalf("expected the original record key preserved, key=%q err=%v", key, err)
			}
		})
	}
}
