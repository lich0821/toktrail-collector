package syncclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
)

func TestRunSyncOversizedBatch10692Records(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)

	const totalRecords = 10692
	const oldBatchID = "oversize-parent-10692"
	records := make([]map[string]any, totalRecords)
	for i := 0; i < totalRecords; i++ {
		records[i] = map[string]any{
			"recordKey":      fmt.Sprintf("rec-%05d", i),
			"kind":           "delta",
			"occurredAt":     "2026-10-22T10:00:00Z",
			"tool":           "Codex",
			"model":          "gpt-4o",
			"input":          "100",
			"cacheRead":      "20",
			"cacheWrite":     "10",
			"output":         "50",
			"adapterVersion": "test-v1",
			"sourceType":     "fixture",
			"groupKey":       strings.Repeat("a", 350), // ~450 bytes per record, total > 4.8 MB
		}
	}

	batchFile := writeBatchFile(t, map[string]any{
		"batchId": oldBatchID,
		"records": records,
	})

	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:               oldBatchID,
		File:                  batchFile,
		Source:                "usage-json",
		Input:                 batchFile,
		RecordCount:           totalRecords,
		OriginConsentRevision: 1,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	var ingestCalls int64
	var lastUploadedBatch BatchRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/self":
			if serveSelf(t, w, r, 1) {
				return
			}
		case "/v1/ingest/batches":
			atomic.AddInt64(&ingestCalls, 1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Server limits check: <= 500 records and <= 1 MiB body
			if len(body) > 1024*1024 {
				http.Error(w, fmt.Sprintf("payload exceeds server limit: %d bytes > 1 MiB", len(body)), http.StatusRequestEntityTooLarge)
				return
			}
			var req BatchRequest
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(req.Records) > 500 {
				http.Error(w, fmt.Sprintf("record count %d exceeds server limit 500", len(req.Records)), http.StatusBadRequest)
				return
			}
			lastUploadedBatch = req
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         req.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(req.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Run sync: should detect oversized batch, reorganize into 22 child batches,
	// and in the SAME run upload the first child batch!
	res, err := Run(context.Background(), store, Options{
		StateDir:  stateDir,
		ServerURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if atomic.LoadInt64(&ingestCalls) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", atomic.LoadInt64(&ingestCalls))
	}
	if res.Receipt.AcceptedRecords != 500 {
		t.Fatalf("expected 500 accepted records in first child upload, got %d", res.Receipt.AcceptedRecords)
	}
	if !strings.HasPrefix(res.Receipt.BatchID, "split-") {
		t.Fatalf("expected child batch ID starting with 'split-', got %s", res.Receipt.BatchID)
	}
	if lastUploadedBatch.BatchID != res.Receipt.BatchID {
		t.Fatalf("uploaded batch %s != result batch %s", lastUploadedBatch.BatchID, res.Receipt.BatchID)
	}
	if len(lastUploadedBatch.Records) != 500 {
		t.Fatalf("expected 500 records in uploaded batch, got %d", len(lastUploadedBatch.Records))
	}

	// Verify outbox state
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("Load ledger: %v", err)
	}

	// 1 parent + 22 children = 23 entries
	// 10692 / 500 = 21 * 500 + 192 = 22 chunks
	expectedChunks := 22
	if len(out.Batches) != 1+expectedChunks {
		t.Fatalf("expected %d total batches in outbox, got %d", 1+expectedChunks, len(out.Batches))
	}

	parentEntry := outboxEntryOf(t, stateDir, oldBatchID)
	if parentEntry.Status != outbox.StatusReorganized {
		t.Fatalf("expected parent status reorganized, got %s", parentEntry.Status)
	}
	childrenIDs := strings.Split(parentEntry.ReorganizedInto, ",")
	if len(childrenIDs) != expectedChunks {
		t.Fatalf("expected %d child IDs in ReorganizedInto, got %d: %s", expectedChunks, len(childrenIDs), parentEntry.ReorganizedInto)
	}

	// First child should be Synced, remaining 21 should be Pending
	firstChildEntry := outboxEntryOf(t, stateDir, childrenIDs[0])
	if firstChildEntry.Status != outbox.StatusSynced {
		t.Fatalf("expected first child status synced, got %s", firstChildEntry.Status)
	}
	for i := 1; i < expectedChunks; i++ {
		childEntry := outboxEntryOf(t, stateDir, childrenIDs[i])
		if childEntry.Status != outbox.StatusPending {
			t.Fatalf("expected child %d status pending, got %s", i, childEntry.Status)
		}
	}

	// Next sync run should upload second child batch
	res2, err := Run(context.Background(), store, Options{
		StateDir:  stateDir,
		ServerURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run 2 failed: %v", err)
	}
	if res2.Receipt.BatchID != childrenIDs[1] {
		t.Fatalf("expected second child batch %s, got %s", childrenIDs[1], res2.Receipt.BatchID)
	}
	if res2.Receipt.AcceptedRecords != 500 {
		t.Fatalf("expected 500 accepted records in second child upload, got %d", res2.Receipt.AcceptedRecords)
	}
}

func TestRunSyncOversizedCrashRecovery(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)

	const totalRecords = 1200
	const oldBatchID = "oversize-crash-1200"
	records := make([]map[string]any, totalRecords)
	for i := 0; i < totalRecords; i++ {
		records[i] = map[string]any{
			"recordKey":      fmt.Sprintf("rec-%04d", i),
			"kind":           "delta",
			"occurredAt":     "2026-10-22T10:00:00Z",
			"tool":           "Codex",
			"model":          "gpt-4o",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-v1",
			"sourceType":     "fixture",
		}
	}

	batchFile := writeBatchFile(t, map[string]any{
		"batchId": oldBatchID,
		"records": records,
	})

	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:               oldBatchID,
		File:                  batchFile,
		Source:                "usage-json",
		Input:                 batchFile,
		RecordCount:           totalRecords,
		OriginConsentRevision: 1,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Reorganize batch into journal, but write the journal file directly
	// to simulate crash right after journal write (before removal).
	entry := *outboxEntryOf(t, stateDir, oldBatchID)
	rawBatch, err := loadBatch(batchFile, oldBatchID)
	if err != nil {
		t.Fatalf("loadBatch: %v", err)
	}
	journal, err := reorganizeOversizedBatch(stateDir, entry, rawBatch)
	if err != nil {
		t.Fatalf("reorganizeOversizedBatch: %v", err)
	}

	// Write the journal to simulate crash before journal removal
	if err := writeReorgJournal(stateDir, journal); err != nil {
		t.Fatalf("writeReorgJournal: %v", err)
	}

	// Verify journal file exists
	if _, err := os.Stat(reorgJournalPath(stateDir)); err != nil {
		t.Fatalf("expected reorg journal on disk: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/self":
			if serveSelf(t, w, r, 1) {
				return
			}
		case "/v1/ingest/batches":
			var req BatchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         req.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(req.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Run should recover the pending journal, delete it, and upload the first child
	res, err := Run(context.Background(), store, Options{
		StateDir:  stateDir,
		ServerURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if _, err := os.Stat(reorgJournalPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("expected journal to be deleted after recovery, but got: %v", err)
	}

	if res.Receipt.AcceptedRecords != 500 {
		t.Fatalf("expected 500 accepted records, got %d", res.Receipt.AcceptedRecords)
	}
}

func TestRunSyncSingleRecordOversizedFailClosed(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)

	hugeData := strings.Repeat("x", 800*1024) // 800 KiB > 768 KiB
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "oversize-single-record",
		"records": []map[string]any{
			{
				"recordKey":      "rec-huge",
				"kind":           "delta",
				"occurredAt":     "2026-10-22T10:00:00Z",
				"tool":           "Codex",
				"model":          "gpt-4o",
				"input":          "10",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "5",
				"adapterVersion": "test-v1",
				"sourceType":     "fixture",
				"groupKey":       hugeData, // valid whitelisted field, but oversized
			},
		},
	})

	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:               "oversize-single-record",
		File:                  batchFile,
		Source:                "usage-json",
		Input:                 batchFile,
		RecordCount:           1,
		OriginConsentRevision: 1,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	var ingestCalls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/self":
			if serveSelf(t, w, r, 1) {
				return
			}
		case "/v1/ingest/batches":
			atomic.AddInt64(&ingestCalls, 1)
			writeJSON(w, http.StatusOK, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err := Run(context.Background(), store, Options{
		StateDir:  stateDir,
		ServerURL: srv.URL,
	})
	if err == nil {
		t.Fatal("expected fail-closed error on record > 768 KiB, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if atomic.LoadInt64(&ingestCalls) != 0 {
		t.Fatalf("expected 0 HTTP ingest calls, got %d", atomic.LoadInt64(&ingestCalls))
	}

	// Verify outbox entry is still pending and no attempts marked
	entry := outboxEntryOf(t, stateDir, "oversize-single-record")
	if entry.Status != outbox.StatusPending {
		t.Fatalf("expected status pending, got %s", entry.Status)
	}
	if !entry.LastAttemptAt.IsZero() {
		t.Fatalf("expected zero LastAttemptAt, got %v", entry.LastAttemptAt)
	}
}

func TestRunSyncOversizedRepointsMessageProgress(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)

	const totalRecords = 1200
	const oldBatchID = "oversize-msg-1200"
	records := make([]map[string]any, totalRecords)
	updates := make([]progress.MessagePendingUpdate, totalRecords)
	u10 := uint64(10)
	for i := 0; i < totalRecords; i++ {
		recKey := fmt.Sprintf("rec-%04d", i)
		msgID := fmt.Sprintf("msg-%04d", i)
		records[i] = map[string]any{
			"recordKey":      recKey,
			"kind":           "delta",
			"occurredAt":     "2026-10-22T10:00:00Z",
			"tool":           "Codex",
			"model":          "gpt-4o",
			"input":          "10",
			"cacheRead":      "0",
			"cacheWrite":     "0",
			"output":         "5",
			"adapterVersion": "test-v1",
			"sourceType":     "fixture",
		}
		updates[i] = progress.MessagePendingUpdate{
			MessageID: msgID,
			RecordKey: recKey,
			To:        &progress.MessageUsageState{Input: &u10},
		}
	}

	batchFile := writeBatchFile(t, map[string]any{
		"batchId": oldBatchID,
		"records": records,
	})

	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:               oldBatchID,
		File:                  batchFile,
		Source:                "claude-code-jsonl",
		Input:                 batchFile,
		RecordCount:           totalRecords,
		OriginConsentRevision: 1,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	cursors := progress.New(stateDir)
	if err := cursors.ApplyMessagePending("claude-code-jsonl", oldBatchID, updates); err != nil {
		t.Fatalf("ApplyMessagePending: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/self":
			if serveSelf(t, w, r, 1) {
				return
			}
		case "/v1/ingest/batches":
			var req BatchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         req.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(req.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := Run(context.Background(), store, Options{
		StateDir:  stateDir,
		ServerURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// 1200 records splits into 3 child batches: 500, 500, 200.
	// First child (500 records) was synced.
	messages, _, err := cursors.LoadMessageProgress()
	if err != nil {
		t.Fatalf("LoadMessageProgress: %v", err)
	}

	// First 500 messages should be confirmed (Pending == nil, Confirmed != nil)
	// Next 500 messages should be pending under child 2
	// Last 200 messages should be pending under child 3
	for i := 0; i < 500; i++ {
		msg := messages[fmt.Sprintf("claude-code-jsonl\x00msg-%04d", i)]
		if msg.Pending != nil {
			t.Fatalf("msg-%04d expected pending nil (confirmed), got %#v", i, msg.Pending)
		}
		if msg.Confirmed == nil || *msg.Confirmed.Input != 10 {
			t.Fatalf("msg-%04d expected confirmed 10, got %#v", i, msg.Confirmed)
		}
	}

	parentEntry := outboxEntryOf(t, stateDir, oldBatchID)
	childrenIDs := strings.Split(parentEntry.ReorganizedInto, ",")
	if len(childrenIDs) != 3 {
		t.Fatalf("expected 3 children, got %d", len(childrenIDs))
	}
	if childrenIDs[0] != res.Receipt.BatchID {
		t.Fatalf("expected first child %s to match res %s", childrenIDs[0], res.Receipt.BatchID)
	}

	for i := 500; i < 1000; i++ {
		msg := messages[fmt.Sprintf("claude-code-jsonl\x00msg-%04d", i)]
		if msg.Pending == nil || msg.Pending.BatchID != childrenIDs[1] {
			t.Fatalf("msg-%04d expected pending under child 2 (%s), got %#v", i, childrenIDs[1], msg.Pending)
		}
	}
	for i := 1000; i < 1200; i++ {
		msg := messages[fmt.Sprintf("claude-code-jsonl\x00msg-%04d", i)]
		if msg.Pending == nil || msg.Pending.BatchID != childrenIDs[2] {
			t.Fatalf("msg-%04d expected pending under child 3 (%s), got %#v", i, childrenIDs[2], msg.Pending)
		}
	}
}
