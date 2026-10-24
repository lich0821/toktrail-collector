package progress

import (
	"testing"
)

func TestReorgMessageBatchWithRecordBatchIDs(t *testing.T) {
	stateDir := t.TempDir()
	store := New(stateDir)

	u100 := uint64(100)
	u200 := uint64(200)
	u300 := uint64(300)

	// Create pending message progress for 3 messages
	err := store.ApplyMessagePending("claude-code-jsonl", "old-batch", []MessagePendingUpdate{
		{
			MessageID: "msg-1",
			RecordKey: "key-1",
			To:        &MessageUsageState{Input: &u100},
		},
		{
			MessageID: "msg-2",
			RecordKey: "key-2",
			To:        &MessageUsageState{Input: &u200},
		},
		{
			MessageID: "msg-3",
			RecordKey: "key-3",
			To:        &MessageUsageState{Input: &u300},
		},
	})
	if err != nil {
		t.Fatalf("ApplyMessagePending: %v", err)
	}

	// Reorganize with RecordBatchIDs routing key-1 and key-2 to child-1, key-3 to child-2
	recordBatchIDs := map[string]string{
		"key-1": "child-1",
		"key-2": "child-1",
		"key-3": "child-2",
	}
	keepKeys := []string{"key-1", "key-2", "key-3"}
	err = store.ReorgMessageBatch(ReorgMessageBatchOptions{
		Source:         "claude-code-jsonl",
		OldBatchID:     "old-batch",
		RecordBatchIDs: recordBatchIDs,
		KeepKeys:       keepKeys,
		Revision:       1,
	})
	if err != nil {
		t.Fatalf("ReorgMessageBatch: %v", err)
	}

	messages, _, err := store.LoadMessageProgress()
	if err != nil {
		t.Fatalf("LoadMessageProgress: %v", err)
	}

	e1 := messages["claude-code-jsonl\x00msg-1"]
	if e1.Pending == nil || e1.Pending.BatchID != "child-1" {
		t.Fatalf("msg-1 pending batch expected child-1, got %#v", e1.Pending)
	}
	e2 := messages["claude-code-jsonl\x00msg-2"]
	if e2.Pending == nil || e2.Pending.BatchID != "child-1" {
		t.Fatalf("msg-2 pending batch expected child-1, got %#v", e2.Pending)
	}
	e3 := messages["claude-code-jsonl\x00msg-3"]
	if e3.Pending == nil || e3.Pending.BatchID != "child-2" {
		t.Fatalf("msg-3 pending batch expected child-2, got %#v", e3.Pending)
	}

	// Idempotent replay
	err = store.ReorgMessageBatch(ReorgMessageBatchOptions{
		Source:         "claude-code-jsonl",
		OldBatchID:     "old-batch",
		RecordBatchIDs: recordBatchIDs,
		KeepKeys:       keepKeys,
		Revision:       1,
	})
	if err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
}
