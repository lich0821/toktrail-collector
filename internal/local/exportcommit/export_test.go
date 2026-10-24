package exportcommit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

func TestCommitExportWritesBatchOutboxAndCursor(t *testing.T) {
	dir := t.TempDir()
	input := writeUsageInput(t, dir)
	output := filepath.Join(dir, "batch.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{Input: input, Output: output, BatchID: "batch-1"})
	if err != nil {
		t.Fatal(err)
	}
	committedAt := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	res, err := CommitExport(ExportOptions{StateDir: dir, Prepared: prepared, Source: adapter.UsageJSONSource, Input: input, CommittedAt: committedAt})
	if err != nil {
		t.Fatal(err)
	}
	if res.BatchID != "batch-1" || res.Records != 1 || res.Output != output || res.Recovered {
		t.Fatalf("unexpected result: %#v", res)
	}
	assertBatchFile(t, output, "batch-1", 1)
	outboxLedger, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(outboxLedger.Batches) != 1 || outboxLedger.Batches[0].BatchID != "batch-1" || outboxLedger.Batches[0].Status != outbox.StatusPending || outboxLedger.Batches[0].File != output {
		t.Fatalf("unexpected outbox: %#v", outboxLedger)
	}
	cursors, err := progress.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].BatchID != "batch-1" || cursors.Cursors[0].RecordCount != 1 || !cursors.Cursors[0].AdvancedAt.Equal(committedAt) {
		t.Fatalf("unexpected cursor ledger: %#v", cursors)
	}
	if _, err := os.Stat(JournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("journal should be removed, stat err=%v", err)
	}
}

func TestRecoverCompletesPendingExportJournal(t *testing.T) {
	dir := t.TempDir()
	input := writeUsageInput(t, dir)
	output := filepath.Join(dir, "recovered-batch.json")
	prepared, err := pipeline.PrepareExport(adapter.Options{Input: input, Output: output, BatchID: "batch-recover-1"})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := journalFromOptions(ExportOptions{StateDir: dir, Prepared: prepared, Source: adapter.UsageJSONSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal); err != nil {
		t.Fatal(err)
	}
	res, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Recovered || res.BatchID != "batch-recover-1" {
		t.Fatalf("unexpected recovery result: %#v", res)
	}
	assertBatchFile(t, output, "batch-recover-1", 1)
	pending, ok, err := outbox.New(dir).NextPending()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || pending.BatchID != "batch-recover-1" || pending.File != output {
		t.Fatalf("unexpected recovered pending entry: %#v ok=%v", pending, ok)
	}
	cursors, err := progress.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].BatchID != "batch-recover-1" {
		t.Fatalf("unexpected recovered cursor: %#v", cursors)
	}
	if _, err := os.Stat(JournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("journal should be removed after recovery, stat err=%v", err)
	}
}

// The claude-code-jsonl progress-integrity gate must stop a commit whose
// prepared records were computed before message-progress.json was lost:
// re-baselining from zero would double count already-uploaded usage.
func TestCommitExportRequiresClaudeProgressStateAfterPriorExport(t *testing.T) {
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionFile := filepath.Join(sessions, "session-a.jsonl")
	writeClaudeJSONL(t, sessionFile,
		claudeAssistantFixture("2026-10-20T01:00:00Z", "msg_1", 10, 5))

	first := adapter.Options{
		Source:   adapter.ClaudeCodeJSONLSource,
		Input:    sessions,
		Output:   filepath.Join(dir, "claude-batch-1.json"),
		BatchID:  "claude-batch-1",
		StateDir: dir,
	}
	prepared, err := pipeline.PrepareExport(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CommitExport(ExportOptions{StateDir: dir, Prepared: prepared, Source: adapter.ClaudeCodeJSONLSource, Input: sessions}); err != nil {
		t.Fatal(err)
	}

	// A second message appears (msg_1 stays frozen while its batch is
	// pending) and the export is prepared while progress state still exists.
	writeClaudeJSONL(t, sessionFile,
		claudeAssistantFixture("2026-10-20T01:00:00Z", "msg_1", 10, 5),
		claudeAssistantFixture("2026-10-20T01:01:00Z", "msg_2", 7, 4))
	second := first
	second.Output = filepath.Join(dir, "claude-batch-2.json")
	second.BatchID = "claude-batch-2"
	prepared2, err := pipeline.PrepareExport(second)
	if err != nil {
		t.Fatal(err)
	}
	if prepared2.Records != 1 {
		t.Fatalf("expected one fresh interval for msg_2, got %d", prepared2.Records)
	}

	// Progress state is lost between prepare and commit.
	if err := os.Remove(progress.New(dir).MessageProgressPath()); err != nil {
		t.Fatal(err)
	}
	_, err = CommitExport(ExportOptions{StateDir: dir, Prepared: prepared2, Source: adapter.ClaudeCodeJSONLSource, Input: sessions})
	if err == nil || !strings.Contains(err.Error(), "message progress state is missing") {
		t.Fatalf("expected missing-progress gate error, got %v", err)
	}
	if _, statErr := os.Stat(JournalPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no journal left behind, stat err=%v", statErr)
	}
	outbox, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(outbox.Batches) != 1 || outbox.Batches[0].BatchID != "claude-batch-1" {
		t.Fatalf("expected only the first batch committed: %#v", outbox)
	}
	cursors, err := progress.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors.Cursors) != 1 || cursors.Cursors[0].BatchID != "claude-batch-1" {
		t.Fatalf("expected cursor untouched by rejected commit: %#v", cursors)
	}
}

func claudeAssistantFixture(timestamp, msgID string, input, output int) map[string]any {
	return map[string]any{
		"type":      "assistant",
		"timestamp": timestamp,
		"message": map[string]any{
			"id": msgID,
			"usage": map[string]any{
				"input_tokens":                input,
				"cache_read_input_tokens":     0,
				"cache_creation_input_tokens": 0,
				"output_tokens":               output,
			},
		},
	}
}

func writeClaudeJSONL(t *testing.T, path string, lines ...map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, line := range lines {
		if err := enc.Encode(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeUsageInput(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "records.json")
	payload := []map[string]any{{
		"recordKey":      "record-1",
		"groupKey":       nil,
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"model":          nil,
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
	}}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertBatchFile(t *testing.T, path string, batchID string, records int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var batch adapter.Batch
	if err := json.Unmarshal(b, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.BatchID != batchID || len(batch.Records) != records {
		t.Fatalf("unexpected batch file: %#v", batch)
	}
}
