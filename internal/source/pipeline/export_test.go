package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
)

func TestSplitPreparedExportSmall(t *testing.T) {
	records := make([]adapter.Record, 10)
	for i := 0; i < 10; i++ {
		records[i] = adapter.Record{
			"recordKey": fmt.Sprintf("rec-%d", i),
			"model":     "test-model",
		}
	}
	batch := adapter.Batch{BatchID: "batch-1", Records: records}
	payload, _ := json.MarshalIndent(batch, "", "  ")

	prepared := PreparedExport{
		BatchID: "batch-1",
		Output:  "/tmp/batches/batch-1.json",
		Records: 10,
		Payload: append(payload, '\n'),
	}

	chunks, err := SplitPreparedExport(prepared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].BatchID != "batch-1" {
		t.Fatalf("expected batchID batch-1, got %s", chunks[0].BatchID)
	}
}

func TestSplitPreparedExportRecordsLimit(t *testing.T) {
	const count = 1050
	records := make([]adapter.Record, count)
	updates := make([]progress.MessagePendingUpdate, count)
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("rec-%04d", i)
		records[i] = adapter.Record{
			"recordKey": key,
			"model":     "test-model",
		}
		updates[i] = progress.MessagePendingUpdate{
			MessageID: fmt.Sprintf("msg-%04d", i),
			RecordKey: key,
		}
	}
	batch := adapter.Batch{BatchID: "parent-batch", Records: records}
	payload, _ := json.MarshalIndent(batch, "", "  ")

	prepared := PreparedExport{
		BatchID:        "parent-batch",
		Output:         "/tmp/batches/parent-batch.json",
		Records:        count,
		Payload:        append(payload, '\n'),
		MessageUpdates: updates,
	}

	chunks, err := SplitPreparedExport(prepared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1050 records / 500 = 3 chunks (500, 500, 50)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	expectedCounts := []int{500, 500, 50}
	totalUpdates := 0
	for i, chunk := range chunks {
		if chunk.Records != expectedCounts[i] {
			t.Fatalf("chunk %d expected %d records, got %d", i, expectedCounts[i], chunk.Records)
		}
		if len(chunk.MessageUpdates) != expectedCounts[i] {
			t.Fatalf("chunk %d expected %d message updates, got %d", i, expectedCounts[i], len(chunk.MessageUpdates))
		}
		totalUpdates += len(chunk.MessageUpdates)

		expectedID := fmt.Sprintf("parent-batch-part-%04d", i+1)
		if chunk.BatchID != expectedID {
			t.Fatalf("chunk %d expected id %s, got %s", i, expectedID, chunk.BatchID)
		}

		var chunkBatch adapter.Batch
		if err := json.Unmarshal(chunk.Payload, &chunkBatch); err != nil {
			t.Fatalf("chunk %d payload invalid JSON: %v", i, err)
		}
		compact, _ := json.Marshal(chunkBatch)
		if len(compact) > MaxBatchPayloadBytes {
			t.Fatalf("chunk %d compact payload %d exceeds max %d", i, len(compact), MaxBatchPayloadBytes)
		}
	}
	if totalUpdates != count {
		t.Fatalf("expected total updates %d, got %d", count, totalUpdates)
	}
}

func TestSplitPreparedExportPayloadLimit(t *testing.T) {
	// 5 records each ~200 KiB -> total > 1 MiB -> must split into multiple chunks so compact envelope <= 768 KiB
	const recCount = 5
	bigData := strings.Repeat("x", 200*1024)
	records := make([]adapter.Record, recCount)
	for i := 0; i < recCount; i++ {
		records[i] = adapter.Record{
			"recordKey": fmt.Sprintf("rec-%d", i),
			"data":      bigData,
		}
	}
	batch := adapter.Batch{BatchID: "parent-batch", Records: records}
	payload, _ := json.MarshalIndent(batch, "", "  ")

	prepared := PreparedExport{
		BatchID: "parent-batch",
		Output:  "/tmp/batches/parent-batch.json",
		Records: recCount,
		Payload: append(payload, '\n'),
	}

	chunks, err := SplitPreparedExport(prepared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}
	totalRecords := 0
	for i, chunk := range chunks {
		totalRecords += chunk.Records
		var chunkBatch adapter.Batch
		if err := json.Unmarshal(chunk.Payload, &chunkBatch); err != nil {
			t.Fatalf("chunk %d payload invalid JSON: %v", i, err)
		}
		compact, _ := json.Marshal(chunkBatch)
		if len(compact) > MaxBatchPayloadBytes {
			t.Fatalf("chunk %d exceeds max payload bytes: %d > %d", i, len(compact), MaxBatchPayloadBytes)
		}
	}
	if totalRecords != recCount {
		t.Fatalf("expected total records %d, got %d", recCount, totalRecords)
	}
}

func TestSplitPreparedExportSingleRecordOversizedFailClosed(t *testing.T) {
	hugeData := strings.Repeat("x", 800*1024) // 800 KiB > 768 KiB
	records := []adapter.Record{
		{
			"recordKey": "huge-rec",
			"data":      hugeData,
		},
	}
	batch := adapter.Batch{BatchID: "huge-batch", Records: records}
	payload, _ := json.MarshalIndent(batch, "", "  ")

	prepared := PreparedExport{
		BatchID: "huge-batch",
		Output:  "/tmp/batches/huge-batch.json",
		Records: 1,
		Payload: append(payload, '\n'),
	}

	_, err := SplitPreparedExport(prepared)
	if err == nil {
		t.Fatal("expected fail closed error on record > 768 KiB, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSplitPreparedExportLongBatchIDBounded128Chars(t *testing.T) {
	longID := strings.Repeat("a", 128)
	records := make([]adapter.Record, 600)
	for i := range records {
		records[i] = adapter.Record{"recordKey": fmt.Sprintf("k-%d", i)}
	}
	batch := adapter.Batch{BatchID: longID, Records: records}
	payload, _ := json.Marshal(batch)

	prepared := PreparedExport{
		BatchID: longID,
		Output:  "/tmp/batches/long.json",
		Records: 600,
		Payload: payload,
	}

	chunks, err := SplitPreparedExport(prepared)
	if err != nil {
		t.Fatalf("SplitPreparedExport: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	for i, chunk := range chunks {
		if len(chunk.BatchID) > 128 {
			t.Fatalf("chunk %d BatchID exceeds 128 chars: len=%d (%s)", i, len(chunk.BatchID), chunk.BatchID)
		}
	}
}
