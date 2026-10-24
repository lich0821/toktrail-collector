package pipeline_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/claudecodejsonl"
	"toktrail-collector/internal/source/codexjsonl"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/source/usagejson"
)

const fourthSourceName = "fourth-source"

func makePrivacySafeRecord(key, tool, input, cacheRead, cacheWrite, output string, occurredAt time.Time) adapter.Record {
	rec := adapter.Record{
		"recordKey":      key,
		"groupKey":       "synthetic-group",
		"resetKey":       "synthetic-reset",
		"kind":           "delta",
		"occurredAt":     occurredAt.Format(time.RFC3339),
		"tool":           tool,
		"model":          "unknown",
		"input":          input,
		"cacheRead":      cacheRead,
		"cacheWrite":     cacheWrite,
		"output":         output,
		"adapterVersion": "v1.0.0",
		"sourceType":     fourthSourceName,
	}
	if !adapter.RecordIsUploadSafe(rec) {
		panic(fmt.Sprintf("synthetic record %s is not upload-safe", key))
	}
	return rec
}

func setupFourthSourcePipeline(fourthAdapter adapter.Adapter) (*pipeline.Pipeline, *registry.Registry, error) {
	reg, err := registry.New(
		usagejson.Adapter(),
		codexjsonl.Adapter(),
		claudecodejsonl.Adapter(),
		fourthAdapter,
	)
	if err != nil {
		return nil, nil, err
	}
	return pipeline.New(reg), reg, nil
}

func TestFourthSourceScan(t *testing.T) {
	t1 := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 24, 9, 30, 0, 0, time.UTC)

	var filterCalls int32
	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter for scanning",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records: []adapter.Record{
					makePrivacySafeRecord("rec-001", "FourthToolA", "100", "20", "10", "50", t1),
					makePrivacySafeRecord("rec-002", "FourthToolB", "200", "40", "20", "100", t2),
				},
				Quarantined: 1,
				Issues: []adapter.LineIssue{
					{File: opt.Input, Line: 3, Reason: "corrupt line quarantined"},
				},
			}, nil
		},
		FilterForExport: func(opt adapter.Options, recs []adapter.Record) ([]adapter.Record, error) {
			atomic.AddInt32(&filterCalls, 1)
			return recs, nil
		},
	}

	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	res, err := pipe.Scan(adapter.Options{
		Source: fourthSourceName,
		Input:  "/path/to/synthetic.input",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify FilterForExport was NOT called during scan
	if calls := atomic.LoadInt32(&filterCalls); calls != 0 {
		t.Fatalf("expected 0 calls to FilterForExport during Scan, got %d", calls)
	}

	if res.Source != fourthSourceName {
		t.Fatalf("expected source %q, got %q", fourthSourceName, res.Source)
	}
	if res.RecordCount != 2 {
		t.Fatalf("expected 2 records, got %d", res.RecordCount)
	}
	if res.ValidRecords != 2 || res.InvalidRecords != 0 {
		t.Fatalf("expected 2 valid records and 0 invalid, got %d valid, %d invalid", res.ValidRecords, res.InvalidRecords)
	}
	if res.KnownIncludeRecords != 2 || res.KnownExcludeRecords != 2 {
		t.Fatalf("expected 2 include and 2 exclude records, got %d include, %d exclude", res.KnownIncludeRecords, res.KnownExcludeRecords)
	}

	// rec1: 100+20+10+50 = 180 include, 100+50 = 150 exclude
	// rec2: 200+40+20+100 = 360 include, 200+100 = 300 exclude
	// total include: 540, total exclude: 450
	if res.TokensInclude == nil || *res.TokensInclude != 540 {
		t.Fatalf("expected TokensInclude 540, got %v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 450 {
		t.Fatalf("expected TokensExclude 450, got %v", res.TokensExclude)
	}

	if res.Tools["FourthToolA"] != 1 || res.Tools["FourthToolB"] != 1 {
		t.Fatalf("unexpected tools map: %#v", res.Tools)
	}
	if res.EarliestOccurredAt == nil || !res.EarliestOccurredAt.Equal(t1) {
		t.Fatalf("expected earliest %v, got %v", t1, res.EarliestOccurredAt)
	}
	if res.LatestOccurredAt == nil || !res.LatestOccurredAt.Equal(t2) {
		t.Fatalf("expected latest %v, got %v", t2, res.LatestOccurredAt)
	}
	if res.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined, got %d", res.Quarantined)
	}
	if len(res.Issues) != 1 || res.Issues[0].Reason != "corrupt line quarantined" {
		t.Fatalf("unexpected issues: %#v", res.Issues)
	}
}

func TestFourthSourcePreview(t *testing.T) {
	t1 := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	var filterCalls int32

	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter for preview",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records: []adapter.Record{
					makePrivacySafeRecord("rec-001", "FourthTool", "100", "20", "10", "50", t1),
					// Invalid record (missing required kind) to verify preview detects validation errors
					{
						"recordKey":      "rec-002-invalid",
						"occurredAt":     t1.Format(time.RFC3339),
						"tool":           "FourthTool",
						"model":          "unknown",
						"adapterVersion": "v1.0.0",
						"sourceType":     fourthSourceName,
					},
				},
			}, nil
		},
		FilterForExport: func(opt adapter.Options, recs []adapter.Record) ([]adapter.Record, error) {
			atomic.AddInt32(&filterCalls, 1)
			return recs, nil
		},
	}

	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	// Limit = 2
	rows, err := pipe.Preview(adapter.Options{
		Source: fourthSourceName,
		Input:  "/path/to/synthetic.input",
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}

	// Verify FilterForExport was NOT called during Preview
	if calls := atomic.LoadInt32(&filterCalls); calls != 0 {
		t.Fatalf("expected 0 calls to FilterForExport during Preview, got %d", calls)
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 preview rows, got %d", len(rows))
	}

	// Row 0: valid
	if rows[0].Index != 0 || rows[0].RecordKey != "rec-001" || !rows[0].Valid || rows[0].Error != "" {
		t.Fatalf("row 0 unexpected: %+v", rows[0])
	}
	if rows[0].Include == nil || *rows[0].Include != 180 {
		t.Fatalf("row 0 expected Include 180, got %v", rows[0].Include)
	}
	if rows[0].Exclude == nil || *rows[0].Exclude != 150 {
		t.Fatalf("row 0 expected Exclude 150, got %v", rows[0].Exclude)
	}

	// Row 1: invalid
	if rows[1].Index != 1 || rows[1].RecordKey != "rec-002-invalid" || rows[1].Valid || rows[1].Error == "" {
		t.Fatalf("row 1 expected invalid, got: %+v", rows[1])
	}
}

func TestFourthSourceExportFilterInvokedOnlyForExport(t *testing.T) {
	t1 := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	var filterCalls int32

	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter testing filter invocation",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records: []adapter.Record{
					makePrivacySafeRecord("rec-keep", "FourthTool", "100", "20", "10", "50", t1),
					makePrivacySafeRecord("rec-drop", "FourthTool", "200", "40", "20", "100", t1),
				},
			}, nil
		},
		FilterForExport: func(opt adapter.Options, recs []adapter.Record) ([]adapter.Record, error) {
			atomic.AddInt32(&filterCalls, 1)
			filtered := make([]adapter.Record, 0, len(recs))
			for _, r := range recs {
				if adapter.StringField(r, "recordKey") != "rec-drop" {
					filtered = append(filtered, r)
				}
			}
			return filtered, nil
		},
	}

	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	opt := adapter.Options{
		Source: fourthSourceName,
		Input:  "/path/to/synthetic.input",
	}

	// 1. Scan must NOT call FilterForExport
	if _, err := pipe.Scan(opt); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if calls := atomic.LoadInt32(&filterCalls); calls != 0 {
		t.Fatalf("FilterForExport called %d times during Scan, expected 0", calls)
	}

	// 2. Preview must NOT call FilterForExport
	if _, err := pipe.Preview(opt); err != nil {
		t.Fatalf("Preview failed: %v", err)
	}
	if calls := atomic.LoadInt32(&filterCalls); calls != 0 {
		t.Fatalf("FilterForExport called %d times during Preview, expected 0", calls)
	}

	// 3. PrepareExport MUST call FilterForExport
	tempDir := t.TempDir()
	exportOut := filepath.Join(tempDir, "export.json")
	opt.Output = exportOut

	prep, err := pipe.PrepareExport(opt)
	if err != nil {
		t.Fatalf("PrepareExport failed: %v", err)
	}
	if calls := atomic.LoadInt32(&filterCalls); calls != 1 {
		t.Fatalf("FilterForExport called %d times after PrepareExport, expected 1", calls)
	}
	// Verify filter dropped rec-drop
	if prep.Records != 1 {
		t.Fatalf("expected 1 record after export filter, got %d", prep.Records)
	}

	// 4. Export MUST also call FilterForExport (via PrepareExport)
	exportOut2 := filepath.Join(tempDir, "export2.json")
	opt.Output = exportOut2
	expRes, err := pipe.Export(opt)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if calls := atomic.LoadInt32(&filterCalls); calls != 2 {
		t.Fatalf("FilterForExport called %d times after Export, expected 2", calls)
	}
	if expRes.Records != 1 {
		t.Fatalf("expected 1 exported record, got %d", expRes.Records)
	}
}

func TestFourthSourcePrepareAndSplitAndWrite(t *testing.T) {
	t0 := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	const totalCount = 520

	records := make([]adapter.Record, totalCount)
	updates := make([]progress.MessagePendingUpdate, totalCount)
	for i := 0; i < totalCount; i++ {
		key := fmt.Sprintf("rec-%04d", i)
		records[i] = makePrivacySafeRecord(key, "FourthTool", "10", "5", "5", "10", t0)
		updates[i] = progress.MessagePendingUpdate{
			MessageID: fmt.Sprintf("msg-%04d", i),
			RecordKey: key,
		}
	}

	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter for split testing",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records:        records,
				MessageUpdates: updates,
			}, nil
		},
	}

	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "batch-output.json")

	// 1. PrepareExport
	prep, err := pipe.PrepareExport(adapter.Options{
		Source:  fourthSourceName,
		Input:   "/dummy/in",
		Output:  outPath,
		BatchID: "custom-batch-4th",
	})
	if err != nil {
		t.Fatalf("PrepareExport failed: %v", err)
	}
	if prep.BatchID != "custom-batch-4th" {
		t.Fatalf("expected BatchID custom-batch-4th, got %q", prep.BatchID)
	}
	if prep.Records != totalCount {
		t.Fatalf("expected %d records, got %d", totalCount, prep.Records)
	}
	if len(prep.MessageUpdates) != totalCount {
		t.Fatalf("expected %d message updates, got %d", totalCount, len(prep.MessageUpdates))
	}

	// 2. SplitPreparedExport splits 520 records into 2 chunks (500 and 20)
	chunks, err := pipe.SplitPreparedExport(prep)
	if err != nil {
		t.Fatalf("SplitPreparedExport failed: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if chunks[0].Records != 500 || chunks[1].Records != 20 {
		t.Fatalf("expected chunk counts 500 and 20, got %d and %d", chunks[0].Records, chunks[1].Records)
	}
	if len(chunks[0].MessageUpdates) != 500 || len(chunks[1].MessageUpdates) != 20 {
		t.Fatalf("expected chunk updates 500 and 20, got %d and %d", len(chunks[0].MessageUpdates), len(chunks[1].MessageUpdates))
	}
	if chunks[0].BatchID != "custom-batch-4th-part-0001" {
		t.Fatalf("expected chunk 0 batch ID custom-batch-4th-part-0001, got %q", chunks[0].BatchID)
	}
	if chunks[1].BatchID != "custom-batch-4th-part-0002" {
		t.Fatalf("expected chunk 1 batch ID custom-batch-4th-part-0002, got %q", chunks[1].BatchID)
	}

	// 3. WritePreparedExport writes to disk with 0600
	writeOut := filepath.Join(tempDir, "written-batch.json")
	chunkToWrite := chunks[0]
	chunkToWrite.Output = writeOut

	if err := pipe.WritePreparedExport(chunkToWrite); err != nil {
		t.Fatalf("WritePreparedExport failed: %v", err)
	}

	fi, err := os.Stat(writeOut)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}

	var parsedBatch adapter.Batch
	b, err := os.ReadFile(writeOut)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if err := json.Unmarshal(b, &parsedBatch); err != nil {
		t.Fatalf("unmarshal written batch: %v", err)
	}
	if parsedBatch.BatchID != "custom-batch-4th-part-0001" {
		t.Fatalf("expected BatchID in payload to match chunk ID, got %q", parsedBatch.BatchID)
	}
	if len(parsedBatch.Records) != 500 {
		t.Fatalf("expected 500 records in written batch, got %d", len(parsedBatch.Records))
	}
	for i, rec := range parsedBatch.Records {
		if !adapter.RecordIsUploadSafe(rec) {
			t.Fatalf("written record %d is not upload-safe: %+v", i, rec)
		}
	}
}

func TestFourthSourceExportEndToEnd(t *testing.T) {
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter for end-to-end export",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records: []adapter.Record{
					makePrivacySafeRecord("rec-e2e-1", "FourthTool", "150", "30", "15", "75", t0),
				},
			}, nil
		},
	}

	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "e2e-out.json")

	res, err := pipe.Export(adapter.Options{
		Source:  fourthSourceName,
		Input:   "/dummy/in",
		Output:  outPath,
		BatchID: "e2e-batch-id",
	})
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if res.BatchID != "e2e-batch-id" || res.Output != outPath || res.Records != 1 {
		t.Fatalf("unexpected ExportResult: %+v", res)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading export output: %v", err)
	}

	var batch adapter.Batch
	if err := json.Unmarshal(content, &batch); err != nil {
		t.Fatalf("failed unmarshaling exported batch: %v", err)
	}
	if batch.BatchID != "e2e-batch-id" {
		t.Fatalf("expected batchId %q, got %q", "e2e-batch-id", batch.BatchID)
	}
	if len(batch.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(batch.Records))
	}
	if key := adapter.StringField(batch.Records[0], "recordKey"); key != "rec-e2e-1" {
		t.Fatalf("expected rec-e2e-1, got %q", key)
	}
	for i, rec := range batch.Records {
		if !adapter.RecordIsUploadSafe(rec) {
			t.Fatalf("exported record %d is not upload-safe: %+v", i, rec)
		}
	}
}

func TestFourthSourceFailClosedOnErrors(t *testing.T) {
	loaderErr := errors.New("synthetic loader read error")
	filterErr := errors.New("synthetic filter hook error")

	// 1. Loader error fails closed across all operations
	failingLoaderAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Failing loader fourth source",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{}, loaderErr
		},
	}

	pipe, _, err := setupFourthSourcePipeline(failingLoaderAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	opt := adapter.Options{
		Source: fourthSourceName,
		Input:  "/dummy/input",
		Output: "/dummy/output",
	}

	if _, err := pipe.Scan(opt); !errors.Is(err, loaderErr) {
		t.Fatalf("expected loaderErr from Scan, got %v", err)
	}
	if _, err := pipe.Preview(opt); !errors.Is(err, loaderErr) {
		t.Fatalf("expected loaderErr from Preview, got %v", err)
	}
	if _, err := pipe.PrepareExport(opt); !errors.Is(err, loaderErr) {
		t.Fatalf("expected loaderErr from PrepareExport, got %v", err)
	}
	if _, err := pipe.Export(opt); !errors.Is(err, loaderErr) {
		t.Fatalf("expected loaderErr from Export, got %v", err)
	}

	// 2. Filter hook error fails closed in PrepareExport and Export
	failingFilterAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Failing filter fourth source",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{
				Records: []adapter.Record{
					makePrivacySafeRecord("rec-1", "FourthTool", "100", "0", "0", "50", time.Now()),
				},
			}, nil
		},
		FilterForExport: func(opt adapter.Options, recs []adapter.Record) ([]adapter.Record, error) {
			return nil, filterErr
		},
	}

	pipeFilterFail, _, err := setupFourthSourcePipeline(failingFilterAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	if _, err := pipeFilterFail.PrepareExport(opt); !errors.Is(err, filterErr) {
		t.Fatalf("expected filterErr from PrepareExport, got %v", err)
	}
	if _, err := pipeFilterFail.Export(opt); !errors.Is(err, filterErr) {
		t.Fatalf("expected filterErr from Export, got %v", err)
	}
}

func TestFourthSourcePrepareExportRecordValidationFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "invalid-out.json")

	// Record with invalid decimal string
	invalidDecimalAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source with invalid decimal",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			rec := adapter.Record{
				"recordKey":      "rec-bad-dec",
				"groupKey":       "grp-1",
				"resetKey":       "rst-1",
				"kind":           "delta",
				"occurredAt":     time.Now().Format(time.RFC3339),
				"tool":           "FourthTool",
				"model":          "unknown",
				"input":          "not-a-number",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "10",
				"adapterVersion": "v1.0.0",
				"sourceType":     fourthSourceName,
			}
			return adapter.LoadResult{Records: []adapter.Record{rec}}, nil
		},
	}
	pipe1, _, err := setupFourthSourcePipeline(invalidDecimalAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}
	_, err = pipe1.PrepareExport(adapter.Options{Source: fourthSourceName, Input: "/in", Output: outPath})
	if err == nil || !strings.Contains(err.Error(), "record 0 invalid") {
		t.Fatalf("expected record invalid error, got: %v", err)
	}

	// Record with missing required field (empty recordKey)
	missingKeyAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source with missing record key",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			rec := adapter.Record{
				"recordKey":      "",
				"groupKey":       "grp-1",
				"resetKey":       "rst-1",
				"kind":           "delta",
				"occurredAt":     time.Now().Format(time.RFC3339),
				"tool":           "FourthTool",
				"model":          "unknown",
				"input":          "100",
				"cacheRead":      "0",
				"cacheWrite":     "0",
				"output":         "10",
				"adapterVersion": "v1.0.0",
				"sourceType":     fourthSourceName,
			}
			return adapter.LoadResult{Records: []adapter.Record{rec}}, nil
		},
	}
	pipe2, _, err := setupFourthSourcePipeline(missingKeyAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}
	_, err = pipe2.PrepareExport(adapter.Options{Source: fourthSourceName, Input: "/in", Output: outPath})
	if err == nil || !strings.Contains(err.Error(), "missing recordKey") {
		t.Fatalf("expected missing recordKey error, got: %v", err)
	}

	// Single record exceeding MaxBatchPayloadBytes (768 KiB)
	// Keeps oversize failure case mechanism working while staying upload-safe in standard schema fields
	oversizedAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source with oversized record",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			rec := makePrivacySafeRecord("rec-huge", "FourthTool", "100", "0", "0", "10", time.Now())
			rec["groupKey"] = strings.Repeat("A", 800*1024)
			return adapter.LoadResult{Records: []adapter.Record{rec}}, nil
		},
	}
	pipe3, _, err := setupFourthSourcePipeline(oversizedAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}
	_, err = pipe3.PrepareExport(adapter.Options{Source: fourthSourceName, Input: "/in", Output: outPath})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Fatalf("expected size exceeded error, got: %v", err)
	}
}

func TestFourthSourceInputValidationFailsClosed(t *testing.T) {
	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceName,
		Description: "Fourth source adapter",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return adapter.LoadResult{}, nil
		},
	}
	pipe, _, err := setupFourthSourcePipeline(fourthAdapter)
	if err != nil {
		t.Fatalf("setupFourthSourcePipeline: %v", err)
	}

	// 1. Unsupported source
	unsupportedOpt := adapter.Options{Source: "nonexistent-source", Input: "/path/to/in"}
	if _, err := pipe.Scan(unsupportedOpt); err == nil || !strings.Contains(err.Error(), "unsupported source") {
		t.Fatalf("expected unsupported source error from Scan, got: %v", err)
	}
	if _, err := pipe.Preview(unsupportedOpt); err == nil || !strings.Contains(err.Error(), "unsupported source") {
		t.Fatalf("expected unsupported source error from Preview, got: %v", err)
	}
	if _, err := pipe.PrepareExport(unsupportedOpt); err == nil || !strings.Contains(err.Error(), "unsupported source") {
		t.Fatalf("expected unsupported source error from PrepareExport, got: %v", err)
	}

	// 2. Missing input path
	missingInputOpt := adapter.Options{Source: fourthSourceName, Input: ""}
	if _, err := pipe.Scan(missingInputOpt); err == nil || !strings.Contains(err.Error(), "missing input path") {
		t.Fatalf("expected missing input path error from Scan, got: %v", err)
	}
	if _, err := pipe.Preview(missingInputOpt); err == nil || !strings.Contains(err.Error(), "missing input path") {
		t.Fatalf("expected missing input path error from Preview, got: %v", err)
	}
	if _, err := pipe.PrepareExport(missingInputOpt); err == nil || !strings.Contains(err.Error(), "missing input path") {
		t.Fatalf("expected missing input path error from PrepareExport, got: %v", err)
	}

	// 3. Missing output file on PrepareExport
	missingOutputOpt := adapter.Options{Source: fourthSourceName, Input: "/in", Output: ""}
	if _, err := pipe.PrepareExport(missingOutputOpt); err == nil || !strings.Contains(err.Error(), "missing output file") {
		t.Fatalf("expected missing output file error from PrepareExport, got: %v", err)
	}
}
