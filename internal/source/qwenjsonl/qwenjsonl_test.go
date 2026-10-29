package qwenjsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

func writeQwenJSONL(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func q(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func apiLine(responseID string, model string, input, output, cacheRead, thoughts, total string) string {
	return `{"uuid":"u-` + responseID + `","sessionId":"s1","timestamp":"2026-10-20T01:00:00.000Z","type":"system","subtype":"ui_telemetry","cwd":"/private/repo","systemPayload":{"uiEvent":{"event.name":"qwen-code.api_response","event.timestamp":"2026-10-20T01:00:01.000Z","response_id":` + q(responseID) + `,"model":` + q(model) + `,"input_token_count":` + input + `,"output_token_count":` + output + `,"cached_content_token_count":` + cacheRead + `,"thoughts_token_count":` + thoughts + `,"total_token_count":` + total + `}}}`
}

func TestLoadRecordsParsesQwenAPIResponseAndIgnoresDuplicateAssistantUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "chats", "s1.jsonl")
	writeQwenJSONL(t, path,
		apiLine("resp-1", "qwen-code", "1001", "21", "300", "7", "1022"),
		`{"uuid":"assistant-1","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","model":"qwen-code","cwd":"/private/repo","usageMetadata":{"promptTokenCount":1001,"candidatesTokenCount":21,"thoughtsTokenCount":7,"cachedContentTokenCount":300,"totalTokenCount":1022}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", res)
	}
	if len(res.Records) != 1 {
		t.Fatalf("got %d records, want 1: %#v", len(res.Records), res.Records)
	}
	rec := res.Records[0]
	if rec["tool"] != "Qwen Code" || rec["sourceType"] != adapter.QwenJSONLSource || rec["model"] != "qwen-code" {
		t.Fatalf("unexpected identity fields: %#v", rec)
	}
	if rec["input"] != "701" || rec["cacheRead"] != "300" || rec["cacheWrite"] != "0" || rec["output"] != "21" {
		t.Fatalf("unexpected usage mapping: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	if err := adapter.ValidateRecord(rec); err != nil {
		t.Fatalf("record violates shared contract: %v", err)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "/private") || strings.Contains(string(raw), "resp-1") || strings.Contains(string(raw), "s1") {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsParsesAssistantUsageFallbackWithGeminiThoughts(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "chats", "s1.jsonl")
	writeQwenJSONL(t, path,
		`{"uuid":"assistant-1","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","model":"qwen-gemini","usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"thoughtsTokenCount":7,"cachedContentTokenCount":40,"totalTokenCount":127}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["input"] != "60" || rec["cacheRead"] != "40" || rec["output"] != "27" {
		t.Fatalf("Gemini-shaped thoughts must be counted as output: %#v", rec)
	}
}

func TestLoadRecordsParsesAssistantUsageFallbackWithOpenAIThoughtsAlreadyInOutput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "chats", "s1.jsonl")
	writeQwenJSONL(t, path,
		`{"uuid":"assistant-1","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","model":"qwen-openai","usageMetadata":{"promptTokenCount":1001,"candidatesTokenCount":21,"thoughtsTokenCount":7,"cachedContentTokenCount":300,"totalTokenCount":1022}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["input"] != "701" || rec["cacheRead"] != "300" || rec["output"] != "21" {
		t.Fatalf("OpenAI-shaped thoughts must not be double counted: %#v", rec)
	}
}

func TestLoadRecordsReportsUnknownWhenModelMissing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "chats", "s1.jsonl")
	writeQwenJSONL(t, path,
		`{"uuid":"assistant-1","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"cachedContentTokenCount":40,"totalTokenCount":120}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 1 || len(res.Records) != 1 {
		t.Fatalf("missing model should diagnose without quarantine: %#v", res)
	}
	if got := res.Records[0]["model"]; got != "unknown" {
		t.Fatalf("missing model must report unknown, got %#v", got)
	}
}

func TestLoadRecordsDeduplicatesBranchedAssistantRecordsByUUID(t *testing.T) {
	root := t.TempDir()
	line := `{"uuid":"same-uuid","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","model":"qwen","usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"cachedContentTokenCount":40,"totalTokenCount":120}}`
	writeQwenJSONL(t, filepath.Join(root, "project-a", "chats", "s1.jsonl"), line)
	writeQwenJSONL(t, filepath.Join(root, "project-a", "chats", "s2.jsonl"), strings.Replace(line, `"sessionId":"s1"`, `"sessionId":"s2"`, 1))

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("duplicate branched record should be kept once: %#v", res)
	}
}

func TestLoadRecordsRejectsAmbiguousThoughtsWithoutTotal(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "chats", "s1.jsonl")
	writeQwenJSONL(t, path,
		`{"uuid":"assistant-1","sessionId":"s1","timestamp":"2026-10-20T01:00:02.000Z","type":"assistant","model":"qwen","usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"thoughtsTokenCount":7,"cachedContentTokenCount":40,"totalTokenCount":0}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
		t.Fatalf("ambiguous thoughts without total must be quarantined: %#v", res)
	}
}
