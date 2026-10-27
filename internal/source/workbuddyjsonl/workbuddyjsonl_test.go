package workbuddyjsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

func writeJSONL(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func wbRecord(id string, messageID string, rawUsage string) string {
	return `{"id":` + quote(id) + `,"timestamp":1780000000100,"type":"function_call","sessionId":"session-1","cwd":"/private/repo","providerData":{"messageId":` + quote(messageID) + `,"requestModelId":"private-route","rawUsage":` + rawUsage + `}}`
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestLoadRecordsParsesWorkBuddyRawUsageAndKeepsPrivateFieldsLocal(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path, wbRecord("call-1", "msg-1", `{"prompt_tokens":140732,"completion_tokens":635,"total_tokens":141367,"prompt_cache_hit_tokens":76032,"cache_creation_input_tokens":1000,"completion_tokens_details":{"reasoning_tokens":27}}`))

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", res)
	}
	if len(res.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(res.Records))
	}
	rec := res.Records[0]
	if rec["tool"] != "WorkBuddy" || rec["model"] != "unknown" || rec["sourceType"] != adapter.WorkBuddyJSONLSource {
		t.Fatalf("unexpected identity fields: %#v", rec)
	}
	if rec["input"] != "63700" || rec["cacheRead"] != "76032" || rec["cacheWrite"] != "1000" || rec["output"] != "635" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "/private") || strings.Contains(string(raw), "private-route") || strings.Contains(string(raw), "call-1") || strings.Contains(string(raw), "msg-1") {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsDeduplicatesMessageAndFunctionCallByMessageID(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path,
		wbRecord("call-1", "shared-message", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`),
		`{"id":"assistant-1","timestamp":1780000000200,"type":"message","role":"assistant","status":"completed","sessionId":"session-1","message":{"role":"assistant"},"providerData":{"messageId":"shared-message","rawUsage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("got %d records, want 1: %#v", len(res.Records), res.Records)
	}
	if res.Records[0]["input"] != "60" || res.Records[0]["cacheRead"] != "40" || res.Records[0]["cacheWrite"] != "0" {
		t.Fatalf("unexpected usage: %#v", res.Records[0])
	}
}

func TestLoadRecordsRejectsConflictingDuplicateUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path,
		wbRecord("call-1", "same", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`),
		wbRecord("call-2", "same", `{"prompt_tokens":101,"completion_tokens":20,"total_tokens":121,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`),
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined == 0 {
		t.Fatalf("conflict must remove the record and report an issue: %#v", res)
	}
}

func TestLoadRecordsTailHandling(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := wbRecord("call-1", "msg-1", `{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_cache_hit_tokens":0,"cache_creation_input_tokens":0}`)
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("complete final line without newline must be counted, got %#v", res)
	}
	if err := os.WriteFile(path, []byte(line[:len(line)-5]), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("torn final line must not be counted: %#v", res)
	}
}
