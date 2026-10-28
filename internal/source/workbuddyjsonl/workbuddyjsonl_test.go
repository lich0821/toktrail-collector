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
	return wbRecordWithModel(id, messageID, rawUsage, "private-route")
}

func wbRecordWithModel(id string, messageID string, rawUsage string, model string) string {
	return `{"id":` + quote(id) + `,"timestamp":1780000000100,"type":"function_call","sessionId":"session-1","cwd":"/private/repo","providerData":{"messageId":` + quote(messageID) + `,"requestModelId":` + quote(model) + `,"rawUsage":` + rawUsage + `}}`
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestLoadRecordsParsesWorkBuddyRawUsageAndPreservesRequestModel(t *testing.T) {
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
	if rec["tool"] != "WorkBuddy" || rec["sourceType"] != adapter.WorkBuddyJSONLSource {
		t.Fatalf("unexpected identity fields: %#v", rec)
	}
	// The recorded request model identifier is collected verbatim: it is
	// the identifier WorkBuddy wrote, never resolved to a backend identity.
	if rec["model"] != "private-route" {
		t.Fatalf("model must preserve the recorded request model identifier, got %#v", rec["model"])
	}
	if rec["input"] != "63700" || rec["cacheRead"] != "76032" || rec["cacheWrite"] != "1000" || rec["output"] != "635" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	if err := adapter.ValidateRecord(rec); err != nil {
		t.Fatalf("record violates the shared record contract: %v", err)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "/private") || strings.Contains(string(raw), "call-1") || strings.Contains(string(raw), "msg-1") {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsReportsUnknownWhenModelMissingOrNull(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path,
		`{"id":"call-1","timestamp":1780000000100,"type":"function_call","sessionId":"session-1","providerData":{"messageId":"msg-1","rawUsage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}}}`,
		`{"id":"call-2","timestamp":1780000000200,"type":"function_call","sessionId":"session-1","providerData":{"messageId":"msg-2","requestModelId":null,"rawUsage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}}}`,
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 2 {
		t.Fatalf("missing models must be diagnosed without quarantine: %#v", res)
	}
	if len(res.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(res.Records))
	}
	for _, rec := range res.Records {
		if rec["model"] != "unknown" {
			t.Fatalf("records without a recorded model must report unknown, got %#v", rec)
		}
	}
}

func TestLiteralUnknownConflictsWithDifferentRecordedModel(t *testing.T) {
	root := t.TempDir()
	usage := `{"prompt_tokens":100,"completion_tokens":20}`
	writeJSONL(t, filepath.Join(root, "session.jsonl"), wbRecordWithModel("call-1", "same", usage, "unknown"), wbRecordWithModel("call-2", "same", usage, "another-model"))
	res, err := LoadRecords(root)
	if err != nil || len(res.Records) != 0 || res.Quarantined != 1 {
		t.Fatalf("conflicting recorded models must be quarantined: %#v %v", res, err)
	}
}

func TestRecordedLiteralUnknownIsNotMissing(t *testing.T) {
	root := t.TempDir()
	writeJSONL(t, filepath.Join(root, "session.jsonl"), wbRecordWithModel("call-1", "msg-1", `{"prompt_tokens":100,"completion_tokens":20}`, "unknown"))
	res, err := LoadRecords(root)
	if err != nil || len(res.Records) != 1 || len(res.Issues) != 0 {
		t.Fatalf("recorded literal model must not be diagnosed as missing: %#v %v", res, err)
	}
}

func TestLoadRecordsKeepsValidModelVerbatimWithoutTrimming(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path, wbRecordWithModel("call-1", "msg-1", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`, "  padded-model-id  "))

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Quarantined != 0 {
		t.Fatalf("unexpected result: %#v", res)
	}
	if got := res.Records[0]["model"]; got != "  padded-model-id  " {
		t.Fatalf("valid model must be preserved verbatim without trimming, got %#v", got)
	}
}

func TestLoadRecordsQuarantinesMalformedRequestModel(t *testing.T) {
	cases := []struct {
		name  string
		model string
	}{
		{"control character", "bad\x07model"},
		{"over 128 bytes", strings.Repeat("m", 129)},
		{"empty string", ""},
		{"whitespace only", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "project-a", "session.jsonl")
			writeJSONL(t, path, wbRecordWithModel("call-1", "msg-1", `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`, tc.model))

			res, err := LoadRecords(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
				t.Fatalf("malformed model must quarantine the record: %#v", res)
			}
			if res.Issues[0].Reason != "invalid request model identifier" {
				t.Fatalf("unexpected issue reason: %#v", res.Issues[0])
			}
		})
	}
	t.Run("non-string", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "project-a", "session.jsonl")
		writeJSONL(t, path, `{"id":"call-1","timestamp":1780000000100,"type":"function_call","sessionId":"session-1","providerData":{"messageId":"msg-1","requestModelId":42,"rawUsage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}}}`)

		res, err := LoadRecords(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
			t.Fatalf("non-string model must quarantine the record: %#v", res)
		}
	})
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
	// The function_call line records the request model; the message line
	// repeats the same request's usage without repeating the model. The
	// merged record carries the recorded identifier, not unknown.
	if res.Records[0]["model"] != "private-route" {
		t.Fatalf("merged duplicate must keep the recorded model, got %#v", res.Records[0]["model"])
	}
}

func TestLoadRecordsMergesModelAcrossDuplicateLinesInBothOrders(t *testing.T) {
	usage := `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`
	noModel := `{"id":"call-1","timestamp":1780000000100,"type":"function_call","sessionId":"session-1","providerData":{"messageId":"same","rawUsage":` + usage + `}}`
	withModel := wbRecord("call-2", "same", usage)

	// Model-bearing line first, model-less line second.
	root := t.TempDir()
	writeJSONL(t, filepath.Join(root, "a", "session.jsonl"), withModel, noModel)
	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "private-route" {
		t.Fatalf("recorded-then-missing must keep the recorded model: %#v", res.Records)
	}

	// Model-less line first, model-bearing line second.
	root = t.TempDir()
	writeJSONL(t, filepath.Join(root, "b", "session.jsonl"), noModel, withModel)
	res, err = LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "private-route" {
		t.Fatalf("missing-then-recorded must keep the recorded model: %#v", res.Records)
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

func TestLoadRecordsIsolatesConflictingDuplicateModels(t *testing.T) {
	usage := `{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_cache_hit_tokens":40,"cache_creation_input_tokens":0}`
	root := t.TempDir()
	path := filepath.Join(root, "project-a", "session.jsonl")
	writeJSONL(t, path,
		wbRecordWithModel("call-1", "same", usage, "model-a"),
		wbRecordWithModel("call-2", "same", usage, "model-b"),
	)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
		t.Fatalf("model conflict must isolate the record and report an issue: %#v", res)
	}
	if res.Issues[0].Reason != "conflicting model for same request" {
		t.Fatalf("unexpected issue reason: %#v", res.Issues[0])
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
