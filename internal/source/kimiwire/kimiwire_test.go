package kimiwire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

func writeWire(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRecordsParsesKimiCLIStatusUpdate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "group-a", "session-a", "wire.jsonl")
	writeWire(t, path,
		`{"type":"metadata","protocol_version":"1.3"}`,
		`{"timestamp":1772857971.158032,"message":{"type":"StatusUpdate","payload":{"message_id":"msg-1","token_usage":{"input_other":100,"input_cache_read":20,"input_cache_creation":5,"output":30}}}}`,
	)

	res, err := LoadRecords(root, KimiCLIConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 1 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "Kimi CLI" || rec["sourceType"] != adapter.KimiCLIJSONLSource || rec["model"] != "unknown" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	if rec["input"] != "100" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	if !adapter.RecordIsUploadSafe(rec) {
		t.Fatalf("record is not upload safe: %#v", rec)
	}
	if err := adapter.ValidateRecord(rec); err != nil {
		t.Fatalf("record violates contract: %v", err)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "session-a") || strings.Contains(string(raw), "msg-1") || strings.Contains(string(raw), root) {
		t.Fatalf("record leaked private source data: %s", raw)
	}
}

func TestLoadRecordsParsesKimiCodeTurnUsageRecordAndSkipsSessionScope(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "workspace-a", "session-a", "agents", "main", "wire.jsonl")
	writeWire(t, path,
		`{"type":"llm.request","time":"2026-10-20T01:00:00Z","requestId":"req-1","model":"moonshot-k2.6","modelAlias":"__kimi_env_model__"}`,
		`{"type":"usage.record","time":"2026-10-20T01:00:01Z","usageScope":"session","model":"__kimi_env_model__","usage":{"inputOther":1000,"inputCacheRead":200,"inputCacheCreation":50,"output":300}}`,
		`{"type":"usage.record","time":"2026-10-20T01:00:02Z","usageScope":"turn","model":"__kimi_env_model__","usage":{"inputOther":100,"inputCacheRead":20,"inputCacheCreation":5,"output":30}}`,
	)

	res, err := LoadRecords(root, KimiCodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("unexpected result: %#v", res)
	}
	rec := res.Records[0]
	if rec["tool"] != "Kimi Code" || rec["sourceType"] != adapter.KimiCodeJSONLSource || rec["model"] != "moonshot-k2.6" {
		t.Fatalf("unexpected identity: %#v", rec)
	}
	if rec["input"] != "100" || rec["cacheRead"] != "20" || rec["cacheWrite"] != "5" || rec["output"] != "30" {
		t.Fatalf("unexpected usage: %#v", rec)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "__kimi_env_model__") {
		t.Fatalf("record leaked private model alias: %s", raw)
	}
}

func TestLoadRecordsDeduplicatesCopiedKimiRecords(t *testing.T) {
	root := t.TempDir()
	request := `{"type":"llm.request","time":"2026-10-20T01:00:00Z","requestId":"same-request","model":"moonshot-k2.6"}`
	usage := `{"type":"usage.record","time":"2026-10-20T01:00:02Z","usageScope":"turn","usage":{"inputOther":100,"inputCacheRead":20,"inputCacheCreation":5,"output":30}}`
	writeWire(t, filepath.Join(root, "workspace-a", "session-a", "agents", "main", "wire.jsonl"), request, usage)
	writeWire(t, filepath.Join(root, "workspace-a", "session-b", "agents", "main", "wire.jsonl"), request, usage)

	res, err := LoadRecords(root, KimiCodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 || len(res.Records) != 1 {
		t.Fatalf("copied turn should be counted once: %#v", res)
	}
}

func TestLoadRecordsReportsUnknownKimiCodeModelWithoutQuarantine(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "workspace-a", "session-a", "agents", "main", "wire.jsonl")
	writeWire(t, path,
		`{"type":"usage.record","time":"2026-10-20T01:00:02Z","usageScope":"turn","model":"__kimi_env_model__","usage":{"inputOther":100,"inputCacheRead":20,"inputCacheCreation":5,"output":30}}`,
	)

	res, err := LoadRecords(root, KimiCodeConfig)
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

func TestLoadRecordsQuarantinesMalformedKimiUsage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "group-a", "session-a", "wire.jsonl")
	writeWire(t, path,
		`{"timestamp":1772857971.158032,"message":{"type":"StatusUpdate","payload":{"message_id":"msg-1","token_usage":{"input_other":-1,"input_cache_read":20,"input_cache_creation":5,"output":30}}}}`,
	)

	res, err := LoadRecords(root, KimiCLIConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 1 || len(res.Issues) != 1 {
		t.Fatalf("malformed usage should be quarantined: %#v", res)
	}
}
