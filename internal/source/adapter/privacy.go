package adapter

import (
	"reflect"
	"strings"
	"time"
)

const (
	codexTool      = "Codex"
	claudeCodeTool = "Claude Code"
)

// usageJSONExportFields is the exact field whitelist of the server ingest
// record schema (server usage.RawRecord). Free-form usage-json inputs may
// carry any extra keys (session ids, file paths, prompts, nested objects);
// anything outside this list must never reach a batch payload, because the
// outbox batch file is uploaded verbatim by sync.
var usageJSONExportFields = []string{
	"recordKey",
	"groupKey",
	"resetKey",
	"kind",
	"occurredAt",
	"tool",
	"model",
	"input",
	"cacheRead",
	"cacheWrite",
	"output",
	"adapterVersion",
	"sourceType",
	"mutationType",
}

// openAIPublicModels lists the public OpenAI model ids the Codex tool may
// report verbatim. Anything else (internal routing names, private
// deployments, experiments) collapses to "unknown" so model strings never
// leak private routing information.
var openAIPublicModels = map[string]bool{
	"codex-mini-latest": true,
	"gpt-4.1":           true,
	"gpt-4.1-mini":      true,
	"gpt-4o":            true,
	"gpt-4o-mini":       true,
	"gpt-5":             true,
	"gpt-5-mini":        true,
	"gpt-5-nano":        true,
	"o3":                true,
	"o3-mini":           true,
	"o4-mini":           true,
}

// publicModelForTool maps a raw model string to the value that may leave the
// device. Each tool has its own public registry: Claude Code models pass
// through the Claude whitelist (including dated and -latest variants), the
// Codex tool passes the public OpenAI registry, and any other tool or
// unlisted id collapses to "unknown". One tool's registry must not be
// applied globally — that would wrongly hide legitimate public models of
// other tools as "unknown".
func publicModelForTool(tool, model string) string {
	id := strings.TrimSpace(model)
	if id == "" {
		return "unknown"
	}
	switch tool {
	case claudeCodeTool:
		return ClaudePublicModel(id)
	case codexTool:
		if openAIPublicModels[id] {
			return id
		}
		return "unknown"
	default:
		return "unknown"
	}
}

// sanitizeUsageJSONRecord projects one free-form usage-json record onto the
// ingest whitelist. It always builds a NEW map — the decoded input map is
// never mutated — and copies protocol fields through unchanged, so the
// recordKey and the idempotent identity stay stable across rescans. Unknown
// free-form fields are dropped, and a string model is collapsed to the
// public registry of the record's tool (nil stays nil; a malformed
// non-string model is dropped).
func sanitizeUsageJSONRecord(record Record) Record {
	out := make(Record, len(record))
	for _, field := range usageJSONExportFields {
		value, ok := record[field]
		if !ok {
			continue
		}
		if field == "model" {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) == "" {
					out[field] = value
					continue
				}
				out[field] = publicModelForTool(StringField(record, "tool"), typed)
			case nil:
				out[field] = value
			default:
				// Malformed model values (numbers, objects) carry no
				// protocol meaning; drop them instead of uploading.
			}
			continue
		}
		out[field] = value
	}
	return out
}

// SanitizeUsageJSONRecords whitelists every record of a free-form usage-json
// input. Codex and Claude Code records are built internally with exactly the
// protocol fields, so only the usage-json path needs this projection.
func SanitizeUsageJSONRecords(records []Record) []Record {
	sanitized := make([]Record, len(records))
	for idx, record := range records {
		sanitized[idx] = sanitizeUsageJSONRecord(record)
	}
	return sanitized
}

// RecordIsUploadSafe reports whether an already-built record conforms to the
// upload whitelist: the record must project onto itself unchanged. Records
// produced by the fixed exporters (exactly the protocol fields, public or
// "unknown" models) always satisfy this; anything carrying extra keys, a
// private model, or a malformed model does not. The sync sender uses this to
// fail closed on pre-existing batch files instead of uploading them.
func RecordIsUploadSafe(record Record) bool {
	if record == nil {
		return false
	}
	sanitized := sanitizeUsageJSONRecord(record)
	if len(sanitized) != len(record) {
		return false
	}
	for field, value := range record {
		projected, ok := sanitized[field]
		if !ok || !reflect.DeepEqual(value, projected) {
			return false
		}
	}
	return true
}

// claudePublicModels is the exact whitelist of public Claude model ids the
// collector may upload. Anything else (private deployments, internal route
// names, gateway labels, display names) maps to "unknown" and never leaves
// the machine.
var claudePublicModels = map[string]bool{
	"claude-3-5-haiku":  true,
	"claude-3-5-sonnet": true,
	"claude-3-7-sonnet": true,
	"claude-3-haiku":    true,
	"claude-3-opus":     true,
	"claude-3-sonnet":   true,
	"claude-haiku-4-5":  true,
	"claude-opus-4":     true,
	"claude-opus-4-1":   true,
	"claude-opus-4-5":   true,
	"claude-sonnet-4":   true,
	"claude-sonnet-4-5": true,
}

// ClaudePublicModel keeps only confirmable public Claude model identifiers:
// one of the whitelisted base ids, optionally with a -YYYYMMDD date suffix
// or -latest. Everything else becomes "unknown" instead of leaking.
func ClaudePublicModel(raw string) string {
	id := strings.TrimSpace(raw)
	if id == "" {
		return "unknown"
	}
	if claudePublicModels[id] {
		return id
	}
	idx := strings.LastIndex(id, "-")
	if idx <= 0 || idx == len(id)-1 {
		return "unknown"
	}
	base, suffix := id[:idx], id[idx+1:]
	if !claudePublicModels[base] {
		return "unknown"
	}
	if suffix == "latest" || claudeDateSuffix(suffix) {
		return id
	}
	return "unknown"
}

// claudeDateSuffix reports whether s is exactly eight digits forming a valid
// calendar date (YYYYMMDD).
func claudeDateSuffix(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, err := time.Parse("20060102", s)
	return err == nil
}
