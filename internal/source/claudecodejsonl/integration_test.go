package claudecodejsonl_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
)

func claudeAssistantLine(timestamp, session, msgID string, usage map[string]any) map[string]any {
	message := map[string]any{"id": msgID, "usage": usage}
	line := map[string]any{"type": "assistant", "timestamp": timestamp, "message": message}
	if session != "" {
		line["sessionId"] = session
	}
	return line
}

func claudeUsage(input, cacheRead, cacheWrite, output any) map[string]any {
	return map[string]any{
		"input_tokens":                input,
		"cache_read_input_tokens":     cacheRead,
		"cache_creation_input_tokens": cacheWrite,
		"output_tokens":               output,
	}
}

func writeRawJSONL(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func u64ptr(v uint64) *uint64 { return &v }

func TestClaudeCodeJSONLDedupesStreamingSnapshotsToOneFinalRecord(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []map[string]any{
		{"type": "user", "timestamp": "2026-10-20T00:59:59Z", "message": map[string]any{"content": "SYNTHETIC_PROMPT_1"}},
		// streaming snapshots of one response: usage grows monotonically
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeAssistantLine("2026-10-20T01:00:01Z", "s1", "msg_1", claudeUsage(10, 2, 3, 8)),
		claudeAssistantLine("2026-10-20T01:00:02Z", "s1", "msg_1", claudeUsage(12, 2, 3, 9)),
		claudeAssistantLine("2026-10-20T01:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)),
		{"type": "summary", "timestamp": "2026-10-20T01:01:30Z"},
		// sidechain assistant turns are usage too
		claudeAssistantLine("2026-10-20T01:02:00Z", "s1", "msg_3", claudeUsage(3, 0, 0, 2)),
	}
	sidechain := lines[len(lines)-1]
	sidechain["isSidechain"] = true
	writeJSONLFile(t, filepath.Join(input, "session-a.jsonl"), lines)

	// No state dir: the stateless view reports the full current usage.
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 3 || res.ValidRecords != 3 || res.InvalidRecords != 0 || res.Quarantined != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	// exactly one record per message, carrying the final observation
	final := res.Records[0]
	if final["input"] != "12" || final["cacheRead"] != "2" || final["cacheWrite"] != "3" || final["output"] != "9" {
		t.Fatalf("expected final snapshot counts, got %#v", final)
	}
	if final["occurredAt"] != "2026-10-20T01:00:02Z" {
		t.Fatalf("expected final observation timestamp, got %v", final["occurredAt"])
	}
	if final["kind"] != "delta" || final["tool"] != "Claude Code" || final["sourceType"] != adapter.ClaudeCodeJSONLSource {
		t.Fatalf("unexpected record metadata: %#v", final)
	}
	if final["groupKey"] == nil || final["resetKey"] != nil {
		t.Fatalf("expected message group key without reset key: %#v", final)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 43 {
		t.Fatalf("unexpected include tokens (snapshots must not be summed twice): %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 37 {
		t.Fatalf("unexpected exclude tokens: %#v", res.TokensExclude)
	}
	if res.KnownIncludeRecords != 3 || res.KnownExcludeRecords != 3 || res.Tools["Claude Code"] != 3 {
		t.Fatalf("unexpected aggregate metadata: %#v", res)
	}
	// rescanning the same input yields identical stable keys
	again, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Records, again.Records) {
		t.Fatalf("expected deterministic records across scans:\n%#v\n%#v", res.Records, again.Records)
	}
}

func TestClaudeCodeJSONLIdentityIsMessageIDAcrossFilesAndSessions(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "a.jsonl"), []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)),
	})
	writeJSONLFile(t, filepath.Join(input, "b.jsonl"), []map[string]any{
		// same message id, same session, different file (copied/renamed log)
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(25, 4, 1, 12)),
	})
	writeJSONLFile(t, filepath.Join(input, "c.jsonl"), []map[string]any{
		// same message id, other session: still the same API message
		claudeAssistantLine("2026-10-20T03:00:00Z", "s2", "m1", claudeUsage(99, 0, 0, 9)),
		claudeAssistantLine("2026-10-20T03:30:00Z", "s2", "m2", claudeUsage(50, 0, 0, 7)),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 {
		t.Fatalf("expected the duplicated message to collapse and the other message to stay: %#v", res)
	}
	m1, m2 := res.Records[0], res.Records[1]
	if m1["input"] != "99" || m1["output"] != "9" {
		t.Fatalf("expected the latest cross-file observation, got %#v", m1)
	}
	if m1["occurredAt"] != "2026-10-20T03:00:00Z" {
		t.Fatalf("expected representative from the latest observation, got %v", m1["occurredAt"])
	}
	if m2["input"] != "50" {
		t.Fatalf("expected separate message record, got %#v", m2)
	}
	if m1["recordKey"] == m2["recordKey"] || m1["groupKey"] == m2["groupKey"] {
		t.Fatalf("expected message id to drive record identity: %#v vs %#v", m1, m2)
	}
}

func TestClaudeCodeJSONLLatestObservationWinsByTimestampNotFileOrder(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	// The lexically first file carries the newest snapshot; a lexically
	// later file holds an older duplicate. The merge must keep the newest
	// observation instead of letting scan order overwrite it.
	writeJSONLFile(t, filepath.Join(input, "a.jsonl"), []map[string]any{
		claudeAssistantLine("2026-10-20T05:00:00Z", "s1", "m1", claudeUsage(99, 1, 2, 9)),
	})
	writeJSONLFile(t, filepath.Join(input, "z.jsonl"), []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(25, 4, 1, 12)),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("expected the duplicated message to collapse: %#v", res)
	}
	m1 := res.Records[0]
	if m1["input"] != "99" || m1["output"] != "9" {
		t.Fatalf("expected the newest observation to survive, got %#v", m1)
	}
	if m1["occurredAt"] != "2026-10-20T05:00:00Z" {
		t.Fatalf("expected representative from the newest observation, got %v", m1["occurredAt"])
	}
}

func TestClaudeCodeJSONLGroupKeyStableWhenSessionIDChanges(t *testing.T) {
	// The same message must produce the same recordKey and groupKey whether
	// its session id is present, absent, or different: session ids never
	// enter the uploaded identity, so sessionId repair in the logs cannot
	// change any interval payload.
	dir := t.TempDir()
	base := filepath.Join(dir, "base.jsonl")
	writeJSONLFile(t, base, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m9", claudeUsage(7, 0, 0, 3)),
	})
	noSession := filepath.Join(dir, "no-session.jsonl")
	writeJSONLFile(t, noSession, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "", "m9", claudeUsage(7, 0, 0, 3)),
	})
	otherSession := filepath.Join(dir, "other-session.jsonl")
	writeJSONLFile(t, otherSession, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s2", "m9", claudeUsage(7, 0, 0, 3)),
	})
	var keys [][2]string
	for _, path := range []string{base, noSession, otherSession} {
		res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path})
		if err != nil {
			t.Fatal(err)
		}
		if res.RecordCount != 1 {
			t.Fatalf("expected one record from %s: %#v", path, res)
		}
		keys = append(keys, [2]string{res.Records[0]["recordKey"].(string), res.Records[0]["groupKey"].(string)})
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] != keys[0] {
			t.Fatalf("expected identical keys regardless of sessionId, got %#v vs %#v", keys[i], keys[0])
		}
	}
}

func TestClaudeCodeJSONLCounterSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "semantics.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(100, 20, 5, 50)),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	record := res.Records[0]
	// input_tokens is the uncached input: cache counters are separate and
	// must NOT be subtracted from input.
	if record["input"] != "100" || record["cacheRead"] != "20" || record["cacheWrite"] != "5" || record["output"] != "50" {
		t.Fatalf("unexpected counters: %#v", record)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 175 {
		t.Fatalf("unexpected include tokens: %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 150 {
		t.Fatalf("unexpected exclude tokens: %#v", res.TokensExclude)
	}
}

func TestClaudeCodeJSONLUnknownVersusZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown-zero.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		// explicit zero counters are known zeros, not unknown
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(0, nil, nil, 0)),
		// a usage object without any known counter carries no information
		claudeAssistantLine("2026-10-20T01:01:00Z", "s1", "m2", map[string]any{}),
		// assistant line without usage is ignored
		{"type": "assistant", "timestamp": "2026-10-20T01:02:00Z", "message": map[string]any{"id": "m3"}},
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("expected only the message with known counters: %#v", res)
	}
	record := res.Records[0]
	if record["input"] != "0" || record["output"] != "0" {
		t.Fatalf("expected explicit zeros: %#v", record)
	}
	if record["cacheRead"] != nil || record["cacheWrite"] != nil {
		t.Fatalf("expected unknown cache counters to stay null: %#v", record)
	}
	if res.KnownIncludeRecords != 0 || res.TokensInclude != nil {
		t.Fatalf("unknown cache counters must keep include unknown: %#v", res)
	}
	if res.KnownExcludeRecords != 1 || res.TokensExclude == nil || *res.TokensExclude != 0 {
		t.Fatalf("expected known zero exclude total: %#v", res)
	}
}

func TestClaudeCodeJSONLHugeAndExactCounters(t *testing.T) {
	dir := t.TempDir()
	// Each huge counter alone is representable and reported exactly.
	maxPath := filepath.Join(dir, "max.jsonl")
	writeRawJSONL(t, maxPath,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:00.123Z","sessionId":"s1","message":{"id":"m_max","usage":{"input_tokens":18446744073709551615,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":0}}}`,
	)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: maxPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 || res.ValidRecords != 1 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	maxRecord := res.Records[0]
	if maxRecord["input"] != "18446744073709551615" {
		t.Fatalf("expected uint64 max counter, got %v", maxRecord["input"])
	}
	if maxRecord["occurredAt"] != "2026-10-20T01:00:00Z" {
		t.Fatalf("expected fractional timestamp normalized to UTC RFC3339, got %v", maxRecord["occurredAt"])
	}
	if res.TokensInclude == nil || *res.TokensInclude != 18446744073709551615 {
		t.Fatalf("expected exact include total, got %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 18446744073709551615 {
		t.Fatalf("expected exact exclude total, got %#v", res.TokensExclude)
	}

	// 2^53+1 must survive as an exact decimal, never a float.
	precPath := filepath.Join(dir, "prec.jsonl")
	writeRawJSONL(t, precPath,
		`{"type":"assistant","timestamp":"2026-10-20T01:01:00Z","sessionId":"s1","message":{"id":"m_prec","usage":{"input_tokens":9007199254740993,"output_tokens":1}}}`,
	)
	res, err = pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: precPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	if res.Records[0]["input"] != "9007199254740993" {
		t.Fatalf("expected exact 2^53+1 counter, got %v", res.Records[0]["input"])
	}

	// Two records whose totals exceed uint64 fail the scan loudly instead of
	// wrapping or silently dropping to unknown.
	bothPath := filepath.Join(dir, "both.jsonl")
	writeRawJSONL(t, bothPath,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:00Z","sessionId":"s1","message":{"id":"m_max2","usage":{"input_tokens":18446744073709551615,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":0}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:01:00Z","sessionId":"s1","message":{"id":"m_prec2","usage":{"input_tokens":9007199254740993,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":1}}}`,
	)
	if _, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: bothPath}); err == nil || !strings.Contains(err.Error(), "token total overflow") {
		t.Fatalf("expected aggregate overflow error, got %v", err)
	}
}

func TestClaudeCodeJSONLQuarantinesBadLinesWithoutBlockingValidUsage(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, "mixed.jsonl")
	writeRawJSONL(t, path,
		`not json at all`,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:00Z","sessionId":"s1","message":{"id":"m_ok","usage":{"input_tokens":10,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":5}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:01:00Z","sessionId":"s1","message":{"id":"m_frac","usage":{"input_tokens":1.5}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:02:00Z","sessionId":"s1","message":{"id":"m_neg","usage":{"output_tokens":-5}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:03:00Z","sessionId":"s1","message":{"id":"m_over","usage":{"input_tokens":18446744073709551616}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:04:00Z","sessionId":"s1","message":{"uuid":"not-a-message-id","usage":{"input_tokens":8}}}`,
		`{"type":"assistant","timestamp":"yesterday","sessionId":"s1","message":{"id":"m_ts","usage":{"input_tokens":8}}}`,
		`{"type":"user","timestamp":"2026-10-20T01:05:00Z","message":{"content":"SYNTHETIC_PROMPT_2"}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:06:00Z","sessionId":"s1","message":{"id":"m_trail","usage":{"input_tokens":8}}} {}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:07:00Z","sessionId":"s1","message":{"id":"m_usage","usage":"many"}}`,
	)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 || res.ValidRecords != 1 {
		t.Fatalf("expected the one valid message to survive: %#v", res)
	}
	record := res.Records[0]
	if record["input"] != "10" || record["output"] != "5" {
		t.Fatalf("unexpected valid record: %#v", record)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 15 {
		t.Fatalf("unexpected include tokens: %#v", res.TokensInclude)
	}
	if res.Quarantined != 8 {
		t.Fatalf("expected 8 quarantined lines, got %d: %#v", res.Quarantined, res.Issues)
	}
	// The valid model-less message additionally carries the local
	// missing-model diagnostic, which must not count as a quarantine.
	if len(res.Issues) != 9 {
		t.Fatalf("expected 8 quarantine issues plus the missing-model diagnostic: %#v", res.Issues)
	}
	reasons := map[int]string{}
	for _, issue := range res.Issues {
		if issue.File != path {
			t.Fatalf("expected issue to reference the source file, got %q", issue.File)
		}
		reasons[issue.Line] = issue.Reason
	}
	for _, line := range []int{1, 3, 4, 5, 6, 7, 9, 10} {
		if reasons[line] == "" {
			t.Fatalf("expected line %d to be quarantined, issues: %#v", line, res.Issues)
		}
	}
	if !strings.Contains(reasons[2], "model missing") {
		t.Fatalf("expected the model-less valid message to carry the missing-model diagnostic, got %q", reasons[2])
	}
	if !strings.Contains(reasons[5], "input_tokens") {
		t.Fatalf("expected overflow reason to name the counter, got %q", reasons[5])
	}
	if !strings.Contains(reasons[6], "message.id") {
		t.Fatalf("expected missing message.id reason, got %q", reasons[6])
	}
}

// TestClaudeCodeJSONLModelCollectionAndContentPrivacy locks the history
// model collection: recorded identifiers are preserved verbatim (no
// whitelist, no rewriting), a missing key or null reports "unknown" with a
// local value-free diagnostic, and a present-but-malformed model
// quarantines the line instead of silently degrading to "unknown". Content
// outside the protocol fields never reaches a record.
func TestClaudeCodeJSONLModelCollectionAndContentPrivacy(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	privateSession := "SYNTHETIC_SESSION_PRIVATE"
	privatePrompt := "SYNTHETIC_PROMPT_PRIVATE"
	privateDisplay := "SYNTHETIC_DISPLAY_PRIVATE"
	privatePath := filepath.Join(dir, "sessions", "private-cwd-marker")
	oversized := "claude-" + strings.Repeat("x", 130)
	lines := []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", privateSession, "msg_model_1", claudeUsage(1, 0, 0, 1)),
		claudeAssistantLine("2026-10-20T01:01:00Z", privateSession, "msg_model_2", claudeUsage(2, 0, 0, 2)),
		claudeAssistantLine("2026-10-20T01:02:00Z", privateSession, "msg_model_3", claudeUsage(3, 0, 0, 3)),
		claudeAssistantLine("2026-10-20T01:03:00Z", privateSession, "msg_model_4", claudeUsage(4, 0, 0, 4)),
		claudeAssistantLine("2026-10-20T01:04:00Z", privateSession, "msg_model_5", claudeUsage(5, 0, 0, 5)),
		claudeAssistantLine("2026-10-20T01:05:00Z", privateSession, "msg_model_6", claudeUsage(6, 0, 0, 6)),
		claudeAssistantLine("2026-10-20T01:06:00Z", privateSession, "msg_model_7", claudeUsage(7, 0, 0, 7)),
		claudeAssistantLine("2026-10-20T01:07:00Z", privateSession, "msg_model_8", claudeUsage(8, 0, 0, 8)),
		claudeAssistantLine("2026-10-20T01:08:00Z", privateSession, "msg_model_9", claudeUsage(9, 0, 0, 9)),
		claudeAssistantLine("2026-10-20T01:09:00Z", privateSession, "msg_model_10", claudeUsage(10, 0, 0, 10)),
	}
	lines[0]["cwd"] = privatePath
	lines[0]["message"].(map[string]any)["content"] = []map[string]any{{"type": "text", "text": privatePrompt}}
	lines[0]["message"].(map[string]any)["model"] = "claude-sonnet-4-5"
	lines[1]["message"].(map[string]any)["model"] = map[string]any{"id": "claude-3-5-haiku-20241022", "display_name": privateDisplay}
	// not in any registry: still the recorded identifier, preserved verbatim
	lines[2]["message"].(map[string]any)["model"] = "claude-sonnet-4-6"
	// missing model key: unknown
	// JSON null model: unknown, not an error
	lines[4]["message"].(map[string]any)["model"] = nil
	// present-but-malformed models quarantine their lines
	lines[5]["message"].(map[string]any)["model"] = map[string]any{"display_name": privateDisplay}
	lines[6]["message"].(map[string]any)["model"] = ""
	lines[7]["message"].(map[string]any)["model"] = 42
	lines[8]["message"].(map[string]any)["model"] = oversized
	lines[9]["message"].(map[string]any)["model"] = "claude-sonnet-4-5\u0001"
	writeJSONLFile(t, filepath.Join(input, "session.jsonl"), lines)

	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	// The five malformed-model lines are quarantined; the other five export.
	if res.RecordCount != 5 || res.ValidRecords != 5 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	models := map[string]string{}
	for _, record := range res.Records {
		models[record["recordKey"].(string)] = record["model"].(string)
	}
	want := map[string]int{
		"claude-sonnet-4-5":         0,
		"claude-3-5-haiku-20241022": 0,
		"claude-sonnet-4-6":         0,
		"unknown":                   0,
	}
	for _, model := range models {
		if _, ok := want[model]; !ok {
			t.Fatalf("unexpected model value %q", model)
		}
		want[model]++
	}
	// exactly one message without a model key and one with null: two unknowns
	if want["unknown"] != 2 || len(models) != 5 {
		t.Fatalf("expected one of each collected model plus two unknowns: %#v", models)
	}
	if res.Quarantined != 5 {
		t.Fatalf("expected the five malformed-model lines to be quarantined: %#v", res.Issues)
	}
	// The two model-less messages (missing key and null) each carry the
	// local missing-model diagnostic in addition to the five quarantines.
	quarantinedLines := map[int]bool{}
	missingModelLines := map[int]bool{}
	for _, issue := range res.Issues {
		switch {
		case strings.Contains(issue.Reason, "invalid model"):
			quarantinedLines[issue.Line] = true
		case strings.Contains(issue.Reason, "model missing"):
			missingModelLines[issue.Line] = true
		default:
			t.Fatalf("unexpected issue reason %q", issue.Reason)
		}
	}
	if len(quarantinedLines) != 5 {
		t.Fatalf("expected five invalid-model quarantines: %#v", res.Issues)
	}
	for _, line := range []int{6, 7, 8, 9, 10} {
		if !quarantinedLines[line] {
			t.Fatalf("expected line %d to be quarantined, issues: %#v", line, res.Issues)
		}
	}
	if len(missingModelLines) != 2 || !missingModelLines[4] || !missingModelLines[5] {
		t.Fatalf("expected missing-model diagnostics for the key-missing and null-model messages: %#v", res.Issues)
	}
	for _, record := range res.Records {
		wire, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{privateSession, privatePrompt, privateDisplay, privatePath, dir, "msg_model_", oversized} {
			if strings.Contains(string(wire), marker) {
				t.Fatalf("private marker %q leaked in %s", marker, string(wire))
			}
		}
		key := record["recordKey"].(string)
		if !strings.HasPrefix(key, "claude-code-jsonl:") || len(key) != len("claude-code-jsonl:")+16 {
			t.Fatalf("expected hashed record key, got %q", key)
		}
		group := record["groupKey"].(string)
		if !strings.HasPrefix(group, "claude-code-message:") || len(group) != len("claude-code-message:")+16 {
			t.Fatalf("expected hashed group key, got %q", group)
		}
	}
}

// TestClaudeCodeJSONLRecordedModelKeptVerbatim locks byte-exact
// preservation: surrounding whitespace and unlisted identifiers survive
// untouched, and the object form takes only the id field.
func TestClaudeCodeJSONLRecordedModelKeptVerbatim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verbatim.jsonl")
	writeRawJSONL(t, path,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:00Z","sessionId":"s1","message":{"id":"m_pad","model":"  claude-sonnet-4-5  ","usage":{"input_tokens":1,"output_tokens":1}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:01:00Z","sessionId":"s1","message":{"id":"m_obj","model":{"id":"claude-opus-4-1-20250805","display_name":"SYNTHETIC_DISPLAY"},"usage":{"input_tokens":2,"output_tokens":2}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:02:00Z","sessionId":"s1","message":{"id":"m_alias","model":"gateway-label-do-not-rewrite","usage":{"input_tokens":3,"output_tokens":3}}}`,
	)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 3 || res.InvalidRecords != 0 || res.Quarantined != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	got := map[string]string{}
	for _, record := range res.Records {
		got[record["recordKey"].(string)] = record["model"].(string)
	}
	seen := map[string]bool{}
	for _, model := range got {
		seen[model] = true
	}
	for _, want := range []string{"  claude-sonnet-4-5  ", "claude-opus-4-1-20250805", "gateway-label-do-not-rewrite"} {
		if !seen[want] {
			t.Fatalf("expected model %q preserved verbatim, got %#v", want, got)
		}
	}
}

// TestClaudeCodeJSONLModelMissingInSnapshotsKeepsIdentifier covers the
// same-message snapshot-missing case: the model is resolved across every
// snapshot of a message, so a later snapshot without a model field neither
// erases the recorded identifier nor blocks the final usage. Resolution is
// independent of file order, and the record identity never depends on the
// model value.
func TestClaudeCodeJSONLModelMissingInSnapshotsKeepsIdentifier(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	first := claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5))
	first["message"].(map[string]any)["model"] = "claude-sonnet-4-5"
	grown := claudeAssistantLine("2026-10-20T01:00:02Z", "s1", "m1", claudeUsage(12, 0, 0, 6))
	grown["message"].(map[string]any)["model"] = "claude-sonnet-4-5"
	writeJSONLFile(t, filepath.Join(input, "session.jsonl"), []map[string]any{
		// first snapshot carries the model
		first,
		// representative snapshot (final usage) carries no model at all
		claudeAssistantLine("2026-10-20T01:00:01Z", "s1", "m1", claudeUsage(11, 0, 0, 5)),
		grown,
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("expected one deduplicated record: %#v", res)
	}
	record := res.Records[0]
	if record["model"] != "claude-sonnet-4-5" {
		t.Fatalf("expected the recorded model to survive model-less snapshots, got %q", record["model"])
	}
	if record["input"] != "12" || record["output"] != "6" || record["occurredAt"] != "2026-10-20T01:00:02Z" {
		t.Fatalf("expected the final usage snapshot and representative: %#v", record)
	}
	if res.Quarantined != 0 || len(res.Issues) != 0 {
		t.Fatalf("model-less snapshots must not be errors: %#v", res.Issues)
	}

	// The same snapshots split across files in reverse chronological order
	// resolve identically: the model follows the message, not the file
	// order or the usage representative.
	split := filepath.Join(dir, "split")
	if err := os.MkdirAll(split, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(split, "a.jsonl"), []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:01Z", "s1", "m1", claudeUsage(11, 0, 0, 5)),
		grown,
	})
	writeJSONLFile(t, filepath.Join(split, "z.jsonl"), []map[string]any{first})
	splitRes, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: split})
	if err != nil {
		t.Fatal(err)
	}
	if splitRes.RecordCount != 1 {
		t.Fatalf("expected one deduplicated record across files: %#v", splitRes)
	}
	splitRecord := splitRes.Records[0]
	if splitRecord["model"] != "claude-sonnet-4-5" {
		t.Fatalf("expected the recorded model across files, got %q", splitRecord["model"])
	}
	if splitRecord["recordKey"] != record["recordKey"] || splitRecord["groupKey"] != record["groupKey"] {
		t.Fatalf("expected identical identity regardless of file layout: %#v vs %#v", splitRecord, record)
	}

	// A message whose snapshots never carry a model reports "unknown" (the
	// explicit missing mapping), and the identity is unchanged: the model
	// value never enters the record key. The gap is surfaced through one
	// local, value-free diagnostic at the usage representative, without
	// quarantining anything.
	noModel := filepath.Join(dir, "no-model.jsonl")
	writeJSONLFile(t, noModel, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)),
		claudeAssistantLine("2026-10-20T01:00:02Z", "s1", "m1", claudeUsage(12, 0, 0, 6)),
	})
	noModelRes, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: noModel})
	if err != nil {
		t.Fatal(err)
	}
	if noModelRes.RecordCount != 1 {
		t.Fatalf("expected one record without models: %#v", noModelRes)
	}
	if noModelRes.Records[0]["model"] != "unknown" {
		t.Fatalf("expected missing model to map to unknown, got %q", noModelRes.Records[0]["model"])
	}
	if noModelRes.Records[0]["recordKey"] != record["recordKey"] {
		t.Fatalf("expected identity to be independent of the model value: %#v vs %#v", noModelRes.Records[0], record)
	}
	if noModelRes.Quarantined != 0 {
		t.Fatalf("a missing model must not quarantine: %#v", noModelRes)
	}
	if len(noModelRes.Issues) != 1 {
		t.Fatalf("expected exactly one missing-model diagnostic, got %#v", noModelRes.Issues)
	}
	missing := noModelRes.Issues[0]
	if missing.File != noModel || missing.Line != 2 || missing.Reason != "model missing from every snapshot of this message; reporting unknown" {
		t.Fatalf("expected the value-free diagnostic at the usage representative, got %#v", missing)
	}

	// A literal recorded "unknown" identifier is data, not a gap: the same
	// record value is reported, but no missing-model diagnostic fires.
	literal := filepath.Join(dir, "literal-unknown.jsonl")
	writeJSONLFile(t, literal, []map[string]any{
		withClaudeModel(claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)), "unknown"),
	})
	literalRes, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: literal})
	if err != nil {
		t.Fatal(err)
	}
	if literalRes.RecordCount != 1 || literalRes.Records[0]["model"] != "unknown" {
		t.Fatalf("expected the literal unknown identifier to be kept: %#v", literalRes.Records)
	}
	if literalRes.Quarantined != 0 || len(literalRes.Issues) != 0 {
		t.Fatalf("a literal unknown model must not be misreported as missing: %#v", literalRes.Issues)
	}
}

// TestClaudeCodeJSONLModelConflictReportsUnknownWithoutGuessing covers the
// same-message model conflict: two different identifiers recorded for one
// message id are never arbitrated — the conflict is reported, the model
// becomes "unknown", and the usage dedup semantics and record identity stay
// exactly as they are.
func TestClaudeCodeJSONLModelConflictReportsUnknownWithoutGuessing(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	conflicting := claudeAssistantLine("2026-10-20T01:00:01Z", "s1", "m1", claudeUsage(12, 0, 0, 6))
	conflicting["message"].(map[string]any)["model"] = "claude-opus-4-5"
	// m2 conflicts between two snapshots with EQUAL usage: the second
	// snapshot does not change the counters, so the conflict handling must
	// be independent of the usage representative selection.
	m2first := claudeAssistantLine("2026-10-20T01:01:00Z", "s1", "m2", claudeUsage(7, 0, 0, 4))
	m2first["message"].(map[string]any)["model"] = "claude-sonnet-4-5"
	m2second := claudeAssistantLine("2026-10-20T01:01:01Z", "s1", "m2", claudeUsage(7, 0, 0, 4))
	m2second["message"].(map[string]any)["model"] = "claude-haiku-4-5"
	writeJSONLFile(t, filepath.Join(input, "session.jsonl"), []map[string]any{
		// m1: growth plus a conflicting model on the newer snapshot
		withClaudeModel(claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)), "claude-sonnet-4-5"),
		conflicting,
		m2first,
		m2second,
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 {
		t.Fatalf("expected both messages to export despite conflicts: %#v", res)
	}
	byInput := map[string]adapter.Record{}
	for _, record := range res.Records {
		byInput[record["input"].(string)] = record
	}
	m1 := byInput["12"]
	if m1 == nil || m1["model"] != "unknown" {
		t.Fatalf("expected conflicted m1 to report unknown, got %#v", m1)
	}
	if m1["input"] != "12" || m1["occurredAt"] != "2026-10-20T01:00:01Z" {
		t.Fatalf("expected usage dedup to stay intact for conflicted m1: %#v", m1)
	}
	m2 := byInput["7"]
	if m2 == nil || m2["model"] != "unknown" {
		t.Fatalf("expected conflicted m2 to report unknown, got %#v", m2)
	}
	if res.Quarantined != 0 {
		t.Fatalf("conflicting valid models must not quarantine lines: %#v", res)
	}
	if len(res.Issues) != 2 {
		t.Fatalf("expected one conflict diagnostic per message, got %#v", res.Issues)
	}
	for _, issue := range res.Issues {
		if !strings.Contains(issue.Reason, "model conflict") {
			t.Fatalf("expected a model conflict diagnostic, got %q", issue.Reason)
		}
	}
	if !claudeHasDiagnostic(res.Issues, `"claude-sonnet-4-5"`) || !claudeHasDiagnostic(res.Issues, `"claude-opus-4-5"`) {
		t.Fatalf("expected the diagnostic to name both conflicting identifiers: %#v", res.Issues)
	}
	if !claudeHasDiagnostic(res.Issues, `"claude-haiku-4-5"`) {
		t.Fatalf("expected the equal-usage conflict to be diagnosed too: %#v", res.Issues)
	}

	// Control: the same fixture with consistent models keeps the identifier
	// and yields the same record keys — only the model value differs.
	control := filepath.Join(dir, "control.jsonl")
	writeJSONLFile(t, control, []map[string]any{
		withClaudeModel(claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)), "claude-sonnet-4-5"),
		withClaudeModel(claudeAssistantLine("2026-10-20T01:00:01Z", "s1", "m1", claudeUsage(12, 0, 0, 6)), "claude-sonnet-4-5"),
		withClaudeModel(claudeAssistantLine("2026-10-20T01:01:00Z", "s1", "m2", claudeUsage(7, 0, 0, 4)), "claude-sonnet-4-5"),
		withClaudeModel(claudeAssistantLine("2026-10-20T01:01:01Z", "s1", "m2", claudeUsage(7, 0, 0, 4)), "claude-sonnet-4-5"),
	})
	controlRes, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: control})
	if err != nil {
		t.Fatal(err)
	}
	if controlRes.RecordCount != 2 {
		t.Fatalf("expected both control messages: %#v", controlRes)
	}
	controlByInput := map[string]adapter.Record{}
	for _, record := range controlRes.Records {
		controlByInput[record["input"].(string)] = record
	}
	for _, key := range []string{"12", "7"} {
		if controlByInput[key]["model"] != "claude-sonnet-4-5" {
			t.Fatalf("expected consistent control model, got %#v", controlByInput[key])
		}
		if controlByInput[key]["recordKey"] != byInput[key]["recordKey"] {
			t.Fatalf("expected record identity to ignore the model value: %#v vs %#v", controlByInput[key], byInput[key])
		}
	}
}

func withClaudeModel(line map[string]any, model string) map[string]any {
	line["message"].(map[string]any)["model"] = model
	return line
}

func TestClaudeCodeJSONLExportReplayStability(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRawJSONL(t, filepath.Join(input, "session.jsonl"),
		`not json at all`,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:00Z","sessionId":"s1","message":{"id":"m1","usage":{"input_tokens":10,"cache_read_input_tokens":2,"cache_creation_input_tokens":3,"output_tokens":5}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:00:01Z","sessionId":"s1","message":{"id":"m1","usage":{"input_tokens":12,"cache_read_input_tokens":2,"cache_creation_input_tokens":3,"output_tokens":9}}}`,
		`{"type":"assistant","timestamp":"2026-10-20T01:01:00Z","sessionId":"s1","message":{"id":"m2","usage":{"input_tokens":7,"output_tokens":4}}}`,
	)
	stateDir := filepath.Join(dir, "state")
	out1 := filepath.Join(dir, "batch-1.json")
	out2 := filepath.Join(dir, "batch-2.json")
	first, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: out1, BatchID: "batch-1", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: out2, BatchID: "batch-2", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if first.Records != 2 || second.Records != 2 {
		t.Fatalf("expected both exports to carry the deduped records: %d %d", first.Records, second.Records)
	}
	var b1, b2 adapter.Batch
	if err := json.Unmarshal(first.Payload, &b1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Payload, &b2); err != nil {
		t.Fatal(err)
	}
	// identical record payloads (only the batch id differs) make the second
	// upload a server-side replay of the same records instead of double count
	if !reflect.DeepEqual(b1.Records, b2.Records) {
		t.Fatalf("expected identical records across exports:\n%s\n%s", first.Payload, second.Payload)
	}
	if b1.BatchID != "batch-1" || b2.BatchID != "batch-2" {
		t.Fatalf("expected distinct batch ids for replay-safe re-export: %q %q", b1.BatchID, b2.BatchID)
	}
	if len(first.MessageUpdates) != 2 {
		t.Fatalf("expected pending updates for both messages: %#v", first.MessageUpdates)
	}
}

func TestClaudeCodeJSONLExportRequiresStateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)),
	})
	_, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path, Output: filepath.Join(dir, "batch.json")})
	if err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("expected export without state dir to fail, got %v", err)
	}
}

// claudeIntervalFixture writes two messages and exports them once.
func claudeIntervalFixture(t *testing.T, usage1, usage2 map[string]any) (string, string, pipeline.PreparedExport) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "session.jsonl")
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", usage1),
		claudeAssistantLine("2026-10-20T01:01:00Z", "s1", "m2", usage2),
	})
	stateDir := filepath.Join(dir, "state")
	prepared, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(dir, "batch.json"), BatchID: "batch-1", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	return input, stateDir, prepared
}

func TestClaudeCodeJSONLIntervalLifecycle(t *testing.T) {
	input, stateDir, first := claudeIntervalFixture(t,
		claudeUsage(10, 2, 3, 5),
		claudeUsage(7, nil, nil, 4),
	)
	if first.Records != 2 || len(first.MessageUpdates) != 2 {
		t.Fatalf("expected fresh full-usage records for both messages: %#v", first)
	}
	m1 := claudeRecordByKeyInput(t, first, "10")
	if m1["input"] != "10" || m1["cacheRead"] != "2" || m1["cacheWrite"] != "3" || m1["output"] != "5" {
		t.Fatalf("expected fresh record to carry full usage: %#v", m1)
	}
	firstKey := m1["recordKey"].(string)

	store := progress.New(stateDir)
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", first.MessageUpdates); err != nil {
		t.Fatal(err)
	}

	// While the batch is unACKed, the messages are frozen: no new records.
	frozen, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "frozen.json"), BatchID: "batch-2", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Records != 0 || len(frozen.MessageUpdates) != 0 {
		t.Fatalf("expected frozen messages to produce no records: %#v", frozen)
	}

	// Full ACK: both messages advance to their pending to-state.
	result, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Advanced != 2 || result.Rejected != 0 {
		t.Fatalf("expected both messages confirmed: %#v", result)
	}

	// No growth: nothing to export.
	unchanged, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "unchanged.json"), BatchID: "batch-3", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Records != 0 {
		t.Fatalf("expected no records without growth: %#v", unchanged)
	}

	// Growth: only the incremental delta is exported under a new key.
	grown := filepath.Join(filepath.Dir(input), "grown.jsonl")
	writeJSONLFile(t, grown, []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(15, 2, 3, 8)),
	})
	delta, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: grown, Output: filepath.Join(filepath.Dir(input), "delta.json"), BatchID: "batch-4", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if delta.Records != 1 || len(delta.MessageUpdates) != 1 {
		t.Fatalf("expected one delta record: %#v", delta)
	}
	d := claudePayloadRecords(t, delta)[0]
	if d["input"] != "5" || d["output"] != "3" || d["cacheRead"] != "0" || d["cacheWrite"] != "0" {
		t.Fatalf("expected incremental delta with zero deltas as \"0\": %#v", d)
	}
	if d["recordKey"] == firstKey {
		t.Fatalf("expected grown interval to use a new record key: %#v", d)
	}
	if d["groupKey"] != m1["groupKey"] {
		t.Fatalf("expected stable group key across intervals: %#v vs %#v", d["groupKey"], m1["groupKey"])
	}
}

func claudeRecordByKeyInput(t *testing.T, prepared pipeline.PreparedExport, input string) adapter.Record {
	t.Helper()
	records := claudePayloadRecords(t, prepared)
	for _, record := range records {
		if record["input"] == input {
			return record
		}
	}
	t.Fatalf("no record with input %q in payload: %s", input, prepared.Payload)
	return nil
}

func claudePayloadRecords(t *testing.T, prepared pipeline.PreparedExport) []adapter.Record {
	t.Helper()
	var batch adapter.Batch
	if err := json.Unmarshal(prepared.Payload, &batch); err != nil {
		t.Fatal(err)
	}
	return batch.Records
}

func TestClaudeCodeJSONLPartialAckAdvancesPerMessage(t *testing.T) {
	input, stateDir, first := claudeIntervalFixture(t,
		claudeUsage(10, 0, 0, 5),
		claudeUsage(7, 0, 0, 4),
	)
	if first.Records != 2 {
		t.Fatalf("expected two fresh records: %#v", first)
	}
	store := progress.New(stateDir)
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", first.MessageUpdates); err != nil {
		t.Fatal(err)
	}
	m1 := claudeRecordByKeyInput(t, first, "10")
	rejectedKey := m1["recordKey"].(string)

	// Partial ACK: m1 (input 10) is rejected by the server, m2 accepted.
	result, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{
		BatchID:      "batch-1",
		RejectedKeys: map[string]string{rejectedKey: "record_conflict"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Advanced != 1 || result.Rejected != 1 {
		t.Fatalf("expected one advanced and one rejected message: %#v", result)
	}

	// The rejected FIRST interval adopts its to-state as the baseline, so
	// unchanged usage is neither resent nor re-counted.
	same, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "same.json"), BatchID: "batch-2", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if same.Records != 0 {
		t.Fatalf("expected rejected interval not to be resent: %#v", same)
	}

	// Growth exports only the delta above the rejected interval's to-state,
	// never the full amount under a new key.
	grown := filepath.Join(filepath.Dir(input), "grown.jsonl")
	writeJSONLFile(t, grown, []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(13, 0, 0, 6)),
	})
	delta, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: grown, Output: filepath.Join(filepath.Dir(input), "delta.json"), BatchID: "batch-3", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if delta.Records != 1 {
		t.Fatalf("expected the rejected message to still export growth: %#v", delta)
	}
	d := claudePayloadRecords(t, delta)[0]
	if d["input"] != "3" || d["output"] != "1" {
		t.Fatalf("expected growth delta above the adopted baseline: %#v", d)
	}
	if d["recordKey"] == rejectedKey {
		t.Fatalf("expected grown interval under a new key: %#v", d)
	}
}

func TestClaudeCodeJSONLRejectedIntervalAfterConfirmedBaseline(t *testing.T) {
	input, stateDir, first := claudeIntervalFixture(t,
		claudeUsage(10, 0, 0, 5),
		claudeUsage(7, 0, 0, 4),
	)
	if first.Records != 2 {
		t.Fatalf("expected two fresh records: %#v", first)
	}
	store := progress.New(stateDir)
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", first.MessageUpdates); err != nil {
		t.Fatal(err)
	}
	// Full ACK: both messages advance; m1 reaches the confirmed baseline 10.
	if result, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-1"}); err != nil || result.Advanced != 2 {
		t.Fatalf("confirm failed: %v %#v", err, result)
	}

	// Growth interval [10 -> 13] is exported, then rejected by the server.
	grown := filepath.Join(filepath.Dir(input), "grown.jsonl")
	writeJSONLFile(t, grown, []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(13, 0, 0, 6)),
	})
	second, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: grown, Output: filepath.Join(filepath.Dir(input), "second.json"), BatchID: "batch-2", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if second.Records != 1 {
		t.Fatalf("expected growth record: %#v", second)
	}
	rejectedKey := claudePayloadRecords(t, second)[0]["recordKey"].(string)
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-2", second.MessageUpdates); err != nil {
		t.Fatal(err)
	}
	result, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{
		BatchID:      "batch-2",
		RejectedKeys: map[string]string{rejectedKey: "record_conflict"},
	})
	if err != nil || result.Rejected != 1 {
		t.Fatalf("expected rejection: %v %#v", err, result)
	}

	// Unchanged usage would rebuild the exact rejected interval key: it is
	// skipped with a diagnostic instead of being resent automatically.
	same, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: grown, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if same.RecordCount != 0 {
		t.Fatalf("expected rejected interval not to be resent: %#v", same)
	}
	if !claudeHasDiagnostic(same.Issues, "rejected by the server") {
		t.Fatalf("expected a rejection diagnostic, issues: %#v", same.Issues)
	}

	// Further growth exports delta-only from the KEPT confirmed baseline (10),
	// under a new key; the rejected interval is never re-included wholesale.
	more := filepath.Join(filepath.Dir(input), "more.jsonl")
	writeJSONLFile(t, more, []map[string]any{
		claudeAssistantLine("2026-10-20T03:00:00Z", "s1", "m1", claudeUsage(15, 0, 0, 7)),
	})
	third, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: more, Output: filepath.Join(filepath.Dir(input), "third.json"), BatchID: "batch-3", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if third.Records != 1 {
		t.Fatalf("expected growth record after rejection: %#v", third)
	}
	d := claudePayloadRecords(t, third)[0]
	if d["input"] != "5" || d["output"] != "2" {
		t.Fatalf("expected delta from the kept confirmed baseline: %#v", d)
	}
	if d["recordKey"] == rejectedKey {
		t.Fatalf("expected a new interval key: %#v", d)
	}
}

func TestClaudeCodeJSONLIntervalUnknownAndRegressionHandling(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "session.jsonl")
	// Confirmed baseline: input known, cache unknown.
	stateDir := filepath.Join(dir, "state")
	store := progress.New(stateDir)
	base := progress.MessageUsageState{Input: u64ptr(10)}
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", []progress.MessagePendingUpdate{{
		MessageID: "m1",
		RecordKey: "claude-code-jsonl:base",
		To:        &base,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-1"}); err != nil {
		t.Fatal(err)
	}

	// unknown -> known: the first known value establishes a new baseline
	// without being counted (no backfill). A baseline-only interval is
	// emitted so the new baseline only advances after the server ACKs it.
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 5, nil, 1)),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("expected one baseline-only interval for unknown->known: %#v", res)
	}
	if !claudeHasDiagnostic(res.Issues, "establishes a new baseline") {
		t.Fatalf("expected unknown->known baseline diagnostic: %#v", res.Issues)
	}
	baselineOnly := res.Records[0]
	// Nothing is counted: known components carry their zero delta, newly
	// known components stay null.
	if baselineOnly["input"] != "0" || baselineOnly["cacheRead"] != nil || baselineOnly["cacheWrite"] != nil || baselineOnly["output"] != nil {
		t.Fatalf("expected baseline-only interval to count nothing: %#v", baselineOnly)
	}
	// The confirmed baseline is unchanged, so the same scan replays the
	// same idempotent baseline-only interval.
	again, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if again.RecordCount != 1 || again.Records[0]["recordKey"] != baselineOnly["recordKey"] {
		t.Fatalf("expected repeated scan to replay the same baseline-only interval: %#v", again)
	}

	// known -> unknown: component not counted, counted value unchanged.
	// The output component becomes known for the first time here, so the
	// message still emits its baseline-only interval (counting nothing).
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(nil, nil, nil, 3)),
	})
	res, err = pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("expected one baseline-only interval for the known->unknown snapshot: %#v", res)
	}
	if rec := res.Records[0]; rec["input"] != nil || rec["cacheRead"] != nil || rec["cacheWrite"] != nil || rec["output"] != nil {
		t.Fatalf("expected known->unknown to count nothing: %#v", rec)
	}
	if !claudeHasDiagnostic(res.Issues, "known to unknown") {
		t.Fatalf("expected known->unknown diagnostic: %#v", res.Issues)
	}

	// regression (current < baseline): whole message skipped, baseline kept.
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T03:00:00Z", "s1", "m1", claudeUsage(5, nil, nil, 9)),
	})
	res, err = pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 0 {
		t.Fatalf("expected regression to skip the message: %#v", res)
	}
	if !claudeHasDiagnostic(res.Issues, "decreased") {
		t.Fatalf("expected regression diagnostic: %#v", res.Issues)
	}

	// After all of that, growth from the original baseline still exports.
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T04:00:00Z", "s1", "m1", claudeUsage(12, nil, nil, 9)),
	})
	grown, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(dir, "g.json"), StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if grown.Records != 1 {
		t.Fatalf("expected growth record: %#v", grown)
	}
	if d := claudePayloadRecords(t, grown)[0]; d["input"] != "2" {
		t.Fatalf("expected delta from original baseline: %#v", d)
	}
}

func claudeHasDiagnostic(issues []adapter.LineIssue, needle string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Reason, needle) {
			return true
		}
	}
	return false
}

// TestClaudeCodeJSONLUnknownToKnownBaselineLifecycle locks the full ACK
// protocol for an unknown->known rebase: the first known value emits a
// baseline-only interval, the baseline never advances before the server
// ACK, the pending interval freezes rescans, and growth after the ACK is a
// normal known->known diff from the new baseline.
func TestClaudeCodeJSONLUnknownToKnownBaselineLifecycle(t *testing.T) {
	input, stateDir, first := claudeIntervalFixture(t,
		claudeUsage(10, nil, nil, 5),
		claudeUsage(7, nil, nil, 4),
	)
	store := progress.New(stateDir)
	// ACK the fresh full-usage interval: m1's confirmed baseline is now
	// input/output with both cache components still unknown.
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", first.MessageUpdates); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-1"}); err != nil {
		t.Fatal(err)
	}

	// unknown -> known: cache components become known for the first time.
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T02:00:00Z", "s1", "m1", claudeUsage(10, 5, 0, 5)),
		claudeAssistantLine("2026-10-20T02:01:00Z", "s1", "m2", claudeUsage(7, nil, nil, 4)),
	})
	rebased, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "rebase.json"), BatchID: "batch-2", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if rebased.Records != 1 || len(rebased.MessageUpdates) != 1 {
		t.Fatalf("expected one baseline-only interval for m1: %#v", rebased)
	}
	rec := claudePayloadRecords(t, rebased)[0]
	if rec["input"] != "0" || rec["cacheRead"] != nil || rec["cacheWrite"] != nil || rec["output"] != "0" {
		t.Fatalf("expected baseline-only interval to count nothing: %#v", rec)
	}
	rebaseKey := rec["recordKey"].(string)
	if err := store.ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-2", rebased.MessageUpdates); err != nil {
		t.Fatal(err)
	}

	// While the rebase interval is unACKed the message is frozen: rescans
	// export nothing and the confirmed baseline does not advance.
	frozen, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "frozen.json"), BatchID: "batch-3", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Records != 0 {
		t.Fatalf("expected frozen rescan to export nothing: %#v", frozen)
	}
	messageProgress, ok, err := store.MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil || !ok {
		t.Fatalf("progress lookup failed: %v %v", ok, err)
	}
	m1 := messageProgress["m1"]
	if m1.Pending == nil || m1.Pending.RecordKey != rebaseKey {
		t.Fatalf("expected pending rebase interval %q: %#v", rebaseKey, m1)
	}
	if m1.Confirmed == nil || m1.Confirmed.Input == nil || m1.Confirmed.CacheRead != nil || m1.Confirmed.CacheWrite != nil {
		t.Fatalf("baseline must not advance before the ACK: %#v", m1.Confirmed)
	}

	// ACK: the new baseline adopts the first known cache values.
	if _, err := store.ConfirmMessageBatch(progress.MessageBatchConfirm{BatchID: "batch-2"}); err != nil {
		t.Fatal(err)
	}
	messageProgress, _, err = store.MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		t.Fatal(err)
	}
	m1 = messageProgress["m1"]
	if m1.Confirmed == nil || m1.Confirmed.CacheRead == nil || *m1.Confirmed.CacheRead != 5 || m1.Confirmed.CacheWrite == nil || *m1.Confirmed.CacheWrite != 0 {
		t.Fatalf("expected ACK to adopt the rebased cache baseline: %#v", m1.Confirmed)
	}

	// Same input after the ACK: the rebased values are never re-counted.
	rest, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "rest.json"), BatchID: "batch-4", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if rest.Records != 0 {
		t.Fatalf("expected no re-count of rebased values: %#v", rest)
	}

	// Growth after the ACK is a normal known->known diff.
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T03:00:00Z", "s1", "m1", claudeUsage(12, 6, 0, 8)),
		claudeAssistantLine("2026-10-20T03:01:00Z", "s1", "m2", claudeUsage(7, nil, nil, 4)),
	})
	grown, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(filepath.Dir(input), "grown.json"), BatchID: "batch-5", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if grown.Records != 1 {
		t.Fatalf("expected one growth interval: %#v", grown)
	}
	d := claudePayloadRecords(t, grown)[0]
	if d["input"] != "2" || d["cacheRead"] != "1" || d["cacheWrite"] != "0" || d["output"] != "3" {
		t.Fatalf("expected known->known diff from the rebased baseline: %#v", d)
	}
	if d["recordKey"] == rebaseKey {
		t.Fatalf("expected growth to use a new interval key: %#v", d)
	}
}

func TestClaudeCodeJSONLProgressIntegrityGate(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "session.jsonl")
	writeJSONLFile(t, input, []map[string]any{
		claudeAssistantLine("2026-10-20T01:00:00Z", "s1", "m1", claudeUsage(10, 0, 0, 5)),
	})
	stateDir := filepath.Join(dir, "state")

	// First initialization on a fresh state directory works.
	if _, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir}); err != nil {
		t.Fatalf("expected first scan to pass: %v", err)
	}

	// Simulate a completed prior export: cursor advanced, then the progress
	// file is lost. Scanning and exporting must hard-fail instead of
	// re-baselining from zero.
	if _, err := progress.New(stateDir).Advance(progress.AdvanceOptions{
		Source:      adapter.ClaudeCodeJSONLSource,
		Input:       input,
		BatchID:     "batch-1",
		RecordCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir}); err == nil {
		t.Fatal("expected scan to fail when progress state was lost after prior exports")
	}
	_, err := pipeline.PrepareExport(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, Output: filepath.Join(dir, "b.json"), StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "refusing to re-baseline") {
		t.Fatalf("expected export to refuse re-baselining, got %v", err)
	}

	// A corrupt progress file is also a hard error.
	if err := progress.New(stateDir).ApplyMessagePending(adapter.ClaudeCodeJSONLSource, "batch-1", []progress.MessagePendingUpdate{{
		MessageID: "m1",
		RecordKey: "claude-code-jsonl:x",
		To:        &progress.MessageUsageState{Input: u64ptr(1)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(progress.New(stateDir).MessageProgressPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: input, StateDir: stateDir}); err == nil {
		t.Fatal("expected scan to fail on corrupt progress state")
	}
}

func TestClaudeCodeJSONLQuarantineReportingIsCapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many-bad.jsonl")
	var lines []string
	for i := 0; i < 50+10; i++ {
		lines = append(lines, fmt.Sprintf(`{"type":"assistant","timestamp":"2026-10-20T01:00:00Z","sessionId":"s1","message":{"id":"m%d","usage":{"input_tokens":1.5}}}`, i))
	}
	writeRawJSONL(t, path, lines...)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.ClaudeCodeJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 50+10 {
		t.Fatalf("expected all bad lines counted, got %d", res.Quarantined)
	}
	if len(res.Issues) != 50 {
		t.Fatalf("expected reported issues capped at %d, got %d", 50, len(res.Issues))
	}
	if res.RecordCount != 0 {
		t.Fatalf("expected no records from bad lines: %#v", res)
	}
}

// writeJSONLFile writes synthetic Claude Code session lines as one JSONL
// fixture file.
func writeJSONLFile(t *testing.T, path string, lines []map[string]any) {
	t.Helper()
	var b strings.Builder
	for _, line := range lines {
		payload, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(payload)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
