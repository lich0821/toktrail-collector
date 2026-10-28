package codexjsonl_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codexjsonl"
	"toktrail-collector/internal/source/pipeline"
)

func TestCodexJSONLConvertsTokenCountDeltasWithoutPrivateFields(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	privateSession := "SYNTHETIC_SESSION_PRIVATE"
	privateModel := "private-model-route-do-not-upload"
	privatePrompt := "SYNTHETIC_PROMPT_PRIVATE"
	lines := []map[string]any{
		{"timestamp": "2026-10-20T01:00:00Z", "type": "session_meta", "payload": map[string]any{"id": privateSession}},
		{"timestamp": "2026-10-20T01:01:00Z", "type": "turn_context", "payload": map[string]any{"model": privateModel}},
		{"timestamp": "2026-10-20T01:02:00Z", "type": "event_msg", "payload": map[string]any{"type": "user_message", "message": privatePrompt}},
		codexCount("2026-10-20T01:03:00Z", 100, 20, 5, 40),
		codexCount("2026-10-20T01:04:00Z", 160, 30, 8, 80),
	}
	path := filepath.Join(input, "rollout-synthetic.jsonl")
	writeJSONLFile(t, path, lines)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 || res.ValidRecords != 1 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	if res.KnownIncludeRecords != 1 || res.TokensInclude == nil || *res.TokensInclude != 100 {
		t.Fatalf("unexpected include tokens: %#v", res)
	}
	if res.KnownExcludeRecords != 1 || res.TokensExclude == nil || *res.TokensExclude != 87 {
		t.Fatalf("unexpected exclude tokens: %#v", res)
	}
	if res.Tools["Codex"] != 1 {
		t.Fatalf("unexpected tool distribution: %#v", res.Tools)
	}
	record := res.Records[0]
	if record["tool"] != "Codex" || record["model"] != privateModel || record["input"] != "47" || record["cacheRead"] != "10" || record["cacheWrite"] != "3" || record["output"] != "40" {
		t.Fatalf("unexpected codex record: %#v", record)
	}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	// The turn_context model is a protocol field and is preserved verbatim
	// (only its wire shape is validated); session ids, prompts, and local
	// paths must still never appear in the exported record.
	for _, marker := range []string{privateSession, privatePrompt, dir} {
		if strings.Contains(string(wire), marker) {
			t.Fatalf("private marker %q leaked in %s", marker, string(wire))
		}
	}
}

func TestCodexJSONLSkipsDecreaseAndStartsNewBaseline(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(input, "decrease.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 100, 20, 5, 40),
		codexCount("2026-10-20T01:01:00Z", 160, 30, 8, 80),
		codexCount("2026-10-20T01:02:00Z", 120, 10, 4, 50),
		codexCount("2026-10-20T01:03:00Z", 150, 15, 7, 70),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 || res.ValidRecords != 2 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	first, second := res.Records[0], res.Records[1]
	if first["input"] != "47" || first["cacheRead"] != "10" || first["cacheWrite"] != "3" || first["output"] != "40" {
		t.Fatalf("unexpected first delta: %#v", first)
	}
	if second["input"] != "22" || second["cacheRead"] != "5" || second["cacheWrite"] != "3" || second["output"] != "20" {
		t.Fatalf("unexpected post-decrease delta: %#v", second)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 150 || res.TokensExclude == nil || *res.TokensExclude != 129 {
		t.Fatalf("unexpected aggregate tokens: include=%#v exclude=%#v", res.TokensInclude, res.TokensExclude)
	}
}

func TestCodexJSONLSeparatesBaselinesPerFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "b.jsonl"), []map[string]any{
		codexCount("2026-10-20T02:00:00Z", 10, 0, 0, 5),
		codexCount("2026-10-20T02:01:00Z", 20, 1, 0, 8),
	})
	writeJSONLFile(t, filepath.Join(input, "a.jsonl"), []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 50, 5, 0, 10),
		codexCount("2026-10-20T01:01:00Z", 70, 8, 1, 30),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 || res.ValidRecords != 2 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	if res.Records[0]["occurredAt"] != "2026-10-20T01:01:00Z" || res.Records[1]["occurredAt"] != "2026-10-20T02:01:00Z" {
		t.Fatalf("expected records in sorted file order with independent baselines: %#v", res.Records)
	}
	if res.Records[0]["groupKey"] == res.Records[1]["groupKey"] {
		t.Fatalf("expected separate group keys per JSONL file: %#v", res.Records)
	}
	if res.TokensInclude == nil || *res.TokensInclude != 53 || res.TokensExclude == nil || *res.TokensExclude != 48 {
		t.Fatalf("unexpected aggregate tokens: include=%#v exclude=%#v", res.TokensInclude, res.TokensExclude)
	}
}

func TestCodexJSONLPreservesCountersAboveFloat64Precision(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "precision.jsonl"), []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 0, 0, 0, 0),
		codexCount("2026-10-20T01:01:00Z", 9007199254740993, 0, 0, 1),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	record := res.Records[0]
	if record["input"] != "9007199254740993" {
		t.Fatalf("expected exact 2^53+1 input counter, got %v", record["input"])
	}
	if res.TokensInclude == nil || *res.TokensInclude != 9007199254740994 {
		t.Fatalf("unexpected include tokens: %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 9007199254740994 {
		t.Fatalf("unexpected exclude tokens: %#v", res.TokensExclude)
	}
}

func TestCodexJSONLAcceptsUint64MaxCounters(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "max.jsonl"), []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 0, 0, 0, 0),
		codexCount("2026-10-20T01:01:00Z", math.MaxUint64, 0, 0, 0),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 || res.ValidRecords != 1 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	if res.Records[0]["input"] != "18446744073709551615" {
		t.Fatalf("expected uint64 max input counter, got %v", res.Records[0]["input"])
	}
	if res.TokensInclude == nil || *res.TokensInclude != math.MaxUint64 || res.TokensExclude == nil || *res.TokensExclude != math.MaxUint64 {
		t.Fatalf("unexpected aggregate tokens: include=%#v exclude=%#v", res.TokensInclude, res.TokensExclude)
	}
}

func TestCodexJSONLRejectsCountersAboveUint64Max(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "above-max.jsonl")
	line := `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":18446744073709551616,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":1}}}}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
	if err == nil {
		t.Fatal("expected counter above uint64 max to be rejected")
	}
	if !strings.Contains(err.Error(), "input_tokens") {
		t.Fatalf("expected error to name the rejected counter: %v", err)
	}
}

func TestCodexJSONLRejectsCachedTokensExceedingInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-cache.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 10, 8, 5, 4),
	})
	_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
	if err == nil {
		t.Fatal("expected cached tokens exceeding input tokens to be rejected")
	}
	if !strings.Contains(err.Error(), "exceed input tokens") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodexJSONLRejectsCachedTokenSumOverflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache-overflow.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		codexCount("2026-10-20T01:00:00Z", 10, math.MaxUint64, 1, 4),
	})
	_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
	if err == nil {
		t.Fatal("expected cached token sum overflow to be rejected")
	}
	if !strings.Contains(err.Error(), "cached token sum") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCodexJSONLRejectsInvalidPresentCacheCounters(t *testing.T) {
	dir := t.TempDir()
	const lineTemplate = `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"cached_input_tokens":%s,"cache_write_input_tokens":0,"output_tokens":4}}}}`
	cases := []string{
		`-5`,
		`1.5`,
		`"abc"`,
		`18446744073709551616`,
	}
	for idx, cached := range cases {
		path := filepath.Join(dir, fmt.Sprintf("invalid-cache-%d.jsonl", idx))
		line := fmt.Sprintf(lineTemplate, cached)
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected present invalid cached_input_tokens %s to be rejected", cached)
		}
		if !strings.Contains(err.Error(), "cached_input_tokens") {
			t.Fatalf("expected error to name cached_input_tokens for %s, got: %v", cached, err)
		}
	}
}

func TestCodexJSONLRejectsTrailingDataAfterJSONValue(t *testing.T) {
	dir := t.TempDir()
	base := `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":4}}}}`
	cases := map[string]string{
		"trailing-object":  base + ` {"timestamp":"2026-10-20T02:00:00Z","type":"event_msg"}`,
		"trailing-garbage": base + ` not-json`,
	}
	for name, line := range cases {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected %s to be rejected", name)
		}
		if !strings.Contains(err.Error(), "trailing data after JSON value") {
			t.Fatalf("unexpected error for %s: %v", name, err)
		}
	}
}

func TestCodexJSONLAcceptsTrailingWhitespaceAfterJSONValue(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	base := `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":4}}}}`
	line := base + " \t"
	if err := os.WriteFile(filepath.Join(input, "ws.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	// A single token_count observation is a baseline only, so no delta records.
	if res.RecordCount != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
}

func TestCodexJSONLHandlesNullAndAbsentInfoWithoutCorruptingBaseline(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []map[string]any{
		{"timestamp": "2026-10-20T01:00:00Z", "type": "session_meta", "payload": map[string]any{"id": "test-session"}},
		codexNullInfo("2026-10-20T01:00:10Z"),
		codexAbsentInfo("2026-10-20T01:00:20Z"),
		codexCount("2026-10-20T01:01:00Z", 100, 20, 5, 40),
		codexNullInfo("2026-10-20T01:01:30Z"),
		codexAbsentInfo("2026-10-20T01:01:45Z"),
		codexCount("2026-10-20T01:02:00Z", 160, 30, 8, 80),
		codexNullInfo("2026-10-20T01:02:30Z"),
		codexCount("2026-10-20T01:03:00Z", 210, 40, 10, 100),
		codexNullInfo("2026-10-20T01:03:30Z"),
		codexAbsentInfo("2026-10-20T01:03:45Z"),
	}
	path := filepath.Join(input, "null-info.jsonl")
	writeJSONLFile(t, path, lines)
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 || res.ValidRecords != 2 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan counts: %#v", res)
	}
	if res.Records[0]["occurredAt"] != "2026-10-20T01:02:00Z" {
		t.Fatalf("expected first record at 01:02:00Z, got %v", res.Records[0]["occurredAt"])
	}
	if res.Records[0]["input"] != "47" || res.Records[0]["cacheRead"] != "10" || res.Records[0]["cacheWrite"] != "3" || res.Records[0]["output"] != "40" {
		t.Fatalf("unexpected first delta: %#v", res.Records[0])
	}
	if res.Records[1]["occurredAt"] != "2026-10-20T01:03:00Z" {
		t.Fatalf("expected second record at 01:03:00Z, got %v", res.Records[1]["occurredAt"])
	}
	if res.Records[1]["input"] != "38" || res.Records[1]["cacheRead"] != "10" || res.Records[1]["cacheWrite"] != "2" || res.Records[1]["output"] != "20" {
		t.Fatalf("unexpected second delta: %#v", res.Records[1])
	}
	if res.TokensInclude == nil || *res.TokensInclude != 170 {
		t.Fatalf("unexpected include tokens: %#v", res.TokensInclude)
	}
	if res.TokensExclude == nil || *res.TokensExclude != 145 {
		t.Fatalf("unexpected exclude tokens: %#v", res.TokensExclude)
	}
}

func TestCodexJSONLNullInfoOnlyYieldsNoRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "all-null.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		{"timestamp": "2026-10-20T01:00:00Z", "type": "session_meta", "payload": map[string]any{"id": "test-session"}},
		codexNullInfo("2026-10-20T01:00:10Z"),
		codexAbsentInfo("2026-10-20T01:00:20Z"),
		codexNullInfo("2026-10-20T01:00:30Z"),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 0 || res.ValidRecords != 0 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
}

func TestCodexJSONLSingleObservationWithSurroundingNullInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single-with-null.jsonl")
	writeJSONLFile(t, path, []map[string]any{
		codexNullInfo("2026-10-20T01:00:10Z"),
		codexCount("2026-10-20T01:01:00Z", 100, 20, 5, 40),
		codexNullInfo("2026-10-20T01:01:30Z"),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 0 {
		t.Fatalf("expected single observation to serve as baseline without delta records, got: %#v", res)
	}
}

func TestCodexJSONLRejectsMalformedInfo(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"string":  `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":"malformed"}}`,
		"number":  `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":123}}`,
		"array":   `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":[]}}`,
		"boolean": `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":true}}`,
	}
	for name, line := range cases {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected %s malformed info to be rejected", name)
		}
		if !strings.Contains(err.Error(), "token_count malformed info") {
			t.Fatalf("unexpected error for %s: %v", name, err)
		}
	}
}

func TestCodexJSONLRejectsMissingOrMalformedTotalTokenUsage(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"empty-info":    `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{}}}`,
		"null-usage":    `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":null}}}`,
		"string-usage":  `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":"bad"}}}`,
		"number-usage":  `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":123}}}`,
		"array-usage":   `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":[]}}}`,
		"boolean-usage": `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":true}}}`,
	}
	for name, line := range cases {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected %s missing/malformed total_token_usage to be rejected", name)
		}
		if !strings.Contains(err.Error(), "total_token_usage") {
			t.Fatalf("unexpected error for %s: %v", name, err)
		}
	}
}

func TestCodexJSONLRejectsMissingOrMalformedCounters(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		line           string
		expectedSubstr string
	}{
		"missing-input": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"output_tokens":10}}}}`,
			expectedSubstr: "input_tokens",
		},
		"missing-output": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10}}}}`,
			expectedSubstr: "output_tokens",
		},
		"negative-input": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":-1,"output_tokens":10}}}}`,
			expectedSubstr: "input_tokens",
		},
		"string-output": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":10,"output_tokens":"bad"}}}}`,
			expectedSubstr: "output_tokens",
		},
	}
	for name, tc := range cases {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected %s to be rejected", name)
		}
		if !strings.Contains(err.Error(), tc.expectedSubstr) {
			t.Fatalf("unexpected error for %s (expected %q): %v", name, tc.expectedSubstr, err)
		}
	}
}

func TestCodexJSONLAttributesTurnContextModel(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "model.jsonl"), []map[string]any{
		codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
		codexCount("2026-10-20T01:01:00Z", 100, 20, 5, 40),
		codexCount("2026-10-20T01:02:00Z", 160, 30, 8, 80),
		codexTurn("2026-10-20T01:03:00Z", "gpt-5"),
		codexCount("2026-10-20T01:04:00Z", 210, 40, 10, 100),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 || res.ValidRecords != 2 || res.InvalidRecords != 0 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	// The second delta straddles a turn boundary, but both turns recorded
	// the same model, so attribution stays exact.
	for idx, want := range []string{"gpt-5", "gpt-5"} {
		if res.Records[idx]["model"] != want {
			t.Fatalf("record %d model = %v, want %q", idx, res.Records[idx]["model"], want)
		}
	}
	if res.Records[0]["input"] != "47" || res.Records[1]["input"] != "38" {
		t.Fatalf("unexpected deltas: %#v", res.Records)
	}
}

func TestCodexJSONLModelSwitchInsideIntervalReportsUnknown(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "switch.jsonl"), []map[string]any{
		codexTurn("2026-10-20T01:00:00Z", "gpt-4o"),
		codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
		codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
		codexTurn("2026-10-20T01:03:00Z", "gpt-5"),
		codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
		codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 3 || res.ValidRecords != 3 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	if res.Records[0]["model"] != "gpt-4o" {
		t.Fatalf("first delta model = %v, want gpt-4o", res.Records[0]["model"])
	}
	// The middle delta spans the tail of the gpt-4o turn and the head of
	// the gpt-5 turn; the cumulative counters cannot split it, so it must
	// not be attributed to either model — in particular not to the model
	// recorded at the end of the interval.
	if got := res.Records[1]["model"]; got != "unknown" {
		t.Fatalf("straddling delta model = %v, want unknown (must not inherit the interval-end model gpt-5)", got)
	}
	if res.Records[2]["model"] != "gpt-5" {
		t.Fatalf("last delta model = %v, want gpt-5", res.Records[2]["model"])
	}
	// Attribution never changes the token deltas themselves.
	if res.Records[1]["input"] != "70" || res.Records[1]["output"] != "10" {
		t.Fatalf("unexpected straddling delta: %#v", res.Records[1])
	}
}

func TestCodexJSONLModelSwitchWithoutCountsStillBlocksAttribution(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "zero-count-switch.jsonl"), []map[string]any{
		codexTurn("2026-10-20T01:00:00Z", "gpt-4o"),
		codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
		codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
		codexTurn("2026-10-20T01:03:00Z", "gpt-5"),
		codexTurn("2026-10-20T01:04:00Z", "gpt-4o"),
		codexCount("2026-10-20T01:05:00Z", 220, 0, 0, 30),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 2 {
		t.Fatalf("unexpected scan result: %#v", res)
	}
	// The interval contains a zero-count turn recorded with a different
	// model; the cumulative counters cannot prove it consumed nothing, so
	// the delta is still ambiguous.
	if got := res.Records[1]["model"]; got != "unknown" {
		t.Fatalf("delta across zero-count model switch = %v, want unknown", got)
	}
	if res.Records[0]["model"] != "gpt-4o" {
		t.Fatalf("first delta model = %v, want gpt-4o", res.Records[0]["model"])
	}
}

func TestCodexJSONLMissingTurnContextModelReportsUnknown(t *testing.T) {
	cases := []struct {
		name     string
		lines    []map[string]any
		expected []string
	}{
		{
			name: "observation before first turn_context",
			lines: []map[string]any{
				codexCount("2026-10-20T01:00:00Z", 100, 0, 0, 10),
				codexTurn("2026-10-20T01:01:00Z", "gpt-5"),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexCount("2026-10-20T01:03:00Z", 220, 0, 0, 30),
			},
			expected: []string{"unknown", "gpt-5"},
		},
		{
			name: "turn without recorded model",
			lines: []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexTurn("2026-10-20T01:03:00Z", nil),
				codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
				codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
			},
			expected: []string{"gpt-5", "unknown", "unknown"},
		},
		{
			name: "turn with null model",
			lines: []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexTurnNullModel("2026-10-20T01:03:00Z"),
				codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
				codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
			},
			expected: []string{"gpt-5", "unknown", "unknown"},
		},
		{
			name: "turn with null payload",
			lines: []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexTurnNullPayload("2026-10-20T01:03:00Z"),
				codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
				codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
			},
			expected: []string{"gpt-5", "unknown", "unknown"},
		},
		{
			name: "no turn_context lines at all",
			lines: []map[string]any{
				codexCount("2026-10-20T01:00:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:01:00Z", 150, 0, 0, 20),
				codexCount("2026-10-20T01:02:00Z", 220, 0, 0, 30),
			},
			expected: []string{"unknown", "unknown"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "sessions")
			if err := os.MkdirAll(input, 0o700); err != nil {
				t.Fatal(err)
			}
			writeJSONLFile(t, filepath.Join(input, "missing.jsonl"), tc.lines)
			res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
			if err != nil {
				t.Fatal(err)
			}
			if res.RecordCount != len(tc.expected) {
				t.Fatalf("unexpected scan result: %#v", res)
			}
			for idx, want := range tc.expected {
				if res.Records[idx]["model"] != want {
					t.Fatalf("record %d model = %v, want %q", idx, res.Records[idx]["model"], want)
				}
			}
		})
	}
}

func TestCodexJSONLPreservesRecordedModelVerbatim(t *testing.T) {
	for _, model := range []string{
		"gpt-5-codex",
		"Company_Private-Route.42+preview",
		"my custom route",
		"GPT-5",
	} {
		t.Run(model, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "sessions")
			if err := os.MkdirAll(input, 0o700); err != nil {
				t.Fatal(err)
			}
			writeJSONLFile(t, filepath.Join(input, "verbatim.jsonl"), []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", model),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
			})
			res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
			if err != nil {
				t.Fatal(err)
			}
			if res.RecordCount != 1 || res.Records[0]["model"] != model {
				t.Fatalf("model = %#v, want verbatim %q", res.Records[0]["model"], model)
			}
		})
	}
}

func TestCodexJSONLRejectsInvalidTurnContextModel(t *testing.T) {
	cases := map[string]any{
		"control-character": "gpt-5\u0001",
		"too-long":          strings.Repeat("m", 129),
		"empty":             "",
		"whitespace-only":   "   ",
		"number":            123,
		"object":            map[string]any{"id": "gpt-5"},
	}
	for name, model := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "sessions")
			if err := os.MkdirAll(input, 0o700); err != nil {
				t.Fatal(err)
			}
			writeJSONLFile(t, filepath.Join(input, "invalid-model.jsonl"), []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", model),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
			})
			_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
			if err == nil {
				t.Fatalf("expected invalid turn_context model %v to be rejected", model)
			}
			if !strings.Contains(err.Error(), "turn_context model") {
				t.Fatalf("unexpected error for %s: %v", name, err)
			}
		})
	}
}

func TestCodexJSONLRejectsMalformedTurnContextLines(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		line           string
		expectedSubstr string
	}{
		"payload-string": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"turn_context","payload":"not-an-object"}`,
			expectedSubstr: "turn_context malformed payload",
		},
		"payload-number": {
			line:           `{"timestamp":"2026-10-20T01:00:00Z","type":"turn_context","payload":123}`,
			expectedSubstr: "turn_context malformed payload",
		},
		"invalid-timestamp": {
			line:           `{"timestamp":"not-a-timestamp","type":"turn_context","payload":{"model":"gpt-5"}}`,
			expectedSubstr: "invalid timestamp",
		},
		"missing-timestamp": {
			line:           `{"type":"turn_context","payload":{"model":"gpt-5"}}`,
			expectedSubstr: "invalid timestamp",
		},
	}
	for name, tc := range cases {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: path})
		if err == nil {
			t.Fatalf("expected %s to be rejected", name)
		}
		if !strings.Contains(err.Error(), tc.expectedSubstr) {
			t.Fatalf("unexpected error for %s (expected %q): %v", name, tc.expectedSubstr, err)
		}
	}
}

func TestCodexJSONLExportFilterStaysStrictAcrossModelEnrichment(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONLFile(t, filepath.Join(input, "model.jsonl"), []map[string]any{
		codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
		codexCount("2026-10-20T01:01:00Z", 100, 20, 5, 40),
		codexCount("2026-10-20T01:02:00Z", 160, 30, 8, 80),
	})
	res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordCount != 1 || res.Records[0]["model"] != "gpt-5" {
		t.Fatalf("fixture did not produce the recorded model record: %#v", res)
	}
	fresh := res.Records

	storeHistory := func(t *testing.T, records []adapter.Record) string {
		t.Helper()
		stateDir := t.TempDir()
		file := filepath.Join(stateDir, "history.json")
		payload, err := json.Marshal(adapter.Batch{BatchID: "history", Records: records})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := outbox.New(stateDir).Save(outbox.Outbox{Batches: []outbox.BatchEntry{{BatchID: "history", File: file, Source: adapter.CodexJSONLSource, Status: outbox.StatusSynced}}}); err != nil {
			t.Fatal(err)
		}
		return stateDir
	}

	// Identical history (same recorded model) dedups cleanly.
	stateDir := storeHistory(t, fresh)
	got, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir}, fresh)
	if err != nil || len(got) != 0 {
		t.Fatalf("identical model history must dedup: %v %v", got, err)
	}

	// A previously exported record with a different model value — for
	// example exported before model collection existed — is an
	// immutable-history conflict: strict idempotency, no upgrade path.
	for _, stale := range []string{"unknown", "gpt-4o"} {
		old := make(adapter.Record, len(fresh[0]))
		for k, v := range fresh[0] {
			old[k] = v
		}
		old["model"] = stale
		stateDir := storeHistory(t, []adapter.Record{old})
		if _, err := codexjsonl.Adapter().FilterForExport(adapter.Options{Source: adapter.CodexJSONLSource, StateDir: stateDir}, fresh); err == nil {
			t.Fatalf("stored model %q drifting to a recorded model must fail closed", stale)
		} else if !strings.Contains(err.Error(), "changed after export") {
			t.Fatalf("unexpected conflict error for stored model %q: %v", stale, err)
		}
	}
}

func TestCodexJSONLScanSurfacesModelDiagnostics(t *testing.T) {
	cases := []struct {
		name            string
		lines           []map[string]any
		unknownLines    []int
		reasonSubstring string
	}{
		{
			name: "model switch within interval",
			lines: []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", "gpt-4o"),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexTurn("2026-10-20T01:03:00Z", "gpt-5"),
				codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
				codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
			},
			unknownLines:    []int{5},
			reasonSubstring: "model switch",
		},
		{
			name: "no turn_context in file",
			lines: []map[string]any{
				codexCount("2026-10-20T01:00:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:01:00Z", 150, 0, 0, 20),
				codexCount("2026-10-20T01:02:00Z", 220, 0, 0, 30),
			},
			unknownLines:    []int{2, 3},
			reasonSubstring: "no turn_context",
		},
		{
			name: "turn_context without recorded model",
			lines: []map[string]any{
				codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
				codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
				codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
				codexTurn("2026-10-20T01:03:00Z", nil),
				codexCount("2026-10-20T01:04:00Z", 220, 0, 0, 30),
				codexCount("2026-10-20T01:05:00Z", 260, 0, 0, 40),
			},
			unknownLines:    []int{5, 6},
			reasonSubstring: "no recorded model",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "sessions")
			if err := os.MkdirAll(input, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(input, "diagnostics.jsonl")
			writeJSONLFile(t, path, tc.lines)
			res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
			if err != nil {
				t.Fatal(err)
			}
			if res.Quarantined != 0 {
				t.Fatalf("model diagnostics must not quarantine lines: %#v", res)
			}
			if len(res.Issues) != len(tc.unknownLines) {
				t.Fatalf("issues = %#v, want %d diagnostics", res.Issues, len(tc.unknownLines))
			}
			for idx, issue := range res.Issues {
				if issue.File != path || issue.Line != tc.unknownLines[idx] {
					t.Fatalf("issue %d = %#v, want %s:%d", idx, issue, path, tc.unknownLines[idx])
				}
				if !strings.Contains(issue.Reason, tc.reasonSubstring) {
					t.Fatalf("issue %d reason = %q, want substring %q", idx, issue.Reason, tc.reasonSubstring)
				}
				// The diagnostic explains the cause without ever carrying a
				// recorded model value.
				if strings.Contains(issue.Reason, "gpt-") {
					t.Fatalf("issue %d reason leaks a model value: %q", idx, issue.Reason)
				}
			}
		})
	}

	// A turn that literally recorded the model "unknown" is exact
	// attribution, not a missing-model or ambiguity diagnostic.
	t.Run("literal unknown model is not misreported", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "sessions")
		if err := os.MkdirAll(input, 0o700); err != nil {
			t.Fatal(err)
		}
		writeJSONLFile(t, filepath.Join(input, "literal-unknown.jsonl"), []map[string]any{
			codexTurn("2026-10-20T01:00:00Z", "unknown"),
			codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
			codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
		})
		res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
		if err != nil {
			t.Fatal(err)
		}
		if res.RecordCount != 1 || res.Records[0]["model"] != "unknown" {
			t.Fatalf("literal unknown model must be recorded verbatim: %#v", res)
		}
		if len(res.Issues) != 0 || res.Quarantined != 0 {
			t.Fatalf("literal unknown model must not be misreported as missing: %#v", res.Issues)
		}
	})

	// The diagnostic list is capped across the whole scan, not per file:
	// 58 unattributed deltas over two files surface at most 50 issues.
	t.Run("diagnostics are capped per scan", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "sessions")
		if err := os.MkdirAll(input, 0o700); err != nil {
			t.Fatal(err)
		}
		first := filepath.Join(input, "a.jsonl")
		second := filepath.Join(input, "b.jsonl")
		for _, path := range []string{first, second} {
			lines := make([]map[string]any, 0, 30)
			for i := 0; i < 30; i++ {
				lines = append(lines, codexCount(
					fmt.Sprintf("2026-10-20T01:%02d:00Z", i),
					uint64(100+10*i), 0, 0, uint64(10+i),
				))
			}
			writeJSONLFile(t, path, lines)
		}
		res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
		if err != nil {
			t.Fatal(err)
		}
		if res.RecordCount != 58 || res.Quarantined != 0 {
			t.Fatalf("unexpected scan result: %#v", res)
		}
		if len(res.Issues) != 50 {
			t.Fatalf("scan-wide diagnostic cap = %d issues, want 50", len(res.Issues))
		}
		if res.Issues[0].File != first || res.Issues[29].File != second {
			t.Fatalf("cap must span the whole scan, not restart per file: %#v", res.Issues)
		}
	})

	// A fully attributed session produces no diagnostics.
	t.Run("attributed session is clean", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "sessions")
		if err := os.MkdirAll(input, 0o700); err != nil {
			t.Fatal(err)
		}
		writeJSONLFile(t, filepath.Join(input, "clean.jsonl"), []map[string]any{
			codexTurn("2026-10-20T01:00:00Z", "gpt-5"),
			codexCount("2026-10-20T01:01:00Z", 100, 0, 0, 10),
			codexCount("2026-10-20T01:02:00Z", 150, 0, 0, 20),
		})
		res, err := pipeline.Scan(adapter.Options{Source: adapter.CodexJSONLSource, Input: input})
		if err != nil {
			t.Fatal(err)
		}
		if res.RecordCount != 1 || len(res.Issues) != 0 || res.Quarantined != 0 {
			t.Fatalf("attributed session must be clean: %#v", res)
		}
	})
}

func overflowTotalRecord(key, input, cacheRead string) map[string]any {
	return map[string]any{
		"recordKey":      key,
		"groupKey":       nil,
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     "2026-10-20T01:00:00Z",
		"tool":           "codex",
		"model":          nil,
		"input":          input,
		"cacheRead":      cacheRead,
		"cacheWrite":     "0",
		"output":         "0",
		"adapterVersion": "fixture-v1",
		"sourceType":     "fixture",
	}
}

func codexCount(timestamp string, input, cacheRead, cacheWrite, output uint64) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{"total_token_usage": map[string]any{
				"input_tokens":             input,
				"cached_input_tokens":      cacheRead,
				"cache_write_input_tokens": cacheWrite,
				"output_tokens":            output,
			}},
		},
	}
}

func codexTurn(timestamp string, model any) map[string]any {
	payload := map[string]any{}
	if model != nil {
		payload["model"] = model
	}
	return map[string]any{
		"timestamp": timestamp,
		"type":      "turn_context",
		"payload":   payload,
	}
}

func codexTurnNullModel(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "turn_context",
		"payload":   map[string]any{"model": nil},
	}
}

func codexTurnNullPayload(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "turn_context",
		"payload":   nil,
	}
}

func codexNullInfo(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": nil,
			"rate_limits": map[string]any{
				"limit_requests": 5000,
			},
		},
	}
}

func codexAbsentInfo(timestamp string) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
		},
	}
}

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

func writeJSONFile(t *testing.T, body any) string {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadRecordsWhitelistsFreeFormFields locks the privacy projection of
// free-form usage-json inputs: unknown free-form fields (session ids, file
// paths, prompts, nested objects) must never survive into the records that
// validation, scan, preview, export, and outbox serialization consume, while
// protocol values and the idempotent recordKey stay byte-identical.
