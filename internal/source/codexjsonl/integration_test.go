package codexjsonl_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"toktrail-collector/internal/source/adapter"
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
	if record["tool"] != "Codex" || record["model"] != "unknown" || record["input"] != "47" || record["cacheRead"] != "10" || record["cacheWrite"] != "3" || record["output"] != "40" {
		t.Fatalf("unexpected codex record: %#v", record)
	}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{privateSession, privateModel, privatePrompt, dir} {
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
