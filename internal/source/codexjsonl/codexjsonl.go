package codexjsonl

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const codexTool = "Codex"

type codexUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type codexObservation struct {
	Timestamp time.Time
	Usage     codexUsage
	Line      int
}

func LoadRecords(path string) ([]adapter.Record, error) {
	paths, err := jsonl.Files(path, jsonl.Options{})
	if err != nil {
		return nil, err
	}
	var records []adapter.Record
	for _, file := range paths {
		fileRecords, err := loadCodexJSONLFile(file)
		if err != nil {
			return nil, err
		}
		records = append(records, fileRecords...)
	}
	sort.Slice(records, func(i, j int) bool {
		a := adapter.StringField(records[i], "occurredAt")
		b := adapter.StringField(records[j], "occurredAt")
		if a == b {
			return adapter.StringField(records[i], "recordKey") < adapter.StringField(records[j], "recordKey")
		}
		return a < b
	})
	return records, nil
}

func loadCodexJSONLFile(path string) ([]adapter.Record, error) {
	var observations []codexObservation
	if err := jsonl.WalkLines(path, func(line jsonl.Line) error {
		obs, ok, err := parseCodexObservation(line.Text, line.Number)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", line.File, line.Number, err)
		}
		if ok {
			observations = append(observations, obs)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(observations) < 2 {
		return nil, nil
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Timestamp.Equal(observations[j].Timestamp) {
			return observations[i].Line < observations[j].Line
		}
		return observations[i].Timestamp.Before(observations[j].Timestamp)
	})
	groupKey := "codex-session:" + adapter.ShortHash(path)
	records := make([]adapter.Record, 0, len(observations)-1)
	prev := observations[0]
	for idx := 1; idx < len(observations); idx++ {
		cur := observations[idx]
		delta, ok := codexDelta(prev.Usage, cur.Usage)
		if !ok {
			prev = cur
			continue
		}
		records = append(records, adapter.Record{
			"recordKey":      fmt.Sprintf("codex-jsonl:%s:%d", adapter.ShortHash(path), cur.Line),
			"groupKey":       groupKey,
			"resetKey":       nil,
			"kind":           "delta",
			"occurredAt":     cur.Timestamp.UTC().Format(time.RFC3339),
			"tool":           codexTool,
			"model":          "unknown",
			"input":          fmt.Sprintf("%d", delta.Input),
			"cacheRead":      fmt.Sprintf("%d", delta.CacheRead),
			"cacheWrite":     fmt.Sprintf("%d", delta.CacheWrite),
			"output":         fmt.Sprintf("%d", delta.Output),
			"adapterVersion": "codex-jsonl-v1",
			"sourceType":     adapter.CodexJSONLSource,
		})
		prev = cur
	}
	return records, nil
}

func parseCodexObservation(line string, lineNo int) (codexObservation, bool, error) {
	raw, err := jsonl.DecodeObject(line)
	if err != nil {
		return codexObservation{}, false, err
	}
	payload, _ := raw["payload"].(map[string]any)
	if adapter.StringAny(payload["type"]) != "token_count" {
		return codexObservation{}, false, nil
	}
	infoVal, infoPresent := payload["info"]
	if !infoPresent || infoVal == nil {
		return codexObservation{}, false, nil
	}
	info, ok := infoVal.(map[string]any)
	if !ok {
		return codexObservation{}, false, errors.New("token_count malformed info")
	}
	usageVal, usagePresent := info["total_token_usage"]
	if !usagePresent || usageVal == nil {
		return codexObservation{}, false, errors.New("token_count missing total_token_usage")
	}
	usageRaw, ok := usageVal.(map[string]any)
	if !ok {
		return codexObservation{}, false, errors.New("token_count malformed total_token_usage")
	}
	timestamp, err := time.Parse(time.RFC3339, adapter.StringAny(raw["timestamp"]))
	if err != nil {
		return codexObservation{}, false, fmt.Errorf("invalid timestamp: %w", err)
	}
	rawInput, err := counterField(usageRaw, "input_tokens", true)
	if err != nil {
		return codexObservation{}, false, err
	}
	cacheRead, err := counterField(usageRaw, "cached_input_tokens", false)
	if err != nil {
		return codexObservation{}, false, err
	}
	cacheWrite, err := counterField(usageRaw, "cache_write_input_tokens", false)
	if err != nil {
		return codexObservation{}, false, err
	}
	output, err := counterField(usageRaw, "output_tokens", true)
	if err != nil {
		return codexObservation{}, false, err
	}
	cached, ok := adapter.AddUint64Checked(cacheRead, cacheWrite)
	if !ok {
		return codexObservation{}, false, fmt.Errorf("token_count cached token sum %d + %d exceeds uint64", cacheRead, cacheWrite)
	}
	if rawInput < cached {
		return codexObservation{}, false, fmt.Errorf("token_count cached tokens %d exceed input tokens %d", cached, rawInput)
	}
	return codexObservation{Timestamp: timestamp, Line: lineNo, Usage: codexUsage{Input: rawInput - cached, CacheRead: cacheRead, CacheWrite: cacheWrite, Output: output}}, true, nil
}

func counterField(usage map[string]any, key string, required bool) (uint64, error) {
	v, present := usage[key]
	if !present || v == nil {
		if required {
			return 0, fmt.Errorf("token_count missing %s", key)
		}
		return 0, nil
	}
	n, ok := adapter.UintAny(v)
	if !ok {
		return 0, fmt.Errorf("token_count %s must be a non-negative integer within uint64 range", key)
	}
	return n, nil
}

func codexDelta(prev, cur codexUsage) (codexUsage, bool) {
	if cur.Input < prev.Input || cur.CacheRead < prev.CacheRead || cur.CacheWrite < prev.CacheWrite || cur.Output < prev.Output {
		return codexUsage{}, false
	}
	return codexUsage{Input: cur.Input - prev.Input, CacheRead: cur.CacheRead - prev.CacheRead, CacheWrite: cur.CacheWrite - prev.CacheWrite, Output: cur.Output - prev.Output}, true
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{Source: adapter.CodexJSONLSource, Description: "Codex session JSONL", Load: func(opt adapter.Options) (adapter.LoadResult, error) {
		records, err := LoadRecords(opt.Input)
		return adapter.LoadResult{Records: records}, err
	}, FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
		if strings.TrimSpace(opt.StateDir) == "" {
			return records, nil
		}
		return filterKnownCodexRecords(opt.StateDir, records)
	}}
}
