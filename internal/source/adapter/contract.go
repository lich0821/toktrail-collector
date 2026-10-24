package adapter

import (
	"toktrail-collector/internal/local/progress"
)

const (
	UsageJSONSource       = "usage-json"
	CodexJSONLSource      = "codex-jsonl"
	ClaudeCodeJSONLSource = "claude-code-jsonl"
)

type Options struct {
	Source  string
	Input   string
	Output  string
	BatchID string
	Limit   int
	// StateDir points at the collector state directory. Interval sources
	// (claude-code-jsonl) use it to load confirmed per-message baselines and
	// to enforce the progress-integrity rule. Empty means stateless: the
	// claude-code-jsonl adapter then reports the full current usage per
	// message without interval state (updates are discarded).
	StateDir string
}

// LoadResult is the raw output of one source loader.
type LoadResult struct {
	Records        []Record
	Issues         []LineIssue
	Quarantined    int
	MessageUpdates []progress.MessagePendingUpdate
}

// SourceLoader dispatches Options to one compiled-in source adapter.
type SourceLoader func(Options) (LoadResult, error)
type Record map[string]any

type Batch struct {
	BatchID string   `json:"batchId"`
	Records []Record `json:"records"`
}

type LineIssue struct {
	File   string
	Line   int
	Reason string
}
type Adapter struct {
	Source          string
	Description     string
	Load            SourceLoader
	FilterForExport func(Options, []Record) ([]Record, error)
	ValidateCommit  func(string) error
}
