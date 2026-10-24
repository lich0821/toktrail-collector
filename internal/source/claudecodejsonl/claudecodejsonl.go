package claudecodejsonl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const (
	claudeCodeAdapterVersion = "claude-code-jsonl-v1"
	claudeCodeTool           = "Claude Code"
)

// maxReportedLineIssues caps how many quarantined lines are kept for
// reporting; the total count is tracked separately.
const maxReportedLineIssues = 50

type claudeCodeUsage struct {
	Input      *uint64
	CacheRead  *uint64
	CacheWrite *uint64
	Output     *uint64
}

func (u claudeCodeUsage) equal(v claudeCodeUsage) bool {
	return usagePointerEqual(u.Input, v.Input) &&
		usagePointerEqual(u.CacheRead, v.CacheRead) &&
		usagePointerEqual(u.CacheWrite, v.CacheWrite) &&
		usagePointerEqual(u.Output, v.Output)
}

func usagePointerEqual(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (u claudeCodeUsage) components() [4]*uint64 {
	return [4]*uint64{u.Input, u.CacheRead, u.CacheWrite, u.Output}
}

func messageUsageComponents(s progress.MessageUsageState) [4]*uint64 {
	return [4]*uint64{s.Input, s.CacheRead, s.CacheWrite, s.Output}
}

// claudeUsageComponentNames are the API field names used in diagnostics.
var claudeUsageComponentNames = [4]string{"input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens"}

// claudeCodeObservation is one assistant message.usage observation. The same
// message.id can appear as several observations: streaming snapshots of one
// response grow toward the final usage, and the same session content can be
// duplicated or renamed across the scanned input.
type claudeCodeObservation struct {
	MessageID string
	Timestamp time.Time
	Usage     claudeCodeUsage
	Model     string
	File      string
	Line      int
}

// claudeCodeMessage is the deduplicated view of one assistant message keyed
// by API message.id. Usage is the latest distinct observed value, selected
// by observation timestamp (newest wins; equal-timestamp ties keep the
// within-file line order). The timestamp, model, and source location come
// from the first observation of that latest distinct value
// (representative), which keeps exports deterministic regardless of file
// order or duplicates.
type claudeCodeMessage struct {
	ID        string
	Model     string
	Timestamp time.Time
	Usage     claudeCodeUsage
	File      string
	Line      int
}

type claudeLineOutcome int

const (
	// claudeLineIgnore: the line carries no usage to attribute (non-assistant
	// line, assistant line without message or usage). Not an error.
	claudeLineIgnore claudeLineOutcome = iota
	// claudeLineObserve: a valid usage observation.
	claudeLineObserve
	// claudeLineQuarantine: the line looks like usage but is invalid, or a
	// usage-bearing assistant line lacks stable message identity.
	claudeLineQuarantine
)

type claudeCodeQuarantine struct {
	issues []adapter.LineIssue
	total  int
}

func (q *claudeCodeQuarantine) add(file string, line int, reason string) {
	q.total++
	if len(q.issues) < maxReportedLineIssues {
		q.issues = append(q.issues, adapter.LineIssue{File: file, Line: line, Reason: reason})
	}
}

// loadClaudeCodeMessages scans Claude Code session JSONL and returns the
// per-message (message.id keyed) latest usage snapshots, sorted by message
// id for deterministic output. Only assistant message.usage counters are
// read; every other field stays local. Invalid lines are quarantined and
// reported instead of aborting the scan.
func loadClaudeCodeMessages(path string) ([]claudeCodeMessage, []adapter.LineIssue, int, error) {
	paths, err := jsonl.Files(path, jsonl.Options{SkipHiddenFiles: true})
	if err != nil {
		return nil, nil, 0, err
	}
	quarantine := &claudeCodeQuarantine{}
	final := map[string]*claudeCodeMessage{}
	for _, file := range paths {
		if err := loadClaudeCodeJSONLFile(file, final, quarantine); err != nil {
			return nil, nil, 0, err
		}
	}
	messages := make([]claudeCodeMessage, 0, len(final))
	for _, message := range final {
		messages = append(messages, *message)
	}
	sort.Slice(messages, func(i, j int) bool { return messages[i].ID < messages[j].ID })
	return messages, quarantine.issues, quarantine.total, nil
}

// applyClaudeObservation merges one observation into the per-message state.
// The latest distinct usage value wins by observation timestamp, not by scan
// order: an observation older than the current snapshot is stale and ignored,
// a newer-or-equal observation replaces the usage and re-selects the
// representative, and an equal usage value keeps the earlier representative.
// Equal-timestamp ties stay resolved by within-file line order, so two
// same-instant observations with different usage remain file-order dependent.
func applyClaudeObservation(final map[string]*claudeCodeMessage, obs claudeCodeObservation) {
	current, ok := final[obs.MessageID]
	if !ok {
		final[obs.MessageID] = &claudeCodeMessage{
			ID:        obs.MessageID,
			Model:     adapter.ClaudePublicModel(obs.Model),
			Timestamp: obs.Timestamp,
			Usage:     obs.Usage,
			File:      obs.File,
			Line:      obs.Line,
		}
		return
	}
	if current.Usage.equal(obs.Usage) {
		return
	}
	if obs.Timestamp.Before(current.Timestamp) {
		// Stale snapshot (e.g. an older duplicate in a lexically later
		// file): the newer observation keeps the latest usage.
		return
	}
	current.Usage = obs.Usage
	current.Timestamp = obs.Timestamp
	current.Model = adapter.ClaudePublicModel(obs.Model)
	current.File = obs.File
	current.Line = obs.Line
}

func loadClaudeCodeJSONLFile(path string, final map[string]*claudeCodeMessage, quarantine *claudeCodeQuarantine) error {
	return jsonl.WalkLines(path, func(line jsonl.Line) error {
		obs, outcome, reason := parseClaudeCodeLine(line.Text, line.File, line.Number)
		switch outcome {
		case claudeLineQuarantine:
			quarantine.add(line.File, line.Number, reason)
		case claudeLineObserve:
			applyClaudeObservation(final, obs)
		}
		return nil
	})
}

func parseClaudeCodeLine(line string, path string, lineNo int) (claudeCodeObservation, claudeLineOutcome, string) {
	var obs claudeCodeObservation
	raw, err := jsonl.DecodeObject(line)
	if err != nil {
		return obs, claudeLineQuarantine, "invalid JSON: " + err.Error()
	}
	if adapter.StringAny(raw["type"]) != "assistant" {
		return obs, claudeLineIgnore, ""
	}
	message, ok := raw["message"].(map[string]any)
	if !ok {
		return obs, claudeLineIgnore, ""
	}
	usageValue, present := message["usage"]
	if !present || usageValue == nil {
		return obs, claudeLineIgnore, ""
	}
	usage, ok := usageValue.(map[string]any)
	if !ok {
		return obs, claudeLineQuarantine, "message.usage must be an object"
	}
	obs.MessageID = adapter.StringAny(message["id"])
	if obs.MessageID == "" {
		// The per-line uuid is NOT a message identity: without message.id the
		// streaming snapshots of one response cannot be grouped, so skip the
		// line conservatively rather than risk double counting.
		return obs, claudeLineQuarantine, "assistant usage line missing message.id"
	}
	timestampStr := adapter.StringAny(raw["timestamp"])
	if timestampStr == "" {
		return obs, claudeLineQuarantine, "missing timestamp"
	}
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return obs, claudeLineQuarantine, "invalid timestamp: " + err.Error()
	}
	usageCounts, reason := parseClaudeCodeUsage(usage)
	if reason != "" {
		return obs, claudeLineQuarantine, reason
	}
	if usageCounts.Input == nil && usageCounts.CacheRead == nil && usageCounts.CacheWrite == nil && usageCounts.Output == nil {
		// A usage object without any known counter carries no usage
		// information; unknown is not zero, so there is nothing to record.
		return obs, claudeLineIgnore, ""
	}
	obs.Timestamp = timestamp
	obs.Usage = usageCounts
	obs.Model = claudeRawModel(message["model"])
	obs.File = path
	obs.Line = lineNo
	return obs, claudeLineObserve, ""
}

// parseClaudeCodeUsage reads the four Anthropic usage counters. Absent or
// null counters stay unknown (nil), never zero. Present counters must be
// exact non-negative decimal integers within uint64; fractions, exponents,
// signs, and overflow are rejected.
func parseClaudeCodeUsage(usage map[string]any) (claudeCodeUsage, string) {
	var u claudeCodeUsage
	fields := []struct {
		key   string
		field **uint64
	}{
		{"input_tokens", &u.Input},
		{"cache_read_input_tokens", &u.CacheRead},
		{"cache_creation_input_tokens", &u.CacheWrite},
		{"output_tokens", &u.Output},
	}
	for _, f := range fields {
		v, present := usage[f.key]
		if !present || v == nil {
			continue
		}
		n, ok := adapter.UintAny(v)
		if !ok {
			return claudeCodeUsage{}, fmt.Sprintf("usage %s must be a non-negative integer within uint64 range", f.key)
		}
		value := n
		*f.field = &value
	}
	return u, ""
}

// claudeRawModel extracts the raw model identifier candidate: the model may
// be a plain string or an object with an id field.
func claudeRawModel(v any) string {
	switch m := v.(type) {
	case string:
		return strings.TrimSpace(m)
	case map[string]any:
		return adapter.StringAny(m["id"])
	default:
		return ""
	}
}

// loadClaudeMessageProgress loads the per-message baselines for
// claude-code-jsonl and enforces the progress-integrity rule: after prior
// claude-code-jsonl exports from this state directory, a missing or empty
// progress state is a hard error, because re-baselining from zero would
// double count usage on the server. The very first initialization on a
// fresh state directory succeeds normally.
func loadClaudeMessageProgress(stateDir string) (map[string]progress.MessageProgress, error) {
	store := progress.New(stateDir)
	progress, _, err := store.MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		return nil, fmt.Errorf("claude-code-jsonl message progress state unusable at %s: %w", store.MessageProgressPath(), err)
	}
	if len(progress) > 0 {
		return progress, nil
	}
	used, err := store.HasSource(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		return nil, fmt.Errorf("claude-code-jsonl cannot check prior export state: %w", err)
	}
	if used {
		return nil, fmt.Errorf("claude-code-jsonl message progress state is missing at %s after prior exports from this state directory; refusing to re-baseline from zero because that would double count already-uploaded usage. Restore the state directory (message-progress.json) from a backup, or start fresh with a new state directory and a newly bound device", store.MessageProgressPath())
	}
	return progress, nil
}

// claudeStateString renders a counted-state snapshot for record identity:
// decimal per known component, "-" per unknown component.
func claudeStateString(vals [4]*uint64) string {
	parts := make([]string, 4)
	for i, v := range vals {
		if v == nil {
			parts[i] = "-"
		} else {
			parts[i] = strconv.FormatUint(*v, 10)
		}
	}
	return strings.Join(parts, ",")
}

// claudeIntervalKey derives the record key for one interval. The key hashes
// only stable identity (message id, from-state, to-state): re-uploading the
// same interval replays identically server-side, while a grown message
// produces a different key carrying only the incremental delta.
func claudeIntervalKey(messageID string, fromState, toState string) string {
	return "claude-code-jsonl:" + adapter.ShortHash(messageID+"\x00"+fromState+"\x00"+toState)
}

// claudeIntervalDelta computes the per-component interval between the
// confirmed baseline and the current snapshot:
//   - fresh message (no baseline): delta = current value, to = current value
//     (explicit zero stays "0", unknown stays null);
//   - both known and current >= baseline: delta = current - baseline;
//   - current < baseline: the whole message is skipped as a diagnostic
//     (regression), baseline untouched;
//   - baseline known, current unknown: component not counted, to keeps the
//     already-counted baseline value (diagnostic);
//   - baseline unknown, current known: the first known value establishes a
//     NEW baseline without being counted (no backfill), so the delta stays
//     nil and to adopts the known value only after the server ACKs the
//     baseline-only interval (rebased = true).
//
// Unknown is never treated as zero.
func claudeIntervalDelta(base *progress.MessageUsageState, cur claudeCodeUsage) (deltas [4]*uint64, to progress.MessageUsageState, diagnostics []string, rebased, regression bool) {
	curVals := cur.components()
	if base == nil {
		to = progress.MessageUsageState{Input: curVals[0], CacheRead: curVals[1], CacheWrite: curVals[2], Output: curVals[3]}
		return curVals, to, nil, false, false
	}
	baseVals := [4]*uint64{base.Input, base.CacheRead, base.CacheWrite, base.Output}
	var toVals [4]*uint64
	for i := 0; i < 4; i++ {
		b, c := baseVals[i], curVals[i]
		name := claudeUsageComponentNames[i]
		switch {
		case b == nil && c == nil:
			toVals[i] = nil
		case b == nil && c != nil:
			diagnostics = append(diagnostics, fmt.Sprintf("%s changed from unknown to known; first known value %d establishes a new baseline and is not counted", name, *c))
			toVals[i] = c
			rebased = true
		case b != nil && c == nil:
			diagnostics = append(diagnostics, fmt.Sprintf("%s changed from known to unknown; counted value unchanged", name))
			toVals[i] = b
		case *c < *b:
			diagnostics = append(diagnostics, fmt.Sprintf("%s decreased from %d to %d; message interval skipped", name, *b, *c))
			regression = true
			toVals[i] = b
		default:
			delta := *c - *b
			deltas[i] = &delta
			toVals[i] = c
		}
	}
	to = progress.MessageUsageState{Input: toVals[0], CacheRead: toVals[1], CacheWrite: toVals[2], Output: toVals[3]}
	return deltas, to, diagnostics, rebased, regression
}

func anyDeltaPositive(deltas [4]*uint64) bool {
	for _, d := range deltas {
		if d != nil && *d > 0 {
			return true
		}
	}
	return false
}

// buildClaudeCodeRecords turns per-message snapshots into interval delta
// records plus pending-state updates. Messages with an unACKed pending
// interval are frozen and skipped. Messages whose last interval the server
// rejected are not re-sent with the same key; growth still exports the
// incremental delta from the unchanged baseline under a new key.
func buildClaudeCodeRecords(messages []claudeCodeMessage, progressByMessage map[string]progress.MessageProgress) ([]adapter.Record, []progress.MessagePendingUpdate, []adapter.LineIssue) {
	var records []adapter.Record
	var updates []progress.MessagePendingUpdate
	var issues []adapter.LineIssue
	addIssue := func(message claudeCodeMessage, reason string) {
		if len(issues) < maxReportedLineIssues {
			issues = append(issues, adapter.LineIssue{File: message.File, Line: message.Line, Reason: reason})
		}
	}
	for _, message := range messages {
		entry := progressByMessage[message.ID]
		if entry.Pending != nil {
			// Frozen until the pending batch is ACKed or rejected.
			continue
		}
		if entry.QuarantinedKey != "" {
			// The last interval fell outside the live consent scope and is
			// held in the recoverable quarantine store. Skipping here breaks
			// the re-export loop: the interval is neither re-emitted nor
			// re-baselined until scope recovery re-pends it and the server
			// ACKs it.
			addIssue(message, fmt.Sprintf("interval %s is quarantined outside the consent scope (%s); waiting for scope recovery before it is re-sent", entry.QuarantinedKey, entry.QuarantinedReason))
			continue
		}
		base := entry.Confirmed
		deltas, to, diagnostics, rebased, regression := claudeIntervalDelta(base, message.Usage)
		for _, diag := range diagnostics {
			addIssue(message, diag)
		}
		if regression {
			continue
		}
		fromState := "0,0,0,0"
		if base != nil {
			fromState = claudeStateString([4]*uint64{base.Input, base.CacheRead, base.CacheWrite, base.Output})
		}
		key := claudeIntervalKey(message.ID, fromState, claudeStateString(messageUsageComponents(to)))
		if entry.RejectedKey != "" && entry.RejectedKey == key {
			addIssue(message, fmt.Sprintf("interval %s was rejected by the server (%s); not resent automatically", key, entry.RejectedCode))
			continue
		}
		// A rebased component (unknown → first known) emits a baseline-only
		// interval: every count is null, nothing is counted, and the new
		// baseline only advances when the server ACKs the batch.
		emit := base == nil || anyDeltaPositive(deltas) || rebased
		if !emit {
			// No growth since the baseline: nothing to upload or re-baseline.
			continue
		}
		records = append(records, claudeCodeRecord(message, key, deltas))
		updates = append(updates, progress.MessagePendingUpdate{
			MessageID: message.ID,
			RecordKey: key,
			To:        &to,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		a := adapter.StringField(records[i], "occurredAt")
		b := adapter.StringField(records[j], "occurredAt")
		if a == b {
			return adapter.StringField(records[i], "recordKey") < adapter.StringField(records[j], "recordKey")
		}
		return a < b
	})
	return records, updates, issues
}

// loadClaudeCodeJSONL is the stateful loader behind Scan, Preview, and
// PrepareExport. With a state directory it loads the confirmed per-message
// baselines (enforcing the progress-integrity rule) and emits incremental
// intervals; without one it emits the full current usage per message.
func Load(opt adapter.Options) (adapter.LoadResult, error) {
	if strings.TrimSpace(opt.StateDir) == "" && strings.TrimSpace(opt.Output) != "" {
		return adapter.LoadResult{}, fmt.Errorf("claude-code-jsonl export requires a state directory (Set --state-dir / TOKTRAIL_HOME) so usage baselines are not double counted")
	}
	messages, issues, quarantined, err := loadClaudeCodeMessages(opt.Input)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	progress := map[string]progress.MessageProgress{}
	if strings.TrimSpace(opt.StateDir) != "" {
		progress, err = loadClaudeMessageProgress(opt.StateDir)
		if err != nil {
			return adapter.LoadResult{}, err
		}
	}
	records, updates, intervalIssues := buildClaudeCodeRecords(messages, progress)
	issues = append(issues, intervalIssues...)
	return adapter.LoadResult{Records: records, Issues: issues, Quarantined: quarantined, MessageUpdates: updates}, nil
}

// claudeCodeRecord builds the interval delta record for one message. The
// recordKey and groupKey derive only from the API message id (never session
// ids, file names, or paths), so copying or renaming log files cannot change
// the uploaded identity.
func claudeCodeRecord(message claudeCodeMessage, key string, deltas [4]*uint64) adapter.Record {
	return adapter.Record{
		"recordKey":      key,
		"groupKey":       "claude-code-message:" + adapter.ShortHash(message.ID),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     message.Timestamp.UTC().Format(time.RFC3339),
		"tool":           claudeCodeTool,
		"model":          message.Model,
		"input":          decimalOrNil(deltas[0]),
		"cacheRead":      decimalOrNil(deltas[1]),
		"cacheWrite":     decimalOrNil(deltas[2]),
		"output":         decimalOrNil(deltas[3]),
		"adapterVersion": claudeCodeAdapterVersion,
		"sourceType":     adapter.ClaudeCodeJSONLSource,
	}
}

func decimalOrNil(v *uint64) any {
	if v == nil {
		return nil
	}
	return fmt.Sprintf("%d", *v)
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{Source: adapter.ClaudeCodeJSONLSource, Description: "Claude Code session JSONL", Load: Load, ValidateCommit: func(stateDir string) error {
		if strings.TrimSpace(stateDir) == "" {
			return nil
		}
		_, err := loadClaudeMessageProgress(stateDir)
		return err
	}}
}
