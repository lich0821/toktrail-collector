// Package deepseekharness_test pins the external contract of the DeepSeek
// Harness (DSH) session-log adapter (package deepseekharness, provided
// separately): Load and FilterForExport behavior on synthetic fixtures that
// mirror the on-disk format verified against the DSH application bundle.
//
// All fixtures are synthetic and self-contained; these tests never read the
// operator's real ~/.dsh/sessions tree.
//
// Pinned format facts (see the adapter package NOTES for DSH source paths):
//   - Layout: <root>/<project>/<encoded-session-id>/session.vN.jsonl[.zstd];
//     "session.jsonl" is generation 0. Only the numerically highest canonical
//     generation per session directory is read; at equal generation a raw
//     .jsonl wins over .jsonl.zstd. Unambiguously noncanonical names
//     (.jsonl.tmp suffixes, wrong case such as Session.v5.jsonl,
//     session.lock) never contribute records. (Whether leading-zero names
//     like session.v04.jsonl are canonical is unconfirmed and deliberately
//     not pinned here.)
//   - Line 0 is the session header
//     {"type":"session","version":...,"id":...,"isSeeded":bool,...}; later
//     lines are events {"type","seq","time"(epoch ms),"data",...}.
//   - Seeded sessions (forks/resumes) embed an inherited event prefix that
//     ends at the last session/end-seed marker with data.inherited=true.
//     Only events after that marker belong to the seeded session, so the
//     prefix is counted only in the session that owns it. A seeded session
//     with no end-seed marker yields no records (fail closed, never
//     double-count).
//
// Pinned usage semantics (token-meter turn collapsing):
//   - Usage is collapsed per turn, mirroring the DSH token-meter's
//     deriveTurnTokenUsage state machine: a turn is countable only when its
//     full lifecycle is well formed (turn/start ... turn/end, steps opened
//     by step/start, each attempt settled exactly once by assistant/message
//     or assistant/attempt, only a retry-settled attempt reopened by
//     llm/retry-started, matching turn/step tags everywhere). An invalid or
//     incomplete turn (duplicate settlement, llm/retry after a message
//     settlement, missing turn/end at end of file, assistant event without
//     step/start) exports NOTHING for that turn — never a partial or double
//     count — while other turns in the same file still export.
//   - One kind=delta record per attempt-closing event that carries a valid
//     usage sample (assistant/message or assistant/attempt) inside a
//     countable turn. Retries are accounted exactly once per attempt;
//     llm/retry closes an attempt without adding a sample, so it never
//     emits a record and never double-counts.
//   - occurredAt is the attempt's settlement event time (the
//     assistant/message or assistant/attempt event that closed it), not the
//     turn/end time — retried attempts land at their own moments so cutoff
//     filters stay accurate.
//   - A usage sample is data.usage for assistant/message when it is a JSON
//     object (a JSON null falls back to the stream) or the last usage chunk
//     of data.stream, where stream entries are wrapped chunks:
//     {"type":"chunk","chunk":{"type":"usage","usage":{...}}}. Counts must
//     be JSON numbers: inputTokens and outputTokens must be present,
//     non-negative JS safe integers (<= 2^53-1) — string-encoded numbers are
//     invalid. cacheReadTokens / cacheWriteTokens are optional and upload
//     per attempt (after per-sample derivation) as null when absent or
//     unprovable. inputTokens is uncached input;
//     outputTokens includes reasoning tokens (reasoning is never uploaded
//     separately).
//   - Omitted cache buckets are proven from the totalTokens residual
//     (total = input + output + cacheRead + cacheWrite): a zero residual
//     proves every omitted bucket zero ("0", not null); a safe positive
//     residual attributes exactly one omitted bucket when the other is
//     known; both omitted with a positive residual, a missing or unsafe
//     total, or an explicitly invalid present cache value keep the buckets
//     null.
//   - Model attribution is faithful to the event's own record: only
//     assistant/message attributes, from message.source.model, and the
//     recorded value (route alias such as coder/main or explicit id such
//     as deepseek-chat) is kept VERBATIM — never rewritten, trimmed, or
//     allowlisted, and never dropped because the recorded provider is
//     missing (no backend speculation). A missing message/source or an
//     absent/null model is unattributable and reports "unknown";
//     assistant/attempt records are always "unknown" (recorded attempts
//     carry no message source). A model that is present but fails the
//     shared adapter.ValidateModel wire check (the explicit empty string,
//     whitespace-only, control characters, over 128 bytes, non-string
//     JSON) is never silently mapped: the whole turn fails closed and an
//     issue is reported.
//   - Raw lines must be valid UTF-8 BEFORE JSON decoding (Go's decoder
//     silently replaces invalid bytes with U+FFFD, rewriting recorded
//     values): invalid lines are rejected as malformed, and the affected
//     turn fails closed through the lifecycle.
//   - Attempt/retry attribution: a step may legally end with an armed
//     retry that never started (DSH's settled-by-retry → idle transition),
//     so the failed attempt's usage is still attributed; a
//     llm/retry-started after its step ended invalidates the turn.
//   - recordKey is stable across session.vN generation rollover (identity
//     derives from the session id and turn, not the file name) and scoped
//     per session; the same logical events in two different sessions get
//     different keys. groupKey groups one session's records; nil is legal.
//   - Load is a stateless full scan: repeated scans of unchanged input
//     return the same records; opt.Limit does not truncate Load output
//     (Limit applies only to preview pipelines). FilterForExport dedups by
//     recordKey against the export WAL (outbox batches in pending, synced,
//     and reorganized status) and the quarantine store, failing closed when
//     stored content for a known key changed.
package deepseekharness_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/deepseekharness"
)

// Pinned contract constants. adapterVersion is intentionally not pinned:
// only presence (via adapter.ValidateRecord) is contractual.
const (
	dshSourceName = "deepseek-harness"
	dshToolName   = "DeepSeek Harness"
)

const msBase = int64(1698000000000)

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

// fx builds one session file's lines. seq is dense from 0; ms steps 1000 per
// event so every event time is uniquely predictable.
type fx struct {
	lines []string
	seq   int
	ms    int64
}

func newFixture(id string, seeded bool) *fx {
	return &fx{
		lines: []string{fmt.Sprintf(`{"type":"session","version":4,"id":%q,"createdAt":%d,"isSeeded":%t,"delegationDepth":0,"cwd":"/work/demo"}`, id, msBase, seeded)},
		ms:    msBase,
	}
}

func (f *fx) next() (int, int64) {
	s := f.seq
	f.seq++
	m := f.ms
	f.ms += 1000
	return s, m
}

func (f *fx) push(line string) { f.lines = append(f.lines, line) }

// Lines returns a copy of the built lines.
func (f *fx) Lines() []string {
	out := make([]string, len(f.lines))
	copy(out, f.lines)
	return out
}

func (f *fx) turnStart(turn int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"turn/start","seq":%d,"time":%d,"data":{"turn":%d}}`, s, m, turn)
}

// turnEnd appends the turn/end event and returns its time.
func (f *fx) turnEnd(turn int) int64 {
	s, m := f.next()
	f.push(fmt.Sprintf(`{"type":"turn/end","seq":%d,"time":%d,"data":{"turn":%d}}`, s, m, turn))
	return m
}

func (f *fx) userMessage(turn int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"user/message","seq":%d,"time":%d,"data":{"turn":%d,"message":{"role":"user","content":"synthetic"}}}`, s, m, turn)
}

func (f *fx) stepStart(turn, step int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"step/start","seq":%d,"time":%d,"data":{"turn":%d,"step":%d}}`, s, m, turn, step)
}

func (f *fx) stepEnd(turn, step int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"step/end","seq":%d,"time":%d,"data":{"turn":%d,"step":%d}}`, s, m, turn, step)
}

func (f *fx) llmRetry(turn, step int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"llm/retry","seq":%d,"time":%d,"data":{"turn":%d,"step":%d}}`, s, m, turn, step)
}

func (f *fx) llmRetryStarted(turn, step int) string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"llm/retry-started","seq":%d,"time":%d,"data":{"turn":%d,"step":%d}}`, s, m, turn, step)
}

func (f *fx) endSeed() string {
	s, m := f.next()
	return fmt.Sprintf(`{"type":"session/end-seed","seq":%d,"time":%d,"data":{"inherited":true}}`, s, m)
}

func assistantMessageJSON(seq int, ms int64, turn, step int, usage, model string) string {
	return fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":%d,"step":%d,"usage":%s,"message":{"source":{"kind":"model","provider":"deepseek","model":%q}}}}`, seq, ms, turn, step, usage, model)
}

// assistantMessageRawSourceJSON builds an assistant/message event whose
// message.source is the literal rawSource JSON (used for sources that the
// typed builder cannot express: empty provider, non-string model, ...).
func assistantMessageRawSourceJSON(seq int, ms int64, turn, step int, usage, rawSource string) string {
	return fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":%d,"step":%d,"usage":%s,"message":{"source":%s}}}`, seq, ms, turn, step, usage, rawSource)
}

// assistantMessageNoSourceJSON builds an assistant/message event with no
// message key at all.
func assistantMessageNoSourceJSON(seq int, ms int64, turn, step int, usage string) string {
	return fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":%d,"step":%d,"usage":%s}}`, seq, ms, turn, step, usage)
}

// assistantAttemptJSON builds an assistant/attempt event whose stream is a
// list of wrapped chunks; usage samples live in
// {"type":"chunk","chunk":{"type":"usage","usage":{...}}} entries.
func assistantAttemptJSON(seq int, ms int64, turn, step int, usages ...string) string {
	var stream strings.Builder
	stream.WriteString(`[{"type":"chunk","chunk":{"type":"text","text":"synthetic"}}`)
	for _, u := range usages {
		stream.WriteString(`,{"type":"chunk","chunk":{"type":"usage","usage":`)
		stream.WriteString(u)
		stream.WriteString(`}}`)
	}
	stream.WriteString(`]`)
	return fmt.Sprintf(`{"type":"assistant/attempt","seq":%d,"time":%d,"data":{"turn":%d,"step":%d,"stream":%s}}`, seq, ms, turn, step, stream.String())
}

// messageTurn appends one complete successful turn whose single assistant
// message carries `usage`; it returns the assistant/message event time (the
// attempt's settlement time).
func (f *fx) messageTurn(turn int, usage, model string) int64 {
	f.push(f.turnStart(turn))
	f.push(f.userMessage(turn))
	f.push(f.stepStart(turn, 0))
	s, m := f.next()
	f.push(assistantMessageJSON(s, m, turn, 0, usage, model))
	f.push(f.stepEnd(turn, 0))
	f.turnEnd(turn)
	return m
}

// messageDualSampleTurn appends a turn whose assistant/message carries BOTH
// data.usage and a stream with one wrapped usage chunk; data.usage must win.
func (f *fx) messageDualSampleTurn(turn int, dataUsage, streamUsage, model string) int64 {
	f.push(f.turnStart(turn))
	f.push(f.userMessage(turn))
	f.push(f.stepStart(turn, 0))
	s, m := f.next()
	f.push(fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":%d,"step":0,"usage":%s,"stream":[{"type":"chunk","chunk":{"type":"usage","usage":%s}}],"message":{"source":{"kind":"model","provider":"deepseek","model":%q}}}}`, s, m, turn, dataUsage, streamUsage, model))
	f.push(f.stepEnd(turn, 0))
	f.turnEnd(turn)
	return m
}

// attemptLastChunkTurn appends a turn whose single assistant/attempt stream
// carries several wrapped usage chunks; the LAST chunk must win.
func (f *fx) attemptLastChunkTurn(turn int, chunks ...string) int64 {
	f.push(f.turnStart(turn))
	f.push(f.userMessage(turn))
	f.push(f.stepStart(turn, 0))
	s, m := f.next()
	f.push(assistantAttemptJSON(s, m, turn, 0, chunks...))
	f.push(f.stepEnd(turn, 0))
	f.turnEnd(turn)
	return m
}

// retryTurn appends one turn whose first attempt fails and is retried: the
// assistant/attempt carries attemptUsage, then llm/retry and
// llm/retry-started open a fresh attempt that succeeds with finalUsage. It
// returns the attempt and final settlement event times.
func (f *fx) retryTurn(turn int, attemptUsage, finalUsage, model string) (int64, int64) {
	f.push(f.turnStart(turn))
	f.push(f.userMessage(turn))
	f.push(f.stepStart(turn, 0))
	s, m := f.next()
	f.push(assistantAttemptJSON(s, m, turn, 0, attemptUsage))
	f.push(f.llmRetry(turn, 0))
	f.push(f.llmRetryStarted(turn, 0))
	s2, m2 := f.next()
	f.push(assistantMessageJSON(s2, m2, turn, 0, finalUsage, model))
	f.push(f.stepEnd(turn, 0))
	f.turnEnd(turn)
	return m, m2
}

// Usage sample literals. inputs are unique per scenario so records can be
// matched by input.
const (
	usageFull               = `{"inputTokens":100,"outputTokens":40,"cacheReadTokens":10,"cacheWriteTokens":20,"reasoningTokens":5,"totalTokens":170}`
	usageNoCache            = `{"inputTokens":250,"outputTokens":60}`
	usageNegative           = `{"inputTokens":-100,"outputTokens":40}`
	usageMissingOut         = `{"inputTokens":300}`
	usageUnsafeLarge        = `{"inputTokens":9007199254740993,"outputTokens":1}` // 2^53+1: not a JS safe integer
	usageMaxSafe            = `{"inputTokens":9007199254740991,"outputTokens":1}` // 2^53-1: largest safe integer
	usageAttemptA           = `{"inputTokens":30,"outputTokens":5}`
	usageRetryFinal         = `{"inputTokens":120,"outputTokens":45,"cacheReadTokens":10,"cacheWriteTokens":20,"totalTokens":195}`
	usageDualData           = `{"inputTokens":130,"outputTokens":13}`
	usageDualStream         = `{"inputTokens":999,"outputTokens":99}`
	usageChunkFirst         = `{"inputTokens":333,"outputTokens":3}`
	usageChunkLast          = `{"inputTokens":33,"outputTokens":3}`
	usageNullFallbackStream = `{"inputTokens":210,"outputTokens":21}`
	usageStringInput        = `{"inputTokens":"280","outputTokens":28}`
	usageB500               = `{"inputTokens":500,"outputTokens":80,"cacheReadTokens":1,"cacheWriteTokens":2,"totalTokens":583}`
	usageB400               = `{"inputTokens":400,"outputTokens":70}`
	usageC700               = `{"inputTokens":700,"outputTokens":70}`
	usageC800               = `{"inputTokens":800,"outputTokens":80}`
	usageD310               = `{"inputTokens":310,"outputTokens":41}`
	usageD320               = `{"inputTokens":320,"outputTokens":42}`
	usageSeed900            = `{"inputTokens":900,"outputTokens":90}`
	usageSeed905            = `{"inputTokens":905,"outputTokens":90}`
	usageSeed910            = `{"inputTokens":910,"outputTokens":91}`
	usageSeed915            = `{"inputTokens":915,"outputTokens":91}`
	usageSeed950            = `{"inputTokens":950,"outputTokens":95}`
	usageW333               = `{"inputTokens":333,"outputTokens":43}`
	usageW444               = `{"inputTokens":444,"outputTokens":44}`
	usageW555               = `{"inputTokens":555,"outputTokens":55}`
	usageW666               = `{"inputTokens":666,"outputTokens":66}`

	// Cache-bucket derivation from the totalTokens residual
	// (total = input + output + cacheRead + cacheWrite).
	usageOmitZero  = `{"inputTokens":220,"outputTokens":22,"totalTokens":242}`
	usageOmitRead  = `{"inputTokens":230,"outputTokens":23,"cacheWriteTokens":4,"totalTokens":261}`
	usageOmitWrite = `{"inputTokens":240,"outputTokens":24,"cacheReadTokens":6,"totalTokens":276}`
	usageOmitBoth  = `{"inputTokens":260,"outputTokens":26,"totalTokens":300}`
	usageBadCache  = `{"inputTokens":270,"outputTokens":27,"cacheReadTokens":-1,"totalTokens":350}`

	// Lifecycle fail-closed scenario literals.
	usageLCFirst  = `{"inputTokens":110,"outputTokens":11}`
	usageLCDup    = `{"inputTokens":111,"outputTokens":11}`
	usageLCAfter  = `{"inputTokens":140,"outputTokens":14}`
	usageLCUnend  = `{"inputTokens":160,"outputTokens":16}`
	usageLCNoStep = `{"inputTokens":180,"outputTokens":18}`
	usageLCTail   = `{"inputTokens":190,"outputTokens":19}`
	// Both attempts of the retried lifecycle turn carry cache buckets, so
	// the collapsed record must sum them (1+10 and 2+20).
	usageLCAttemptCache = `{"inputTokens":30,"outputTokens":5,"cacheReadTokens":1,"cacheWriteTokens":2,"totalTokens":38}`

	// Model-attribution scenario literals (unique inputs per turn).
	usageModA = `{"inputTokens":101,"outputTokens":10}`
	usageModB = `{"inputTokens":102,"outputTokens":10}`
	usageModC = `{"inputTokens":103,"outputTokens":10}`
	usageModD = `{"inputTokens":104,"outputTokens":10}`
	usageModE = `{"inputTokens":105,"outputTokens":10}`
	usageModF = `{"inputTokens":106,"outputTokens":10}`
	usageModG = `{"inputTokens":107,"outputTokens":10}`
	usageModH = `{"inputTokens":108,"outputTokens":10}`
	usageModI = `{"inputTokens":109,"outputTokens":10}`
	// Armed-retry step attribution (turn with a never-started retry).
	usageArmedRetry = `{"inputTokens":40,"outputTokens":4}`
)

// ---------------------------------------------------------------------------
// File writers
// ---------------------------------------------------------------------------

func sessionFile(root, project, sessionDir, name string) string {
	return filepath.Join(root, project, sessionDir, name)
}

func writePlain(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func zstdFrame(t *testing.T, lines []string) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	out := enc.EncodeAll([]byte(strings.Join(lines, "\n")+"\n"), nil)
	if err := enc.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return out
}

// writeZstd writes one .zstd file whose content is several independent
// concatenated frames, mirroring DSH's append-one-frame-per-batch layout.
func writeZstd(t *testing.T, path string, parts ...[]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	var body []byte
	for _, part := range parts {
		body = append(body, zstdFrame(t, part)...)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// Load / filter drivers and shared assertions
// ---------------------------------------------------------------------------

func loadAll(t *testing.T, root string) []adapter.Record {
	t.Helper()
	res, err := deepseekharness.Adapter().Load(adapter.Options{Source: dshSourceName, Input: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertCommonInvariants(t, res.Records)
	return res.Records
}

// assertCommonInvariants checks the contract every loaded record must hold.
func assertCommonInvariants(t *testing.T, recs []adapter.Record) {
	t.Helper()
	keys := map[string]bool{}
	for _, rec := range recs {
		if err := adapter.ValidateRecord(rec); err != nil {
			t.Errorf("record fails validation: %v (%v)", err, rec)
		}
		key := adapter.StringField(rec, "recordKey")
		if key == "" {
			t.Fatalf("record without recordKey: %v", rec)
		}
		if keys[key] {
			t.Fatalf("duplicate recordKey %s", key)
		}
		keys[key] = true
		if got := adapter.StringField(rec, "kind"); got != "delta" {
			t.Errorf("kind = %q, want delta", got)
		}
		if rec["resetKey"] != nil {
			t.Errorf("resetKey = %v, want nil (per-turn collapsed deltas)", rec["resetKey"])
		}
		if got := adapter.StringField(rec, "sourceType"); got != dshSourceName {
			t.Errorf("sourceType = %q, want %q", got, dshSourceName)
		}
		if got := adapter.StringField(rec, "tool"); got != dshToolName {
			t.Errorf("tool = %q, want %q", got, dshToolName)
		}
		if got := adapter.StringField(rec, "model"); got == "" {
			t.Errorf("model is empty: %v", rec)
		}
		// Privacy: every record must project onto the upload whitelist
		// unchanged (no message bodies, no extra keys, public models
		// only).
		if !adapter.RecordIsUploadSafe(rec) {
			t.Errorf("record is not upload-safe: %v", rec)
		}
	}
}

type wantRec struct {
	input      string
	output     string
	cacheRead  any // string or nil
	cacheWrite any // string or nil
	unixSec    int64
}

// assertRecords matches records to wants by input (inputs are unique per
// scenario) and checks each want's fields exactly.
func assertRecords(t *testing.T, recs []adapter.Record, want []wantRec) {
	t.Helper()
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d", len(recs), len(want))
	}
	byInput := map[string]adapter.Record{}
	for _, rec := range recs {
		in := adapter.StringField(rec, "input")
		if in == "" {
			t.Fatalf("record without input: %v", rec)
		}
		if _, dup := byInput[in]; dup {
			t.Fatalf("two records share input %s", in)
		}
		byInput[in] = rec
	}
	for _, w := range want {
		rec, ok := byInput[w.input]
		if !ok {
			t.Fatalf("missing record with input %s", w.input)
		}
		if got := adapter.StringField(rec, "output"); got != w.output {
			t.Errorf("input %s: output = %q, want %q", w.input, got, w.output)
		}
		if got := rec["cacheRead"]; got != w.cacheRead {
			t.Errorf("input %s: cacheRead = %v, want %v", w.input, got, w.cacheRead)
		}
		if got := rec["cacheWrite"]; got != w.cacheWrite {
			t.Errorf("input %s: cacheWrite = %v, want %v", w.input, got, w.cacheWrite)
		}
		ts, err := time.Parse(time.RFC3339, adapter.StringField(rec, "occurredAt"))
		if err != nil {
			t.Errorf("input %s: occurredAt %q: %v", w.input, adapter.StringField(rec, "occurredAt"), err)
			continue
		}
		if ts.Unix() != w.unixSec {
			t.Errorf("input %s: occurredAt unix = %d, want %d", w.input, ts.Unix(), w.unixSec)
		}
	}
}

func recordKeyOf(t *testing.T, rec adapter.Record) string {
	t.Helper()
	key := adapter.StringField(rec, "recordKey")
	if key == "" {
		t.Fatalf("record without recordKey: %v", rec)
	}
	return key
}

func canonicalOf(t *testing.T, rec adapter.Record) string {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return string(b)
}

func recordWithInput(t *testing.T, recs []adapter.Record, input string) adapter.Record {
	t.Helper()
	for _, rec := range recs {
		if adapter.StringField(rec, "input") == input {
			return rec
		}
	}
	t.Fatalf("no record with input %s", input)
	return nil
}

func hasInput(recs []adapter.Record, input string) bool {
	for _, rec := range recs {
		if adapter.StringField(rec, "input") == input {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDeepSeekHarnessAdapterContract(t *testing.T) {
	ad := deepseekharness.Adapter()
	if ad.Source != dshSourceName {
		t.Fatalf("Source = %q, want %q", ad.Source, dshSourceName)
	}
	if strings.TrimSpace(ad.Description) == "" {
		t.Fatal("Description is empty")
	}
	if ad.Load == nil {
		t.Fatal("Load is nil")
	}
	if ad.FilterForExport == nil {
		t.Fatal("FilterForExport is nil")
	}
}

func TestLoadEmptyRootYieldsNoRecords(t *testing.T) {
	root := t.TempDir()
	recs := loadAll(t, root)
	if len(recs) != 0 {
		t.Fatalf("got %d records from empty root, want 0", len(recs))
	}
}

// TestLoadPlainAndZstdGenerationsAndIgnoredNames covers:
//   - plain and zstd files in the same tree,
//   - multi-frame (appended batch) zstd decoding,
//   - highest-generation selection (v4 shadows v3; identity survives),
//   - raw winning over .zstd at the same generation,
//   - unambiguously noncanonical file names contributing nothing,
//   - deterministic repeat scans and Load ignoring opt.Limit.
func TestLoadPlainAndZstdGenerationsAndIgnoredNames(t *testing.T) {
	root := t.TempDir()

	const idA = "aaaaaaaa-0000-4000-8000-000000000001"

	// Session A starts at generation 3 (zstd) with one message turn.
	fxA := newFixture(idA, false)
	msA0 := fxA.messageTurn(0, usageFull, "deepseek-chat")
	writeZstd(t, sessionFile(root, "--demo--", idA, "session.v3.jsonl.zstd"), fxA.Lines())

	first := loadAll(t, root)
	assertRecords(t, first, []wantRec{{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(msA0).Unix()}})
	recA0First := recordWithInput(t, first, "100")

	// Session A rolls to generation 4 (plain) holding the full history plus
	// one new turn. The v3 file stays on disk but must never be read again.
	fxA2 := newFixture(idA, false)
	fxA2.messageTurn(0, usageFull, "deepseek-chat")
	msA1 := fxA2.messageTurn(1, usageNoCache, "deepseek-reasoner")
	writePlain(t, sessionFile(root, "--demo--", idA, "session.v4.jsonl"), fxA2.Lines())

	// Session B: same generation as raw and .zstd with different content;
	// the raw file must win.
	const idB = "bbbbbbbb-0000-4000-8000-000000000002"
	fxBraw := newFixture(idB, false)
	msB := fxBraw.messageTurn(0, usageB500, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", "session-"+idB, "session.v4.jsonl"), fxBraw.Lines())
	fxBz := newFixture(idB, false)
	fxBz.messageTurn(0, usageB400, "deepseek-chat")
	writeZstd(t, sessionFile(root, "--demo--", "session-"+idB, "session.v4.jsonl.zstd"), fxBz.Lines())

	// Session C: only unambiguously noncanonical names — nothing may be
	// read. (session.v04.jsonl is deliberately not tested: whether
	// leading-zero generation names are canonical is unconfirmed.)
	const idC = "cccccccc-0000-4000-8000-000000000003"
	fxC2 := newFixture(idC, false)
	fxC2.messageTurn(0, usageC700, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", idC, "session.v4.jsonl.tmp"), fxC2.Lines())
	fxC3 := newFixture(idC, false)
	fxC3.messageTurn(0, usageC800, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", idC, "Session.v5.jsonl"), fxC3.Lines())
	if err := os.WriteFile(sessionFile(root, "--demo--", idC, "session.lock"), []byte(`{"pid":123}`), 0o644); err != nil {
		t.Fatalf("write session.lock: %v", err)
	}

	// Session D (no-cwd project dir): zstd written as two appended frames,
	// one batch per frame.
	const idD = "dddddddd-0000-4000-8000-000000000004"
	fxD1 := newFixture(idD, false)
	msD0 := fxD1.messageTurn(0, usageD310, "deepseek-chat")
	fxD2 := newFixture(idD, false)
	fxD2.messageTurn(0, usageD310, "deepseek-chat") // rebuild identical prefix
	msD1 := fxD2.messageTurn(1, usageD320, "deepseek-chat")
	writeZstd(t,
		sessionFile(root, "_no-cwd", idD, "session.v4.jsonl.zstd"),
		fxD1.Lines(), fxD2.Lines()[len(fxD1.Lines()):],
	)

	recs := loadAll(t, root)
	assertRecords(t, recs, []wantRec{
		{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(msA0).Unix()},
		{input: "250", output: "60", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msA1).Unix()},
		{input: "500", output: "80", cacheRead: "1", cacheWrite: "2", unixSec: time.UnixMilli(msB).Unix()},
		{input: "310", output: "41", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msD0).Unix()},
		{input: "320", output: "42", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msD1).Unix()},
	})
	for _, absent := range []string{"400", "700", "800"} {
		if hasInput(recs, absent) {
			t.Errorf("record with input %s must not exist (wrong file was read)", absent)
		}
	}

	// Generation rollover keeps record identity: the turn-0 record loaded
	// from v4 must equal the one loaded earlier from v3.
	recA0 := recordWithInput(t, recs, "100")
	if recordKeyOf(t, recA0) != recordKeyOf(t, recA0First) {
		t.Errorf("recordKey changed across generation rollover: %q -> %q", recordKeyOf(t, recA0First), recordKeyOf(t, recA0))
	}
	if canonicalOf(t, recA0) != canonicalOf(t, recA0First) {
		t.Errorf("record content changed across generation rollover")
	}
	if adapter.StringField(recA0, "groupKey") != adapter.StringField(recA0First, "groupKey") {
		t.Errorf("groupKey changed across generation rollover")
	}

	// Records of one session share groupKey (nil is a legal groupKey and
	// is shared as nil; cross-session distinctness is not pinned).
	if adapter.StringField(recA0, "groupKey") != adapter.StringField(recordWithInput(t, recs, "250"), "groupKey") {
		t.Errorf("records of one session must share groupKey")
	}

	// Repeat scans are deterministic.
	again := loadAll(t, root)
	if len(again) != len(recs) {
		t.Fatalf("repeat scan got %d records, want %d", len(again), len(recs))
	}
	for i := range recs {
		if canonicalOf(t, recs[i]) != canonicalOf(t, again[i]) {
			t.Fatalf("repeat scan is not deterministic at index %d", i)
		}
	}

	// Load must not truncate on opt.Limit (Limit applies only to preview).
	limited, err := deepseekharness.Adapter().Load(adapter.Options{Source: dshSourceName, Input: root, Limit: 1})
	if err != nil {
		t.Fatalf("Load with Limit: %v", err)
	}
	if len(limited.Records) != len(recs) {
		t.Fatalf("Load with Limit=1 returned %d records, want all %d", len(limited.Records), len(recs))
	}
}

// TestLoadSeededPrefix covers seeded-session deduplication: the inherited
// prefix (through the last session/end-seed marker) belongs to the source
// session and must never be counted again in the seeded copy.
func TestLoadSeededPrefix(t *testing.T) {
	root := t.TempDir()

	const id1 = "11111111-0000-4000-8000-000000000011"
	const id2 = "22222222-0000-4000-8000-000000000022"
	const id3 = "33333333-0000-4000-8000-000000000033"
	const id4 = "44444444-0000-4000-8000-000000000044"
	const id5 = "55555555-0000-4000-8000-000000000055"

	// Source session s1 owns turn 0.
	fx1 := newFixture(id1, false)
	fx1.messageTurn(0, usageFull, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id1, "session.v4.jsonl"), fx1.Lines())

	// Seeded s2 physically contains s1's events (the inherited prefix),
	// ends the seed, then adds its own turn.
	fx2 := newFixture(id2, true)
	fx2.messageTurn(0, usageFull, "deepseek-chat") // inherited prefix
	fx2.push(fx2.endSeed())
	ms2 := fx2.messageTurn(1, usageSeed900, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", "session-"+id2, "session.v4.jsonl"), fx2.Lines())

	// Seeded s3 has no end-seed marker: fail closed, no records at all.
	fx3 := newFixture(id3, true)
	fx3.messageTurn(0, usageSeed950, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id3, "session.v4.jsonl"), fx3.Lines())

	// Seeded s4 contains two end-seed markers: only events after the LAST
	// marker belong to it.
	fx4 := newFixture(id4, true)
	fx4.messageTurn(0, usageSeed905, "deepseek-chat")
	fx4.push(fx4.endSeed())
	fx4.messageTurn(1, usageSeed910, "deepseek-chat")
	fx4.push(fx4.endSeed())
	ms4 := fx4.messageTurn(2, usageSeed915, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id4, "session.v4.jsonl"), fx4.Lines())

	// Unseeded s5 replays s1's exact events under a different session id:
	// both sessions count, with distinct recordKeys.
	fx5 := newFixture(id5, false)
	fx5.messageTurn(0, usageFull, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id5, "session.v4.jsonl"), fx5.Lines())

	recs := loadAll(t, root)
	// s1 (input 100) + s2 own turn (900) + s4 last turn (915) + s5 (100).
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	var hundreds []adapter.Record
	for _, rec := range recs {
		if adapter.StringField(rec, "input") == "100" {
			hundreds = append(hundreds, rec)
		}
	}
	if len(hundreds) != 2 {
		t.Fatalf("got %d records with input 100, want 2 (s1 and s5)", len(hundreds))
	}
	if recordKeyOf(t, hundreds[0]) == recordKeyOf(t, hundreds[1]) {
		t.Fatal("same logical events in different sessions must get different recordKeys")
	}
	if !hasInput(recs, "900") {
		t.Error("seeded session's own turn (input 900) is missing")
	}
	if !hasInput(recs, "915") {
		t.Error("events after the LAST end-seed marker (input 915) are missing")
	}
	for _, absent := range []string{"905", "910", "950"} {
		if hasInput(recs, absent) {
			t.Errorf("inherited prefix event (input %s) must not be counted in the seeded copy", absent)
		}
	}
	seedOwn := recordWithInput(t, recs, "900")
	if got := adapter.StringField(seedOwn, "output"); got != "90" {
		t.Errorf("seeded own turn output = %q, want 90", got)
	}
	if ts, err := time.Parse(time.RFC3339, adapter.StringField(seedOwn, "occurredAt")); err != nil || ts.Unix() != time.UnixMilli(ms2).Unix() {
		t.Errorf("seeded own turn occurredAt mismatch (err %v)", err)
	}
	lastMarker := recordWithInput(t, recs, "915")
	if ts, err := time.Parse(time.RFC3339, adapter.StringField(lastMarker, "occurredAt")); err != nil || ts.Unix() != time.UnixMilli(ms4).Unix() {
		t.Errorf("post-last-marker turn occurredAt mismatch (err %v)", err)
	}
}

// TestLoadUsageValidationAndAttemptAccounting covers invalid usage samples
// (never partial records), safe-integer bounds, string-encoded numbers,
// per-attempt retry settlement without double counting, data.usage winning
// over the stream, null data.usage falling back to the stream, and the last
// stream usage chunk winning for attempts.
func TestLoadUsageValidationAndAttemptAccounting(t *testing.T) {
	root := t.TempDir()
	const id = "eeeeeeee-0000-4000-8000-00000000000e"

	fx := newFixture(id, false)
	ms0 := fx.messageTurn(0, usageFull, "deepseek-chat")    // valid
	fx.messageTurn(1, usageNegative, "deepseek-chat")       // negative input: invalid turn
	fx.messageTurn(2, usageMissingOut, "deepseek-chat")     // missing output: invalid turn
	fx.messageTurn(3, usageUnsafeLarge, "deepseek-chat")    // 2^53+1: unsafe: invalid turn
	ms4 := fx.messageTurn(4, usageMaxSafe, "deepseek-chat") // 2^53-1: valid
	// Retried turn: the failed attempt and the final attempt each settle
	// at their own event time.
	msA5, msF5 := fx.retryTurn(5, usageAttemptA, usageRetryFinal, "deepseek-chat")
	fx.messageTurn(6, `null`, "deepseek-chat") // null usage, no stream: invalid turn
	// data.usage wins over the wrapped stream usage chunk.
	ms7 := fx.messageDualSampleTurn(7, usageDualData, usageDualStream, "deepseek-chat")
	// The last wrapped usage chunk of an attempt wins.
	ms8 := fx.attemptLastChunkTurn(8, usageChunkFirst, usageChunkLast)
	// A JSON-null data.usage falls back to the wrapped stream chunk.
	ms9 := fx.messageDualSampleTurn(9, `null`, usageNullFallbackStream, "deepseek-chat")
	// String-encoded counts are invalid (DSH accepts numbers only).
	fx.messageTurn(10, usageStringInput, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	recs := loadAll(t, root)
	assertRecords(t, recs, []wantRec{
		{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(ms0).Unix()},
		{input: "9007199254740991", output: "1", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms4).Unix()},
		// The retried attempt settles per attempt: one record each, at
		// each settlement event time; llm/retry itself adds nothing.
		{input: "30", output: "5", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msA5).Unix()},
		{input: "120", output: "45", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(msF5).Unix()},
		{input: "130", output: "13", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms7).Unix()},
		{input: "33", output: "3", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms8).Unix()},
		{input: "210", output: "21", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms9).Unix()},
	})
	if got := adapter.StringField(recordWithInput(t, recs, "100"), "model"); got != "deepseek-chat" {
		t.Fatalf("message model = %q, want deepseek-chat", got)
	}
	if got := adapter.StringField(recordWithInput(t, recs, "30"), "model"); got != "unknown" {
		t.Fatalf("attempt model = %q, want unknown", got)
	}
	for _, absent := range []string{"-100", "300", "9007199254740993", "999", "280"} {
		if hasInput(recs, absent) {
			t.Errorf("invalid or shadowed usage sample (input %s) must produce no record", absent)
		}
	}
}

// TestLoadModelAttributionFaithful pins historical model attribution: only
// assistant/message attributes, from message.source.model, and the recorded
// value (alias or explicit id, whitespace padding included) survives
// VERBATIM — no allowlist, no trimming, no rewriting, and no dropping a
// recorded model because its provider is missing. A missing message/source
// or an absent/null model reports "unknown" while still counting the
// tokens; a present-but-illegal model (the explicit empty string,
// whitespace-only, control characters, over 128 bytes, non-string JSON) is
// never silently mapped and fails the whole turn closed with a reported
// issue.
func TestLoadModelAttributionFaithful(t *testing.T) {
	root := t.TempDir()
	const id = "a1b2c3d4-0000-4000-8000-0000000000f1"

	fx := newFixture(id, false)
	msA := fx.messageTurn(0, usageModA, "coder")         // route alias, verbatim
	msB := fx.messageTurn(1, usageModB, "deepseek-chat") // explicit id, verbatim
	// A whitespace-padded but otherwise valid recorded value is kept
	// verbatim too: the shared wire validation never rewrites valid raws.
	msC := fx.messageTurn(2, usageModC, "  main  ")
	// assistant/attempt carries no message source in recorded history.
	msD := fx.attemptLastChunkTurn(3, usageModD)

	msgTurnRawSource := func(turn int, usage, rawSource string) int64 {
		fx.push(fx.turnStart(turn))
		fx.push(fx.userMessage(turn))
		fx.push(fx.stepStart(turn, 0))
		s, m := fx.next()
		fx.push(assistantMessageRawSourceJSON(s, m, turn, 0, usage, rawSource))
		fx.push(fx.stepEnd(turn, 0))
		fx.turnEnd(turn)
		return m
	}
	msgTurnNoSource := func(turn int, usage string) int64 {
		fx.push(fx.turnStart(turn))
		fx.push(fx.userMessage(turn))
		fx.push(fx.stepStart(turn, 0))
		s, m := fx.next()
		fx.push(assistantMessageNoSourceJSON(s, m, turn, 0, usage))
		fx.push(fx.stepEnd(turn, 0))
		fx.turnEnd(turn)
		return m
	}
	// A recorded model survives even when the provider is missing: the
	// model is the event's own record, and no backend is speculated.
	msE := msgTurnRawSource(4, usageModE, `{"kind":"model","provider":"","model":"deepseek-chat"}`)
	msG := msgTurnRawSource(6, usageModG, `{"kind":"model","provider":"llm","model":null}`)
	msH := msgTurnNoSource(7, usageModH)

	// Present-but-illegal models — including the explicit empty string,
	// which is a present value, not a missing one: the whole turn must
	// fail closed with a reported issue — never a silent "unknown" and
	// never a rewritten value.
	msgTurnRawSource(5, usageModF, `{"kind":"model","provider":"llm","model":""}`)   // explicit empty string
	fx.messageTurn(8, usageModI, "bad\nmodel")                                       // control character
	fx.messageTurn(9, usageModI, strings.Repeat("m", 129))                           // over 128 bytes
	msgTurnRawSource(10, usageModI, `{"kind":"model","provider":"llm","model":123}`) // non-string
	fx.messageTurn(11, usageModI, "   ")                                             // whitespace-only
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	res, err := deepseekharness.Adapter().Load(adapter.Options{Source: dshSourceName, Input: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertCommonInvariants(t, res.Records)
	recs := res.Records

	assertRecords(t, recs, []wantRec{
		{input: "101", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msA).Unix()},
		{input: "102", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msB).Unix()},
		{input: "103", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msC).Unix()},
		{input: "104", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msD).Unix()},
		{input: "105", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msE).Unix()},
		{input: "107", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msG).Unix()},
		{input: "108", output: "10", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(msH).Unix()},
	})
	wantModels := map[string]string{
		"101": "coder",
		"102": "deepseek-chat",
		"103": "  main  ",      // verbatim: padding is part of the recorded value
		"104": "unknown",       // assistant/attempt never carries a source
		"105": "deepseek-chat", // provider missing: the recorded model is still kept
		"107": "unknown",       // null model: nothing recorded to attribute
		"108": "unknown",       // no message at all
	}
	for input, want := range wantModels {
		rec := recordWithInput(t, recs, input)
		if got := rec["model"]; got != want {
			t.Errorf("input %s: model = %#v, want %#v (verbatim)", input, got, want)
		}
	}
	// The illegal-model turns (inputs 106 and 109) must be gone entirely.
	for _, absent := range []string{"106", "109"} {
		if hasInput(recs, absent) {
			t.Errorf("a turn with an illegal recorded model (input %s) must export nothing", absent)
		}
	}
	// ...and the failures must be reported, not silent.
	invalidModel := 0
	missingModel := 0
	for _, issue := range res.Issues {
		if strings.Contains(issue.Reason, "model reported unknown") {
			missingModel++
		}
		if strings.Contains(issue.Reason, "invalid recorded model") || strings.Contains(issue.Reason, "recorded model is not a JSON string") {
			invalidModel++
		}
	}
	if missingModel != 3 {
		t.Errorf("got %d missing-model diagnostics, want 3; issues: %v", missingModel, res.Issues)
	}
	if invalidModel != 5 {
		t.Errorf("got %d invalid-model issues, want 5 (one per illegal turn); issues: %v", invalidModel, res.Issues)
	}
	if res.Quarantined == 0 {
		t.Error("illegal recorded models must be quarantined/reported, not silently mapped")
	}
}

// TestLoadRejectsInvalidUTF8Lines pins the pre-decode UTF-8 guard: Go's
// JSON decoder silently replaces invalid bytes with U+FFFD, which would
// rewrite a recorded model under a passing validation. Such lines are
// rejected as malformed before decoding, and the affected turn fails
// closed through the lifecycle.
func TestLoadRejectsInvalidUTF8Lines(t *testing.T) {
	root := t.TempDir()
	const id = "b2c3d4e5-0000-4000-8000-0000000000f2"

	fx := newFixture(id, false)
	ms0 := fx.messageTurn(0, usageFull, "coder")
	// Turn 1: the assistant/message line embeds raw invalid UTF-8 bytes in
	// the model string. The line is structurally JSON apart from those
	// bytes, so only the UTF-8 guard can catch it before the decoder
	// rewrites the model to contain U+FFFD.
	fx.push(fx.turnStart(1))
	fx.push(fx.userMessage(1))
	fx.push(fx.stepStart(1, 0))
	s, m := fx.next()
	fx.push(fmt.Sprintf(`{"type":"assistant/message","seq":%d,"time":%d,"data":{"turn":1,"step":0,"usage":{"inputTokens":120,"outputTokens":12},"message":{"source":{"kind":"model","provider":"llm","model":"bad`+"\xff\xfe"+`model"}}}}`, s, m))
	fx.push(fx.stepEnd(1, 0))
	fx.turnEnd(1)
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	res, err := deepseekharness.Adapter().Load(adapter.Options{Source: dshSourceName, Input: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertCommonInvariants(t, res.Records)
	// Only the well-formed turn survives; the corrupted turn's settlement
	// never happened, so its step/end invalidates the whole turn.
	assertRecords(t, res.Records, []wantRec{
		{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(ms0).Unix()},
	})
	if hasInput(res.Records, "120") {
		t.Error("the turn whose settlement line had invalid UTF-8 must export nothing")
	}
	// The rejection must be reported...
	found := false
	for _, issue := range res.Issues {
		if strings.Contains(issue.Reason, "invalid UTF-8") {
			found = true
		}
	}
	if !found {
		t.Errorf("invalid-UTF-8 line was not reported; issues: %v", res.Issues)
	}
	// ...and no model may have been silently rewritten to U+FFFD.
	for _, rec := range res.Records {
		if model, _ := rec["model"].(string); strings.ContainsRune(model, '�') {
			t.Errorf("model was silently rewritten to contain U+FFFD: %q", model)
		}
	}
}

// TestLoadStepEndAfterArmedRetry pins attempt/retry attribution for a step
// whose final attempt failed and whose armed retry never started: DSH's
// deriveTurnTokenUsage ends such steps legally (settled-by-retry → idle),
// so the failed attempt's usage must still be attributed. A
// llm/retry-started that arrives after its step already ended must
// invalidate the turn instead of reopening the attempt.
func TestLoadStepEndAfterArmedRetry(t *testing.T) {
	root := t.TempDir()
	const id = "c3d4e5f6-0000-4000-8000-0000000000f3"

	fx := newFixture(id, false)
	// Turn 0: attempt fails, retry is armed, the step ends without the
	// retry ever starting, and the turn completes. The failed attempt is
	// the only usage and must be attributed at its own settlement time.
	fx.push(fx.turnStart(0))
	fx.push(fx.userMessage(0))
	fx.push(fx.stepStart(0, 0))
	s, m := fx.next()
	fx.push(assistantAttemptJSON(s, m, 0, 0, usageArmedRetry))
	fx.push(fx.llmRetry(0, 0))
	fx.push(fx.stepEnd(0, 0))
	fx.turnEnd(0)
	// Turn 1: the same shape, but llm/retry-started arrives AFTER step/end.
	// The step is already closed, so the turn must fail closed.
	fx.push(fx.turnStart(1))
	fx.push(fx.userMessage(1))
	fx.push(fx.stepStart(1, 0))
	s2, m2 := fx.next()
	fx.push(assistantAttemptJSON(s2, m2, 1, 0, usageArmedRetry))
	fx.push(fx.llmRetry(1, 0))
	fx.push(fx.stepEnd(1, 0))
	fx.push(fx.llmRetryStarted(1, 0))
	fx.turnEnd(1)
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	recs := loadAll(t, root)
	assertRecords(t, recs, []wantRec{
		{input: "40", output: "4", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(m).Unix()},
	})
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1 (only the armed-retry turn exports)", len(recs))
	}
	if got := recs[0]["model"]; got != "unknown" {
		t.Errorf("attempt record model = %#v, want unknown", got)
	}
}

// TestLoadCacheDerivationFromTotal covers the omitted⟺zero encoding of DSH
// cache buckets: omitted buckets are proven from the totalTokens residual
// (total = input + output + cacheRead + cacheWrite), while unprovable or
// explicitly invalid buckets stay null.
func TestLoadCacheDerivationFromTotal(t *testing.T) {
	root := t.TempDir()
	const id = "99999999-0000-4000-8000-000000000099"

	fx := newFixture(id, false)
	ms0 := fx.messageTurn(0, usageOmitZero, "deepseek-chat")  // residual 0: omitted = zero
	ms1 := fx.messageTurn(1, usageOmitRead, "deepseek-chat")  // cacheRead derived from residual
	ms2 := fx.messageTurn(2, usageOmitWrite, "deepseek-chat") // cacheWrite derived from residual
	ms3 := fx.messageTurn(3, usageOmitBoth, "deepseek-chat")  // both omitted, residual > 0: unprovable
	fx.messageTurn(4, usageBadCache, "deepseek-chat")         // invalid present value rejects the sample
	ms5 := fx.messageTurn(5, `{"inputTokens":0,"outputTokens":0,"cacheReadTokens":0,"totalTokens":100}`, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	recs := loadAll(t, root)
	assertRecords(t, recs, []wantRec{
		{input: "220", output: "22", cacheRead: "0", cacheWrite: "0", unixSec: time.UnixMilli(ms0).Unix()},
		{input: "230", output: "23", cacheRead: "4", cacheWrite: "4", unixSec: time.UnixMilli(ms1).Unix()},
		{input: "240", output: "24", cacheRead: "6", cacheWrite: "6", unixSec: time.UnixMilli(ms2).Unix()},
		{input: "260", output: "26", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms3).Unix()},
		{input: "0", output: "0", cacheRead: "0", cacheWrite: "100", unixSec: time.UnixMilli(ms5).Unix()},
	})
}

// TestLoadLifecycleFailClosed covers the token-meter lifecycle state
// machine: an invalid or incomplete turn exports nothing at all, while
// neighboring well-formed turns in the same file still export.
func TestLoadLifecycleFailClosed(t *testing.T) {
	root := t.TempDir()
	const id = "llllllll-0000-4000-8000-00000000000l"

	fx := newFixture(id, false)

	// Turn 0: well-formed reference turn (must export).
	ms0 := fx.messageTurn(0, usageFull, "deepseek-chat")

	// Turn 1: duplicate settlement — a second assistant/message settles
	// the same attempt again. The whole turn must not export.
	fx.push(fx.turnStart(1))
	fx.push(fx.userMessage(1))
	fx.push(fx.stepStart(1, 0))
	s, m := fx.next()
	fx.push(assistantMessageJSON(s, m, 1, 0, usageLCFirst, "deepseek-chat"))
	s, m = fx.next()
	fx.push(assistantMessageJSON(s, m, 1, 0, usageLCDup, "deepseek-chat"))
	fx.push(fx.stepEnd(1, 0))
	fx.turnEnd(1)

	// Turn 2: llm/retry after a message settlement — only a retry-settled
	// attempt may be reopened. The whole turn must not export.
	fx.push(fx.turnStart(2))
	fx.push(fx.userMessage(2))
	fx.push(fx.stepStart(2, 0))
	s, m = fx.next()
	fx.push(assistantMessageJSON(s, m, 2, 0, usageLCAfter, "deepseek-chat"))
	fx.push(fx.llmRetry(2, 0))
	fx.push(fx.stepEnd(2, 0))
	fx.turnEnd(2)

	// Turn 3: incomplete turn at end of log — no turn/end event, so the
	// turn never became countable. (Deliberately the last turn.)
	fx.push(fx.turnStart(3))
	fx.push(fx.userMessage(3))
	fx.push(fx.stepStart(3, 0))
	s, m = fx.next()
	fx.push(assistantMessageJSON(s, m, 3, 0, usageLCUnend, "deepseek-chat"))
	fx.push(fx.stepEnd(3, 0))

	// Turn 4: assistant/message without step/start — no step context.
	fx.push(fx.turnStart(4))
	fx.push(fx.userMessage(4))
	s, m = fx.next()
	fx.push(assistantMessageJSON(s, m, 4, 0, usageLCNoStep, "deepseek-chat"))
	fx.turnEnd(4)

	// Turn 5: empty turn (no steps, no attempts) — nothing to report.
	fx.push(fx.turnStart(5))
	fx.turnEnd(5)

	// Turn 6: well-formed retried turn; both attempts settle, each at its
	// own settlement event time with its own cache buckets.
	msA6, msF6 := fx.retryTurn(6, usageLCAttemptCache, usageRetryFinal, "deepseek-chat")

	// Turn 7: well-formed tail turn (must export).
	ms7 := fx.messageTurn(7, usageLCTail, "deepseek-chat")

	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	recs := loadAll(t, root)
	assertRecords(t, recs, []wantRec{
		{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(ms0).Unix()},
		{input: "30", output: "5", cacheRead: "1", cacheWrite: "2", unixSec: time.UnixMilli(msA6).Unix()},
		{input: "120", output: "45", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(msF6).Unix()},
		{input: "190", output: "19", cacheRead: nil, cacheWrite: nil, unixSec: time.UnixMilli(ms7).Unix()},
	})
	for _, absent := range []string{"110", "111", "140", "160", "180"} {
		if hasInput(recs, absent) {
			t.Errorf("invalid or incomplete turn (input %s) must export nothing", absent)
		}
	}
}

// TestLoadTornTailPlainJSONL covers crash recovery: an incomplete final line
// (no trailing newline, truncated JSON) yields no record — the truncated
// turn is incomplete and fails closed — and repairing it surfaces the
// record on the next scan.
func TestLoadTornTailPlainJSONL(t *testing.T) {
	root := t.TempDir()
	const id = "tttttttt-0000-4000-8000-0000000000tt"

	fx := newFixture(id, false)
	ms0 := fx.messageTurn(0, usageFull, "deepseek-chat")
	fx.messageTurn(1, usageNoCache, "deepseek-reasoner")
	lines := fx.Lines()
	path := sessionFile(root, "--demo--", id, "session.v4.jsonl")

	// Tear the final line: drop its last bytes and the trailing newline.
	torn := lines[len(lines)-1]
	if len(torn) < 24 {
		t.Fatalf("fixture line too short to tear: %q", torn)
	}
	body := strings.Join(lines[:len(lines)-1], "\n") + "\n" + torn[:len(torn)-12]
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write torn file: %v", err)
	}

	first := loadAll(t, root)
	assertRecords(t, first, []wantRec{{input: "100", output: "40", cacheRead: "10", cacheWrite: "20", unixSec: time.UnixMilli(ms0).Unix()}})

	// Repair the file; the completed turn now yields its record.
	writePlain(t, path, lines)
	second := loadAll(t, root)
	if len(second) != 2 {
		t.Fatalf("after repair got %d records, want 2", len(second))
	}
	if !hasInput(second, "250") {
		t.Error("repaired turn's record (input 250) is missing")
	}
}

// TestFilterForExportFirstRepeatAppendAndRollover is the WAL acceptance
// scenario: a repeatedly scanned source with stable recordKeys must neither
// regenerate already-exported batches nor miss later records. It walks
// first run, repeat run, append, generation rollover, quarantine, foreign
// sources, and the fail-closed immutability check.
func TestFilterForExportFirstRepeatAppendAndRollover(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()
	const id = "wwwwwwww-0000-4000-8000-0000000000ww"

	fx := newFixture(id, false)
	fx.messageTurn(0, usageFull, "deepseek-chat")
	fx.messageTurn(1, usageNoCache, "deepseek-reasoner")
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	filter := func(recs []adapter.Record) []adapter.Record {
		t.Helper()
		fresh, err := deepseekharness.Adapter().FilterForExport(adapter.Options{Source: dshSourceName, StateDir: stateDir}, recs)
		if err != nil {
			t.Fatalf("FilterForExport: %v", err)
		}
		return fresh
	}

	// First run: everything is fresh, including with no state dir at all.
	loaded := loadAll(t, root)
	if len(loaded) != 2 {
		t.Fatalf("first load got %d records, want 2", len(loaded))
	}
	if fresh := filter(loaded); len(fresh) != 2 {
		t.Fatalf("first filter got %d fresh, want 2", len(fresh))
	}
	noState, err := deepseekharness.Adapter().FilterForExport(adapter.Options{Source: dshSourceName, StateDir: ""}, loaded)
	if err != nil {
		t.Fatalf("FilterForExport without state dir: %v", err)
	}
	if len(noState) != 2 {
		t.Fatalf("filter without state dir got %d records, want 2", len(noState))
	}

	// Repeat run: a pending batch already carries both records.
	writeBatchFile(t, stateDir, "b1", dshSourceName, loaded)
	loaded = loadAll(t, root)
	if fresh := filter(loaded); len(fresh) != 0 {
		t.Fatalf("repeat run with pending batch got %d fresh, want 0", len(fresh))
	}

	// ...and a synced batch dedups identically.
	markSynced(t, stateDir, "b1", len(loaded))
	loaded = loadAll(t, root)
	if fresh := filter(loaded); len(fresh) != 0 {
		t.Fatalf("repeat run with synced batch got %d fresh, want 0", len(fresh))
	}

	// Append run: a new turn adds exactly one new record.
	fx.messageTurn(2, usageW333, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())
	loaded = loadAll(t, root)
	if len(loaded) != 3 {
		t.Fatalf("append load got %d records, want 3", len(loaded))
	}
	fresh := filter(loaded)
	if len(fresh) != 1 || adapter.StringField(fresh[0], "input") != "333" {
		t.Fatalf("append filter got %v, want exactly the new input-333 record", fresh)
	}
	rec333 := fresh[0]

	// A reorganized (terminal) batch also keeps its records known.
	writeBatchFile(t, stateDir, "b2", dshSourceName, []adapter.Record{rec333})
	if err := outbox.New(stateDir).MarkReorganized("b2", "b2-next", 1, time.Now().UTC()); err != nil {
		t.Fatalf("mark reorganized: %v", err)
	}
	loaded = loadAll(t, root)
	if fresh := filter(loaded); len(fresh) != 0 {
		t.Fatalf("after reorganized batch got %d fresh, want 0", len(fresh))
	}

	// Generation rollover: v5 (zstd, two appended frames) holds the full
	// history plus one new turn. Old recordKeys stay known; only the new
	// record is fresh — the whole history is never re-exported.
	fx5 := newFixture(id, false)
	fx5.messageTurn(0, usageFull, "deepseek-chat")
	fx5.messageTurn(1, usageNoCache, "deepseek-reasoner")
	fx5.messageTurn(2, usageW333, "deepseek-chat")
	part1 := fx5.Lines()
	fx5.messageTurn(3, usageW444, "deepseek-chat")
	writeZstd(t, sessionFile(root, "--demo--", id, "session.v5.jsonl.zstd"), part1, fx5.Lines()[len(part1):])
	loaded = loadAll(t, root)
	if len(loaded) != 4 {
		t.Fatalf("rollover load got %d records, want 4", len(loaded))
	}
	fresh = filter(loaded)
	if len(fresh) != 1 || adapter.StringField(fresh[0], "input") != "444" {
		t.Fatalf("rollover filter got %v, want exactly the new input-444 record", len(fresh))
	}
	writeBatchFile(t, stateDir, "b3", dshSourceName, fresh)

	// Quarantined records are known too.
	fx5.messageTurn(4, usageW555, "deepseek-chat")
	writeZstd(t, sessionFile(root, "--demo--", id, "session.v5.jsonl.zstd"), fx5.Lines())
	loaded = loadAll(t, root)
	if len(loaded) != 5 {
		t.Fatalf("after v5 extension got %d records, want 5", len(loaded))
	}
	fresh = filter(loaded)
	if len(fresh) != 1 || adapter.StringField(fresh[0], "input") != "555" {
		t.Fatalf("quarantine setup filter got %d fresh, want the new 555 record", len(fresh))
	}
	rec555 := fresh[0]
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
		Source:        dshSourceName,
		RecordKey:     recordKeyOf(t, rec555),
		Record:        json.RawMessage(canonicalOf(t, rec555)),
		OriginBatchID: "b1",
		Reason:        quarantine.ReasonBeforeHistoryFrom,
		QuarantinedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatalf("quarantine append: %v", err)
	}
	loaded = loadAll(t, root)
	if fresh := filter(loaded); len(fresh) != 0 {
		t.Fatalf("quarantined record re-emitted: %d fresh, want 0", len(fresh))
	}

	// Batches from other sources must be ignored, not merged.
	fx5.messageTurn(5, usageW666, "deepseek-chat")
	writeZstd(t, sessionFile(root, "--demo--", id, "session.v5.jsonl.zstd"), fx5.Lines())
	loaded = loadAll(t, root)
	fresh = filter(loaded)
	if len(fresh) != 1 || adapter.StringField(fresh[0], "input") != "666" {
		t.Fatalf("foreign-source setup filter got %d fresh, want the new 666 record", len(fresh))
	}
	rec666 := fresh[0]
	writeBatchFile(t, stateDir, "b4", "codex-jsonl", []adapter.Record{rec666})
	loaded = loadAll(t, root)
	if fresh := filter(loaded); len(fresh) != 1 || adapter.StringField(fresh[0], "input") != "666" {
		t.Fatalf("foreign-source batch filtered our record: got %d fresh, want the 666 record", len(fresh))
	}

	// Fail closed: a stored record whose content changed under a known key
	// is an error, never a silent overwrite.
	tampered := map[string]any{}
	for k, v := range recordWithInput(t, loaded, "100") {
		tampered[k] = v
	}
	tampered["output"] = "41"
	writeBatchFile(t, stateDir, "b3", dshSourceName, []adapter.Record{tampered})
	if _, err := deepseekharness.Adapter().FilterForExport(adapter.Options{Source: dshSourceName, StateDir: stateDir}, loaded); err == nil {
		t.Fatal("FilterForExport accepted a changed record under a known key; want fail-closed error")
	}
}

// TestFilterForExportFailsClosedOnModelDrift pins immutable history with no
// old-version compatibility branch (there are no real users to upgrade): a
// stored record whose model differs from the freshly loaded record under a
// known key is content drift and must fail closed.
func TestFilterForExportFailsClosedOnModelDrift(t *testing.T) {
	root := t.TempDir()
	stateDir := t.TempDir()
	const id = "mmmmmmmm-0000-4000-8000-00000000000m"

	fx := newFixture(id, false)
	fx.messageTurn(0, usageFull, "deepseek-chat")
	writePlain(t, sessionFile(root, "--demo--", id, "session.v4.jsonl"), fx.Lines())

	loaded := loadAll(t, root)
	if len(loaded) != 1 || adapter.StringField(loaded[0], "model") != "deepseek-chat" {
		t.Fatalf("fixture did not produce the model record: %#v", loaded)
	}
	old := make(adapter.Record, len(loaded[0]))
	for k, v := range loaded[0] {
		old[k] = v
	}
	old["model"] = "unknown"
	writeBatchFile(t, stateDir, "old-model-batch", dshSourceName, []adapter.Record{old})

	if _, err := deepseekharness.Adapter().FilterForExport(adapter.Options{Source: dshSourceName, StateDir: stateDir}, loaded); err == nil {
		t.Fatal("FilterForExport accepted model drift under a known key; want fail-closed error")
	}
}

// ---------------------------------------------------------------------------
// State-dir helpers (outbox / quarantine fixtures)
// ---------------------------------------------------------------------------

// writeBatchFile writes a batch file into stateDir and registers it as a
// pending outbox batch for the given source.
func writeBatchFile(t *testing.T, stateDir, batchID, source string, records []adapter.Record) string {
	t.Helper()
	type batchFile struct {
		BatchID string            `json:"batchId"`
		Records []json.RawMessage `json:"records"`
	}
	bf := batchFile{BatchID: batchID}
	for _, rec := range records {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		bf.Records = append(bf.Records, raw)
	}
	body, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	path := filepath.Join(stateDir, batchID+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write batch file: %v", err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		Source:      source,
		RecordCount: len(records),
	}); err != nil {
		t.Fatalf("add pending batch: %v", err)
	}
	return path
}

func markSynced(t *testing.T, stateDir, batchID string, count int) {
	t.Helper()
	if err := outbox.New(stateDir).MarkSynced(outbox.Receipt{
		BatchID:         batchID,
		Status:          "accepted",
		AcceptedRecords: count,
		ReceivedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("mark synced: %v", err)
	}
}
