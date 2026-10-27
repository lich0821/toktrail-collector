package collection

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
)

// WorkBuddy integration test: one explicit workbuddy-jsonl grant over a
// synthetic local WorkBuddy 5.3 projects directory drives the full periodic
// lifecycle — first collection sync, a replay run over an unchanged input,
// and an appended request producing exactly one new record. Everything is
// fixture data inside t.TempDir() and the only server is the loopback fake
// below: no real user data is read and no real network is touched.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// Privacy sentinels embedded in the raw fixture lines. None of this raw
// content may ever appear in an uploaded batch: the WorkBuddy adapter hashes
// identity fields into record keys and reports only usage counters, and the
// sync sender fails closed on records outside the ingest whitelist. The
// session/file sentinels also prove file paths and session ids never leave
// the device.
const (
	workbuddySessionIDSentinel = "wb-private-session-4d81c7"
	workbuddyFileIDSentinel    = "wb-private-file-9e2f"
	workbuddyArgsSentinel      = "WB-PRIVATE-ARGS-b52a90"
	workbuddyCWDSentinel       = "/Users/fixture/wb-private-cwd-1a4b6e"
)

var workbuddyPrivacySentinels = []string{
	workbuddySessionIDSentinel,
	workbuddyFileIDSentinel,
	workbuddyArgsSentinel,
	workbuddyCWDSentinel,
}

// workbuddyFixtureCall describes one synthetic WorkBuddy 5.3 function_call
// request line and the record the collector must derive from it. Every
// rawUsage counter is set explicitly (including the zero cache-creation
// counter) so assertions only ever reference known fields.
type workbuddyFixtureCall struct {
	messageID string
	at        time.Time
	prompt    int64 // rawUsage.prompt_tokens
	cacheHit  int64 // rawUsage.prompt_cache_hit_tokens
	cacheNew  int64 // rawUsage.cache_creation_input_tokens
	output    int64 // rawUsage.completion_tokens
}

// totalTokens mirrors the WorkBuddy 5.3 rawUsage invariant the parser
// enforces: total_tokens = prompt_tokens + completion_tokens (prompt tokens
// include the cached portion).
func (c workbuddyFixtureCall) totalTokens() int64 { return c.prompt + c.output }

// recordInput is the non-cached input the record must report: the WorkBuddy
// adapter subtracts cache read and cache creation from prompt tokens, so
// input + cacheRead + cacheWrite + output = total_tokens per record.
func (c workbuddyFixtureCall) recordInput() int64 { return c.prompt - c.cacheHit - c.cacheNew }

// line renders the call as one WorkBuddy 5.3 session JSONL line: epoch
// millisecond timestamp, providerData.messageId identity and
// providerData.rawUsage counters, plus plausible non-usage payload the
// collector must never upload.
func (c workbuddyFixtureCall) line(t *testing.T) string {
	t.Helper()
	row := map[string]any{
		"type":      "function_call",
		"status":    "completed",
		"timestamp": c.at.UnixMilli(),
		"sessionId": workbuddySessionIDSentinel,
		"providerData": map[string]any{
			"messageId": c.messageID,
			"rawUsage": map[string]any{
				"prompt_tokens":               c.prompt,
				"completion_tokens":           c.output,
				"total_tokens":                c.totalTokens(),
				"prompt_cache_hit_tokens":     c.cacheHit,
				"cache_creation_input_tokens": c.cacheNew,
			},
		},
		"name":      "searchWorkspace",
		"arguments": map[string]any{"query": workbuddyArgsSentinel},
		"cwd":       workbuddyCWDSentinel,
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeWorkBuddySession writes a synthetic WorkBuddy session JSONL file under
// the granted projects directory. Every line ends with a newline because the
// WorkBuddy parser deliberately ignores an unterminated trailing line
// (concurrent-write guard).
func writeWorkBuddySession(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// appendWorkBuddyLine appends one complete (newline-terminated) request line
// so the next periodic run observes it.
func appendWorkBuddyLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// fake ingest server with batch capture
// ---------------------------------------------------------------------------

// workbuddyIngestBatch is one decoded POST /v1/ingest/batches body.
type workbuddyIngestBatch struct {
	BatchID string
	Records []map[string]any
}

// workbuddyCaptureServer mirrors fakeCollectorServer (device self preflight,
// batch ingest, tool-status reports) and additionally keeps every uploaded
// batch body so the test can assert exactly what left the device. Only
// synthetic fixtures are ever sent to it.
type workbuddyCaptureServer struct {
	*httptest.Server
	total   atomic.Int64
	self    atomic.Int64
	ingest  atomic.Int64
	tooling atomic.Int64

	mu      sync.Mutex
	batches []workbuddyIngestBatch
	reports []toolStatusReport
}

func (s *workbuddyCaptureServer) totalRequests() int64      { return s.total.Load() }
func (s *workbuddyCaptureServer) selfRequests() int64       { return s.self.Load() }
func (s *workbuddyCaptureServer) ingestRequests() int64     { return s.ingest.Load() }
func (s *workbuddyCaptureServer) toolStatusRequests() int64 { return s.tooling.Load() }

func (s *workbuddyCaptureServer) capturedBatches() []workbuddyIngestBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]workbuddyIngestBatch, len(s.batches))
	copy(out, s.batches)
	return out
}

func (s *workbuddyCaptureServer) toolStatusReports() []toolStatusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]toolStatusReport, len(s.reports))
	copy(out, s.reports)
	return out
}

func newWorkBuddyCaptureServer(t *testing.T) *workbuddyCaptureServer {
	t.Helper()
	s := &workbuddyCaptureServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handle(t, w, r)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func (s *workbuddyCaptureServer) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	s.total.Add(1)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
		s.self.Add(1)
		writeJSONForTest(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     "app-1",
			"externalSubjectId": "sub-1",
			"deviceName":        "collector",
			"platform":          "darwin",
			"consentRevision":   7,
			"uploadAuthorized":  true,
			"publicAuthorized":  false,
			"revoked":           false,
			"checkedAt":         "2026-10-21T04:00:00Z",
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
		s.ingest.Add(1)
		var body struct {
			BatchID string           `json:"batchId"`
			Records []map[string]any `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("invalid ingest body: %v", err)
		}
		s.mu.Lock()
		s.batches = append(s.batches, workbuddyIngestBatch{BatchID: body.BatchID, Records: body.Records})
		s.mu.Unlock()
		writeJSONForTest(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId":         body.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(body.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      "2026-10-21T04:01:00Z",
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
		s.tooling.Add(1)
		var body struct {
			Statuses []toolStatusReport `json:"statuses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("invalid tool-status body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body.Statuses) == 0 {
			t.Errorf("tool-status POST must carry at least one statuses[] entry")
		}
		s.mu.Lock()
		s.reports = append(s.reports, body.Statuses...)
		s.mu.Unlock()
		writeJSONForTest(w, http.StatusAccepted, map[string]any{"accepted": true})
	default:
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// uploaded-record assertions
// ---------------------------------------------------------------------------

// workbuddyUploadWhitelist mirrors the server ingest record schema the sync
// sender enforces fail-closed before any upload (adapter.RecordIsUploadSafe):
// nothing outside this set may appear in a WorkBuddy batch payload.
var workbuddyUploadWhitelist = map[string]bool{
	"recordKey":      true,
	"groupKey":       true,
	"resetKey":       true,
	"kind":           true,
	"occurredAt":     true,
	"tool":           true,
	"model":          true,
	"input":          true,
	"cacheRead":      true,
	"cacheWrite":     true,
	"output":         true,
	"adapterVersion": true,
	"sourceType":     true,
	"mutationType":   true,
}

// assertWorkBuddyUploadedRecord checks one uploaded record against its
// fixture call: the record contract, the WorkBuddy receipt identity fields,
// the millisecond-timestamp instant, and the rawUsage counter mapping
// (input = prompt − cacheRead − cacheWrite, cacheRead/cacheWrite/output
// verbatim). Only fields with fixture-known values are asserted.
func assertWorkBuddyUploadedRecord(t *testing.T, got map[string]any, call workbuddyFixtureCall) {
	t.Helper()
	record := adapter.Record(got)
	if err := adapter.ValidateRecord(record); err != nil {
		t.Fatalf("uploaded WorkBuddy record violates the record contract: %v (%#v)", err, got)
	}
	if field := adapter.StringField(record, "tool"); field != "WorkBuddy" {
		t.Fatalf("uploaded record tool must be WorkBuddy, got %q", field)
	}
	if field := adapter.StringField(record, "sourceType"); field != adapter.WorkBuddyJSONLSource {
		t.Fatalf("uploaded record sourceType must be %s, got %q", adapter.WorkBuddyJSONLSource, field)
	}
	if field := adapter.StringField(record, "kind"); field != "delta" {
		t.Fatalf("per-request WorkBuddy usage must be a delta record, got kind %q", field)
	}
	if field := adapter.StringField(record, "model"); field != "unknown" {
		t.Fatalf("WorkBuddy records carry no model information and must report unknown, got %q", field)
	}
	if field := adapter.StringField(record, "recordKey"); !strings.HasPrefix(field, "workbuddy-jsonl:") {
		t.Fatalf("WorkBuddy recordKey must use the workbuddy-jsonl: namespace, got %q", field)
	}
	occurred, ok := adapter.OccurredAt(record)
	if !ok || !occurred.Equal(call.at) {
		t.Fatalf("occurredAt must preserve the fixture timestamp %s, got %#v", call.at, got["occurredAt"])
	}
	want := map[string]string{
		"input":      strconv.FormatInt(call.recordInput(), 10),
		"cacheRead":  strconv.FormatInt(call.cacheHit, 10),
		"cacheWrite": strconv.FormatInt(call.cacheNew, 10),
		"output":     strconv.FormatInt(call.output, 10),
	}
	for field, expected := range want {
		if value := adapter.StringField(record, field); value != expected {
			t.Fatalf("record %s must be %s for request %s, got %q (%#v)", field, expected, call.messageID, value, got)
		}
	}
	// Privacy: only whitelisted ingest fields may leave the device.
	for field := range got {
		if !workbuddyUploadWhitelist[field] {
			t.Fatalf("uploaded record carries non-whitelisted field %q: %#v", field, got)
		}
	}
}

// assertNoWorkBuddyRawContent verifies none of the raw fixture content
// (session id, file identity, call arguments, working-directory path) leaked
// into an uploaded batch payload.
func assertNoWorkBuddyRawContent(t *testing.T, batch workbuddyIngestBatch) {
	t.Helper()
	raw, err := json.Marshal(batch.Records)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range workbuddyPrivacySentinels {
		if strings.Contains(string(raw), sentinel) {
			t.Fatalf("raw WorkBuddy content sentinel %q leaked into the uploaded batch", sentinel)
		}
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// End to end over one explicit workbuddy-jsonl grant: the first periodic run
// exports and syncs the two fixture requests and reports a WorkBuddy synced
// receipt; a second run over the unchanged input exports nothing, replays no
// ingest and only reports the empty-scan status; appending exactly one
// request produces exactly one new uploaded record and a second synced
// receipt. Cache totals and the privacy whitelist of the uploaded batches
// are asserted along the way.
func TestRunWorkBuddyJSONLPeriodicSyncLifecycle(t *testing.T) {
	stateDir := t.TempDir()
	server := newWorkBuddyCaptureServer(t)
	bindDevice(t, stateDir, server.URL)

	projects := filepath.Join(t.TempDir(), "workbuddy-projects")
	base := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	callA := workbuddyFixtureCall{messageID: "msg_wb_0001", at: base, prompt: 10, cacheHit: 3, cacheNew: 0, output: 5}
	callB := workbuddyFixtureCall{messageID: "msg_wb_0002", at: base.Add(time.Minute), prompt: 7, cacheHit: 2, cacheNew: 0, output: 4}
	session := writeWorkBuddySession(t, projects, workbuddyFileIDSentinel+".jsonl",
		callA.line(t), callB.line(t))
	enableGrant(t, stateDir, adapter.WorkBuddyJSONLSource, projects)
	now := func() time.Time { return time.Date(2026, 10, 21, 4, 5, 0, 0, time.UTC) }

	// --- First periodic run: initial collection sync. ---
	res, err := Run(t.Context(), Options{StateDir: stateDir, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("first collection must export and sync exactly one batch, got %#v", res)
	}
	if res.ExportedRecords != 2 || res.SyncedRecords != 2 {
		t.Fatalf("first collection must carry both fixture requests, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("the WorkBuddy batch must be fully drained, got %#v", res)
	}
	if len(res.GrantOutcomes) != 1 || res.GrantOutcomes[0].Source != adapter.WorkBuddyJSONLSource ||
		!res.GrantOutcomes[0].Exported || res.GrantOutcomes[0].Records != 2 || res.GrantOutcomes[0].Skipped != "" {
		t.Fatalf("expected one exported WorkBuddy grant outcome, got %#v", res.GrantOutcomes)
	}
	// First-run network: grant-sync self fetch, drain preflight + upload, then
	// the synced receipt (self preflight + tool-status POST).
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("first collection must upload exactly one batch, got %d", got)
	}
	if got := server.selfRequests(); got != 3 {
		t.Fatalf("expected grant-sync, drain and receipt preflights, got %d self requests", got)
	}
	if got := server.toolStatusRequests(); got != 1 {
		t.Fatalf("first collection must send exactly one synced receipt, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{Tool: "WorkBuddy", Status: "synced"}) {
		t.Fatalf("expected a single WorkBuddy synced receipt, got %#v", reports)
	}

	batches := server.capturedBatches()
	if len(batches) != 1 || len(batches[0].Records) != 2 {
		t.Fatalf("first collection must capture one batch with both records, got %#v", batches)
	}
	firstBatch := batches[0]
	assertNoWorkBuddyRawContent(t, firstBatch)
	byOccurrence := map[string]workbuddyFixtureCall{
		callA.at.Format(time.RFC3339Nano): callA,
		callB.at.Format(time.RFC3339Nano): callB,
	}
	uploadedKeys := map[string]bool{}
	cacheReadTotal := 0
	for _, got := range firstBatch.Records {
		occurred, ok := adapter.OccurredAt(adapter.Record(got))
		if !ok {
			t.Fatalf("uploaded record has no parseable occurredAt: %#v", got)
		}
		call, known := byOccurrence[occurred.Format(time.RFC3339Nano)]
		if !known {
			t.Fatalf("uploaded record does not match any fixture timestamp: %#v", got)
		}
		assertWorkBuddyUploadedRecord(t, got, call)
		key := adapter.StringField(adapter.Record(got), "recordKey")
		if uploadedKeys[key] {
			t.Fatalf("recordKey %s uploaded twice in the same batch", key)
		}
		uploadedKeys[key] = true
		cacheRead, ok := adapter.DecimalField(adapter.Record(got), "cacheRead")
		if !ok {
			t.Fatalf("uploaded record cacheRead must be a decimal counter: %#v", got)
		}
		cacheReadTotal += int(cacheRead)
	}
	if cacheReadTotal != 5 {
		t.Fatalf("cache-read total across the first batch must be 3+2=5, got %d", cacheReadTotal)
	}

	// --- Second periodic run: unchanged input, no new upload. ---
	before, ingestBefore := server.totalRequests(), server.ingestRequests()
	res2, err := Run(t.Context(), Options{StateDir: stateDir, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ExportedBatches != 0 || res2.SyncedBatches != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("replay run over the unchanged input must be a no-op, got %#v", res2)
	}
	if len(res2.GrantOutcomes) != 1 || res2.GrantOutcomes[0].Skipped != "no new records since the last confirmed baselines" {
		t.Fatalf("expected the unchanged input to skip with the baseline reason, got %#v", res2.GrantOutcomes)
	}
	if got := server.ingestRequests(); got != ingestBefore {
		t.Fatalf("replay run must not re-upload any batch: %d -> %d", ingestBefore, got)
	}
	// Grant-sync self fetch plus the empty-scan status report (self preflight
	// + tool-status POST), and strictly no ingest replay.
	if n := server.totalRequests(); n != before+3 {
		t.Fatalf("replay run must only add the grant-sync fetch and the empty-scan status report: %d -> %d requests", before, n)
	}
	if got := server.toolStatusRequests(); got != 2 {
		t.Fatalf("replay run must add exactly one tool-status POST, got %d total", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 2 ||
		reports[1] != (toolStatusReport{
			Tool:   "WorkBuddy",
			Status: "no_new_records",
			Detail: "no new records since last confirmed baseline",
		}) {
		t.Fatalf("expected a WorkBuddy no_new_records status after the synced receipt, got %#v", reports)
	}
	if got := len(server.capturedBatches()); got != 1 {
		t.Fatalf("replay run must not capture any new batch, got %d", got)
	}

	// --- Third periodic run: one appended request, exactly one new record. ---
	callC := workbuddyFixtureCall{messageID: "msg_wb_0003", at: base.Add(3 * time.Minute), prompt: 20, cacheHit: 6, cacheNew: 0, output: 9}
	appendWorkBuddyLine(t, session, callC.line(t))

	res3, err := Run(t.Context(), Options{StateDir: stateDir, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if res3.ExportedBatches != 1 || res3.SyncedBatches != 1 || res3.ExportedRecords != 1 || res3.SyncedRecords != 1 {
		t.Fatalf("appending one request must produce exactly one new exported and synced record, got %#v", res3)
	}
	if res3.PendingRemaining != 0 || res3.DrainStopped != "" {
		t.Fatalf("the appended record's batch must be fully drained, got %#v", res3)
	}
	if len(res3.GrantOutcomes) != 1 || !res3.GrantOutcomes[0].Exported || res3.GrantOutcomes[0].Records != 1 {
		t.Fatalf("expected the appended request as the only new grant outcome record, got %#v", res3.GrantOutcomes)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("the appended request must add exactly one new upload, got %d ingest POSTs", got)
	}
	batches = server.capturedBatches()
	if len(batches) != 2 || len(batches[1].Records) != 1 {
		t.Fatalf("the second upload must carry exactly the one new record, got %#v", batches)
	}
	secondBatch := batches[1]
	assertNoWorkBuddyRawContent(t, secondBatch)
	assertWorkBuddyUploadedRecord(t, secondBatch.Records[0], callC)
	if key := adapter.StringField(adapter.Record(secondBatch.Records[0]), "recordKey"); uploadedKeys[key] {
		t.Fatalf("the appended record must be a new identity, but recordKey %s was already uploaded", key)
	}
	if got := server.toolStatusRequests(); got != 3 {
		t.Fatalf("the appended record must add exactly one synced receipt, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 3 ||
		reports[2] != (toolStatusReport{Tool: "WorkBuddy", Status: "synced"}) {
		t.Fatalf("expected a second WorkBuddy synced receipt, got %#v", reports)
	}
}
