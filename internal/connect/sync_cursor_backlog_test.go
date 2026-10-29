package connect

// Cursor regressions for the shared Sync orchestration (the flow the
// resync CLI drives with a nil AccountTools list):
//
//   - backlog drain passes never repeat the forced cursor round
//     (ForceResync is a one-round recovery semantic; repeating it would
//     re-pull and re-emit the whole history every pass and a large
//     cursor backlog could never converge);
//   - a failed cursor round is never swallowed when no explicit account
//     tool list names it;
//   - a permit that exists in ANY status (login_expired included) under
//     a grant that allows Cursor owes completion;
//   - a cursor the server never authorized, or a device with no permit,
//     skipping normally is NOT an incompleteness;
//   - a round that skipped rows without a stable upstream event id left
//     usage uncounted and is never a complete success.
//
// Everything is synthetic: tempdir state, one httptest TokTrail double
// and injected cursor auth/verify/pull fakes. No real Cursor state,
// credential or account is ever read.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/identity"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/cursor/usage"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
)

const (
	cursorBacklogAccount = "user_backlogtest"
	cursorBacklogToken   = "synthetic-backlog-access-token"
	cursorBacklogSession = "synthetic-backlog-session-token"
	cursorBacklogSource  = "cursor-src-backlog-1"
	cursorBacklogDevice  = "dev-backlog-1"
)

var cursorBacklogNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// cursorBacklogMock fakes the TokTrail server a cursor-wired Sync run
// talks to: the device self view (grant protocol + account sources),
// cursor source-batch ingest, device batch ingest, tool-status reports
// and the capability probe. Everything else (grant acks, ...) gets a
// permissive 200.
type cursorBacklogMock struct {
	*httptest.Server

	mu struct {
		sync.Mutex
		allowedTools  []string
		source        *protocol.Source
		srcBatchPosts int
		toolStatus    int
		selfCalls     int
		devicePosts   int
		flipped       bool
		// Scope-move knobs: once triggered, the self view serves
		// consentRevision 6 instead of 5, modeling a server-side scope
		// change mid-run. Triggers are evaluated on self requests:
		// bumpAfterSelfCalls fires once that many self calls happened;
		// bumpAfterDevicePosts fires once at least that many device
		// batch uploads happened (deterministic across the phases).
		bumpAfterSelfCalls  int
		bumpAfterDevicePost int
	}
}

func startCursorBacklogMock(t *testing.T) *cursorBacklogMock {
	t.Helper()
	m := &cursorBacklogMock{}
	m.mu.source = &protocol.Source{
		SourceInstanceID: cursorBacklogSource,
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     1,
	}
	writeJSON := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			m.mu.Lock()
			m.mu.selfCalls++
			tools, src := m.mu.allowedTools, m.mu.source
			if (m.mu.bumpAfterSelfCalls > 0 && m.mu.selfCalls >= m.mu.bumpAfterSelfCalls) ||
				(m.mu.bumpAfterDevicePost > 0 && m.mu.devicePosts >= m.mu.bumpAfterDevicePost) {
				m.mu.flipped = true
			}
			revision := int64(5)
			if m.mu.flipped {
				revision = 6
			}
			m.mu.Unlock()
			device := map[string]any{
				"deviceId":             cursorBacklogDevice,
				"applicationId":        "app-backlog",
				"externalSubjectId":    "sub-backlog",
				"consentRevision":      revision,
				"uploadAuthorized":     true,
				"revoked":              false,
				"paused":               false,
				"grantProtocolVersion": 1,
				"allowedTools":         tools,
			}
			if src != nil {
				device["accountSources"] = []protocol.Source{*src}
			}
			writeJSON(w, http.StatusOK, map[string]any{"device": device})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/source-batches":
			var batch struct {
				BatchID string            `json:"batchId"`
				Records []json.RawMessage `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("invalid source-batch body: %v", err)
				writeJSON(w, http.StatusBadRequest, map[string]any{})
				return
			}
			m.mu.Lock()
			m.mu.srcBatchPosts++
			m.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(batch.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorBacklogNow.Format(time.RFC3339Nano),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			var body struct {
				BatchID string           `json:"batchId"`
				Records []map[string]any `json:"records"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.mu.devicePosts++
			m.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      cursorBacklogNow.Format(time.RFC3339Nano),
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/tool-status":
			m.mu.Lock()
			m.mu.toolStatus++
			m.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities":
			writeJSON(w, http.StatusOK, map[string]any{"features": []string{"device-grants", "account-sources"}})
		default:
			writeJSON(w, http.StatusOK, map[string]any{})
		}
	}))
	t.Cleanup(m.Server.Close)
	return m
}

func (m *cursorBacklogMock) setAllowedTools(tools []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.allowedTools = tools
}

// bumpRevisionAfterSelfCalls makes every self request from the n-th one
// on serve consentRevision 6.
func (m *cursorBacklogMock) bumpRevisionAfterSelfCalls(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.bumpAfterSelfCalls = n
}

// bumpRevisionAfterDevicePosts makes every self request observe
// consentRevision 6 once n device batch uploads have happened.
func (m *cursorBacklogMock) bumpRevisionAfterDevicePosts(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.bumpAfterDevicePost = n
}

func (m *cursorBacklogMock) srcBatchPosts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.srcBatchPosts
}

// cursorBacklogAuth / cursorBacklogVerify / cursorBacklogPull are the
// synthetic cursor-side collaborators. The pull fake records every
// requested window so tests can prove the forced full-window pull ran
// exactly once and backlog passes fell back to the overlap window.
type cursorBacklogAuth struct {
	fail bool
}

func (a *cursorBacklogAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	if a.fail {
		return auth.Credential{}, fmt.Errorf("synthetic credential read failure")
	}
	return auth.Credential{AccessToken: cursorBacklogToken, Source: "test-fixture"}, nil
}

type cursorBacklogVerify struct {
	fail bool
}

func (v *cursorBacklogVerify) verify(ctx context.Context, accessToken string) (api.VerifyResult, error) {
	if v.fail {
		return api.VerifyResult{}, fmt.Errorf("synthetic verification failure")
	}
	if accessToken != cursorBacklogToken {
		return api.VerifyResult{}, fmt.Errorf("unexpected credential handed to verify")
	}
	return api.VerifyResult{AccountID: cursorBacklogAccount, SessionToken: cursorBacklogSession}, nil
}

type cursorBacklogPull struct {
	events []api.UsageEvent
	calls  []struct{ from, to time.Time }
}

func (p *cursorBacklogPull) pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	if sessionToken != cursorBacklogSession {
		return nil, fmt.Errorf("pull called with an unverified session token")
	}
	p.calls = append(p.calls, struct{ from, to time.Time }{from, to})
	var out []api.UsageEvent
	for _, ev := range p.events {
		ts := time.UnixMilli(ev.TimestampMS)
		if (from.IsZero() || !ts.Before(from)) && ts.Before(to) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// cursorBacklogEvents returns two synthetic events well inside the fixed
// clock (visible to a full-window pull from the zero time, invisible to
// the one-hour overlap pull a normal round uses).
func cursorBacklogEvents() []api.UsageEvent {
	mk := func(id string, age time.Duration, in, out int64) api.UsageEvent {
		zero := int64(0)
		return api.UsageEvent{
			UsageEventID: id, ConversationID: "conv-" + id,
			TimestampMS: cursorBacklogNow.Add(-age).UnixMilli(), Model: "cursor-claude-4.5",
			InputTokens: &in, OutputTokens: &out, CacheReadTokens: &zero, CacheWriteTokens: &zero,
		}
	}
	return []api.UsageEvent{
		mk("usage-event-alpha", 2*time.Hour, 120, 30),
		mk("usage-event-beta", 90*time.Minute, 80, 20),
	}
}

// seedCursorBacklogState writes a bound device state matching the mock.
func seedCursorBacklogState(t *testing.T, dir, serverURL string) {
	t.Helper()
	if err := statedir.New(dir).Save(statedir.DeviceState{
		DeviceID:          cursorBacklogDevice,
		DeviceSecret:      "synthetic-device-secret-backlog",
		ServerURL:         serverURL,
		ApplicationID:     "app-backlog",
		ExternalSubjectID: "sub-backlog",
		ConsentRevision:   5,
		UploadAuthorized:  true,
	}); err != nil {
		t.Fatalf("write device state: %v", err)
	}
}

// seedCursorBacklogPermit writes a cursor permit for the synthetic
// account; status selects the permit state under test.
func seedCursorBacklogPermit(t *testing.T, dir string, status cursorsource.Status) {
	t.Helper()
	if err := cursorsource.New(dir).Save(cursorsource.License{
		SourceInstanceID: cursorBacklogSource,
		SourceType:       cursorsource.SourceType,
		AccountMatchID:   identity.MatchAccount(cursorBacklogAccount),
		Status:           status,
		ConfirmedAt:      cursorBacklogNow,
		NextRevision:     1,
		FenceVersion:     1,
	}); err != nil {
		t.Fatalf("write cursor permit: %v", err)
	}
}

// seedCursorBacklogBatch persists one hand-built pending cursor batch
// (fence 1, the synthetic source) with n distinct records.
func seedCursorBacklogBatch(t *testing.T, dir, batchID string, n int) {
	t.Helper()
	records := make([]protocol.Event, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, protocol.Event{
			EventKey:       protocol.EventKeyPrefix + strings.Repeat("0", 63) + strconv.Itoa(i+1),
			Revision:       1,
			Kind:           "event",
			OccurredAt:     cursorBacklogNow.Format(time.RFC3339Nano),
			Tool:           protocol.Tool,
			AdapterVersion: usage.AdapterVersion,
			SourceType:     protocol.SourceType,
		})
	}
	batch := protocol.Batch{BatchID: batchID, SourceInstanceID: cursorBacklogSource, Records: records}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatalf("encode seed batch: %v", err)
	}
	if _, err := cursoroutbox.New(dir).AddBatch(batch, 1, encoded); err != nil {
		t.Fatalf("seed pending cursor batch: %v", err)
	}
}

// runCursorBacklogSync drives one Sync exactly the way the resync CLI
// does: cursor wiring, NO explicit account-tool list.
func runCursorBacklogSync(t *testing.T, dir, serverURL string, a *cursorBacklogAuth, v *cursorBacklogVerify, p *cursorBacklogPull, maxBatches int) (SyncResult, error) {
	t.Helper()
	return Sync(context.Background(), SyncOptions{
		StateDir:  dir,
		ServerURL: serverURL,
		Now:       func() time.Time { return cursorBacklogNow },
		Cursor: &cursorsync.Options{
			Auth:       a,
			Verify:     v.verify,
			Pull:       p.pull,
			Now:        func() time.Time { return cursorBacklogNow },
			MaxBatches: maxBatches,
		},
	})
}

// TestSyncBacklogPassesDoNotRepeatForcedCursor verifies the backlog fix:
// the initial pass forces one full-window cursor recovery round (re-
// emitting the unchanged events), and the backlog passes that drain the
// remaining cursor batches neither re-pull the full window nor re-emit
// anything — the backlog converges instead of growing forever.
func TestSyncBacklogPassesDoNotRepeatForcedCursor(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	// Warm the event ledger exactly like a previous collection leaves
	// it: the reinstall scenario re-covers events the local cache already
	// knows, so the forced initial round must RE-EMIT them (a normal
	// round would skip them as unchanged).
	warmCache, err := usage.LoadCache(dir)
	if err != nil {
		t.Fatalf("load cursor cache: %v", err)
	}
	_, staged, _, err := usage.Normalize(cursorBacklogEvents(), identity.SubjectNamespace("app-backlog", "sub-backlog"), cursorBacklogAccount, 1, warmCache)
	if err != nil {
		t.Fatalf("warm cursor cache: %v", err)
	}
	warmCache.Apply(staged)
	if err := warmCache.Commit(); err != nil {
		t.Fatalf("commit cursor cache: %v", err)
	}
	// Three pending cursor batches against a per-round drain bound of
	// two: the initial pass cannot drain them all, so at least one
	// backlog pass must run.
	seedCursorBacklogBatch(t, dir, "cbl-seed-1", 1)
	seedCursorBacklogBatch(t, dir, "cbl-seed-2", 1)
	seedCursorBacklogBatch(t, dir, "cbl-seed-3", 1)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err != nil {
		t.Fatalf("sync with cursor backlog: %v", err)
	}
	if len(res.Incomplete) != 0 {
		t.Fatalf("a converged cursor backlog is complete, got %v", res.Incomplete)
	}
	// The initial pass forced the recovery round: full-window pull, both
	// unchanged events re-emitted.
	if !res.Collection.Cursor.Ran || res.Collection.Cursor.ReemittedRecords != 2 {
		t.Fatalf("the initial pass must force the cursor recovery round: %+v", res.Collection.Cursor)
	}
	if len(pull.calls) < 2 || !pull.calls[0].from.IsZero() {
		t.Fatalf("the initial pass must pull the full window, got %+v", pull.calls)
	}
	// The backlog passes drain the remainder WITHOUT re-forcing: no
	// re-emission, overlap windows only, and the backlog converges.
	if res.Backlog.Passes < 1 || res.Backlog.CursorPendingRemaining != 0 {
		t.Fatalf("the cursor backlog must converge through backlog passes: %+v", res.Backlog)
	}
	if res.Backlog.Result.Cursor.ReemittedRecords != 0 {
		t.Fatalf("backlog passes must not re-emit unchanged events (ForceResync repeated), got %d", res.Backlog.Result.Cursor.ReemittedRecords)
	}
	for _, call := range pull.calls[1:] {
		if call.from.IsZero() {
			t.Fatal("a backlog pass must not repeat the forced full-window pull")
		}
		if !call.from.Equal(cursorBacklogNow.Add(-cursorsync.PullOverlap)) {
			t.Fatalf("a backlog pass must use the overlap window, got from=%s", call.from)
		}
	}
	if got := mock.srcBatchPosts(); got != 4 {
		t.Fatalf("expected 4 cursor batch uploads (3 seeded + 1 re-emitted), got %d", got)
	}
}

// TestSyncCursorFailureNotSwallowedWithoutAccountTools verifies the
// nil-AccountTools path (the resync CLI): a cursor round that fails is
// reported as incomplete, never as a complete sync.
func TestSyncCursorFailureNotSwallowedWithoutAccountTools(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{fail: true}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a failed cursor round must make the sync incomplete, got %v", err)
	}
	if !res.Collection.Cursor.Ran {
		t.Fatalf("the cursor round ran and failed: %+v", res.Collection.Cursor)
	}
	if len(pull.calls) != 0 {
		t.Fatal("a failed verification must not pull")
	}
	if !containsReason(res.Incomplete, "account source Cursor failed") {
		t.Fatalf("the cursor failure must be named, got %v", res.Incomplete)
	}
}

// TestSyncCursorExpiredPermitIsIncompleteNotMasked verifies that a
// permit which exists in a non-collectable status (login_expired) still
// owes completion when the grant allows Cursor: the skip is reported,
// not masked as success. The current authorization needs the data.
func TestSyncCursorExpiredPermitIsIncompleteNotMasked(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusLoginExpired)
	pull := &cursorBacklogPull{events: cursorBacklogEvents()}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("a login-expired cursor permit must make the sync incomplete, got %v", err)
	}
	if res.Collection.Cursor.Ran || len(pull.calls) != 0 {
		t.Fatalf("a login-expired permit must not run a round: ran=%t pulls=%d", res.Collection.Cursor.Ran, len(pull.calls))
	}
	if !containsReason(res.Incomplete, "account source Cursor did not run") {
		t.Fatalf("the login-expired skip must be named, got %v", res.Incomplete)
	}
}

// TestSyncCursorLegitimateSkipsAreNotIncomplete verifies the two skips
// that must NOT be judged as failures without an explicit account-tool
// list: no local permit at all (never enabled or logged out), and a
// server grant that excludes Cursor (an authorization verdict).
func TestSyncCursorLegitimateSkipsAreNotIncomplete(t *testing.T) {
	t.Run("no local permit", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)
		pull := &cursorBacklogPull{events: cursorBacklogEvents()}

		res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
		if err != nil {
			t.Fatalf("a device without a cursor permit must sync cleanly, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "account source Cursor") {
			t.Fatalf("a never-enabled cursor must not be reported, got %v", res.Incomplete)
		}
	})
	t.Run("grant excludes cursor", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.setAllowedTools([]string{"SomeFutureTool"})
		seedCursorBacklogState(t, dir, mock.URL)
		seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
		pull := &cursorBacklogPull{events: cursorBacklogEvents()}

		res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
		if err != nil {
			t.Fatalf("an unauthorized cursor skipping normally must not fail the sync, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "account source Cursor") {
			t.Fatalf("an unauthorized cursor must not be reported, got %v", res.Incomplete)
		}
	})
}

// TestSyncCursorSkippedNoStableIDIsIncomplete verifies that a round
// which dropped usage rows without a stable upstream event id is never
// reported as a complete success: the uncounted events are a gap.
func TestSyncCursorSkippedNoStableIDIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	mock := startCursorBacklogMock(t)
	seedCursorBacklogState(t, dir, mock.URL)
	seedCursorBacklogPermit(t, dir, cursorsource.StatusActive)
	// One normal event plus one without a stable id: the round succeeds
	// but leaves one usage event uncounted.
	idless := cursorBacklogEvents()[0]
	idless.UsageEventID = ""
	pull := &cursorBacklogPull{events: []api.UsageEvent{idless, cursorBacklogEvents()[1]}}

	res, err := runCursorBacklogSync(t, dir, mock.URL, &cursorBacklogAuth{}, &cursorBacklogVerify{}, pull, 2)
	if err == nil || !isErrSyncIncomplete(err) {
		t.Fatalf("dropped id-less usage events must make the sync incomplete, got %v", err)
	}
	if res.Collection.Cursor.SkippedNoStableID != 1 || res.Collection.Cursor.NewRecords != 1 {
		t.Fatalf("round accounting: %+v", res.Collection.Cursor)
	}
	if !containsReason(res.Incomplete, "without a stable upstream id") {
		t.Fatalf("the uncounted events must be named, got %v", res.Incomplete)
	}
}

func isErrSyncIncomplete(err error) bool { return errors.Is(err, ErrSyncIncomplete) }

func containsReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// seedDeviceBacklogBatch writes one pending device batch attributed to a
// codex grant, mirroring what a prior collection round exported (the
// record shape passes the drain's upload gates and resync's offline
// validation).
func seedDeviceBacklogBatch(t *testing.T, dir, homeDir, batchID, key string) {
	t.Helper()
	batchesDir := filepath.Join(dir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"recordKey":      key,
		"kind":           "delta",
		"tool":           "Codex",
		"model":          "gpt-5.4",
		"occurredAt":     cursorBacklogNow.Add(-time.Hour).Format(time.RFC3339),
		"input":          "100",
		"output":         "50",
		"cacheRead":      "20",
		"cacheWrite":     "5",
		"adapterVersion": "synthetic",
		"sourceType":     "fixture",
	}
	raw, err := json.Marshal(map[string]any{"batchId": batchID, "records": []map[string]any{record}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchesDir, batchID+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := outbox.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	out.Batches = append(out.Batches, outbox.BatchEntry{
		BatchID:     batchID,
		File:        path,
		Source:      "codex-jsonl",
		Input:       input,
		Status:      outbox.StatusPending,
		RecordCount: 1,
		CreatedAt:   cursorBacklogNow.Add(-time.Duration(len(out.Batches)+1) * time.Minute),
	})
	if err := outbox.New(dir).Save(out); err != nil {
		t.Fatal(err)
	}
}

// seedCodexSessionsGrant enables the codex grant the seeded device
// batches are attributed to (resync eligibility requires it).
func seedCodexSessionsGrant(t *testing.T, dir, homeDir string) string {
	t.Helper()
	input := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.New(dir).Enable("codex-jsonl", input); err != nil {
		t.Fatalf("enable grant: %v", err)
	}
	return input
}

// TestSyncCrossPhaseScopeChangeRefusesSuccess verifies the cross-phase
// scope consistency rule: the initial collection, the history
// retransmission and the backlog drain passes must all have observed the
// same consent revision (under the active grant protocol). A run that
// straddles a server-side scope change — or cannot confirm the live
// scope at all — refuses success, because the collection drain recovered
// quarantine and uploaded under the old scope and the current
// authorization is not fully covered.
func TestSyncCrossPhaseScopeChangeRefusesSuccess(t *testing.T) {
	// The scope moves right after the initial collection's drain upload:
	// the retransmission preflight observes revision 6 while the
	// collection ran under 5.
	t.Run("retransmission sees the newer scope", func(t *testing.T) {
		dir := t.TempDir()
		homeDir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.bumpRevisionAfterDevicePosts(1)
		seedCursorBacklogState(t, dir, mock.URL)
		seedCodexSessionsGrant(t, dir, homeDir)
		seedDeviceBacklogBatch(t, dir, homeDir, "cbl-dev-1", "cbl-dev-key-1")

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("a scope change between the collection and the retransmission must refuse success, got %v", err)
		}
		if res.Collection.GrantSync.ConsentRevision != 5 || res.Resync.ConsentRevision != 6 {
			t.Fatalf("revisions: collection=%d retransmission=%d, want 5/6", res.Collection.GrantSync.ConsentRevision, res.Resync.ConsentRevision)
		}
		if !res.Resync.Completed {
			t.Fatalf("the retransmission itself finished under the fresh scope; only the run must refuse success: %+v", res.Resync)
		}
		if !containsReason(res.Incomplete, "consent scope moved between the collection") {
			t.Fatalf("the scope move must be named, got %v", res.Incomplete)
		}
	})

	// No grants and no batches: the retransmission has nothing eligible
	// and never prefetches, so connect's own fresh self confirmation must
	// observe the scope move (revision 6 on its self request after the
	// grant sync's).
	t.Run("empty retransmission confirms the fresh scope", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		mock.bumpRevisionAfterSelfCalls(2)
		seedCursorBacklogState(t, dir, mock.URL)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("an empty retransmission must still confirm the live scope, got %v", err)
		}
		if res.Resync.ConsentRevision != 6 {
			t.Fatalf("the fresh self confirmation must observe revision 6, got %d", res.Resync.ConsentRevision)
		}
		if !containsReason(res.Incomplete, "consent scope moved between the collection") {
			t.Fatalf("the scope move must be named, got %v", res.Incomplete)
		}
	})

	// The scope moves only after the retransmission completed under 5
	// (after its 5 retransmitted batches; the first backlog pass drains
	// 5 more): the last backlog pass's grant sync applies 6, mixing
	// old-scope and new-scope uploads. The retransmission itself stays
	// complete — the backlog comparison must refuse the success.
	t.Run("backlog drain runs under the newer scope", func(t *testing.T) {
		dir := t.TempDir()
		homeDir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)
		seedCodexSessionsGrant(t, dir, homeDir)
		// 12 pending batches: the initial round drains 5 (the round
		// bound), the retransmission replays those 5 (device posts
		// 6-10), backlog pass 1 drains 5 more (posts 11-15), and backlog
		// pass 2 drains the last 2 under the moved scope.
		for i := 1; i <= 12; i++ {
			seedDeviceBacklogBatch(t, dir, homeDir, fmt.Sprintf("cbl-mix-%d", i), fmt.Sprintf("cbl-mix-key-%d", i))
		}
		mock.bumpRevisionAfterDevicePosts(15)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err == nil || !isErrSyncIncomplete(err) {
			t.Fatalf("a backlog drain under a moved scope must refuse success, got %v", err)
		}
		if res.Collection.GrantSync.ConsentRevision != 5 || res.Resync.ConsentRevision != 5 || !res.Resync.Completed {
			t.Fatalf("the collection and the retransmission must both have run under 5: collected=%d resync=%d completed=%t", res.Collection.GrantSync.ConsentRevision, res.Resync.ConsentRevision, res.Resync.Completed)
		}
		if res.Backlog.Passes < 2 || res.Backlog.Result.GrantSync.ConsentRevision != 6 {
			t.Fatalf("the last backlog pass must have applied the moved revision: passes=%d lastRevision=%d", res.Backlog.Passes, res.Backlog.Result.GrantSync.ConsentRevision)
		}
		if !containsReason(res.Incomplete, "backlog drain") {
			t.Fatalf("the backlog scope move must be named, got %v", res.Incomplete)
		}
	})

	// Control: a stable scope across all phases stays complete.
	t.Run("stable scope stays complete", func(t *testing.T) {
		dir := t.TempDir()
		mock := startCursorBacklogMock(t)
		seedCursorBacklogState(t, dir, mock.URL)

		res, err := Sync(context.Background(), SyncOptions{
			StateDir: dir, ServerURL: mock.URL,
			Now: func() time.Time { return cursorBacklogNow },
		})
		if err != nil {
			t.Fatalf("a stable scope must stay complete, got %v (incomplete=%v)", err, res.Incomplete)
		}
		if containsReason(res.Incomplete, "consent scope moved") {
			t.Fatalf("no scope move may be reported, got %v", res.Incomplete)
		}
	})
}
