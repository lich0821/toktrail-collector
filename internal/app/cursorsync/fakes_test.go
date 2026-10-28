// Synthetic test doubles for the cursorsync orchestration tests.
//
// Nothing here touches a real Cursor desktop state, a real credential or
// the network beyond a local httptest server speaking the TokTrail wire
// protocol: the auth provider hands out synthetic tokens, Verify maps
// them onto synthetic accounts, Pull serves windowed synthetic events,
// and the fake TokTrail server answers /v1/devices/self,
// /v1/account-sources/enable, /v1/ingest/source-batches and
// /v1/capabilities.
package cursorsync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/cursor/api"
	"toktrail-collector/internal/cursor/auth"
	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/statedir"
	synccmd "toktrail-collector/internal/syncclient"
)

// baseTime is the frozen round clock used by every test.
var baseTime = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// Synthetic account identities (user_ + >= 8 alphanumerics, per the api
// account id policy). Tokens map onto them through fakeVerify only.
const (
	accountA = "user_testaccounta"
	accountB = "user_testaccountb"
)

const (
	testDeviceID     = "dev_test0001"
	testDeviceSecret = "sec_test0001"
	testApplication  = "app_test0001"
	testSubject      = "subject-1"
)

func i64(v int64) *int64 { return &v }

// ev builds one synthetic collapsed usage event.
func ev(id string, ts time.Time, in, cacheRead, cacheWrite, out int64) api.UsageEvent {
	return api.UsageEvent{
		UsageEventID:     id,
		TimestampMS:      ts.UnixMilli(),
		Model:            "claude-sonnet-4-5",
		InputTokens:      i64(in),
		CacheReadTokens:  i64(cacheRead),
		CacheWriteTokens: i64(cacheWrite),
		OutputTokens:     i64(out),
	}
}

// ---------------------------------------------------------------------------
// fake TokTrail server (httptest)
// ---------------------------------------------------------------------------

// fakeTokTrail is a local TokTrail control-plane double. Knobs are
// guarded by a mutex so tests can flip them between rounds.
type fakeTokTrail struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	deviceID        string
	consentRevision int64
	paused          bool
	allowedTools    []string
	historyFrom     *time.Time
	uploadUntil     *time.Time

	// source is the server's account source for this device; nil means
	// the server currently lists none (never enabled, or deleted).
	source       *protocol.Source
	instanceSeq  int
	capsEnabled  bool
	ingestFails  bool
	ingestStatus int    // 0 = accept; non-0 = answer this HTTP status
	ingestCode   string // non-empty = answer HTTP 409 with this stable error code
	// rejectIndex/rejectCode model a partial_error receipt: the record at
	// rejectIndex comes back rejected with the given (whitelisted) code.
	rejectIndex int
	rejectCode  string

	selfCalls   int
	enableCalls int
	ingestCalls int
	capsCalls   int
	ingested    []protocol.Batch
}

func newFakeTokTrail(t *testing.T, deviceID string) *fakeTokTrail {
	f := &fakeTokTrail{t: t, deviceID: deviceID, consentRevision: 5, capsEnabled: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/devices/self", f.handleSelf)
	mux.HandleFunc("/v1/account-sources/enable", f.handleEnable)
	mux.HandleFunc("/v1/ingest/source-batches", f.handleIngest)
	mux.HandleFunc("/v1/capabilities", f.handleCaps)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTokTrail) url() string { return f.srv.URL }

func (f *fakeTokTrail) handleSelf(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.selfCalls++
	snap := synccmd.SelfStatus{
		DeviceID:         f.deviceID,
		ConsentRevision:  f.consentRevision,
		UploadAuthorized: true,
		Paused:           f.paused,
		AllowedTools:     append([]string(nil), f.allowedTools...),
		HistoryFrom:      f.historyFrom,
		UploadUntil:      f.uploadUntil,
	}
	if f.source != nil {
		snap.AccountSources = []protocol.Source{*f.source}
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Device *synccmd.SelfStatus `json:"device"`
	}{&snap})
}

func (f *fakeTokTrail) handleEnable(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.enableCalls++
	if f.source == nil {
		f.instanceSeq++
		f.source = &protocol.Source{
			SourceInstanceID: fmt.Sprintf("src_inst_%d", f.instanceSeq),
			SourceType:       protocol.SourceType,
			State:            "active",
			FenceVersion:     1,
			NextRevision:     1,
		}
	}
	src := *f.source
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Source *protocol.Source `json:"source"`
	}{&src})
}

func (f *fakeTokTrail) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	var batch protocol.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "bad batch", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.ingestCalls++
	fails := f.ingestFails
	status := f.ingestStatus
	errCode := f.ingestCode
	rejIndex, rejCode := f.rejectIndex, f.rejectCode
	if !fails && status == 0 && errCode == "" && rejCode == "" {
		f.ingested = append(f.ingested, batch)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if fails || status != 0 {
		if status == 0 {
			status = http.StatusServiceUnavailable
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "unavailable", "message": "synthetic offline"},
		})
		return
	}
	if errCode != "" {
		// A stable control-plane error code (mapped onto the drain's
		// terminal-stop sentinels by the sourcebatch client).
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": errCode, "message": "synthetic stop"},
		})
		return
	}
	w.WriteHeader(http.StatusAccepted)
	if rejCode != "" {
		// A partial_error receipt: everything but rejectIndex is
		// accepted, the rejected record carries the whitelisted code.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"batch": map[string]any{
				"batchId":         batch.BatchID,
				"status":          "partial_error",
				"acceptedRecords": len(batch.Records) - 1,
				"rejectedRecords": 1,
				"replay":          false,
				"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
				"recordErrors":    []map[string]any{{"index": rejIndex, "code": rejCode}},
			},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"batch": map[string]any{
			"batchId":         batch.BatchID,
			"status":          "accepted",
			"acceptedRecords": len(batch.Records),
			"rejectedRecords": 0,
			"replay":          false,
			"receivedAt":      time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
}

func (f *fakeTokTrail) handleCaps(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.capsCalls++
	enabled := f.capsEnabled
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !enabled {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "not_found", "message": "no such endpoint"},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"features": []string{"device-grants", "account-sources"},
	})
}

// setSource replaces the server's view of this device's account source.
func (f *fakeTokTrail) setSource(s protocol.Source) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = &s
}

// dropSource removes the source server-side (deletion / reassignment
// elsewhere); the next enable call creates a fresh instance.
func (f *fakeTokTrail) dropSource() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = nil
}

func (f *fakeTokTrail) setHistory(from, until *time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.historyFrom, f.uploadUntil = from, until
}

func (f *fakeTokTrail) setAllowedTools(tools []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowedTools = tools
}

func (f *fakeTokTrail) setIngestFails(fails bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestFails = fails
}

// setIngestStatus answers every ingest with the given HTTP status (0
// restores acceptance).
func (f *fakeTokTrail) setIngestStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestStatus = status
}

// setIngestCode answers every ingest with HTTP 409 carrying the stable
// error code (empty restores acceptance).
func (f *fakeTokTrail) setIngestCode(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ingestCode = code
}

// setIngestPartialRejection answers every ingest with a partial_error
// receipt rejecting the record at index with the whitelisted code.
func (f *fakeTokTrail) setIngestPartialRejection(index int, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectIndex, f.rejectCode = index, code
}

func (f *fakeTokTrail) setCapsEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.capsEnabled = enabled
}

// stats snapshots the call counters and ingested batches.
func (f *fakeTokTrail) stats() (self, enable, ingest, caps int, batches []protocol.Batch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.selfCalls, f.enableCalls, f.ingestCalls, f.capsCalls, append([]protocol.Batch(nil), f.ingested...)
}

// ---------------------------------------------------------------------------
// fake Cursor auth / verify / pull / confirm
// ---------------------------------------------------------------------------

// fakeAuth hands out a switchable synthetic desktop credential and
// records read order into the shared event log.
type fakeAuth struct {
	mu      sync.Mutex
	token   string
	err     error
	fetches int
	order   *[]string
}

func (a *fakeAuth) Fetch(ctx context.Context) (auth.Credential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fetches++
	if a.order != nil {
		*a.order = append(*a.order, "auth")
	}
	if a.err != nil {
		return auth.Credential{}, a.err
	}
	return auth.Credential{AccessToken: a.token, Source: "fake-test"}, nil
}

func (a *fakeAuth) setToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

func (a *fakeAuth) fetchCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fetches
}

// fakeVerify maps synthetic tokens onto synthetic accounts.
type fakeVerify struct {
	mu    sync.Mutex
	calls []string
}

func (v *fakeVerify) verify(ctx context.Context, token string) (api.VerifyResult, error) {
	v.mu.Lock()
	v.calls = append(v.calls, token)
	v.mu.Unlock()
	switch token {
	case "tok-A":
		return api.VerifyResult{AccountID: accountA, SessionToken: "sess-A"}, nil
	case "tok-B":
		return api.VerifyResult{AccountID: accountB, SessionToken: "sess-B"}, nil
	}
	return api.VerifyResult{}, fmt.Errorf("unknown synthetic token: %w", api.ErrSessionExpired)
}

func (v *fakeVerify) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls)
}

// pullCall records one synthetic pull request.
type pullCall struct {
	sessionToken string
	from, to     time.Time
}

// fakePull serves the configured events filtered to the requested
// window, like the real dashboard API would. With unfiltered set it
// ignores the window entirely, modeling a divergent upstream that
// answers rows outside the range it was asked for.
type fakePull struct {
	mu         sync.Mutex
	events     []api.UsageEvent
	calls      []pullCall
	unfiltered bool
}

func (p *fakePull) pull(ctx context.Context, sessionToken string, from, to time.Time) ([]api.UsageEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, pullCall{sessionToken: sessionToken, from: from, to: to})
	out := make([]api.UsageEvent, 0, len(p.events))
	for _, e := range p.events {
		if p.unfiltered {
			out = append(out, e)
			continue
		}
		if !from.IsZero() && e.TimestampMS < from.UnixMilli() {
			continue
		}
		if e.TimestampMS >= to.UnixMilli() {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (p *fakePull) setUnfiltered(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unfiltered = v
}

func (p *fakePull) setEvents(events ...api.UsageEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append([]api.UsageEvent(nil), events...)
}

func (p *fakePull) callLog() []pullCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pullCall(nil), p.calls...)
}

// fakeConfirm answers the local confirmation prompt and records order.
type fakeConfirm struct {
	mu         sync.Mutex
	calls      int
	answer     bool
	err        error
	order      *[]string
	lastNotice string
}

func (c *fakeConfirm) confirm(notice string, out io.Writer) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastNotice = notice
	if c.order != nil {
		*c.order = append(*c.order, "confirm")
	}
	if c.err != nil {
		return false, c.err
	}
	return c.answer, nil
}

func (c *fakeConfirm) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeConfirm) notice() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastNotice
}

// fakeClock is a settable Now for Options.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// harness wires one state directory, one fake TokTrail server and the
// fake Cursor-side collaborators together.
type harness struct {
	srv    *fakeTokTrail
	dir    string
	auth   *fakeAuth
	verify *fakeVerify
	pull   *fakePull
	clock  *fakeClock
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	srv := newFakeTokTrail(t, testDeviceID)
	st := statedir.DeviceState{
		ServerURL:         srv.url(),
		ApplicationID:     testApplication,
		ExternalSubjectID: testSubject,
		DeviceID:          testDeviceID,
		DeviceSecret:      testDeviceSecret,
	}
	if err := statedir.New(dir).Save(st); err != nil {
		t.Fatalf("write device state: %v", err)
	}
	return &harness{
		srv:    srv,
		dir:    dir,
		auth:   &fakeAuth{token: "tok-A"},
		verify: &fakeVerify{},
		pull:   &fakePull{},
		clock:  &fakeClock{t: baseTime},
	}
}

func (h *harness) options() cursorsync.Options {
	return cursorsync.Options{
		StateDir:  h.dir,
		ServerURL: h.srv.url(),
		Auth:      h.auth,
		Verify:    h.verify.verify,
		Pull:      h.pull.pull,
		Now:       h.clock.Now,
	}
}

// defaultSource is the server source matching a license written with
// sourceInstanceID "src_inst_1".
func defaultSource() protocol.Source {
	return protocol.Source{
		SourceInstanceID: "src_inst_1",
		SourceType:       protocol.SourceType,
		State:            "active",
		FenceVersion:     1,
		NextRevision:     1,
	}
}
