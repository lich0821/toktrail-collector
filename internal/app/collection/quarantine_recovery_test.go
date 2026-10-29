package collection

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

// ---------------------------------------------------------------------------
// quarantine-recovery fixtures
// ---------------------------------------------------------------------------

// quarantineEntry builds one synthetic quarantined-record entry. The record
// uses the fixed exporter's upload-whitelist shape so a recovered batch
// passes the send-path privacy gate; only synthetic fixture data is ever
// involved.
func quarantineEntry(t *testing.T, source, input, recordKey, tool, occurredAt string, revision int64) quarantine.Entry {
	t.Helper()
	record := map[string]any{
		"recordKey":      recordKey,
		"kind":           "delta",
		"occurredAt":     occurredAt,
		"tool":           tool,
		"input":          "10",
		"cacheRead":      "0",
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "collection-test-1",
		"sourceType":     "fixture",
	}
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return quarantine.Entry{
		Source:          source,
		Input:           input,
		RecordKey:       recordKey,
		Record:          b,
		OriginBatchID:   "batch-quarantined-1",
		Reason:          quarantine.ReasonToolNotAllowed,
		ConsentRevision: revision,
		QuarantinedAt:   time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC),
	}
}

// seedQuarantine persists synthetic quarantine entries.
func seedQuarantine(t *testing.T, stateDir string, entries ...quarantine.Entry) {
	t.Helper()
	if err := quarantine.New(stateDir).Append(entries); err != nil {
		t.Fatal(err)
	}
}

// quarantinedCount reports how many records the quarantine store holds.
func quarantinedCount(t *testing.T, stateDir string) int {
	t.Helper()
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// idleClaudeGrant enables an explicit grant over an empty Claude Code
// session directory and returns the directory: the export phase stays idle
// (no new data) so the drain can be exercised in isolation. The returned
// directory doubles as the quarantine provenance input.
func idleClaudeGrant(t *testing.T, stateDir string) string {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	return sessions
}

// grantedUsageInput enables a generic usage-json grant over an empty usage
// file and returns the path. The generic source's files can carry records
// for arbitrary tools, so its quarantined records are grant-authorized
// while this grant is enabled — and the source has no message-progress
// state, keeping the fixture independent of message-backed integrity
// rules.
func grantedUsageInput(t *testing.T, stateDir string) string {
	t.Helper()
	input := filepath.Join(t.TempDir(), "usage.jsonl")
	if err := os.WriteFile(input, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "usage-json", input)
	return input
}

// ingestPost is one recorded ingest upload.
type ingestPost struct {
	BatchID         string
	RecordKeys      []string
	ConsentRevision string // X-Consent-Revision header echoed on the POST
}

// ingestLog records every ingest POST seen by a wrapped fake server.
type ingestLog struct {
	mu    sync.Mutex
	posts []ingestPost
}

func (l *ingestLog) record(post ingestPost) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.posts = append(l.posts, post)
}

func (l *ingestLog) snapshot() []ingestPost {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ingestPost, len(l.posts))
	copy(out, l.posts)
	return out
}

// captureIngest wraps the fake server's handler so every ingest POST is
// recorded (batch id, record keys, consent header) before being served
// unchanged. Only synthetic fixtures are ever posted.
func captureIngest(t *testing.T, server *grantProtocolServer) *ingestLog {
	t.Helper()
	log := &ingestLog{}
	wrapped := server.Server.Config.Handler
	server.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("cannot read ingest body: %v", err)
				r.Body = io.NopCloser(bytes.NewReader(nil))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var body struct {
					BatchID string           `json:"batchId"`
					Records []map[string]any `json:"records"`
				}
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Errorf("invalid ingest body: %v", err)
				} else {
					keys := make([]string, 0, len(body.Records))
					for _, record := range body.Records {
						key, _ := record["recordKey"].(string)
						keys = append(keys, key)
					}
					log.record(ingestPost{BatchID: body.BatchID, RecordKeys: keys, ConsentRevision: r.Header.Get("X-Consent-Revision")})
				}
			}
		}
		wrapped.ServeHTTP(w, r)
	})
	return log
}

// recoveryOutboxEntry returns the quarantine-recovery batch
// ("recovery-<hash>") in the outbox.
func recoveryOutboxEntry(t *testing.T, stateDir string) *outbox.BatchEntry {
	t.Helper()
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Batches {
		if strings.HasPrefix(out.Batches[i].BatchID, "recovery-") {
			return &out.Batches[i]
		}
	}
	t.Fatalf("outbox has no recovery batch: %#v", out.Batches)
	return nil
}

// ---------------------------------------------------------------------------
// empty pending queue: quarantine recovery through the periodic run
// ---------------------------------------------------------------------------

// Empty pending queue + quarantined records + a live scope that allows them
// again (a strictly newer revision re-authorizing the tool): the periodic
// run must recover the quarantined records and drain them in the SAME run,
// through the normal sync path (device credentials, fresh consent
// preflight, scope gate, ingest POST) — never a local scope decision. The
// quarantined records belong to the generic usage-json source, whose
// enabled grant authorizes their recovery on this grant-configured device.
// Before the fix the drain returned at the empty pending queue, so a device
// with no new data never recovered its quarantine.
func TestRunEmptyPendingQueueRecoversQuarantineWhenScopeWidens(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	// The live scope re-authorizes Claude Code under revision 35; the
	// records were quarantined under revision 34 for tool_not_allowed.
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	idleClaudeGrant(t, stateDir)
	usageInput := grantedUsageInput(t, stateDir)
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "usage-json", usageInput, "record-q-1", "Claude Code", "2026-10-26T04:00:00Z", 34),
		quarantineEntry(t, "usage-json", usageInput, "record-q-2", "Claude Code", "2026-10-26T04:01:00Z", 34),
	)
	posted := captureIngest(t, server)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Recovered != 2 || res.SyncedBatches != 1 || res.SyncedRecords != 2 {
		t.Fatalf("expected the quarantined records recovered and drained in the same run, got %#v", res)
	}
	if res.Quarantined != 0 || res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("expected a fully settled drain, got %#v", res)
	}
	if !res.GrantSync.Active || res.GrantSync.ConsentRevision != 35 {
		t.Fatalf("expected the run governed by the live grant view, got %#v", res.GrantSync)
	}
	if got := quarantinedCount(t, stateDir); got != 0 {
		t.Fatalf("expected the quarantine store drained, got %d entries", got)
	}
	// The recovery batch is a normal pending batch born under the live
	// revision, provenance intact, and is marked synced after the upload.
	entry := recoveryOutboxEntry(t, stateDir)
	if entry.Status != outbox.StatusSynced || entry.RecordCount != 2 || entry.OriginConsentRevision != 35 ||
		entry.Source != "usage-json" || entry.Input != usageInput {
		t.Fatalf("expected the recovery batch synced under revision 35 with its provenance, got %#v", entry)
	}
	posts := posted.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected exactly one ingest upload, got %#v", posts)
	}
	if !strings.HasPrefix(posts[0].BatchID, "recovery-") ||
		len(posts[0].RecordKeys) != 2 ||
		posts[0].RecordKeys[0] != "record-q-1" || posts[0].RecordKeys[1] != "record-q-2" {
		t.Fatalf("expected the original record keys posted verbatim, got %#v", posts)
	}
	if posts[0].ConsentRevision != "35" {
		t.Fatalf("expected the upload to echo the fresh consent revision, got %q", posts[0].ConsentRevision)
	}
	// The recovery round rides the normal sync traffic: grant sync
	// (self + ack), the recovery preflight, the upload preflight + POST,
	// then the idle grant's empty-scan report (self + tool-status POST).
	if got := server.self.Load(); got != 4 {
		t.Fatalf("expected 4 self requests (grant sync, recovery, upload, status), got %d", got)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly the grant-sync ack, got %d", got)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("expected exactly one ingest upload, got %d", got)
	}
	if got := server.tooling.Load(); got != 1 {
		t.Fatalf("expected exactly one tool-status POST, got %d", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0] != (toolStatusReport{Tool: "Claude Code", Status: "no_new_records", Detail: "no new records since last confirmed baseline"}) {
		t.Fatalf("expected the idle Claude Code empty-scan report, got %#v", reports)
	}
	server.requireAuthBearer(t)

	// The next run over the drained state is a plain idle run: no
	// re-recovery, no replay, only the grant-sync refresh and the
	// empty-scan status report.
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Recovered != 0 || res2.SyncedBatches != 0 || res2.Quarantined != 0 || res2.PendingRemaining != 0 {
		t.Fatalf("the run after a full recovery must be a no-op, got %#v", res2)
	}
	if got := server.self.Load(); got != 6 {
		t.Fatalf("the settled run must add only the grant-sync and status preflights, got %d self requests", got)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("the settled run must not replay the upload, got %d ingests", got)
	}
	if got := server.tooling.Load(); got != 2 {
		t.Fatalf("the settled run must add exactly the empty-scan report, got %d tool-status POSTs", got)
	}
}

// Empty pending queue + quarantined records the live scope still excludes
// (the tool is not allowed again yet): a normal steady state, not a run
// failure. The run reports the held records through res.Quarantined,
// uploads nothing, and still performs the empty-scan status report of an
// idle device.
func TestRunEmptyPendingQueueHeldQuarantineIsNotAFailure(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	sessions := idleClaudeGrant(t, stateDir)
	// The fresh snapshot is strictly newer than the quarantine revision,
	// but the scope still excludes the records: their tool is not allowed.
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-held-1", "Codex", "2026-10-26T04:00:00Z", 34),
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-held-2", "Codex", "2026-10-26T04:01:00Z", 34),
	)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("quarantined records the live scope still excludes must not fail the run, got %v", err)
	}
	if res.Recovered != 0 || res.SyncedBatches != 0 || res.SyncedRecords != 0 {
		t.Fatalf("nothing must be recovered or uploaded, got %#v", res)
	}
	if res.Quarantined != 2 {
		t.Fatalf("the held records must be reported, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("a held quarantine is a settled drain, not an early stop, got %#v", res)
	}
	if got := quarantinedCount(t, stateDir); got != 2 {
		t.Fatalf("the quarantined records must stay recoverable, got %d entries", got)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("nothing must be uploaded while the scope excludes the records, got %d ingests", got)
	}
	// Network: grant sync (self + ack), the recovery round's fresh self
	// fetch, then the idle device's empty-scan report (self + POST).
	if got := server.self.Load(); got != 3 {
		t.Fatalf("expected grant-sync, recovery and status preflights, got %d self requests", got)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly the grant ack, got %d", got)
	}
	if got := server.tooling.Load(); got != 1 {
		t.Fatalf("expected exactly the empty-scan report, got %d tool-status POSTs", got)
	}
	reports := server.toolStatusReports()
	if len(reports) != 1 || reports[0] != (toolStatusReport{Tool: "Claude Code", Status: "no_new_records", Detail: "no new records since last confirmed baseline"}) {
		t.Fatalf("expected the idle Claude Code empty-scan report, got %#v", reports)
	}
}

// Recovery requires a STRICTLY newer consent revision: quarantined records
// under the same revision the live snapshot still serves stay put (no
// quarantine/recovery loop within one revision) and the run still succeeds.
func TestRunEmptyPendingQueueDoesNotRecoverWithinSameRevision(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	sessions := idleClaudeGrant(t, stateDir)
	// The record would fit the live scope (its tool is allowed), but it
	// was quarantined under the SAME revision the server still serves.
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-same-rev", "Claude Code", "2026-10-26T04:00:00Z", 35),
	)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("a same-revision hold must not fail the run, got %v", err)
	}
	if res.Recovered != 0 || res.SyncedBatches != 0 || res.Quarantined != 1 {
		t.Fatalf("same-revision quarantined records must stay put, got %#v", res)
	}
	if got := quarantinedCount(t, stateDir); got != 1 {
		t.Fatalf("the record must stay quarantined, got %d entries", got)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("nothing must be uploaded, got %d ingests", got)
	}
}

// Scope widening can be partial: when the live scope re-admits only some
// quarantined records (the tool is allowed again but a history cutoff still
// excludes older records), exactly the allowed records are recovered,
// drained, and reported; the excluded ones stay quarantined — untouched and
// still recoverable — without failing the run.
func TestRunEmptyPendingQueueRecoversOnlyRecordsTheLiveScopeAllows(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	cutoff := "2026-10-26T00:00:00Z"
	server.mu.Lock()
	server.historyFrom = &cutoff
	server.mu.Unlock()
	bindDevice(t, stateDir, server.URL)
	sessions := idleClaudeGrant(t, stateDir)
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-in-window", "Claude Code", "2026-10-26T04:00:00Z", 34),
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-before-cutoff", "Claude Code", "2026-10-25T04:00:00Z", 34),
	)
	posted := captureIngest(t, server)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Recovered != 1 || res.SyncedBatches != 1 || res.SyncedRecords != 1 {
		t.Fatalf("expected exactly the in-window record recovered and drained, got %#v", res)
	}
	if res.Quarantined != 1 || res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("expected one held record and a settled drain, got %#v", res)
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RecordKey != "record-before-cutoff" || entries[0].ConsentRevision != 34 {
		t.Fatalf("expected the pre-cutoff record held with its provenance untouched, got %#v", entries)
	}
	posts := posted.snapshot()
	if len(posts) != 1 || len(posts[0].RecordKeys) != 1 || posts[0].RecordKeys[0] != "record-in-window" {
		t.Fatalf("expected only the allowed record posted, got %#v", posts)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("expected exactly one ingest upload, got %d", got)
	}
}

// Empty pending queue and an EMPTY quarantine store: the drain must not
// attempt a recovery round — no extra network beyond the grant sync and the
// idle empty-scan report. (Regression guard for the empty-queue fix: the
// recovery round is reserved for a non-empty quarantine store.)
func TestRunEmptyPendingQueueWithoutQuarantineSkipsRecovery(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	idleClaudeGrant(t, stateDir)

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Recovered != 0 || res.SyncedBatches != 0 || res.Quarantined != 0 || res.PendingRemaining != 0 {
		t.Fatalf("an idle run with nothing quarantined must be a no-op, got %#v", res)
	}
	if res.DrainStopped != "" {
		t.Fatalf("an idle run must not report a drain stop, got %#v", res)
	}
	// Network: grant sync (self + ack) and the empty-scan report
	// (self + tool-status POST). No recovery self fetch, no upload.
	if got := server.self.Load(); got != 2 {
		t.Fatalf("expected only the grant-sync and status preflights, got %d self requests", got)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly the grant ack, got %d", got)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("an idle run must not upload, got %d ingests", got)
	}
	if got := server.tooling.Load(); got != 1 {
		t.Fatalf("expected exactly the empty-scan report, got %d tool-status POSTs", got)
	}
	if got := server.totalRequests(); got != 4 {
		t.Fatalf("unexpected total network requests: %d", got)
	}
}

// A REAL failure inside the recovery round (the fresh consent check fails
// mid-run) must surface as a run failure with the held records untouched:
// only the normal nothing-recoverable diagnosis is treated as a settled
// state, never an arbitrary error.
func TestRunEmptyPendingQueueRecoveryFailureSurfaces(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	sessions := idleClaudeGrant(t, stateDir)
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-fail-1", "Claude Code", "2026-10-26T04:00:00Z", 34),
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-fail-2", "Claude Code", "2026-10-26T04:01:00Z", 34),
	)
	// Fail every self GET once the grant sync has fetched its view and
	// acknowledged it: the recovery round's fresh consent check then fails
	// exactly like an upload preflight would.
	var acked atomic.Bool
	wrapped := server.Server.Config.Handler
	server.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack" && acked.CompareAndSwap(false, true) {
			status := http.StatusInternalServerError
			server.mu.Lock()
			server.failSelfWith = &status
			server.mu.Unlock()
		}
	})

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected the recovery-round failure to surface")
	}
	if !strings.Contains(err.Error(), "device self check failed") {
		t.Fatalf("expected the self-check failure, got %v", err)
	}
	if res.Recovered != 0 || res.SyncedBatches != 0 {
		t.Fatalf("nothing must be recovered or synced, got %#v", res)
	}
	if res.Quarantined != 2 || res.DrainStopped == "" || !strings.Contains(res.DrainStopped, "quarantine recovery round failed") {
		t.Fatalf("expected the held records reported with a drain-stop reason, got %#v", res)
	}
	if got := quarantinedCount(t, stateDir); got != 2 {
		t.Fatalf("the quarantined records must stay untouched, got %d entries", got)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("nothing must be uploaded, got %d ingests", got)
	}
}

// A grant closed after the records were quarantined — the connect flow
// disables (source, input) pairs that left the authorized list, exactly
// like a manual `toktrail sources disable` — must hold its quarantined
// records even when the live server scope would allow them again: the
// revoked local authorization is not bypassed. The run still succeeds (a
// held quarantine is a steady state, surfaced through res.Quarantined),
// and re-enabling the grant lets the next run recover and drain them.
func TestRunEmptyPendingQueueHoldsQuarantineWhenGrantRevoked(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	// The live scope re-authorizes Claude Code under revision 35.
	server.setView(t, false, []string{"Claude Code"}, 35)
	bindDevice(t, stateDir, server.URL)
	sessions := idleClaudeGrant(t, stateDir)
	// A second, still-enabled grant keeps the periodic run past the
	// no-grants early return, so the drain — and its recovery gate —
	// actually runs while the Claude grant is closed.
	codexSessions := filepath.Join(t.TempDir(), "codex-sessions")
	if err := os.MkdirAll(codexSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir, "codex-jsonl", codexSessions)
	seedQuarantine(t, stateDir,
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-revoked-1", "Claude Code", "2026-10-26T04:00:00Z", 34),
		quarantineEntry(t, "claude-code-jsonl", sessions, "record-revoked-2", "Claude Code", "2026-10-26T04:01:00Z", 34),
	)
	// Close the Claude grant the way connect does for tools that left the
	// authorized list: the (source, input) pair stays recorded, disabled.
	if _, _, err := grants.New(stateDir).Disable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}

	// Run 1: the server scope would allow the records again, but the
	// local grant is revoked. Nothing recovers, nothing uploads, and the
	// run reports success with the held records.
	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("a revoked local grant must hold the quarantine without failing the run, got %v", err)
	}
	if res.Recovered != 0 || res.SyncedBatches != 0 || res.SyncedRecords != 0 {
		t.Fatalf("nothing must be recovered or uploaded while the grant is closed, got %#v", res)
	}
	if res.Quarantined != 2 {
		t.Fatalf("the records held by the closed grant must be reported, got %#v", res)
	}
	if res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("a grant-held quarantine is a settled drain, not an early stop, got %#v", res)
	}
	if got := quarantinedCount(t, stateDir); got != 2 {
		t.Fatalf("the records must stay quarantined and recoverable, got %d entries", got)
	}
	if got := server.ingestRequests(); got != 0 {
		t.Fatalf("nothing must be uploaded while the grant is closed, got %d ingests", got)
	}
	// The held round still performed its one fresh authorization fetch:
	// grant sync, the closed tool's restriction report, and the recovery
	// round's self check.
	if got := server.self.Load(); got != 3 {
		t.Fatalf("expected grant-sync, restriction and recovery preflights, got %d self requests", got)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly the grant ack, got %d", got)
	}
	if got := server.tooling.Load(); got != 1 {
		t.Fatalf("expected exactly the closed tool's restriction report, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) != 1 ||
		reports[0].Tool != "Claude Code" || reports[0].Status != "not_detected" {
		t.Fatalf("expected the closed Claude Code grant reported as not detected, got %#v", reports)
	}

	// Run 2: re-enabling the grant (the user re-authorizes the tool) lets
	// the same widened scope recover and drain the records.
	if _, err := grants.New(stateDir).Enable("claude-code-jsonl", sessions); err != nil {
		t.Fatal(err)
	}
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Recovered != 2 || res2.SyncedBatches != 1 || res2.SyncedRecords != 2 || res2.Quarantined != 0 {
		t.Fatalf("expected the records recovered and drained after re-authorization, got %#v", res2)
	}
	if res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected a settled drain after re-authorization, got %#v", res2)
	}
	if got := quarantinedCount(t, stateDir); got != 0 {
		t.Fatalf("expected the quarantine drained after re-authorization, got %d entries", got)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("expected exactly the recovery upload after re-authorization, got %d ingests", got)
	}
}

// Cross-run lifecycle with a REAL granted source and server receipts,
// exercising the revision changes 7→30 and 30→7:
//
//   - Run 1 exports two real Claude Code messages under a wide view
//     (revision 6, no cutoff). The server then narrows to revision 7 with
//     a history cutoff mid-run — between the grant sync and the upload —
//     so the drain's pre-POST scope gate quarantines the pre-cutoff
//     message under revision 7 (recoverably, with its message provenance)
//     while the in-window message uploads and gets its server receipt.
//     The same-run recovery round correctly holds the record (revision 7
//     is not strictly newer than itself).
//
//   - Run 2 (revision 30, cutoff lifted — the 7→30 widening) has NO new
//     data: the quarantined message is exactly what the empty-queue
//     recovery round must bring back. It is recovered under the enabled
//     grant, re-batched with its original record key, uploaded, and
//     receipted by the server.
//
//   - Run 3 (revision 7 with the cutoff again — the 30→7 narrowing) is a
//     settled idle run: nothing re-recoverable, nothing re-uploaded, no
//     loop, and the run succeeds.
func TestRunRealSourceQuarantineRecoveredAcrossRunsAndScopeChanges(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	cutoff := "2026-10-26T04:00:00Z"

	// A real granted Claude Code session with one message before and one
	// after the cutoff the server will impose mid-run.
	sessions := filepath.Join(t.TempDir(), "sessions")
	writeClaudeSession(t, sessions, "session.jsonl",
		claudeLine(t, "2026-10-26T03:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-26T05:00:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))
	bindDevice(t, stateDir, server.URL)
	enableGrant(t, stateDir, "claude-code-jsonl", sessions)
	posted := captureIngest(t, server)

	// Run 1: the grant sync sees the wide revision-6 view; the server
	// narrows to revision 7 with the cutoff right after the grant ack, so
	// the drain's upload preflight quarantines the pre-cutoff message.
	server.setView(t, false, []string{"Claude Code"}, 6)
	var grantSyncDone atomic.Bool
	wrapped := server.Server.Config.Handler
	server.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/devices/grant-ack" && grantSyncDone.CompareAndSwap(false, true) {
			server.setView(t, false, []string{"Claude Code"}, 7)
			server.mu.Lock()
			server.historyFrom = &cutoff
			server.mu.Unlock()
		}
	})

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 || res.SyncedRecords != 1 {
		t.Fatalf("expected the real export uploaded with the in-window record kept, got %#v", res)
	}
	if res.Recovered != 0 || res.Quarantined != 1 || res.PendingRemaining != 0 || res.DrainStopped != "" {
		t.Fatalf("expected one record quarantined and a settled drain, got %#v", res)
	}
	entries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(entries) != 1 {
		t.Fatalf("expected one quarantined record, err=%v: %#v", qErr, entries)
	}
	held := entries[0]
	if held.Reason != quarantine.ReasonBeforeHistoryFrom || held.ConsentRevision != 7 || held.MessageID == "" || held.Source != "claude-code-jsonl" || held.Input != sessions {
		t.Fatalf("expected the pre-cutoff message quarantined under revision 7 with real provenance, got %#v", held)
	}
	posts := posted.snapshot()
	if len(posts) != 1 || !strings.HasPrefix(posts[0].BatchID, "reorg-") ||
		len(posts[0].RecordKeys) != 1 || posts[0].RecordKeys[0] == held.RecordKey || posts[0].ConsentRevision != "7" {
		t.Fatalf("expected only the in-window record posted under revision 7, got %#v (held %q)", posts, held.RecordKey)
	}
	// self: grant sync, upload preflight, synced receipt, recovery round.
	if got := server.self.Load(); got != 4 {
		t.Fatalf("expected 4 self requests in run 1, got %d", got)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly the grant ack in run 1, got %d", got)
	}
	if got := server.ingestRequests(); got != 1 {
		t.Fatalf("expected exactly one upload in run 1, got %d", got)
	}
	if got := server.tooling.Load(); got != 1 {
		t.Fatalf("expected exactly the synced receipt in run 1, got %d tool-status POSTs", got)
	}

	// Run 2 (7→30): the cutoff lifts under a strictly newer revision and
	// no new data exists — the empty-queue recovery round must bring the
	// quarantined message back and drain it with a server receipt.
	server.setView(t, false, []string{"Claude Code"}, 30)
	server.mu.Lock()
	server.historyFrom = nil
	server.mu.Unlock()

	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ExportedBatches != 0 || res2.Recovered != 1 || res2.SyncedBatches != 1 || res2.SyncedRecords != 1 {
		t.Fatalf("expected the quarantined message recovered and drained with no new data, got %#v", res2)
	}
	if res2.Quarantined != 0 || res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected a fully settled drain after recovery, got %#v", res2)
	}
	posts = posted.snapshot()
	if len(posts) != 2 || !strings.HasPrefix(posts[1].BatchID, "recovery-") ||
		len(posts[1].RecordKeys) != 1 || posts[1].RecordKeys[0] != held.RecordKey || posts[1].ConsentRevision != "30" {
		t.Fatalf("expected the original record key re-sent verbatim under revision 30, got %#v (want key %q)", posts, held.RecordKey)
	}
	if got := quarantinedCount(t, stateDir); got != 0 {
		t.Fatalf("expected the quarantine drained, got %d entries", got)
	}
	// self: grant sync, recovery round, upload preflight, synced receipt.
	if got := server.self.Load(); got != 8 {
		t.Fatalf("expected 8 self requests after run 2, got %d", got)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("expected the revision-30 re-ack, got %d", got)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("expected exactly one more upload in run 2, got %d", got)
	}
	if got := server.tooling.Load(); got != 2 {
		t.Fatalf("expected the recovery synced receipt, got %d tool-status POSTs", got)
	}

	// Run 3 (30→7): the cutoff returns under the old revision. Everything
	// is already confirmed and the quarantine is empty, so the run is a
	// settled idle scan: no re-recovery, no re-upload, no failure.
	server.setView(t, false, []string{"Claude Code"}, 7)
	server.mu.Lock()
	server.historyFrom = &cutoff
	server.mu.Unlock()

	res3, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res3.ExportedBatches != 0 || res3.Recovered != 0 || res3.SyncedBatches != 0 || res3.Quarantined != 0 || res3.PendingRemaining != 0 {
		t.Fatalf("the narrowed rerun over drained state must be a no-op, got %#v", res3)
	}
	if got := server.ingestRequests(); got != 2 {
		t.Fatalf("the narrowed rerun must not upload anything, got %d ingests", got)
	}
	if got := quarantinedCount(t, stateDir); got != 0 {
		t.Fatalf("the narrowed rerun must not re-quarantine or hold records, got %d entries", got)
	}
	// self: grant sync and the empty-scan status preflight.
	if got := server.self.Load(); got != 10 {
		t.Fatalf("expected 10 self requests after run 3, got %d", got)
	}
	if got := server.ackRequests(); got != 3 {
		t.Fatalf("expected the revision-7 re-ack, got %d", got)
	}
	if got := server.tooling.Load(); got != 3 {
		t.Fatalf("expected the empty-scan report, got %d tool-status POSTs", got)
	}
	if reports := server.toolStatusReports(); len(reports) == 0 ||
		reports[len(reports)-1] != (toolStatusReport{Tool: "Claude Code", Status: "no_new_records", Detail: "no new records since last confirmed baseline"}) {
		t.Fatalf("expected the final empty-scan report, got %#v", reports)
	}
	server.requireAuthBearer(t)
}
