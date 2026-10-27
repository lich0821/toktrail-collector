package collection

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/source/registry"
	synccmd "toktrail-collector/internal/syncclient"
)

// expectedAckSupportedTools mirrors the ack's supported-tools list: the
// canonical names of every tool registered in this build, sorted.
func expectedAckSupportedTools() []string {
	specs := registry.SupportedTools()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Tool)
	}
	sortStrings(names)
	return names
}

// The grant-ack carries the collector's capability report: the registered
// supported-tools list and one closed-code reason per restricted tool —
// names and codes only, never local paths. The overlay caches exactly the
// confirmed payload, and an unchanged revision with an unchanged
// capability payload does not re-ack.
func TestGrantSyncAckReportsSupportedToolsAndPendingReasons(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	// Codex's default directory does not exist (missing_input) and
	// FutureTool has no adapter (unsupported_tool); both are pending.
	server.setView(t, false, []string{"Codex", "FutureTool"}, 40)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Acked || len(res.GrantSync.Pending) != 2 {
		t.Fatalf("expected a pending-acked run with two restrictions, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected exactly one ack, got %d", got)
	}
	body := server.lastAckBody()
	if body.ApplyState != "pending" {
		t.Fatalf("expected applyState=pending, got %#v", body)
	}
	if !sameAckedTools(body.SupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("the ack must list the registered tools, got %#v", body.SupportedTools)
	}
	want := []grantAckPendingReasonBody{
		{Tool: "Codex", Code: "missing_input"},
		{Tool: "FutureTool", Code: "unsupported_tool"},
	}
	if len(body.PendingReasons) != 2 || body.PendingReasons[0] != want[0] || body.PendingReasons[1] != want[1] {
		t.Fatalf("unexpected pendingReasons: %#v (want %#v)", body.PendingReasons, want)
	}
	// The raw wire payload contains no local path (the free-text reason
	// for Codex embeds the default directory; only the code may travel).
	for _, raw := range server.allAckRawBodies() {
		if strings.Contains(raw, home) || strings.Contains(raw, filepath.Join(home, ".codex")) {
			t.Fatalf("the ack payload must not contain local paths: %s", raw)
		}
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 40 || o.AckedApplyState != "pending" {
		t.Fatalf("overlay must record the pending ack, got %#v", o)
	}
	if !sameAckedTools(o.AckedSupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("overlay must cache the confirmed supported list, got %#v", o.AckedSupportedTools)
	}
	if !sameAckedPendingReasons(o.AckedPendingReasons, map[string]string{"Codex": "missing_input", "FutureTool": "unsupported_tool"}) {
		t.Fatalf("overlay must cache the confirmed reasons, got %#v", o.AckedPendingReasons)
	}

	// Unchanged revision, state, and capability payload: no re-ack.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("an unchanged capability payload must not re-ack, got %d acks", got)
	}
}

// A changed pending reason re-acks the SAME revision even while
// applyState stays "pending": the structured reason payload is part of
// the local ack cache key, so the server's device view cannot keep
// showing a stale restriction.
func TestGrantSyncAckPendingReasonChangeReAcksSameRevision(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "FutureTool"}, 41)
	bindDevice(t, stateDir, server.URL)
	home := t.TempDir()

	// Run 1: the codex default directory is missing.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected the initial ack, got %d", got)
	}
	if last := server.lastAckBody(); len(last.PendingReasons) != 2 {
		t.Fatalf("expected two pending reasons initially, got %#v", last.PendingReasons)
	}

	// The user installs the codex default directory; FutureTool stays
	// unknown, so the revision remains pending — but its reason set
	// changed.
	codexDefault := filepath.Join(home, ".codex", "sessions")
	writeCodexSession(t, codexDefault, "rollout-a.jsonl",
		codexTokenCount("2026-10-26T04:00:00Z", 100, 0, 0, 50))

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Acked || res.GrantSync.ConsentRevision != 41 {
		t.Fatalf("the same revision must be re-acked, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("the reason change must re-ack the same revision, got %d acks", got)
	}
	last := server.lastAckBody()
	if last.ApplyState != "pending" || last.ConsentRevision != 41 {
		t.Fatalf("expected a pending re-ack of revision 41, got %#v", last)
	}
	if len(last.PendingReasons) != 1 || last.PendingReasons[0] != (grantAckPendingReasonBody{Tool: "FutureTool", Code: "unsupported_tool"}) {
		t.Fatalf("expected only the FutureTool restriction on the wire, got %#v", last.PendingReasons)
	}
	o := loadOverlayForTest(t, stateDir)
	if !sameAckedPendingReasons(o.AckedPendingReasons, map[string]string{"FutureTool": "unsupported_tool"}) {
		t.Fatalf("overlay must cache the updated reasons, got %#v", o.AckedPendingReasons)
	}
}

// A changed supported-tools list re-acks the SAME revision: a collector
// upgrade that registers (or drops) a tool must refresh the server's
// capability view even when nothing else moved.
func TestGrantSyncAckSupportedToolsChangeReAcksSameRevision(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 42)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 1 {
		t.Fatalf("expected the initial ack, got %d", got)
	}

	// Simulate the previous collector build having registered a smaller
	// tool set: the cached ack confirms a stale capability list.
	o := loadOverlayForTest(t, stateDir)
	o.AckedSupportedTools = []string{"Codex"}
	if err := managedconsent.New(stateDir).Save(o); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Acked || res.GrantSync.ConsentRevision != 42 {
		t.Fatalf("the same revision must be re-acked, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("the capability change must re-ack the same revision, got %d acks", got)
	}
	if last := server.lastAckBody(); !sameAckedTools(last.SupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("the re-ack must carry the current registered list, got %#v", last.SupportedTools)
	}
	o = loadOverlayForTest(t, stateDir)
	if !sameAckedTools(o.AckedSupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("overlay must cache the refreshed list, got %#v", o.AckedSupportedTools)
	}
}

// Unit coverage for the unmapped-reason semantics that the full Run path
// cannot produce (mergeManagedGrants emits only the three known reason
// formats): a reason without a closed code omits pendingReasons from the
// wire (never [] and never a partial list), and completeness is part of
// the local ack cache key.
func TestGrantSyncUnmappedReasonSemantics(t *testing.T) {
	// Classification is prefix-based and detects unmapped reasons.
	reasons, unmapped := ackPendingReasons(map[string]string{
		"Codex":       "default directory not found: /home/x/unknown tool/.codex/sessions",
		"FutureTool":  "unknown tool: not supported by this collector version",
		"Claude Code": "default-directory grant is manually disabled; re-enable it (toktrail sources enable) to resume collection",
		"OddTool":     "some future restriction format",
	})
	if !sameAckedPendingReasons(reasons, map[string]string{
		"Codex": "missing_input", "FutureTool": "unsupported_tool", "Claude Code": "disabled",
	}) {
		t.Fatalf("unexpected mapped reasons: %#v", reasons)
	}
	if len(unmapped) != 1 || unmapped[0] != "OddTool" {
		t.Fatalf("unexpected unmapped tools: %#v", unmapped)
	}

	tools := expectedAckSupportedTools()

	// Complete mapping (no restriction): pendingReasons serializes as [].
	complete := ackRequestFor(7, "applied", "", tools, nil, false)
	if complete.PendingReasons == nil || len(*complete.PendingReasons) != 0 {
		t.Fatalf("a complete applied report must carry an explicit empty pendingReasons, got %#v", complete.PendingReasons)
	}
	// Complete mapping with restrictions: the codes travel.
	completePending := ackRequestFor(7, "pending", "", tools, map[string]string{"Codex": "missing_input"}, false)
	if completePending.PendingReasons == nil || len(*completePending.PendingReasons) != 1 ||
		(*completePending.PendingReasons)[0] != (synccmd.GrantAckPendingReason{Tool: "Codex", Code: "missing_input"}) {
		t.Fatalf("a complete restricted report must carry its codes, got %#v", completePending.PendingReasons)
	}
	// Unmapped reason: the field is omitted entirely (unknown), while the
	// supported-tools report still travels.
	incomplete := ackRequestFor(7, "pending", "", tools, reasons, true)
	if incomplete.PendingReasons != nil || incomplete.SupportedTools == nil {
		t.Fatalf("an unmapped reason must omit pendingReasons but keep supportedTools, got %#v", incomplete)
	}

	// The cache key covers completeness: complete vs incomplete re-acks
	// the same revision in both directions, and while incomplete the
	// unchanged wire payload (omitted reasons) stays current even when
	// the mapped subset shifts.
	base := managedconsent.Overlay{
		AckedRevision: 7, AckedApplyState: "pending", AckedCollectorVersion: "",
		AckedSupportedTools: tools, AckedPendingReasons: map[string]string{"Codex": "missing_input"},
	}
	if !ackedPayloadCurrent(base, 7, "pending", "", tools, map[string]string{"Codex": "missing_input"}, false) {
		t.Fatal("an unchanged complete report must be current")
	}
	if ackedPayloadCurrent(base, 7, "pending", "", tools, map[string]string{"Codex": "missing_input"}, true) {
		t.Fatal("a completeness change must re-ack")
	}
	incompleteAck := managedconsent.Overlay{
		AckedRevision: 7, AckedApplyState: "pending", AckedCollectorVersion: "",
		AckedSupportedTools: tools, AckedReasonsIncomplete: true,
	}
	if !ackedPayloadCurrent(incompleteAck, 7, "pending", "", tools, map[string]string{"Codex": "missing_input", "Other": "disabled"}, true) {
		t.Fatal("an unchanged incomplete report is wire-identical and must stay current")
	}
	if ackedPayloadCurrent(incompleteAck, 7, "pending", "", tools, nil, false) {
		t.Fatal("restrictions clearing (incomplete -> complete []) must re-ack")
	}
}

// The tool-status channel uses the same fixed-prefix classification: a
// default-directory path containing the classification words must not
// flip the reported status, and a reason with no known format is omitted
// rather than given a fabricated path-specific detail.
func TestGrantSyncPendingToolStatusesResistPathWords(t *testing.T) {
	statuses := pendingToolStatuses(map[string]string{
		"Codex":   "default directory not found: /tmp/unknown tool/manually disabled/.codex/sessions",
		"Future":  "unknown tool: not supported by this collector version",
		"Claude":  "default-directory grant is manually disabled; re-enable it (toktrail sources enable) to resume collection",
		"Mystery": "some future restriction format",
	})
	if len(statuses) != 3 {
		t.Fatalf("the unmapped tool must be omitted, got %#v", statuses)
	}
	byTool := map[string]synccmd.ToolStatus{}
	for _, s := range statuses {
		byTool[s.Tool] = s
	}
	if s := byTool["Codex"]; s.Status != "not_detected" || s.Detail != "default directory not found" {
		t.Fatalf("path words must not flip the missing-directory status, got %#v", s)
	}
	if s := byTool["Future"]; s.Status != "unsupported" || s.Detail != "unsupported tool" {
		t.Fatalf("unexpected unsupported status, got %#v", s)
	}
	if s := byTool["Claude"]; s.Status != "not_detected" || s.Detail != "default directory grant disabled" {
		t.Fatalf("unexpected disabled status, got %#v", s)
	}
	if _, ok := byTool["Mystery"]; ok {
		t.Fatalf("an unmappable reason must not be reported with a fabricated detail, got %#v", byTool["Mystery"])
	}
}

// A default-directory path that literally contains the classification
// words ("unknown tool", "manually disabled") must not flip the closed
// reason code: matching is by fixed reason prefix, never substring. The
// free-text reason (with its path) never travels — only the code does.
func TestGrantSyncAckPendingReasonsResistPathWords(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Codex", "FutureTool"}, 45)
	bindDevice(t, stateDir, server.URL)

	// The home directory name carries both classification words; Codex's
	// missing default directory therefore embeds them in its reason text.
	home := filepath.Join(t.TempDir(), "unknown tool", "manually disabled")

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("the run must still ack as pending, got %#v", res.GrantSync)
	}
	last := server.lastAckBody()
	if last.ApplyState != "pending" {
		t.Fatalf("expected applyState=pending, got %#v", last)
	}
	want := []grantAckPendingReasonBody{
		{Tool: "Codex", Code: "missing_input"},
		{Tool: "FutureTool", Code: "unsupported_tool"},
	}
	if len(last.PendingReasons) != 2 || last.PendingReasons[0] != want[0] || last.PendingReasons[1] != want[1] {
		t.Fatalf("path words must not change the closed codes, got %#v (want %#v)", last.PendingReasons, want)
	}
	for _, raw := range server.allAckRawBodies() {
		if strings.Contains(raw, home) {
			t.Fatalf("the ack payload must not contain the local path: %s", raw)
		}
	}
	o := loadOverlayForTest(t, stateDir)
	if !sameAckedPendingReasons(o.AckedPendingReasons, map[string]string{"Codex": "missing_input", "FutureTool": "unsupported_tool"}) {
		t.Fatalf("the overlay must cache the correctly classified codes, got %#v", o.AckedPendingReasons)
	}
}

// When the legacy retry fails too (the 400/422 was not about the
// capability fields after all), the run keeps today's ordinary ack
// semantics: the failure is non-fatal, nothing is acknowledged, both
// attempts are visible, and the next run retries.
func TestGrantSyncLegacyFallbackFailureIsOrdinaryAckFailure(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 44)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	// Every grant-ack is rejected with 400 and an empty body.
	server.mu.Lock()
	server.ackStatus = http.StatusBadRequest
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("an ack failure must not fail the run: %v", err)
	}
	if res.GrantSync.Acked {
		t.Fatalf("nothing may be acknowledged when both payloads fail, got %#v", res.GrantSync)
	}
	// Exactly two attempts: the capability payload, then the legacy
	// fallback. No silent swallowing, no further retries this run.
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("expected the capability attempt plus one legacy retry, got %d", got)
	}
	bodies := server.allAckBodies()
	if !bodies[0].carriesCapabilities() || bodies[1].carriesCapabilities() {
		t.Fatalf("expected capability-then-legacy attempts, got %#v", bodies)
	}
	if res.GrantSync.Note == "" || !strings.Contains(res.GrantSync.Note, "grant ack not confirmed") {
		t.Fatalf("the dual failure must surface as the ordinary ack note, got %q", res.GrantSync.Note)
	}
	if !strings.Contains(res.GrantSync.Note, "capability-fields rejection") {
		t.Fatalf("the note must keep the original rejection visible, got %q", res.GrantSync.Note)
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 0 || len(o.AckedSupportedTools) != 0 {
		t.Fatalf("no ack may be recorded when both payloads fail, got %#v", o)
	}
}

// An old server that rejects the unknown capability fields gets exactly
// one explicit legacy-shape retry. The fallback is honest: the overlay
// never records the capability report as delivered (so it is retried on
// the next run and never faked), the run still succeeds, and the
// downgrade is surfaced as a note rather than silently swallowed.
func TestGrantSyncLegacyServerCapabilityFallback(t *testing.T) {
	stateDir := t.TempDir()
	server := grantProtocolServerStart(t)
	server.setView(t, false, []string{"Claude Code"}, 43)
	bindDevice(t, stateDir, server.URL)
	enableIdleGrant(t, stateDir)

	server.mu.Lock()
	server.rejectAckCapabilities = true
	server.mu.Unlock()

	res, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("the legacy fallback must not fail the run: %v", err)
	}
	if !res.GrantSync.Acked {
		t.Fatalf("the legacy payload ack must be confirmed, got %#v", res.GrantSync)
	}
	if got := server.ackRequests(); got != 2 {
		t.Fatalf("expected one rejected capability ack plus one legacy ack, got %d", got)
	}
	bodies := server.allAckBodies()
	raw := server.allAckRawBodies()
	if len(bodies) != 2 || len(raw) != 2 {
		t.Fatalf("expected two ack requests, got %d", len(bodies))
	}
	if !bodies[0].carriesCapabilities() || !strings.Contains(raw[0], "supportedTools") {
		t.Fatalf("the first attempt must carry the capability report, got %s", raw[0])
	}
	if bodies[1].carriesCapabilities() || strings.Contains(raw[1], "supportedTools") || strings.Contains(raw[1], "pendingReasons") {
		t.Fatalf("the fallback payload must be byte-legacy, got %s", raw[1])
	}
	o := loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 43 || len(o.AckedSupportedTools) != 0 || o.AckedPendingReasons != nil {
		t.Fatalf("a legacy-confirmed ack must never claim the capability report, got %#v", o)
	}
	if res.GrantSync.Note == "" || !strings.Contains(res.GrantSync.Note, "legacy payload") {
		t.Fatalf("the downgrade must be surfaced as a note, got %q", res.GrantSync.Note)
	}

	// Next run: the cached capability payload (none delivered) never
	// satisfies the desired report, so the capability fields are
	// re-attempted first and fall back again. Still never faked.
	res2, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.GrantSync.Acked {
		t.Fatalf("the second legacy fallback must also be confirmed, got %#v", res2.GrantSync)
	}
	if got := server.ackRequests(); got != 4 {
		t.Fatalf("the capability report must be retried each run against the old server, got %d acks", got)
	}
	bodies = server.allAckBodies()
	if !bodies[2].carriesCapabilities() || bodies[3].carriesCapabilities() {
		t.Fatalf("expected attempt-then-fallback again, got %#v", bodies)
	}
	o = loadOverlayForTest(t, stateDir)
	if o.AckedRevision != 43 || len(o.AckedSupportedTools) != 0 {
		t.Fatalf("the capability report must still not be claimed as delivered, got %#v", o)
	}

	// The server is upgraded to accept the capability fields: the very
	// next run delivers the report on the first attempt and the overlay
	// finally records it.
	server.mu.Lock()
	server.rejectAckCapabilities = false
	server.mu.Unlock()
	res3, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res3.GrantSync.Acked {
		t.Fatalf("the upgraded server must confirm the capability ack, got %#v", res3.GrantSync)
	}
	if got := server.ackRequests(); got != 5 {
		t.Fatalf("expected exactly one ack against the upgraded server, got %d", got)
	}
	if last := server.lastAckBody(); !sameAckedTools(last.SupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("the delivered capability list must be current, got %#v", last.SupportedTools)
	}
	o = loadOverlayForTest(t, stateDir)
	if !sameAckedTools(o.AckedSupportedTools, expectedAckSupportedTools()) {
		t.Fatalf("the overlay must record the delivered capability list, got %#v", o.AckedSupportedTools)
	}
	if res3.GrantSync.Note != "" && strings.Contains(res3.GrantSync.Note, "legacy payload") {
		t.Fatalf("a successful capability ack must not carry the downgrade note, got %q", res3.GrantSync.Note)
	}

	// And the delivered report settles: no further acks while unchanged.
	if _, err := Run(t.Context(), Options{StateDir: stateDir, HomeDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := server.ackRequests(); got != 5 {
		t.Fatalf("a delivered, unchanged capability payload must not re-ack, got %d acks", got)
	}
}
