package resync

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// This file mirrors the consent-scope semantics that live unexported in
// internal/syncclient (reorg.go liveScopeFromSelf/evaluateRecord/fingerprint,
// sync.go preflightSelf/checkNotPaused). resync uses the mirrors only to
// PLAN and to classify outcomes; the authoritative enforcement of every
// upload remains syncclient.Run's own fresh preflight and local scope gate,
// which re-checks the live consent on every POST. The mirror must stay in
// lockstep with those semantics: non-empty allowed-tools means membership,
// historyFrom is inclusive, uploadUntil is exclusive, and anything that
// cannot be evaluated is an error — unknown never becomes zero.

// pausedToolSentinel mirrors syncclient's paused marker in allowedTools.
const pausedToolSentinel = "__toktrail_paused__"

// devicePaused mirrors syncclient.checkNotPaused: only grant-protocol
// snapshots can pause; the explicit flag or the allowedTools sentinel both
// count. Old-protocol snapshots never pause.
func devicePaused(self syncclient.SelfStatus) bool {
	if self.GrantProtocolVersion == nil {
		return false
	}
	if self.Paused {
		return true
	}
	for _, tool := range self.AllowedTools {
		if strings.TrimSpace(tool) == pausedToolSentinel {
			return true
		}
	}
	return false
}

// liveScope mirrors syncclient's scope snapshot, always derived from a fresh
// GET /v1/devices/self, never from a rejected request, and never guessed.
type liveScope struct {
	revision     int64
	historyFrom  *time.Time
	uploadUntil  *time.Time
	allowedTools map[string]struct{}
}

// scopeFromSelf mirrors syncclient.liveScopeFromSelf plus the legacy
// never-widen adjustment of syncclient.preflightSelf: on old-protocol
// servers the bind-time cutoff stays authoritative. A missing or
// non-positive revision means the scope is unknown: fail closed, never
// treat unknown as unrestricted.
func scopeFromSelf(self syncclient.SelfStatus, st statedir.DeviceState) (liveScope, error) {
	if strings.TrimSpace(self.DeviceID) == "" || self.ConsentRevision <= 0 {
		return liveScope{}, fmt.Errorf("device self status does not report a valid consent revision (%d); the consent scope is unknown, so resync fails closed without retransmitting anything", self.ConsentRevision)
	}
	if self.GrantProtocolVersion == nil && st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
		if self.HistoryFrom == nil || self.HistoryFrom.Before(*st.HistoryFrom) {
			hf := *st.HistoryFrom
			self.HistoryFrom = &hf
		}
	}
	scope := liveScope{revision: self.ConsentRevision, historyFrom: self.HistoryFrom, uploadUntil: self.UploadUntil}
	if len(self.AllowedTools) > 0 {
		scope.allowedTools = make(map[string]struct{}, len(self.AllowedTools))
		for _, tool := range self.AllowedTools {
			// The paused sentinel is handled by devicePaused before any
			// scope evaluation runs; filtering it here keeps the mirror
			// from treating it as a real tool name.
			if trimmed := strings.TrimSpace(tool); trimmed != "" && trimmed != pausedToolSentinel {
				scope.allowedTools[trimmed] = struct{}{}
			}
		}
	}
	return scope, nil
}

// evaluateRecord mirrors syncclient liveScope.evaluateRecord exactly. The
// quarantine reason constants are reused verbatim so reports speak the same
// vocabulary as the pending-batch reorganization path.
func (s liveScope) evaluateRecord(raw json.RawMessage) (bool, string, error) {
	var probe struct {
		RecordKey  string `json:"recordKey"`
		Tool       string `json:"tool"`
		OccurredAt string `json:"occurredAt"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false, "", fmt.Errorf("cannot evaluate record against the consent scope: %w", err)
	}
	if strings.TrimSpace(probe.RecordKey) == "" {
		return false, "", errors.New("record has no recordKey; cannot evaluate it against the consent scope, failing closed")
	}
	if strings.TrimSpace(probe.OccurredAt) == "" {
		return false, "", fmt.Errorf("record %s has no occurredAt; cannot evaluate it against the consent scope, failing closed", probe.RecordKey)
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(probe.OccurredAt))
	if err != nil {
		return false, "", fmt.Errorf("record %s has unparseable occurredAt %q: %w", probe.RecordKey, probe.OccurredAt, err)
	}
	if len(s.allowedTools) > 0 {
		if _, ok := s.allowedTools[probe.Tool]; !ok {
			return false, quarantine.ReasonToolNotAllowed, nil
		}
	}
	if s.historyFrom != nil && occurredAt.Before(*s.historyFrom) {
		return false, quarantine.ReasonBeforeHistoryFrom, nil
	}
	if s.uploadUntil != nil && !occurredAt.Before(*s.uploadUntil) {
		return false, quarantine.ReasonAfterUploadUntil, nil
	}
	return true, "", nil
}

// recordKeyOf extracts the record key of one raw record (the stable server
// de-duplication identity), mirroring syncclient.recordKeyOf.
func recordKeyOf(raw json.RawMessage) (string, error) {
	var probe struct {
		RecordKey string `json:"recordKey"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	key := strings.TrimSpace(probe.RecordKey)
	if key == "" {
		return "", errors.New("record has no recordKey")
	}
	return key, nil
}

// fingerprint mirrors syncclient liveScope.fingerprint: a deterministic
// rendering of the scope CONTENT (not the revision) so derived child batch
// identities differ whenever the scope content differs.
func (s liveScope) fingerprint() string {
	tools := make([]string, 0, len(s.allowedTools))
	for tool := range s.allowedTools {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	probe := struct {
		HistoryFrom  *time.Time `json:"historyFrom,omitempty"`
		UploadUntil  *time.Time `json:"uploadUntil,omitempty"`
		AllowedTools []string   `json:"allowedTools,omitempty"`
	}{s.historyFrom, s.uploadUntil, tools}
	b, err := json.Marshal(probe)
	if err != nil {
		return ""
	}
	return string(b)
}

// sortedTools renders the scope's allowed tools deterministically.
func (s liveScope) sortedTools() []string {
	tools := make([]string, 0, len(s.allowedTools))
	for tool := range s.allowedTools {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools
}

// snapshotScope freezes the live scope into its durable journal form so a
// later resume can tell exactly which authorization the job's recorded
// done/skip decisions were made under.
func snapshotScope(scope liveScope) *jobScope {
	return &jobScope{
		Revision:     scope.revision,
		Fingerprint:  scope.fingerprint(),
		HistoryFrom:  scope.historyFrom,
		UploadUntil:  scope.uploadUntil,
		AllowedTools: scope.sortedTools(),
	}
}

// matches reports whether the recorded baseline still equals the fresh
// live scope. The revision is the server's authoritative consent version
// (a consent change always bumps it), and the fingerprint comparison
// additionally fails closed when the scope content changed without a
// revision bump — the same never-guess rule syncclient applies to
// reorganizations.
func (s *jobScope) matches(scope liveScope) bool {
	if s == nil || s.Revision != scope.revision {
		return false
	}
	return s.Fingerprint == scope.fingerprint()
}

// describeScopeChange renders the divergence between a job's recorded
// baseline and the fresh live scope for stop messages. legacyRevision is
// the per-batch attributed revision of a journal without a recorded scope
// snapshot; zero means the decisions could not be attributed at all.
func describeScopeChange(old *jobScope, legacyRevision int64, fresh liveScope) string {
	renderTime := func(t *time.Time) string {
		if t == nil {
			return "(none)"
		}
		return t.UTC().Format(time.RFC3339)
	}
	renderTools := func(tools []string) string {
		if len(tools) == 0 {
			return "(any)"
		}
		return "[" + strings.Join(tools, ",") + "]"
	}
	if old == nil {
		if legacyRevision > 0 {
			return fmt.Sprintf("consent revision %d -> %d (the job's scope content was not recorded)", legacyRevision, fresh.revision)
		}
		return fmt.Sprintf("consent revision mixed or unrecorded -> %d", fresh.revision)
	}
	parts := []string{fmt.Sprintf("consent revision %d -> %d", old.Revision, fresh.revision)}
	if !sameTimePtr(old.HistoryFrom, fresh.historyFrom) {
		parts = append(parts, fmt.Sprintf("historyFrom %s -> %s", renderTime(old.HistoryFrom), renderTime(fresh.historyFrom)))
	}
	if !sameTimePtr(old.UploadUntil, fresh.uploadUntil) {
		parts = append(parts, fmt.Sprintf("uploadUntil %s -> %s", renderTime(old.UploadUntil), renderTime(fresh.uploadUntil)))
	}
	freshTools := fresh.sortedTools()
	if !sameStrings(old.AllowedTools, freshTools) {
		parts = append(parts, fmt.Sprintf("allowedTools %s -> %s", renderTools(old.AllowedTools), renderTools(freshTools)))
	}
	return strings.Join(parts, "; ")
}

func sameTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

// selfDrift reports whether an observed device self snapshot (the one
// syncclient prefetched for an upload, or a fresh completion check) no
// longer equals the scope this run derived its keep/skip decisions from,
// with a human-readable description of the divergence. An unevaluable
// snapshot counts as drift: unknown never becomes unchanged.
func selfDrift(planned liveScope, self syncclient.SelfStatus, st statedir.DeviceState) (bool, string) {
	live, err := scopeFromSelf(self, st)
	if err != nil {
		return true, err.Error()
	}
	if live.revision == planned.revision && live.fingerprint() == planned.fingerprint() {
		return false, ""
	}
	return true, describeScopeChange(snapshotScope(planned), 0, live)
}
