package syncclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
)

// Scope reorganization: when the server rejects an outbox batch with
// scope_changed/outside_scope, the collector persistently re-batches it under
// the live consent scope instead of leaving the batch to block the outbox
// head forever. The old batch file and its records stay byte-identical; kept
// records move to a brand-new batch with new deterministic ID; out-of-scope
// records are quarantined recoverably (never counted accepted, never
// advancing a baseline); the outbox head is freed either way.
//
// The whole migration is driven by a write-ahead journal
// (scope-reorg-transaction.json) that is committed atomically and replayed
// idempotently at the start of the next run after a crash, so a half-applied
// migration can neither lose records nor double-count them.

// maxRecordsPerBatch mirrors the server's per-batch record cap; reorg and
// recovery batches never exceed it.
const maxRecordsPerBatch = 500

const reorgJournalFileName = "scope-reorg-transaction.json"

// liveScope is the consent scope snapshot a reorganization decision is made
// against. It is always derived from a fresh GET /v1/devices/self, never from
// the rejected request, and never guessed.
type liveScope struct {
	revision     int64
	historyFrom  *time.Time
	uploadUntil  *time.Time
	allowedTools map[string]struct{}
}

// liveScopeFromSelf builds a scope from a self snapshot. A missing or
// non-positive revision means the scope is unknown: fail closed, never treat
// unknown as unrestricted.
func liveScopeFromSelf(self SelfStatus) (liveScope, error) {
	if strings.TrimSpace(self.DeviceID) == "" || self.ConsentRevision <= 0 {
		return liveScope{}, fmt.Errorf("device self status does not report a valid consent revision (%d); the consent scope is unknown, so the collector fails closed without moving, quarantining, or recovering any record", self.ConsentRevision)
	}
	scope := liveScope{revision: self.ConsentRevision, historyFrom: self.HistoryFrom, uploadUntil: self.UploadUntil}
	if len(self.AllowedTools) > 0 {
		scope.allowedTools = make(map[string]struct{}, len(self.AllowedTools))
		for _, tool := range self.AllowedTools {
			if trimmed := strings.TrimSpace(tool); trimmed != "" {
				scope.allowedTools[trimmed] = struct{}{}
			}
		}
	}
	return scope, nil
}

// fingerprint renders the scope content (not the revision) deterministically
// so batch IDs derived from it differ whenever the scope content differs.
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

// evaluateRecord mirrors the server's per-record scope semantics exactly:
// non-empty allowed-tools means the record tool must be a member;
// historyFrom is inclusive; uploadUntil is exclusive. A record that cannot
// be evaluated (missing/unparseable occurredAt) is an error, never an
// out-of-scope verdict — unknown never becomes zero.
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

// recordKeyOf extracts just the record key for deterministic batch IDs.
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

// reorgBatchID derives a fixed-length, deterministic new batch ID for a
// scope reorganization: hash(origin batch + revision + scope content +
// sorted kept record keys). Identical inputs replay to the identical ID;
// different scope content or record sets under the same revision produce
// different batches instead of colliding.
func reorgBatchID(oldBatchID string, revision int64, scope liveScope, recordKeys []string) string {
	h := sha256.New()
	h.Write([]byte(oldBatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(revision, 10)))
	h.Write([]byte{0})
	h.Write([]byte(scope.fingerprint()))
	writeKeys(h, recordKeys)
	return "reorg-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// recoveryBatchID derives the deterministic batch ID for a quarantine
// recovery (hash of source + revision + sorted record keys).
func recoveryBatchID(source string, revision int64, recordKeys []string) string {
	h := sha256.New()
	h.Write([]byte(source))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(revision, 10)))
	writeKeys(h, recordKeys)
	return "recovery-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func writeKeys(h io.Writer, recordKeys []string) {
	sorted := append([]string(nil), recordKeys...)
	sort.Strings(sorted)
	for _, key := range sorted {
		h.Write([]byte{0})
		h.Write([]byte(key))
	}
}

const (
	MaxBatchRecords      = 500
	MaxBatchPayloadBytes = 768 * 1024 // 786432 bytes
)

// splitBatchID derives a fixed-length, deterministic new batch ID for a child
// chunk created by an oversize split (hash of oldBatchID + sorted record keys).
func splitBatchID(oldBatchID string, recordKeys []string) string {
	h := sha256.New()
	h.Write([]byte(oldBatchID))
	writeKeys(h, recordKeys)
	return "split-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// reorgBatchPlan is one new batch to create from a reorganization.
type reorgBatchPlan struct {
	BatchID string            `json:"batchId"`
	Source  string            `json:"source,omitempty"`
	Input   string            `json:"input,omitempty"`
	Records []json.RawMessage `json:"records"`
}

// reorgRecoveryItem re-pends one quarantined message interval under its
// recovery batch, restoring the recorded to-state verbatim.
type reorgRecoveryItem struct {
	Source    string                      `json:"source"`
	MessageID string                      `json:"messageId,omitempty"`
	RecordKey string                      `json:"recordKey"`
	BatchID   string                      `json:"batchId"`
	To        *progress.MessageUsageState `json:"to,omitempty"`
}

// reorgJournal is the write-ahead journal for both scope-error re-batching
// (kind "scope-error") and quarantine recovery (kind "quarantine-recovery").
// It is written (tmp+rename) before any state is touched, applied
// idempotently, and removed only after every step succeeded.
type reorgJournal struct {
	Kind            string              `json:"kind"`
	OldBatchID      string              `json:"oldBatchId,omitempty"`
	OldSource       string              `json:"oldSource,omitempty"`
	NewBatches      []reorgBatchPlan    `json:"newBatches,omitempty"`
	Quarantine      []quarantine.Entry  `json:"quarantine,omitempty"`
	Recover         []reorgRecoveryItem `json:"recover,omitempty"`
	ConsentRevision int64               `json:"consentRevision"`
	CreatedAt       time.Time           `json:"createdAt"`
}

func reorgJournalPath(stateDir string) string {
	return filepath.Join(stateDir, reorgJournalFileName)
}

func batchFilePath(stateDir, batchID string) string {
	return filepath.Join(stateDir, "batches", batchID+".json")
}

func writeReorgJournal(stateDir string, journal reorgJournal) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	tmp := reorgJournalPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, reorgJournalPath(stateDir))
}

func loadReorgJournal(stateDir string) (reorgJournal, bool, error) {
	b, err := os.ReadFile(reorgJournalPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return reorgJournal{}, false, nil
	}
	if err != nil {
		return reorgJournal{}, false, err
	}
	var journal reorgJournal
	if err := json.Unmarshal(b, &journal); err != nil {
		return reorgJournal{}, false, fmt.Errorf("corrupt %s: %w; failing closed", reorgJournalPath(stateDir), err)
	}
	if strings.TrimSpace(journal.Kind) == "" || (journal.Kind != "oversize-split" && journal.ConsentRevision <= 0) {
		return reorgJournal{}, false, fmt.Errorf("corrupt %s: missing kind or consent revision; failing closed", reorgJournalPath(stateDir))
	}
	return journal, true, nil
}

func removeReorgJournal(stateDir string) error {
	if err := os.Remove(reorgJournalPath(stateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// recoverPendingReorg replays a half-applied reorganization journal at run
// start. Every apply step is idempotent, so a crash at any point converges:
// records are never lost and never counted twice.
func recoverPendingReorg(stateDir string) error {
	journal, ok, err := loadReorgJournal(stateDir)
	if err != nil || !ok {
		return err
	}
	if err := applyReorgJournal(stateDir, journal); err != nil {
		return err
	}
	return removeReorgJournal(stateDir)
}

// commitReorgJournal durably commits a reorganization: journal first, apply,
// remove. A crash before removal leaves a replayable journal.
func commitReorgJournal(stateDir string, journal reorgJournal) error {
	if err := writeReorgJournal(stateDir, journal); err != nil {
		return err
	}
	if err := applyReorgJournal(stateDir, journal); err != nil {
		return err
	}
	return removeReorgJournal(stateDir)
}

// applyReorgJournal applies every step idempotently. Steps: write new batch
// files (verbatim records, new IDs) → mark the old batch reorganized → add
// the new batches to the outbox as pending → append quarantine entries →
// remove recovered entries from the quarantine store → migrate per-message
// pending intervals / cursor pointers. The old batch file is never modified.
func applyReorgJournal(stateDir string, journal reorgJournal) error {
	ledger := outbox.New(stateDir)
	out, err := ledger.Load()
	if err != nil {
		return err
	}
	existing := make(map[string]outbox.BatchEntry, len(out.Batches))
	for _, entry := range out.Batches {
		existing[entry.BatchID] = entry
	}
	// 1. New batch files: identical content on replay, divergence is fatal.
	for _, plan := range journal.NewBatches {
		if err := writeReorgBatchFile(stateDir, plan); err != nil {
			return err
		}
	}
	// 2. Old batch becomes terminally reorganized (content stays immutable).
	if journal.OldBatchID != "" {
		into := ""
		if len(journal.NewBatches) == 1 {
			into = journal.NewBatches[0].BatchID
		} else if len(journal.NewBatches) > 1 {
			childIDs := make([]string, len(journal.NewBatches))
			for i, b := range journal.NewBatches {
				childIDs[i] = b.BatchID
			}
			into = strings.Join(childIDs, ",")
		}
		if err := ledger.MarkReorganized(journal.OldBatchID, into, journal.ConsentRevision, journal.CreatedAt); err != nil {
			return err
		}
	}
	// 3. New batches join the outbox as pending, born under this revision.
	for _, plan := range journal.NewBatches {
		if prior, ok := existing[plan.BatchID]; ok && prior.Status == outbox.StatusSynced {
			return fmt.Errorf("reorg batch %s is already synced; refusing to reset it", plan.BatchID)
		}
		if _, err := ledger.AddPending(outbox.AddBatchOptions{
			BatchID:               plan.BatchID,
			File:                  batchFilePath(stateDir, plan.BatchID),
			Source:                plan.Source,
			Input:                 plan.Input,
			RecordCount:           len(plan.Records),
			OriginConsentRevision: journal.ConsentRevision,
		}); err != nil {
			return err
		}
	}
	// 4. Quarantined records persist recoverably.
	if len(journal.Quarantine) > 0 {
		if err := appendScopeQuarantine(stateDir, journal.Quarantine); err != nil {
			return err
		}
	}
	// 5. Recovered records leave the quarantine store. Removal is by
	// compound identity (source + record key): generic usage-json inputs
	// can share a record key across sources, and removing by key alone
	// could silently drop another source's quarantined record.
	if len(journal.Recover) > 0 {
		keys := make([]quarantine.RemoveKey, 0, len(journal.Recover))
		for _, item := range journal.Recover {
			keys = append(keys, quarantine.RemoveKey{Source: item.Source, RecordKey: item.RecordKey})
		}
		if err := quarantine.New(stateDir).Remove(keys); err != nil {
			return err
		}
	}
	// 6. Per-message state: kept intervals re-point to the new batch,
	// quarantined intervals are released and marked; recovered intervals are
	// re-pended under their recovery batch. Confirmed baselines never move.
	cursors := progress.New(stateDir)
	if journal.OldBatchID != "" && strings.TrimSpace(journal.OldSource) != "" {
		keepKeys := make([]string, 0)
		recordBatchIDs := make(map[string]string)
		for _, plan := range journal.NewBatches {
			for _, raw := range plan.Records {
				key, err := recordKeyOf(raw)
				if err != nil {
					return err
				}
				keepKeys = append(keepKeys, key)
				recordBatchIDs[key] = plan.BatchID
			}
		}
		marks := make(map[string]progress.MessageQuarantineMark, len(journal.Quarantine))
		for _, entry := range journal.Quarantine {
			marks[entry.RecordKey] = progress.MessageQuarantineMark{RecordKey: entry.RecordKey, Reason: entry.Reason}
		}
		newBatchID := ""
		if len(journal.NewBatches) == 1 {
			newBatchID = journal.NewBatches[0].BatchID
		}
		if len(keepKeys)+len(marks) > 0 {
			if err := cursors.ReorgMessageBatch(progress.ReorgMessageBatchOptions{
				Source:         journal.OldSource,
				OldBatchID:     journal.OldBatchID,
				NewBatchID:     newBatchID,
				RecordBatchIDs: recordBatchIDs,
				KeepKeys:       keepKeys,
				Quarantine:     marks,
				Revision:       journal.ConsentRevision,
			}); err != nil {
				return err
			}
		}
	}
	recoveryByBatch := make(map[string][]progress.MessagePendingUpdate)
	recoverySource := make(map[string]string)
	for _, item := range journal.Recover {
		if item.MessageID == "" {
			continue
		}
		recoveryByBatch[item.BatchID] = append(recoveryByBatch[item.BatchID], progress.MessagePendingUpdate{
			MessageID: item.MessageID,
			RecordKey: item.RecordKey,
			To:        item.To,
		})
		recoverySource[item.BatchID] = item.Source
	}
	for batchID, updates := range recoveryByBatch {
		if err := cursors.RecoverMessageQuarantine(recoverySource[batchID], batchID, updates); err != nil {
			return err
		}
	}
	// 7. Cursor pointers follow the batch migration (bookkeeping only;
	// confirmed state is untouchable here).
	if journal.OldBatchID != "" {
		for _, plan := range journal.NewBatches {
			if plan.Source == "" || plan.Input == "" {
				continue
			}
			if err := cursors.ReorgBatch(plan.Source, plan.Input, journal.OldBatchID, plan.BatchID, len(plan.Records)); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeReorgBatchFile writes one new batch file atomically. Records are
// copied verbatim; the only new content is the wrapper and batch ID. An
// existing identical file is a replay no-op; a conflicting file is fatal.
func writeReorgBatchFile(stateDir string, plan reorgBatchPlan) error {
	payload, err := json.Marshal(BatchRequest{BatchID: plan.BatchID, Records: plan.Records})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(batchFilePath(stateDir, plan.BatchID)), 0o700); err != nil {
		return err
	}
	if prior, err := os.ReadFile(batchFilePath(stateDir, plan.BatchID)); err == nil {
		var priorBatch BatchRequest
		if err := json.Unmarshal(prior, &priorBatch); err != nil || priorBatch.BatchID != plan.BatchID || len(priorBatch.Records) != len(plan.Records) {
			return fmt.Errorf("batch file %s already exists with different content; failing closed", batchFilePath(stateDir, plan.BatchID))
		}
		// Compare canonically: the journal file re-indents embedded
		// records when it round-trips through MarshalIndent, so raw byte
		// equality would spuriously fail on replay. Re-marshalling both
		// sides compacts them, making the comparison formatting-stable
		// while still rejecting genuinely different content.
		priorPayload, err := json.Marshal(priorBatch)
		if err != nil || !bytes.Equal(priorPayload, payload) {
			return fmt.Errorf("batch file %s already exists with different content; failing closed", batchFilePath(stateDir, plan.BatchID))
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := batchFilePath(stateDir, plan.BatchID) + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, batchFilePath(stateDir, plan.BatchID))
}

// pendingIntervalInfo ties one pending interval to its message identity and
// confirmed baseline so a quarantine entry can restore it verbatim later.
type pendingIntervalInfo struct {
	MessageID string
	Pending   *progress.MessagePendingInterval
	Confirmed *progress.MessageUsageState
}

// pendingIntervalsOf loads the per-message pending intervals of one source
// batch, keyed by record key, so quarantined entries can carry their exact
// message identity, interval endpoint, and pre-quarantine baseline.
func pendingIntervalsOf(stateDir, source, batchID string) (map[string]pendingIntervalInfo, error) {
	intervals := make(map[string]pendingIntervalInfo)
	if strings.TrimSpace(source) == "" {
		return intervals, nil
	}
	progress, _, err := progress.New(stateDir).MessageProgressFor(source)
	if err != nil {
		return nil, err
	}
	for messageID, entry := range progress {
		if entry.Pending != nil && entry.Pending.BatchID == batchID {
			intervals[entry.Pending.RecordKey] = pendingIntervalInfo{
				MessageID: messageID,
				Pending:   entry.Pending,
				Confirmed: entry.Confirmed,
			}
		}
	}
	return intervals, nil
}

// reorganizeBatchAfterScopeError durably re-batches an outbox batch the
// server just rejected with scope_changed/outside_scope. The batch content
// is immutable; kept records get a new deterministic batch, out-of-scope
// records are quarantined recoverably; either way the outbox head is freed.
// Every failure path leaves all state unchanged (the batch stays pending).
func reorganizeBatchAfterScopeError(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState, stateDir string, entry outbox.BatchEntry, batch BatchRequest) (reorgJournal, error) {
	// Durable authorization-attempt accounting before the extra self GET:
	// if this write fails, zero HTTP traffic of any kind happened.
	if _, err := outbox.New(stateDir).RecordPreflightAttempt(time.Now().UTC()); err != nil {
		return reorgJournal{}, fmt.Errorf("cannot persist preflight attempt accounting before re-reading the consent scope; batch %s stays pending and no records were moved: %w", batch.BatchID, err)
	}
	fresh, err := preflightSelf(ctx, client, serverURL, st)
	if err != nil {
		return reorgJournal{}, fmt.Errorf("cannot re-read the consent scope after the scope error; batch %s stays pending and no records were moved: %w", batch.BatchID, err)
	}
	scope, err := liveScopeFromSelf(fresh)
	if err != nil {
		return reorgJournal{}, fmt.Errorf("batch %s stays pending and no records were moved: %w", batch.BatchID, err)
	}
	if entry.OriginConsentRevision > 0 && entry.OriginConsentRevision >= scope.revision {
		return reorgJournal{}, fmt.Errorf("batch %s was already reorganized under consent revision %d but the server still rejects it at revision %d; the scope appears to have changed without a revision bump; failing closed with the batch pending and no records moved", batch.BatchID, entry.OriginConsentRevision, scope.revision)
	}
	return splitBatchUnderScope(stateDir, entry, batch, scope, "scope-error")
}

// splitBatchUnderScope partitions a batch against the live scope and
// durably publishes the result with zero network traffic: out-of-scope
// records are quarantined recoverably (carrying the scope revision so
// recovery needs a strictly newer one), in-scope records move to a new
// pending child batch, and the old batch becomes terminal so the outbox
// head can never block on them. Legitimate records keep draining.
func splitBatchUnderScope(stateDir string, entry outbox.BatchEntry, batch BatchRequest, scope liveScope, journalKind string) (reorgJournal, error) {
	if entry.OriginConsentRevision > 0 && entry.OriginConsentRevision >= scope.revision {
		return reorgJournal{}, fmt.Errorf("batch %s was already reorganized under consent revision %d but is still out of scope at revision %d; the scope appears to have changed without a revision bump; failing closed with the batch pending and no records moved", batch.BatchID, entry.OriginConsentRevision, scope.revision)
	}
	intervals, err := pendingIntervalsOf(stateDir, entry.Source, batch.BatchID)
	if err != nil {
		return reorgJournal{}, fmt.Errorf("cannot load pending intervals of batch %s; it stays pending and no records were moved: %w", batch.BatchID, err)
	}
	now := time.Now().UTC()
	keep := make([]json.RawMessage, 0, len(batch.Records))
	keepKeys := make([]string, 0, len(batch.Records))
	quarantineEntries := make([]quarantine.Entry, 0)
	for _, raw := range batch.Records {
		key, err := recordKeyOf(raw)
		if err != nil {
			return reorgJournal{}, fmt.Errorf("batch %s stays pending and no records were moved: %w", batch.BatchID, err)
		}
		inScope, reason, err := scope.evaluateRecord(raw)
		if err != nil {
			return reorgJournal{}, fmt.Errorf("batch %s stays pending and no records were moved: %w", batch.BatchID, err)
		}
		if inScope {
			keep = append(keep, raw)
			keepKeys = append(keepKeys, key)
			continue
		}
		qEntry := quarantine.Entry{
			RecordKey:       key,
			Record:          raw,
			OriginBatchID:   batch.BatchID,
			Reason:          reason,
			ConsentRevision: scope.revision,
			QuarantinedAt:   now,
			Source:          entry.Source,
			Input:           entry.Input,
		}
		if interval, ok := intervals[key]; ok {
			qEntry.MessageID = interval.MessageID
			qEntry.FromState = interval.Confirmed
			qEntry.ToState = interval.Pending.To
		}
		quarantineEntries = append(quarantineEntries, qEntry)
	}
	journal := reorgJournal{
		Kind:            journalKind,
		OldBatchID:      batch.BatchID,
		OldSource:       entry.Source,
		Quarantine:      quarantineEntries,
		ConsentRevision: scope.revision,
		CreatedAt:       now,
	}
	if len(keep) > 0 {
		journal.NewBatches = []reorgBatchPlan{{
			BatchID: reorgBatchID(batch.BatchID, scope.revision, scope, keepKeys),
			Source:  entry.Source,
			Input:   entry.Input,
			Records: keep,
		}}
	}
	if err := commitReorgJournal(stateDir, journal); err != nil {
		return reorgJournal{}, fmt.Errorf("committing the scope reorganization of batch %s failed; it stays pending and no records were moved: %w", batch.BatchID, err)
	}
	return journal, nil
}

// reorgSummary renders the human-readable outcome of a reorganization.
func reorgSummary(journal reorgJournal) string {
	kept := 0
	for _, plan := range journal.NewBatches {
		kept += len(plan.Records)
	}
	reasons := make(map[string]int)
	for _, entry := range journal.Quarantine {
		reasons[entry.Reason]++
	}
	parts := make([]string, 0, len(reasons))
	for _, reason := range sortedKeysOfMap(reasons) {
		parts = append(parts, fmt.Sprintf("%s=%d", reason, reasons[reason]))
	}
	summary := fmt.Sprintf("consent revision %d: %d record(s) kept", journal.ConsentRevision, kept)
	if len(journal.NewBatches) == 1 {
		summary += fmt.Sprintf(" in pending batch %s", journal.NewBatches[0].BatchID)
	} else {
		summary += " (no new batch)"
	}
	summary += fmt.Sprintf("; %d record(s) quarantined recoverably outside the scope", len(journal.Quarantine))
	if len(parts) > 0 {
		summary += " (" + strings.Join(parts, ", ") + ")"
	}
	summary += "; the old batch is immutable and terminal; the next sync uploads the reorganized batch"
	return summary
}

func sortedKeysOfMap(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// recoverQuarantinedWithScope recovers quarantined records that are back
// inside the live consent scope. Recovery requires the live revision to be
// strictly newer than the revision the record was quarantined under (no
// quarantine/recovery loops within one revision) and the current scope to
// allow the record. Original record keys and interval endpoints are kept
// verbatim, so the server's dedup makes a repeated recovery safe. Any
// inconsistency (missing progress entry, mismatched quarantine marker,
// changed confirmed baseline) fails closed and leaves everything
// quarantined.
func recoverQuarantinedWithScope(stateDir string, self SelfStatus) (int, error) {
	if strings.TrimSpace(stateDir) == "" {
		return 0, nil
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}
	scope, err := liveScopeFromSelf(self)
	if err != nil {
		return 0, err
	}
	cursors := progress.New(stateDir)
	fitting := make([]quarantine.Entry, 0, len(entries))
	for _, entry := range entries {
		if scope.revision <= entry.ConsentRevision {
			// Same (or older) revision: never auto-recover, the scope that
			// quarantined the record is still authoritative.
			continue
		}
		if entry.MessageID != "" {
			progress, _, err := cursors.MessageProgressFor(entry.Source)
			if err != nil {
				return 0, err
			}
			msg, ok := progress[entry.MessageID]
			if !ok {
				return 0, fmt.Errorf("quarantined message %s of source %s has no progress entry; failing closed and leaving everything quarantined", entry.MessageID, entry.Source)
			}
			if msg.QuarantinedKey != entry.RecordKey {
				return 0, fmt.Errorf("quarantine marker of message %s points at record %s, not %s; failing closed and leaving everything quarantined", entry.MessageID, msg.QuarantinedKey, entry.RecordKey)
			}
			if msg.Pending != nil {
				return 0, fmt.Errorf("quarantined message %s is also pending; state is inconsistent, failing closed and leaving everything quarantined", entry.MessageID)
			}
			if !msg.Confirmed.Equal(entry.FromState) {
				return 0, fmt.Errorf("confirmed baseline of message %s changed since it was quarantined; failing closed and leaving everything quarantined", entry.MessageID)
			}
		}
		inScope, _, err := scope.evaluateRecord(entry.Record)
		if err != nil {
			return 0, err
		}
		if inScope {
			fitting = append(fitting, entry)
		}
	}
	if len(fitting) == 0 {
		return 0, nil
	}
	bySource := make(map[string][]quarantine.Entry)
	sources := make([]string, 0)
	for _, entry := range fitting {
		if _, ok := bySource[entry.Source]; !ok {
			sources = append(sources, entry.Source)
		}
		bySource[entry.Source] = append(bySource[entry.Source], entry)
	}
	sort.Strings(sources)
	journal := reorgJournal{Kind: "quarantine-recovery", ConsentRevision: scope.revision, CreatedAt: time.Now().UTC()}
	recovered := 0
	for _, source := range sources {
		group := bySource[source]
		for start := 0; start < len(group); start += maxRecordsPerBatch {
			chunk := group[start:min(start+maxRecordsPerBatch, len(group))]
			keys := make([]string, 0, len(chunk))
			records := make([]json.RawMessage, 0, len(chunk))
			for _, entry := range chunk {
				keys = append(keys, entry.RecordKey)
				records = append(records, entry.Record)
			}
			batchID := recoveryBatchID(source, scope.revision, keys)
			journal.NewBatches = append(journal.NewBatches, reorgBatchPlan{
				BatchID: batchID,
				Source:  source,
				Input:   chunk[0].Input,
				Records: records,
			})
			for _, entry := range chunk {
				// Every recovered record leaves the quarantine store, not
				// only message-backed ones: applyReorgJournal removes
				// quarantine entries from the Recover items alone, so
				// skipping empty MessageIDs here would strand generic
				// (usage-json/Codex) records in quarantine forever and make
				// the next run re-recover the same already-synced batch.
				// Per-message interval restoration below still branches on
				// MessageID being non-empty.
				journal.Recover = append(journal.Recover, reorgRecoveryItem{
					Source:    entry.Source,
					MessageID: entry.MessageID,
					RecordKey: entry.RecordKey,
					BatchID:   batchID,
					To:        entry.ToState,
				})
			}
			recovered += len(chunk)
		}
	}
	if err := commitReorgJournal(stateDir, journal); err != nil {
		return 0, err
	}
	return recovered, nil
}

// recoverQuarantinedWithFreshSelf is the recovery-only path used when the
// outbox is empty but quarantined records exist. It performs exactly one
// self GET, preceded by durable attempt accounting; if that accounting
// cannot be written, zero HTTP traffic happens. No ingest POST is performed
// in this path.
func recoverQuarantinedWithFreshSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState, stateDir string) (SelfStatus, int, error) {
	if _, err := outbox.New(stateDir).RecordPreflightAttempt(time.Now().UTC()); err != nil {
		return SelfStatus{}, 0, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; nothing was recovered and no HTTP request was made: %w", err)
	}
	self, err := preflightSelf(ctx, client, serverURL, st)
	if err != nil {
		return SelfStatus{}, 0, err
	}
	recovered, err := recoverQuarantinedWithScope(stateDir, self)
	if err != nil {
		return SelfStatus{}, 0, err
	}
	return self, recovered, nil
}

// quarantineCount reports how many records currently sit in the quarantine
// store (0 when there is no state directory or no store file).
func quarantineCount(stateDir string) int {
	if strings.TrimSpace(stateDir) == "" {
		return 0
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0
	}
	return len(entries)
}

func compactRawRecord(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isOversizedBatch(batch BatchRequest) bool {
	if len(batch.Records) > MaxBatchRecords {
		return true
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return false
	}
	return len(payload) > MaxBatchPayloadBytes
}

// reorganizeOversizedBatch splits an oversized pending batch (> 500 records or > 768 KiB)
// into deterministic child batches (<= 500 records and <= 768 KiB compact body)
// via a write-ahead journal of kind "oversize-split".
func reorganizeOversizedBatch(stateDir string, entry outbox.BatchEntry, batch BatchRequest) (reorgJournal, error) {
	if len(batch.Records) == 0 {
		return reorgJournal{}, errors.New("cannot reorganize empty batch")
	}

	// 1. Validate each record and ensure none exceeds MaxBatchPayloadBytes (fail closed).
	compactRecords := make([]json.RawMessage, len(batch.Records))
	recordKeys := make([]string, len(batch.Records))
	for idx, raw := range batch.Records {
		compact, err := compactRawRecord(raw)
		if err != nil {
			return reorgJournal{}, fmt.Errorf("record %d invalid json: %w", idx, err)
		}
		if len(compact) > MaxBatchPayloadBytes {
			return reorgJournal{}, fmt.Errorf("record %d exceeds maximum allowed size (%d bytes > %d bytes); failing closed", idx, len(compact), MaxBatchPayloadBytes)
		}
		key, err := recordKeyOf(compact)
		if err != nil {
			return reorgJournal{}, fmt.Errorf("record %d missing recordKey: %w", idx, err)
		}
		compactRecords[idx] = compact
		recordKeys[idx] = key
	}

	// 2. Partition records into chunks: <= 500 records and compact envelope <= 768 KiB.
	const dummyOverhead = len(`{"batchId":"split-0123456789abcdef","records":[]}`)
	var chunks [][]json.RawMessage
	var chunkKeysList [][]string

	var currentChunk []json.RawMessage
	var currentKeys []string
	currentSize := dummyOverhead

	for idx, rec := range compactRecords {
		recSize := len(rec)
		if dummyOverhead+recSize > MaxBatchPayloadBytes {
			return reorgJournal{}, fmt.Errorf("record %d with envelope exceeds %d bytes; failing closed", idx, MaxBatchPayloadBytes)
		}
		projected := currentSize + recSize
		if len(currentChunk) > 0 {
			projected += 1 // comma separator
		}
		if len(currentChunk) > 0 && (len(currentChunk) >= MaxBatchRecords || projected > MaxBatchPayloadBytes) {
			chunks = append(chunks, currentChunk)
			chunkKeysList = append(chunkKeysList, currentKeys)
			currentChunk = nil
			currentKeys = nil
			currentSize = dummyOverhead
			projected = dummyOverhead + recSize
		}
		currentChunk = append(currentChunk, rec)
		currentKeys = append(currentKeys, recordKeys[idx])
		currentSize = projected
	}
	if len(currentChunk) > 0 {
		chunks = append(chunks, currentChunk)
		chunkKeysList = append(chunkKeysList, currentKeys)
	}

	plans := make([]reorgBatchPlan, len(chunks))
	for i, chunk := range chunks {
		childID := splitBatchID(batch.BatchID, chunkKeysList[i])
		testPayload, err := json.Marshal(BatchRequest{BatchID: childID, Records: chunk})
		if err != nil {
			return reorgJournal{}, fmt.Errorf("marshal child batch %s: %w", childID, err)
		}
		if len(testPayload) > MaxBatchPayloadBytes {
			return reorgJournal{}, fmt.Errorf("child batch %s envelope exceeds %d bytes; failing closed", childID, MaxBatchPayloadBytes)
		}
		plans[i] = reorgBatchPlan{
			BatchID: childID,
			Source:  entry.Source,
			Input:   entry.Input,
			Records: chunk,
		}
	}

	journal := reorgJournal{
		Kind:            "oversize-split",
		OldBatchID:      batch.BatchID,
		OldSource:       entry.Source,
		NewBatches:      plans,
		ConsentRevision: entry.OriginConsentRevision,
		CreatedAt:       time.Now().UTC(),
	}

	if err := commitReorgJournal(stateDir, journal); err != nil {
		return reorgJournal{}, fmt.Errorf("commit oversize-split reorg journal for %s: %w", batch.BatchID, err)
	}
	return journal, nil
}
