package progress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// message-progress.json persists per-message confirmed usage baselines and
// pending intervals for incremental (interval) export sources such as
// claude-code-jsonl. Keys are source + "\x00" + message id, so message
// identity is exactly the API message id: moving, copying, or renaming log
// files never changes a baseline.
const messageProgressFileName = "message-progress.json"

// MessageUsageState is the four-counter snapshot of one message. A nil
// component means unknown, never zero.
type MessageUsageState struct {
	Input      *uint64 `json:"input,omitempty"`
	CacheRead  *uint64 `json:"cacheRead,omitempty"`
	CacheWrite *uint64 `json:"cacheWrite,omitempty"`
	Output     *uint64 `json:"output,omitempty"`
}

// Equal compares two states component-wise. Unknown (nil) never equals a
// known value, mirroring the never-treat-unknown-as-zero rule.
func (m *MessageUsageState) Equal(other *MessageUsageState) bool {
	if m == nil || other == nil {
		return m == nil && other == nil
	}
	left := [4]*uint64{m.Input, m.CacheRead, m.CacheWrite, m.Output}
	right := [4]*uint64{other.Input, other.CacheRead, other.CacheWrite, other.Output}
	for i := range left {
		if (left[i] == nil) != (right[i] == nil) {
			return false
		}
		if left[i] != nil && *left[i] != *right[i] {
			return false
		}
	}
	return true
}

// MessagePendingInterval describes one exported interval that is waiting for
// a batch ACK. While pending, the message is frozen: a new export never emits
// or re-baselines it, so a lost or duplicated batch can never double count.
type MessagePendingInterval struct {
	BatchID   string             `json:"batchId"`
	RecordKey string             `json:"recordKey"`
	To        *MessageUsageState `json:"to"`
}

// MessageProgress is the persisted per-message state.
type MessageProgress struct {
	// Confirmed is the last server-ACKed counted value (nil components stay
	// unknown). Nil means the message was never confirmed.
	Confirmed *MessageUsageState `json:"confirmed,omitempty"`
	// Pending freezes the message until its batch is ACKed.
	Pending *MessagePendingInterval `json:"pending,omitempty"`
	// RejectedKey/RejectedCode record the last server rejection for this
	// message so the exact same interval is never re-sent automatically.
	RejectedKey  string `json:"rejectedKey,omitempty"`
	RejectedCode string `json:"rejectedCode,omitempty"`
	// QuarantinedKey/QuarantinedReason/QuarantinedRevision mark a message
	// whose pending interval was released by a scope reorganization because
	// its record fell outside the live consent scope. Confirmed is untouched
	// (a quarantined record is never counted as accepted), Pending is nil,
	// and exports skip the message until scope recovery re-pends it.
	QuarantinedKey      string    `json:"quarantinedKey,omitempty"`
	QuarantinedReason   string    `json:"quarantinedReason,omitempty"`
	QuarantinedRevision int64     `json:"quarantinedRevision,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type messageProgressFile struct {
	Version  string                     `json:"version"`
	Messages map[string]MessageProgress `json:"messages"`
}

// MessagePendingUpdate is one message interval carried by an export
// transaction journal so a crash mid-commit cannot lose the freeze.
type MessagePendingUpdate struct {
	MessageID string             `json:"messageId"`
	RecordKey string             `json:"recordKey"`
	To        *MessageUsageState `json:"to"`
}

// MessageBatchConfirm applies one batch receipt to per-message state.
// RejectedKeys maps recordKey -> server error code.
type MessageBatchConfirm struct {
	BatchID      string            `json:"batchId"`
	RejectedKeys map[string]string `json:"rejectedKeys,omitempty"`
}

// ConfirmMessageBatchResult reports how many messages advanced or were
// rejected when a receipt was applied.
type ConfirmMessageBatchResult struct {
	Advanced int
	Rejected int
}

func (s Store) MessageProgressPath() string {
	return filepath.Join(s.dir, messageProgressFileName)
}

// LoadMessageProgress returns all per-message entries. existed reports
// whether the progress file exists; a corrupt file is always an error, never
// a silent re-baseline.
func (s Store) LoadMessageProgress() (map[string]MessageProgress, bool, error) {
	b, err := os.ReadFile(s.MessageProgressPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]MessageProgress{}, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var file messageProgressFile
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, true, fmt.Errorf("corrupt %s: %w", s.MessageProgressPath(), err)
	}
	if file.Messages == nil {
		file.Messages = map[string]MessageProgress{}
	}
	return file.Messages, true, nil
}

// MessageProgressFor returns the entries of one source keyed by message id.
// existed reports whether the progress file itself exists.
func (s Store) MessageProgressFor(source string) (map[string]MessageProgress, bool, error) {
	all, existed, err := s.LoadMessageProgress()
	if err != nil {
		return nil, existed, err
	}
	prefix := source + "\x00"
	out := make(map[string]MessageProgress, len(all))
	for key, entry := range all {
		if strings.HasPrefix(key, prefix) {
			out[strings.TrimPrefix(key, prefix)] = entry
		}
	}
	return out, existed, nil
}

func (s Store) saveMessageProgress(messages map[string]MessageProgress) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	file := messageProgressFile{Version: "1", Messages: messages}
	if file.Messages == nil {
		file.Messages = map[string]MessageProgress{}
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.MessageProgressPath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.MessageProgressPath())
}

// HasSource reports whether the cursor ledger contains any entry for source,
// i.e. whether the source was ever exported from this state directory.
func (s Store) HasSource(source string) (bool, error) {
	ledger, err := s.Load()
	if err != nil {
		return false, err
	}
	for _, cursor := range ledger.Cursors {
		if cursor.Source == source {
			return true, nil
		}
	}
	return false, nil
}

// ApplyMessagePending freezes the given message intervals under one batch.
// It is idempotent per batch: replaying the same export journal writes the
// same pending state. A message already pending in a different batch is an
// error (it should have been frozen in the adapter first).
func (s Store) ApplyMessagePending(source string, batchID string, updates []MessagePendingUpdate) error {
	source = strings.TrimSpace(source)
	batchID = strings.TrimSpace(batchID)
	if source == "" || batchID == "" {
		return errors.New("message progress update requires source and batch id")
	}
	if len(updates) == 0 {
		return nil
	}
	messages, _, err := s.LoadMessageProgress()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, update := range updates {
		if strings.TrimSpace(update.MessageID) == "" || strings.TrimSpace(update.RecordKey) == "" || update.To == nil {
			return fmt.Errorf("message progress update for source %s requires message id, record key, and to-state", source)
		}
		key := source + "\x00" + update.MessageID
		entry := messages[key]
		if entry.QuarantinedKey != "" {
			return fmt.Errorf("message %s is quarantined outside the consent scope (%s); scope recovery must re-pend it, not an export", update.MessageID, entry.QuarantinedReason)
		}
		if entry.Pending != nil && entry.Pending.BatchID != batchID {
			return fmt.Errorf("message %s already has a pending interval in batch %s; export again only after that batch is synced", update.MessageID, entry.Pending.BatchID)
		}
		entry.Pending = &MessagePendingInterval{BatchID: batchID, RecordKey: update.RecordKey, To: update.To}
		entry.UpdatedAt = now
		messages[key] = entry
	}
	return s.saveMessageProgress(messages)
}

// EstablishConfirmedBaseline sets or updates the confirmed baseline for messages
// without requiring an export batch. If a message has no confirmed baseline, it adopts
// update.To so historical tokens are never replayed as deltas later.
func (s Store) EstablishConfirmedBaseline(source string, updates []MessagePendingUpdate) error {
	source = strings.TrimSpace(source)
	if source == "" || len(updates) == 0 {
		return nil
	}
	messages, _, err := s.LoadMessageProgress()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	changed := false
	for _, update := range updates {
		if strings.TrimSpace(update.MessageID) == "" || update.To == nil {
			continue
		}
		key := source + "\x00" + update.MessageID
		entry := messages[key]
		if entry.Confirmed == nil {
			entry.Confirmed = update.To
			entry.UpdatedAt = now
			messages[key] = entry
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveMessageProgress(messages)
}

// ConfirmMessageBatch applies a batch receipt per message: accepted messages
// advance Confirmed to their pending to-state and unfreeze; rejected messages
// unfreeze but keep Confirmed and record the rejected interval key so it is
// never auto-resent (growth still exports delta-only under a new key). A
// rejected FIRST interval has no baseline to keep, so its to-state becomes the
// baseline: the rejected interval is never resent and later growth exports
// only the delta above it, never the full amount under a new key.
// Rejected messages never block accepted ones. Idempotent: a replayed ACK
// journal finds no matching pending intervals and changes nothing.
func (s Store) ConfirmMessageBatch(confirm MessageBatchConfirm) (ConfirmMessageBatchResult, error) {
	batchID := strings.TrimSpace(confirm.BatchID)
	if batchID == "" {
		return ConfirmMessageBatchResult{}, errors.New("message batch confirm requires batch id")
	}
	messages, _, err := s.LoadMessageProgress()
	if err != nil {
		return ConfirmMessageBatchResult{}, err
	}
	now := time.Now().UTC()
	result := ConfirmMessageBatchResult{}
	changed := false
	for key, entry := range messages {
		if entry.Pending == nil || entry.Pending.BatchID != batchID {
			continue
		}
		changed = true
		if code, rejected := confirm.RejectedKeys[entry.Pending.RecordKey]; rejected {
			entry.RejectedKey = entry.Pending.RecordKey
			entry.RejectedCode = code
			if entry.Confirmed == nil && entry.Pending.To != nil {
				// No prior baseline: adopt the rejected interval's to-state so
				// growth exports delta-only instead of the full amount.
				entry.Confirmed = entry.Pending.To
			}
			entry.Pending = nil
			result.Rejected++
		} else {
			entry.Confirmed = entry.Pending.To
			entry.Pending = nil
			result.Advanced++
		}
		entry.UpdatedAt = now
		messages[key] = entry
	}
	if !changed {
		return result, nil
	}
	return result, s.saveMessageProgress(messages)
}

// MessageQuarantineMark names one record key that a scope reorganization
// removed from its batch, with the human-readable reason it fell outside the
// live consent scope.
type MessageQuarantineMark struct {
	RecordKey string
	Reason    string
}

// ReorgMessageBatch migrates per-message pending intervals after a consent
// scope reorganization redistributed a batch:
//   - a kept record's pending interval is re-pointed to the new batch id
//     (still frozen, still awaiting the server ACK — only the batch id
//     changes, never the record key or to-state);
//   - a quarantined record's pending interval is released and the message is
//     marked quarantined. Confirmed stays untouched, so a quarantined record
//     is never counted as accepted and later scope recovery can re-send the
//     exact same interval without double counting.
//
// The migration is idempotent for journal replay. A pending record key that is
// neither kept nor quarantined is an error: the caller must fail closed
// instead of guessing where the record belongs.
func (s Store) ReorgMessageBatch(opt ReorgMessageBatchOptions) error {
	source := strings.TrimSpace(opt.Source)
	oldBatchID := strings.TrimSpace(opt.OldBatchID)
	newBatchID := strings.TrimSpace(opt.NewBatchID)
	if source == "" || oldBatchID == "" {
		return errors.New("message batch reorg requires source and old batch id")
	}
	if newBatchID == "" && len(opt.RecordBatchIDs) == 0 && len(opt.KeepKeys) > 0 {
		return errors.New("message batch reorg requires a new batch id when records are kept")
	}
	keep := make(map[string]bool, len(opt.KeepKeys))
	for _, key := range opt.KeepKeys {
		keep[strings.TrimSpace(key)] = true
	}
	for key := range keep {
		if _, quarantined := opt.Quarantine[key]; quarantined {
			return fmt.Errorf("record %s is both kept and quarantined by the reorg of batch %s", key, oldBatchID)
		}
	}
	messages, _, err := s.LoadMessageProgress()
	if err != nil {
		return err
	}
	prefix := source + "\x00"
	now := time.Now().UTC()
	changed := false
	for storageKey, entry := range messages {
		if !strings.HasPrefix(storageKey, prefix) {
			continue
		}
		if entry.Pending != nil && entry.Pending.BatchID == oldBatchID {
			recordKey := entry.Pending.RecordKey
			switch {
			case keep[recordKey]:
				targetBatchID := newBatchID
				if opt.RecordBatchIDs != nil && opt.RecordBatchIDs[recordKey] != "" {
					targetBatchID = opt.RecordBatchIDs[recordKey]
				}
				if targetBatchID == "" {
					return fmt.Errorf("record %s of batch %s kept without target batch id", recordKey, oldBatchID)
				}
				entry.Pending.BatchID = targetBatchID
			default:
				mark, quarantined := opt.Quarantine[recordKey]
				if !quarantined {
					return fmt.Errorf("record %s of batch %s is neither kept nor quarantined by the reorg; failing closed", recordKey, oldBatchID)
				}
				entry.QuarantinedKey = recordKey
				entry.QuarantinedReason = mark.Reason
				entry.QuarantinedRevision = opt.Revision
				entry.Pending = nil
			}
			entry.UpdatedAt = now
			messages[storageKey] = entry
			changed = true
			continue
		}
		if entry.Pending == nil && entry.QuarantinedKey != "" {
			// Idempotent replay: already released by this reorg.
			continue
		}
		if entry.Pending != nil {
			targetBatchID := newBatchID
			if opt.RecordBatchIDs != nil && opt.RecordBatchIDs[entry.Pending.RecordKey] != "" {
				targetBatchID = opt.RecordBatchIDs[entry.Pending.RecordKey]
			}
			if targetBatchID != "" && entry.Pending.BatchID == targetBatchID {
				// Idempotent replay: already re-pointed by this reorg.
				continue
			}
		}
	}
	if !changed {
		return nil
	}
	return s.saveMessageProgress(messages)
}

// ReorgMessageBatchOptions describes one scope reorganization of a batch's
// per-message state. KeepKeys are record keys that moved to NewBatchID;
// Quarantine maps removed record keys to their out-of-scope reason.
type ReorgMessageBatchOptions struct {
	Source         string
	OldBatchID     string
	NewBatchID     string
	RecordBatchIDs map[string]string
	KeepKeys       []string
	Quarantine     map[string]MessageQuarantineMark
	Revision       int64
}

// RecoverMessageQuarantine re-pends quarantined messages under a recovery
// batch: Pending is restored to the recorded interval (same record key,
// same to-state) and the quarantine marker is cleared. Confirmed is still
// untouched — only a server ACK may advance a baseline. The update must match
// the message's quarantine marker exactly; anything stale or inconsistent is
// an error so the caller can fail closed and keep the record quarantined.
// Idempotent per batch for journal replay.
func (s Store) RecoverMessageQuarantine(source, batchID string, updates []MessagePendingUpdate) error {
	source = strings.TrimSpace(source)
	batchID = strings.TrimSpace(batchID)
	if source == "" || batchID == "" {
		return errors.New("quarantine recovery requires source and batch id")
	}
	if len(updates) == 0 {
		return nil
	}
	messages, _, err := s.LoadMessageProgress()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	changed := false
	for _, update := range updates {
		if strings.TrimSpace(update.MessageID) == "" || strings.TrimSpace(update.RecordKey) == "" || update.To == nil {
			return fmt.Errorf("quarantine recovery for source %s requires message id, record key, and to-state", source)
		}
		key := source + "\x00" + update.MessageID
		entry := messages[key]
		if entry.QuarantinedKey == "" {
			if entry.Pending != nil && entry.Pending.BatchID == batchID && entry.Pending.RecordKey == update.RecordKey {
				// Idempotent replay.
				continue
			}
			return fmt.Errorf("message %s is not quarantined; recovery must not re-pend it", update.MessageID)
		}
		if entry.QuarantinedKey != update.RecordKey {
			return fmt.Errorf("message %s is quarantined for record %s, not %s; failing closed", update.MessageID, entry.QuarantinedKey, update.RecordKey)
		}
		if entry.Pending != nil {
			return fmt.Errorf("message %s is quarantined and pending at once; state is inconsistent", update.MessageID)
		}
		entry.Pending = &MessagePendingInterval{BatchID: batchID, RecordKey: update.RecordKey, To: update.To}
		entry.QuarantinedKey = ""
		entry.QuarantinedReason = ""
		entry.QuarantinedRevision = 0
		entry.UpdatedAt = now
		messages[key] = entry
		changed = true
	}
	if !changed {
		return nil
	}
	return s.saveMessageProgress(messages)
}
