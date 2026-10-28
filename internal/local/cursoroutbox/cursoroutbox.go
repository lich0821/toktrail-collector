// Package cursoroutbox is the durable pending queue for account-level
// cursor source batches. It is deliberately separate from the device
// outbox (internal/local/outbox): cursor records never travel to the
// device ingest endpoint, and their upload authorization carries the
// source fence, not just the device consent revision.
//
// Durability protocol (crash-safe, replay-safe):
//
//   - AddBatch re-validates the encoded wire bytes itself
//     (protocol.DecodeBatch) and cross-checks them against the caller's
//     batch descriptor; it never trusts the caller's claim about the
//     bytes.
//   - The immutable batch file is staged as "<batchID>.json.tmp" with
//     O_EXCL, the ledger entry (referencing the final path) is saved
//     next, and only then is the temp file renamed into place. A crash
//     leaves either a temp file without a ledger entry (removed by
//     Recover — the round did not advance, the next pull re-produces the
//     records) or a ledger entry whose final file is still staged
//     (Recover completes the rename).
//   - Final files therefore never exist without a ledger entry, and no
//     step ever overwrites an existing file.
//   - A batch whose upload succeeded but whose MarkSynced crashed is
//     re-sent verbatim on the next drain; the server answers with a
//     replay receipt (same immutable bytes, same revision), so cold-start
//     replay is safe.
//   - Entries record the source fence they were created under; when the
//     server moves the fence, stale pending entries are fenced out
//     instead of re-sent.
package cursoroutbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
)

const (
	outboxFileName = "cursor-outbox.json"
	// BatchesDir is the directory holding the immutable batch files.
	BatchesDir = "cursor-batches"
	// tempSuffix marks a staged batch file whose commit may be incomplete.
	tempSuffix = ".tmp"

	StatusPending = "pending"
	StatusSynced  = "synced"
	// StatusFenced marks a pending batch created under a source fence the
	// server has since moved. Fenced batches are terminal: they are never
	// re-sent (the new executor re-pulls and re-uploads with fresh
	// revisions); their immutable files stay on disk for inspection.
	StatusFenced = "fenced"
)

// Entry is one pending or terminal batch record.
type Entry struct {
	BatchID          string    `json:"batchId"`
	File             string    `json:"file"`
	SourceInstanceID string    `json:"sourceInstanceId"`
	RecordCount      int       `json:"recordCount"`
	Revision         int64     `json:"revision"`
	FenceVersion     int64     `json:"fenceVersion"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"createdAt"`
	LastAttemptAt    time.Time `json:"lastAttemptAt,omitempty"`
	SyncedAt         time.Time `json:"syncedAt,omitempty"`
	ReceiptStatus    string    `json:"receiptStatus,omitempty"`
	AcceptedRecords  int       `json:"acceptedRecords"`
	RejectedRecords  int       `json:"rejectedRecords"`
}

// RecordError is one server-rejected record with its index in the batch
// and a stable, sanitized reason code (never free text).
type RecordError struct {
	Index int    `json:"index"`
	Code  string `json:"code,omitempty"`
}

// Receipt mirrors the device-batch ingest receipt shape
// (internal/syncclient.BatchReceipt) so the server can reuse the format.
type Receipt struct {
	BatchID         string        `json:"batchId"`
	Status          string        `json:"status"`
	AcceptedRecords int           `json:"acceptedRecords"`
	RejectedRecords int           `json:"rejectedRecords"`
	Replay          bool          `json:"replay"`
	ReceivedAt      time.Time     `json:"receivedAt"`
	RecordErrors    []RecordError `json:"recordErrors,omitempty"`
}

// Store reads and writes the cursor outbox under a state directory.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, outboxFileName) }

func (s Store) batchesDir() string { return filepath.Join(s.dir, BatchesDir) }

// finalPath resolves the immutable file path for batchID inside
// batchesDir. It refuses labels that could escape the directory.
func (s Store) finalPath(batchID string) (string, error) {
	if batchID == "" || batchID == "." || batchID == ".." ||
		strings.ContainsAny(batchID, `/\`) || filepath.Base(batchID) != batchID {
		return "", fmt.Errorf("unsafe cursor batch id %q", batchID)
	}
	dir := s.batchesDir()
	path := filepath.Join(dir, batchID+".json")
	if filepath.Dir(path) != dir {
		return "", fmt.Errorf("cursor batch id %q escapes the batches directory", batchID)
	}
	return path, nil
}

type outboxFile struct {
	Batches []Entry `json:"batches"`
}

func (s Store) Load() ([]Entry, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out outboxFile
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", s.Path(), err)
	}
	return out.Batches, nil
}

func (s Store) save(entries []Entry) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(outboxFile{Batches: entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

// AddBatch durably persists one batch. The encoded bytes are re-validated
// here (fail closed on unknown fields or any validation drift) and must
// describe exactly the caller's batch: same batch id, same source
// instance, same record count. The file is staged with O_EXCL (never
// overwriting), the ledger entry is saved, and the staged file is renamed
// into place last.
func (s Store) AddBatch(batch protocol.Batch, fenceVersion int64, encoded []byte) (Entry, error) {
	// Re-validate the wire bytes ourselves: never trust the caller.
	decoded, err := protocol.DecodeBatch(encoded)
	if err != nil {
		return Entry{}, fmt.Errorf("refusing to persist unvalidated cursor batch: %w", err)
	}
	if decoded.BatchID != batch.BatchID || decoded.SourceInstanceID != batch.SourceInstanceID || len(decoded.Records) != len(batch.Records) {
		return Entry{}, fmt.Errorf("cursor batch bytes do not match the batch descriptor")
	}
	finalPath, err := s.finalPath(batch.BatchID)
	if err != nil {
		return Entry{}, err
	}
	entries, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	for _, e := range entries {
		if e.BatchID == batch.BatchID {
			return Entry{}, fmt.Errorf("cursor batch %s already exists in the outbox", batch.BatchID)
		}
	}
	if err := os.MkdirAll(s.batchesDir(), 0o700); err != nil {
		return Entry{}, err
	}
	// An unregistered file already occupying the final path is a conflict:
	// the rename at the end of this protocol would silently overwrite it.
	// Never overwrite existing batch files — fail loudly instead.
	if _, statErr := os.Stat(finalPath); statErr == nil {
		return Entry{}, fmt.Errorf("cursor batch file for %s already exists without an outbox entry; refusing to overwrite", batch.BatchID)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return Entry{}, statErr
	}
	// Stage with O_EXCL: an existing staged file means a previous crashed
	// attempt whose ledger save never happened; fail loudly so Recover
	// can clean it rather than silently overwriting evidence.
	staged := finalPath + tempSuffix
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("stage cursor batch %s: %w", batch.BatchID, err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return Entry{}, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return Entry{}, err
	}
	if err := f.Close(); err != nil {
		return Entry{}, err
	}
	revision := int64(0)
	for _, r := range decoded.Records {
		if r.Revision > revision {
			revision = r.Revision
		}
	}
	entry := Entry{
		BatchID:          batch.BatchID,
		File:             finalPath,
		SourceInstanceID: batch.SourceInstanceID,
		RecordCount:      len(decoded.Records),
		Revision:         revision,
		FenceVersion:     fenceVersion,
		Status:           StatusPending,
		CreatedAt:        time.Now().UTC(),
	}
	entries = append(entries, entry)
	if err := s.save(entries); err != nil {
		// The ledger is authoritative: without it the staged file is an
		// orphan Recover will remove (the round did not advance).
		return Entry{}, err
	}
	if err := os.Rename(staged, finalPath); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// Recover completes or discards crashed AddBatch attempts:
//
//   - a ledger entry whose final file is missing but whose staged temp
//     exists: the ledger save succeeded and the rename crashed — complete
//     the rename (the batch is legitimately pending);
//   - a staged temp with no matching ledger entry: the ledger save
//     failed — remove it (the round did not advance, the next pull
//     re-produces the records; nothing is lost).
//
// It reports how many renames were completed and how many staged files
// were discarded.
func (s Store) Recover() (completed, discarded int, err error) {
	entries, err := s.Load()
	if err != nil {
		return 0, 0, err
	}
	known := make(map[string]bool, len(entries))
	for idx := range entries {
		known[entries[idx].BatchID] = true
		if _, statErr := os.Stat(entries[idx].File); errors.Is(statErr, os.ErrNotExist) {
			staged := entries[idx].File + tempSuffix
			if _, statErr := os.Stat(staged); statErr == nil {
				if err := os.Rename(staged, entries[idx].File); err != nil {
					return completed, discarded, err
				}
				completed++
			}
		}
	}
	// Discard staged files for batch ids the ledger never recorded.
	files, err := os.ReadDir(s.batchesDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return completed, discarded, err
	}
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".json"+tempSuffix) || f.IsDir() {
			continue
		}
		batchID := strings.TrimSuffix(strings.TrimSuffix(name, tempSuffix), ".json")
		if known[batchID] {
			continue
		}
		if err := os.Remove(filepath.Join(s.batchesDir(), name)); err != nil {
			return completed, discarded, err
		}
		discarded++
	}
	return completed, discarded, nil
}

// NextPending returns the oldest pending entry.
func (s Store) NextPending() (Entry, bool, error) {
	entries, err := s.Load()
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range entries {
		if e.Status == StatusPending {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

// LoadBatchBytes reads and re-validates the immutable batch file for an
// entry. Fail closed: the file must live in this store's batches
// directory, the wire bytes must re-validate, and the decoded batch must
// match the entry's recorded metadata (id, source instance, record count,
// revision, fence) before anything is uploaded.
func (s Store) LoadBatchBytes(entry Entry) (protocol.Batch, error) {
	if filepath.Dir(entry.File) != s.batchesDir() {
		return protocol.Batch{}, fmt.Errorf("cursor batch %s file is outside the batches directory", entry.BatchID)
	}
	b, err := os.ReadFile(entry.File)
	if err != nil {
		return protocol.Batch{}, err
	}
	batch, err := protocol.DecodeBatch(b)
	if err != nil {
		return protocol.Batch{}, fmt.Errorf("cursor batch %s failed re-validation: %w", entry.BatchID, err)
	}
	if batch.BatchID != entry.BatchID || batch.SourceInstanceID != entry.SourceInstanceID {
		return protocol.Batch{}, fmt.Errorf("cursor batch %s file content does not match its outbox entry", entry.BatchID)
	}
	if len(batch.Records) != entry.RecordCount {
		return protocol.Batch{}, fmt.Errorf("cursor batch %s carries %d records, its entry recorded %d", entry.BatchID, len(batch.Records), entry.RecordCount)
	}
	maxRev := int64(0)
	for _, r := range batch.Records {
		if r.Revision > maxRev {
			maxRev = r.Revision
		}
	}
	if maxRev != entry.Revision {
		return protocol.Batch{}, fmt.Errorf("cursor batch %s max revision %d does not match its entry revision %d", entry.BatchID, maxRev, entry.Revision)
	}
	return batch, nil
}

// MarkAttempt records an upload attempt timestamp.
func (s Store) MarkAttempt(batchID string, at time.Time) error {
	entries, err := s.Load()
	if err != nil {
		return err
	}
	for idx := range entries {
		if entries[idx].BatchID == batchID {
			entries[idx].LastAttemptAt = at.UTC()
			return s.save(entries)
		}
	}
	return nil
}

// MarkSynced records a FULLY acknowledged upload. A receipt with rejected
// records is not a full acknowledgment: the caller must surface the
// rejection and leave the batch pending instead of marking it synced.
func (s Store) MarkSynced(receipt Receipt) error {
	if receipt.RejectedRecords > 0 {
		return fmt.Errorf("cursor batch %s had %d record(s) rejected; refusing to mark the batch synced", receipt.BatchID, receipt.RejectedRecords)
	}
	entries, err := s.Load()
	if err != nil {
		return err
	}
	for idx := range entries {
		if entries[idx].BatchID == receipt.BatchID {
			entries[idx].Status = StatusSynced
			entries[idx].ReceiptStatus = strings.TrimSpace(receipt.Status)
			entries[idx].AcceptedRecords = receipt.AcceptedRecords
			entries[idx].RejectedRecords = receipt.RejectedRecords
			entries[idx].SyncedAt = receipt.ReceivedAt.UTC()
			if entries[idx].SyncedAt.IsZero() {
				entries[idx].SyncedAt = time.Now().UTC()
			}
			return s.save(entries)
		}
	}
	return nil
}

// MarkFenced terminally fences every pending entry whose fence version
// does not match the current server fence. It reports how many entries
// were fenced. Fenced entries are never re-sent; their files stay for
// inspection.
func (s Store) MarkFenced(currentFence int64) (int, error) {
	entries, err := s.Load()
	if err != nil {
		return 0, err
	}
	fenced := 0
	for idx := range entries {
		if entries[idx].Status == StatusPending && entries[idx].FenceVersion != currentFence {
			entries[idx].Status = StatusFenced
			fenced++
		}
	}
	if fenced == 0 {
		return 0, nil
	}
	if err := s.save(entries); err != nil {
		return 0, err
	}
	return fenced, nil
}

// MarkFencedForSource terminally fences every pending entry that can no
// longer upload under the given source identity: entries belonging to
// another source instance (after a server-side recreation the upload
// preflight rejects foreign source ids, so they would block the drain
// head forever) and entries recorded under a different fence version —
// the numbers alone are not discriminating enough, because a recreated
// source restarts its fence at 1 just like the old one. It reports how
// many entries were fenced. Fenced entries are never re-sent; their
// immutable files stay on disk for inspection and the recovery pull
// re-produces their events under the new source identity.
func (s Store) MarkFencedForSource(sourceInstanceID string, currentFence int64) (int, error) {
	entries, err := s.Load()
	if err != nil {
		return 0, err
	}
	fenced := 0
	for idx := range entries {
		if entries[idx].Status == StatusPending &&
			(entries[idx].SourceInstanceID != sourceInstanceID || entries[idx].FenceVersion != currentFence) {
			entries[idx].Status = StatusFenced
			fenced++
		}
	}
	if fenced == 0 {
		return 0, nil
	}
	if err := s.save(entries); err != nil {
		return 0, err
	}
	return fenced, nil
}

// CountPending returns the number of pending entries.
func (s Store) CountPending() (int, error) {
	entries, err := s.Load()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.Status == StatusPending {
			n++
		}
	}
	return n, nil
}

// Purge removes the outbox file, the batch files directory and the event
// cache (logout --purge-cache). Uploaded data is never touched.
func Purge(stateDir string) error {
	dir := strings.TrimSpace(stateDir)
	if err := os.Remove(filepath.Join(dir, outboxFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(filepath.Join(dir, BatchesDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
