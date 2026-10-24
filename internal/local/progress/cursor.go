package progress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cursorFileName = "adapter-cursors.json"

type Store struct{ dir string }

type Ledger struct {
	Cursors []Cursor `json:"cursors"`
}

type Cursor struct {
	Source               string     `json:"source"`
	InputHash            string     `json:"inputHash"`
	Input                string     `json:"input,omitempty"`
	BatchID              string     `json:"batchId"`
	RecordCount          int        `json:"recordCount"`
	AdvancedAt           time.Time  `json:"advancedAt"`
	ConfirmedBatchID     string     `json:"confirmedBatchId,omitempty"`
	ConfirmedRecordCount int        `json:"confirmedRecordCount,omitempty"`
	ConfirmedStatus      string     `json:"confirmedStatus,omitempty"`
	ConfirmedAt          *time.Time `json:"confirmedAt,omitempty"`
}

type AdvanceOptions struct {
	Source      string
	Input       string
	BatchID     string
	RecordCount int
	AdvancedAt  time.Time
}

type ConfirmOptions struct {
	Source      string
	Input       string
	BatchID     string
	RecordCount int
	Status      string
	ConfirmedAt time.Time
}

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, cursorFileName) }

func (s Store) Load() (Ledger, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Ledger{}, nil
	}
	if err != nil {
		return Ledger{}, err
	}
	var ledger Ledger
	if err := json.Unmarshal(b, &ledger); err != nil {
		return Ledger{}, err
	}
	return ledger, nil
}

func (s Store) Save(ledger Ledger) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

func (s Store) Advance(opt AdvanceOptions) (Cursor, error) {
	ledger, err := s.Load()
	if err != nil {
		return Cursor{}, err
	}
	cursor := Cursor{
		Source:      strings.TrimSpace(opt.Source),
		InputHash:   inputHash(opt.Input),
		Input:       strings.TrimSpace(opt.Input),
		BatchID:     strings.TrimSpace(opt.BatchID),
		RecordCount: opt.RecordCount,
		AdvancedAt:  opt.AdvancedAt.UTC(),
	}
	if cursor.AdvancedAt.IsZero() {
		cursor.AdvancedAt = time.Now().UTC()
	}
	for idx := range ledger.Cursors {
		if ledger.Cursors[idx].Source == cursor.Source && ledger.Cursors[idx].InputHash == cursor.InputHash {
			if ledger.Cursors[idx].ConfirmedBatchID == cursor.BatchID {
				cursor.ConfirmedBatchID = ledger.Cursors[idx].ConfirmedBatchID
				cursor.ConfirmedRecordCount = ledger.Cursors[idx].ConfirmedRecordCount
				cursor.ConfirmedStatus = ledger.Cursors[idx].ConfirmedStatus
				cursor.ConfirmedAt = ledger.Cursors[idx].ConfirmedAt
			}
			ledger.Cursors[idx] = cursor
			return cursor, s.Save(ledger)
		}
	}
	ledger.Cursors = append(ledger.Cursors, cursor)
	return cursor, s.Save(ledger)
}

func (s Store) Confirm(opt ConfirmOptions) (Cursor, error) {
	ledger, err := s.Load()
	if err != nil {
		return Cursor{}, err
	}
	cursor := Cursor{
		Source:               strings.TrimSpace(opt.Source),
		InputHash:            inputHash(opt.Input),
		Input:                strings.TrimSpace(opt.Input),
		BatchID:              strings.TrimSpace(opt.BatchID),
		RecordCount:          opt.RecordCount,
		ConfirmedBatchID:     strings.TrimSpace(opt.BatchID),
		ConfirmedRecordCount: opt.RecordCount,
		ConfirmedStatus:      strings.TrimSpace(opt.Status),
	}
	at := opt.ConfirmedAt.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	cursor.ConfirmedAt = &at
	for idx := range ledger.Cursors {
		if ledger.Cursors[idx].Source == cursor.Source && ledger.Cursors[idx].InputHash == cursor.InputHash {
			ledger.Cursors[idx].ConfirmedBatchID = cursor.ConfirmedBatchID
			ledger.Cursors[idx].ConfirmedRecordCount = cursor.ConfirmedRecordCount
			ledger.Cursors[idx].ConfirmedStatus = cursor.ConfirmedStatus
			ledger.Cursors[idx].ConfirmedAt = cursor.ConfirmedAt
			if ledger.Cursors[idx].BatchID == "" {
				ledger.Cursors[idx].BatchID = cursor.BatchID
				ledger.Cursors[idx].RecordCount = cursor.RecordCount
				ledger.Cursors[idx].AdvancedAt = at
			}
			return ledger.Cursors[idx], s.Save(ledger)
		}
	}
	cursor.AdvancedAt = at
	ledger.Cursors = append(ledger.Cursors, cursor)
	return cursor, s.Save(ledger)
}

func inputHash(input string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(input)))
	return hex.EncodeToString(sum[:])[:16]
}

// ReorgBatch migrates a cursor entry's current batch pointer after a scope
// reorganization. The cursor ledger is bookkeeping: exports derive their
// position from confirmed state, never from the unconfirmed pointer, so a
// migration is best-effort — if the entry was already overwritten by a newer
// export batch, it is left untouched. Confirmed* fields are never modified:
// only a server ACK confirms a batch.
func (s Store) ReorgBatch(source, input, oldBatchID, newBatchID string, recordCount int) error {
	source = strings.TrimSpace(source)
	oldBatchID = strings.TrimSpace(oldBatchID)
	newBatchID = strings.TrimSpace(newBatchID)
	if source == "" || oldBatchID == "" || newBatchID == "" {
		return errors.New("cursor reorg requires source and batch ids")
	}
	ledger, err := s.Load()
	if err != nil {
		return err
	}
	hash := inputHash(input)
	for idx := range ledger.Cursors {
		if ledger.Cursors[idx].Source != source || ledger.Cursors[idx].InputHash != hash {
			continue
		}
		switch ledger.Cursors[idx].BatchID {
		case newBatchID:
			// Idempotent replay.
			return nil
		case oldBatchID:
			ledger.Cursors[idx].BatchID = newBatchID
			ledger.Cursors[idx].RecordCount = recordCount
			ledger.Cursors[idx].AdvancedAt = time.Now().UTC()
			return s.Save(ledger)
		}
		// Superseded by a newer export: leave the newer pointer alone.
		return nil
	}
	return nil
}
