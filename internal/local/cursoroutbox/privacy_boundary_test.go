package cursoroutbox_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
)

func privateBoundaryBatch() protocol.Batch {
	return protocol.Batch{
		BatchID: "safe-batch", SourceInstanceID: "source-1",
		Records: []protocol.Event{{EventKey: protocol.EventKeyPrefix + strings.Repeat("a", 64), Revision: 1, Kind: "event", OccurredAt: "2026-10-28T12:00:00Z", Tool: protocol.Tool, SourceType: protocol.SourceType, AdapterVersion: "cursor-v1"}},
	}
}

func TestAddBatchRejectsUnsafeIdentityBeforeFilesystemWrite(t *testing.T) {
	dir := t.TempDir()
	store := cursoroutbox.New(dir)
	batch := privateBoundaryBatch()
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	batch.BatchID = "../escape"
	if _, err = store.AddBatch(batch, 1, encoded); err == nil {
		t.Fatal("unsafe batch identity accepted")
	}
	if _, err = os.Stat(filepath.Join(dir, "escape.json")); !os.IsNotExist(err) {
		t.Fatal("invalid batch escaped batch directory")
	}
}

func TestAddBatchRejectsCredentialBytesAndMismatchedPayload(t *testing.T) {
	for _, body := range []string{
		`{"batchId":"safe-batch","sourceInstanceId":"source-1","cookie":"PRIVATE","records":[]}`,
		`{"batchId":"another-batch","sourceInstanceId":"source-1","records":[]}`,
	} {
		store := cursoroutbox.New(t.TempDir())
		if _, err := store.AddBatch(privateBoundaryBatch(), 1, []byte(body)); err == nil {
			t.Fatal("unsafe wire bytes accepted into pending queue")
		}
	}
}

func TestOutboxDoesNotOverwriteExistingUnregisteredBatch(t *testing.T) {
	dir := t.TempDir()
	batch := privateBoundaryBatch()
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	batchDir := filepath.Join(dir, cursoroutbox.BatchesDir)
	if err = os.MkdirAll(batchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(batchDir, batch.BatchID+".json")
	original := []byte("immutable prior payload")
	if err = os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = cursoroutbox.New(dir).AddBatch(batch, 1, encoded); err == nil {
		t.Fatal("unregistered conflicting batch should fail closed")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatal("existing batch overwritten")
	}
}
