package connect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/outbox"
)

func TestSyncConfirmsWhenNoArchivedBatchIsEligible(t *testing.T) {
	stateDir := t.TempDir()
	homeDir := t.TempDir()
	mock := startSyncToktrailMock(t, "dev-confirm-empty")
	seedBoundState(t, stateDir, mock.URL, "dev-confirm-empty")
	seedBatch(t, stateDir, homeDir, "old-synced", outbox.StatusSynced,
		syncRecord("old-key", syncTestNow.Add(-time.Hour).Format(time.RFC3339)))
	seedBatch(t, stateDir, homeDir, "new-pending", outbox.StatusPending,
		syncRecord("new-key", syncTestNow.Format(time.RFC3339)))
	calls := 0
	_, err := Sync(context.Background(), SyncOptions{
		StateDir: stateDir, ServerURL: mock.URL, HTTPClient: mock.Client(),
		ResyncConfirm: func(resync.Plan) error {
			calls++
			return errors.New("declined")
		},
	})
	if calls != 1 || err == nil || !strings.Contains(err.Error(), "aborted before any collection or upload") {
		t.Fatalf("expected confirmation before work: calls=%d err=%v", calls, err)
	}
	if mock.selfCount() != 0 || mock.totalIngests() != 0 || pendingCount(t, stateDir) != 1 {
		t.Fatalf("declined confirmation must not perform sync work")
	}
}
