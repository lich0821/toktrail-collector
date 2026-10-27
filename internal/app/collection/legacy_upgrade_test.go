package collection

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/runlock"
)

// Note on test methodology (simulated legacy vs actual preview.4-generated state):
// The regression tests in this file simulate the legacy layout by populating version 1 schema
// sources.json and on-disk ledger structures (batches, outbox, progress cursors) directly
// within t.TempDir(). This validates the collection runtime and state machine transitions
// identically to on-disk layouts, but does not execute a pre-compiled historical
// v0.4.0-preview.4 binary artifact in a subshell.

// ---------------------------------------------------------------------------
// legacy upgrade helpers
// ---------------------------------------------------------------------------

func codexTokenCount(timestamp string, input, cacheRead, cacheWrite, output uint64) map[string]any {
	return map[string]any{
		"timestamp": timestamp,
		"type":      "event_msg",
		"payload": map[string]any{
			"type": "token_count",
			"info": map[string]any{
				"total_token_usage": map[string]any{
					"input_tokens":             input,
					"cached_input_tokens":      cacheRead,
					"cache_write_input_tokens": cacheWrite,
					"output_tokens":            output,
				},
			},
		},
	}
}

func writeCodexSession(t *testing.T, dir, name string, lines ...map[string]any) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	var b strings.Builder
	for _, line := range lines {
		raw, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func appendFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
}

func writeLegacySourcesConfig(t *testing.T, stateDir string, cfg grants.Config) {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "sources.json")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLegacySourcesRaw(t *testing.T, stateDir string, raw []byte) {
	t.Helper()
	path := filepath.Join(stateDir, "sources.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeEmptyGrantsConfig(t *testing.T, stateDir string) {
	t.Helper()
	cfg := grants.Config{
		Version: 1,
		Grants:  []grants.Grant{},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "grants.json")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// safeRemoveTempFile ensures we ONLY remove files within verified resolved temp paths.
func safeRemoveTempFile(t *testing.T, targetPath, verifiedTempDir string) {
	t.Helper()
	realTemp, err := filepath.EvalSymlinks(verifiedTempDir)
	if err != nil {
		t.Fatalf("failed to resolve temp dir %s: %v", verifiedTempDir, err)
	}
	realTarget, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		t.Fatalf("failed to resolve target path %s: %v", targetPath, err)
	}
	rel, err := filepath.Rel(realTemp, realTarget)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		t.Fatalf("safety assertion failed: target path %s is outside verified temp directory %s", realTarget, realTemp)
	}
	if err := os.Remove(realTarget); err != nil {
		t.Fatalf("failed to remove %s: %v", realTarget, err)
	}
}

// fakeServerWithFlake accepts normal preflight and batches, with an optional
// one-shot failure on ingest batch upload.
func fakeServerWithFlake(t *testing.T, failUploadOnce *atomic.Bool) *fakeCollectorServer {
	t.Helper()
	s := fakeServer(t)
	if failUploadOnce != nil {
		s.failIngestOnce = failUploadOnce
	}
	return s
}

// ---------------------------------------------------------------------------
// upgrade regression tests
// ---------------------------------------------------------------------------

// TestRunUpgradeFromLegacySourcesPreservesHistoricalProgressAndZeroReplay tests
// the full upgrade lifecycle with real historical collection state:
//  1. Initial collection.Run establishes actual batch, outbox, and progress files
//     for both claude-code-jsonl (message baseline) and codex-jsonl (cursor/history).
//  2. Simulate legacy snapshot by writing same grant content into sources.json and
//     removing grants.json only within the verified temp path.
//  3. Repeat collection.Run triggers migration, creates current grants.json, and
//     proves zero new exports, zero new syncs/uploads, and no duplicate facts/progress.
func TestRunUpgradeFromLegacySourcesPreservesHistoricalProgressAndZeroReplay(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session-a.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-21T04:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))

	codexDir := filepath.Join(t.TempDir(), "codex-sessions")
	writeCodexSession(t, codexDir, "rollout-a.jsonl",
		codexTokenCount("2026-10-21T04:00:00Z", 100, 20, 5, 40),
		codexTokenCount("2026-10-21T04:01:00Z", 160, 30, 8, 80))

	// Initial phase: enable grants and run first collection.Run to establish historical ledgers.
	enableGrant(t, stateDir, "claude-code-jsonl", claudeDir)
	enableGrant(t, stateDir, "codex-jsonl", codexDir)

	grantsPath := filepath.Join(stateDir, "grants.json")
	grantContentBytes, err := os.ReadFile(grantsPath)
	if err != nil {
		t.Fatalf("failed to read created grants.json: %v", err)
	}

	res1, err := Run(t.Context(), Options{
		StateDir: stateDir,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 4, 2, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("first collection.Run failed: %v", err)
	}
	if res1.ExportedBatches != 2 || res1.SyncedBatches != 2 {
		t.Fatalf("expected 2 exported and 2 synced batches, got %#v", res1)
	}
	if res1.PendingRemaining != 0 || res1.DrainStopped != "" {
		t.Fatalf("expected fully drained outbox, got %#v", res1)
	}
	requestsAfterFirstRun := server.totalRequests()
	if requestsAfterFirstRun == 0 {
		t.Fatal("expected server requests for first run preflight and uploads")
	}
	ingestAfterFirstRun := server.ingestRequests()

	// Verify initial ledgers exist and take snapshot.
	cursorLedgerBefore, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load cursor ledger: %v", err)
	}
	if len(cursorLedgerBefore.Cursors) != 2 {
		t.Fatalf("expected 2 cursors (one per source), got %d", len(cursorLedgerBefore.Cursors))
	}
	cursorMapBefore := make(map[string]progress.Cursor)
	for _, c := range cursorLedgerBefore.Cursors {
		cursorMapBefore[c.Source] = c
	}
	codexCursorBefore, ok := cursorMapBefore["codex-jsonl"]
	if !ok || codexCursorBefore.ConfirmedBatchID == "" || codexCursorBefore.ConfirmedRecordCount != 1 {
		t.Fatalf("expected confirmed codex cursor, got %#v", codexCursorBefore)
	}
	claudeCursorBefore, ok := cursorMapBefore["claude-code-jsonl"]
	if !ok || claudeCursorBefore.ConfirmedBatchID == "" || claudeCursorBefore.ConfirmedRecordCount != 2 {
		t.Fatalf("expected confirmed claude cursor, got %#v", claudeCursorBefore)
	}

	msgProgressBefore, existed, err := progress.New(stateDir).LoadMessageProgress()
	if err != nil || !existed {
		t.Fatalf("failed to load message progress: %v", err)
	}
	if len(msgProgressBefore) != 2 {
		t.Fatalf("expected 2 claude message progress entries, got %d", len(msgProgressBefore))
	}
	for msgID, p := range msgProgressBefore {
		if p.Confirmed == nil {
			t.Fatalf("message %s must have confirmed baseline: %#v", msgID, p)
		}
		if p.Pending != nil {
			t.Fatalf("message %s pending must be nil after sync: %#v", msgID, p)
		}
	}

	outboxLedgerBefore, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load outbox ledger: %v", err)
	}
	if len(outboxLedgerBefore.Batches) != 2 {
		t.Fatalf("expected 2 outbox batches, got %d", len(outboxLedgerBefore.Batches))
	}
	for _, b := range outboxLedgerBefore.Batches {
		if b.Status != outbox.StatusSynced {
			t.Fatalf("expected batch %s to be synced, got %s", b.BatchID, b.Status)
		}
	}

	batchesDir := filepath.Join(stateDir, "batches")
	batchFilesBefore, err := os.ReadDir(batchesDir)
	if err != nil {
		t.Fatalf("failed to read batches directory: %v", err)
	}
	if len(batchFilesBefore) != 2 {
		t.Fatalf("expected 2 batch files, got %d", len(batchFilesBefore))
	}

	// Simulate legacy snapshot:
	// Put the same grant content in sources.json and remove grants.json ONLY in verified temp path.
	sourcesPath := filepath.Join(stateDir, "sources.json")
	if err := os.WriteFile(sourcesPath, grantContentBytes, 0o600); err != nil {
		t.Fatalf("failed to write legacy sources.json: %v", err)
	}
	safeRemoveTempFile(t, grantsPath, stateDir)

	if _, err := os.Stat(grantsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("grants.json must not exist before second run, got err=%v", err)
	}

	// Second phase: repeat collection.Run.
	// MigrateLegacy must restore grants.json without causing duplicate export or upload.
	res2, err := Run(t.Context(), Options{
		StateDir: stateDir,
		Now: func() time.Time {
			return time.Date(2026, 10, 21, 4, 3, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("second collection.Run failed: %v", err)
	}

	// Assert current grants.json was created.
	if _, err := os.Stat(grantsPath); err != nil {
		t.Fatalf("grants.json must be created by migration: %v", err)
	}
	migratedCfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load migrated grants.json: %v", err)
	}
	if len(migratedCfg.Grants) != 2 {
		t.Fatalf("expected 2 migrated grants, got %d", len(migratedCfg.Grants))
	}

	// Assert zero new exports and zero new syncs.
	if res2.ExportedBatches != 0 || res2.ExportedRecords != 0 {
		t.Fatalf("expected 0 exported batches on unchanged input after migration, got %#v", res2)
	}
	if res2.SyncedBatches != 0 || res2.SyncedRecords != 0 {
		t.Fatalf("expected 0 synced batches on unchanged input after migration, got %#v", res2)
	}
	if res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("outbox must remain fully drained, got %#v", res2)
	}

	// Assert the second run only reports the empty-scan status: no ingest
	// replay, one self preflight, and one deduplicated tool-status POST that
	// covers both migrated tools.
	requestsAfterSecondRun := server.totalRequests()
	if requestsAfterSecondRun != requestsAfterFirstRun+3 {
		t.Fatalf("second collection.Run must only add the grant-sync fetch and the empty-scan status report: before=%d, after=%d",
			requestsAfterFirstRun, requestsAfterSecondRun)
	}
	if got := server.ingestRequests(); got != ingestAfterFirstRun {
		t.Fatalf("second collection.Run must not replay any ingest upload: before=%d, after=%d",
			ingestAfterFirstRun, got)
	}
	if got := server.toolStatusRequests(); got != 3 { // 2 synced receipts from run 1 + 1 empty-scan POST
		t.Fatalf("second collection.Run must add exactly one tool-status POST, got %d total", got)
	}
	reports := server.lastToolStatusReports()
	wantTools := map[string]bool{"Claude Code": false, "Codex": false}
	for _, r := range reports {
		if r.Status != "no_new_records" {
			t.Fatalf("expected no_new_records for %s, got %#v", r.Tool, r)
		}
		if r.Detail != "no new records since last confirmed baseline" {
			t.Fatalf("expected the baseline detail for %s, got %#v", r.Tool, r)
		}
		if _, known := wantTools[r.Tool]; !known {
			t.Fatalf("unexpected tool %q in status report", r.Tool)
		}
		wantTools[r.Tool] = true
	}
	for tool, seen := range wantTools {
		if !seen {
			t.Fatalf("tool %q missing from the status report: %#v", tool, reports)
		}
	}
	if len(reports) != 2 {
		t.Fatalf("expected both tools in one deduplicated POST, got %#v", reports)
	}

	// Assert no duplicate facts or progress regressions.
	cursorLedgerAfter, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to reload cursor ledger: %v", err)
	}
	if len(cursorLedgerAfter.Cursors) != 2 {
		t.Fatalf("cursor count changed: before=%d, after=%d",
			len(cursorLedgerBefore.Cursors), len(cursorLedgerAfter.Cursors))
	}
	for _, cAfter := range cursorLedgerAfter.Cursors {
		cBefore, exists := cursorMapBefore[cAfter.Source]
		if !exists {
			t.Fatalf("unexpected cursor for source %s after migration", cAfter.Source)
		}
		if cAfter.ConfirmedBatchID != cBefore.ConfirmedBatchID ||
			cAfter.ConfirmedRecordCount != cBefore.ConfirmedRecordCount {
			t.Fatalf("cursor for %s mutated after migration: before=%#v, after=%#v",
				cAfter.Source, cBefore, cAfter)
		}
	}

	msgProgressAfter, _, err := progress.New(stateDir).LoadMessageProgress()
	if err != nil {
		t.Fatalf("failed to reload message progress: %v", err)
	}
	if len(msgProgressAfter) != len(msgProgressBefore) {
		t.Fatalf("message progress count changed: before=%d, after=%d",
			len(msgProgressBefore), len(msgProgressAfter))
	}
	for msgID, beforeP := range msgProgressBefore {
		afterP, ok := msgProgressAfter[msgID]
		if !ok {
			t.Fatalf("message %s missing after migration", msgID)
		}
		if !beforeP.Confirmed.Equal(afterP.Confirmed) {
			t.Fatalf("message %s confirmed state changed: before=%#v, after=%#v",
				msgID, beforeP.Confirmed, afterP.Confirmed)
		}
		if afterP.Pending != nil {
			t.Fatalf("message %s pending must remain nil: %#v", msgID, afterP)
		}
	}

	outboxLedgerAfter, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to reload outbox ledger: %v", err)
	}
	if len(outboxLedgerAfter.Batches) != len(outboxLedgerBefore.Batches) {
		t.Fatalf("outbox batch count changed: before=%d, after=%d",
			len(outboxLedgerBefore.Batches), len(outboxLedgerAfter.Batches))
	}

	batchFilesAfter, err := os.ReadDir(batchesDir)
	if err != nil {
		t.Fatalf("failed to read batches dir after second run: %v", err)
	}
	if len(batchFilesAfter) != len(batchFilesBefore) {
		t.Fatalf("batch files count changed: before=%d, after=%d",
			len(batchFilesBefore), len(batchFilesAfter))
	}
}

// TestRunUpgradeLegacyWithPendingOutboxDrainsAndConfirmsOnce tests an upgrade scenario
// where real batches were exported and recorded as pending in outbox.json before
// migration, but an upload failure prevented them from receiving an ACK.
// The next Run executes migration, drains the pending outbox, confirms cursors/progress
// exactly once, and a subsequent unchanged run produces zero replay and zero network calls.
func TestRunUpgradeLegacyWithPendingOutboxDrainsAndConfirmsOnce(t *testing.T) {
	stateDir := t.TempDir()
	failUploadOnce := &atomic.Bool{}
	failUploadOnce.Store(true)
	server := fakeServerWithFlake(t, failUploadOnce)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session-a.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))

	codexDir := filepath.Join(t.TempDir(), "codex-sessions")
	writeCodexSession(t, codexDir, "rollout-a.jsonl",
		codexTokenCount("2026-10-21T04:00:00Z", 100, 20, 5, 40),
		codexTokenCount("2026-10-21T04:01:00Z", 160, 30, 8, 80))

	// Initial phase: set legacy sources.json with authorized grants.
	legacyConfig := grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: true},
			{Source: "codex-jsonl", Input: codexDir, Enabled: true},
		},
	}
	writeLegacySourcesConfig(t, stateDir, legacyConfig)

	grantsPath := filepath.Join(stateDir, "grants.json")

	// Run 1: exports batches, but upload fails on first batch due to 500 server error.
	res1, err := Run(t.Context(), Options{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected Run 1 to fail due to upload error")
	}
	if res1.ExportedBatches != 2 {
		t.Fatalf("expected 2 exported batches in Run 1, got %d", res1.ExportedBatches)
	}
	if res1.PendingRemaining == 0 || res1.DrainStopped == "" {
		t.Fatalf("expected pending batches remaining after failed upload, got %#v", res1)
	}

	// Verify pending outbox batches exist.
	outboxStore := outbox.New(stateDir)
	pendingCount, err := countPending(outboxStore)
	if err != nil {
		t.Fatalf("failed to count pending outbox: %v", err)
	}
	if pendingCount == 0 {
		t.Fatal("expected pending outbox batches after upload failure")
	}

	// Simulate legacy snapshot before ACK:
	// If grants.json was created during Run 1, remove it to strictly test the upgrade path
	// when existing pending outbox batches and unconfirmed progress are present.
	if _, err := os.Stat(grantsPath); err == nil {
		safeRemoveTempFile(t, grantsPath, stateDir)
	}

	// Run 2: migration occurs, server accepts upload (failUploadOnce is now false),
	// outbox drains all pending batches, and progress is confirmed.
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Run 2 failed: %v", err)
	}

	// Verify grants.json was created by migration.
	if _, err := os.Stat(grantsPath); err != nil {
		t.Fatalf("grants.json must exist after Run 2 migration: %v", err)
	}
	if res2.ExportedBatches != 0 {
		t.Fatalf("Run 2 should not export new batches, got %d", res2.ExportedBatches)
	}
	if res2.SyncedBatches != pendingCount {
		t.Fatalf("expected Run 2 to sync exactly all %d pending batches, got %d", pendingCount, res2.SyncedBatches)
	}
	if res2.PendingRemaining != 0 || res2.DrainStopped != "" {
		t.Fatalf("expected outbox to be fully drained after Run 2, got %#v", res2)
	}

	// Verify confirmed progress state after Run 2.
	cursorLedger, err := progress.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load cursor ledger: %v", err)
	}
	for _, c := range cursorLedger.Cursors {
		if c.ConfirmedBatchID == "" {
			t.Fatalf("cursor for %s must be confirmed: %#v", c.Source, c)
		}
	}
	msgProgress, _, err := progress.New(stateDir).LoadMessageProgress()
	if err != nil {
		t.Fatalf("failed to load message progress: %v", err)
	}
	for msgID, p := range msgProgress {
		if p.Confirmed == nil {
			t.Fatalf("message %s must have confirmed baseline: %#v", msgID, p)
		}
		if p.Pending != nil {
			t.Fatalf("message %s pending must be cleared: %#v", msgID, p)
		}
	}

	reqsAfterRun2 := server.totalRequests()
	ingestAfterRun2 := server.ingestRequests()

	// Run 3: unchanged run must not re-export or replay any upload; its only
	// traffic is the empty-scan status report for both tools.
	res3, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Run 3 failed: %v", err)
	}
	if res3.ExportedBatches != 0 || res3.SyncedBatches != 0 {
		t.Fatalf("Run 3 must be a zero-work no-op, got %#v", res3)
	}
	if got := server.ingestRequests(); got != ingestAfterRun2 {
		t.Fatalf("Run 3 must not replay any ingest upload: before=%d, after=%d", ingestAfterRun2, got)
	}
	if n := server.totalRequests(); n != reqsAfterRun2+3 {
		t.Fatalf("Run 3 must only add the grant-sync fetch and the empty-scan status report: before=%d, after=%d", reqsAfterRun2, n)
	}
}

// TestRunUpgradeAppendNewUsageAfterMigrationSyncsOnlyDelta tests continued uploading
// after migration: appending new source usage to both claude and codex sessions produces
// new delta records that are exported and synced exactly once without replaying historical records.
func TestRunUpgradeAppendNewUsageAfterMigrationSyncsOnlyDelta(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	claudeFile := writeClaudeSession(t, claudeDir, "session-a.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)),
		claudeLine(t, "2026-10-21T04:01:00Z", "s1", "msg_2", claudeUsage(7, 1, 0, 4)))

	codexDir := filepath.Join(t.TempDir(), "codex-sessions")
	codexFile := writeCodexSession(t, codexDir, "rollout-a.jsonl",
		codexTokenCount("2026-10-21T04:00:00Z", 100, 20, 5, 40),
		codexTokenCount("2026-10-21T04:01:00Z", 160, 30, 8, 80))

	// Write legacy sources.json.
	writeLegacySourcesConfig(t, stateDir, grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: true},
			{Source: "codex-jsonl", Input: codexDir, Enabled: true},
		},
	})

	// Run 1: migration lands, initial historical usage exported and synced (3 records total).
	res1, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Run 1 failed: %v", err)
	}
	if res1.ExportedBatches != 2 || res1.SyncedBatches != 2 {
		t.Fatalf("expected 2 batches exported and synced in Run 1, got %#v", res1)
	}
	if res1.ExportedRecords != 3 {
		t.Fatalf("expected 3 total records in Run 1 (2 claude + 1 codex delta), got %d", res1.ExportedRecords)
	}

	// Append NEW usage to both sessions:
	// - Claude: append msg_3 with new usage.
	newClaudeLine := claudeLine(t, "2026-10-21T04:02:00Z", "s1", "msg_3", claudeUsage(5, 0, 0, 2))
	appendFile(t, claudeFile, []byte(newClaudeLine+"\n"))

	// - Codex: append 3rd token_count line creating a new delta.
	newCodexLine, err := json.Marshal(codexTokenCount("2026-10-21T04:02:00Z", 210, 40, 10, 100))
	if err != nil {
		t.Fatal(err)
	}
	appendFile(t, codexFile, append(newCodexLine, '\n'))

	// Run 2: only the new delta usage is exported and synced.
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Run 2 failed: %v", err)
	}
	if res2.ExportedBatches != 2 || res2.SyncedBatches != 2 {
		t.Fatalf("expected 2 new delta batches in Run 2, got %#v", res2)
	}
	// Exactly 2 new records: 1 for claude msg_3, 1 for codex line 2->3 delta.
	if res2.ExportedRecords != 2 || res2.SyncedRecords != 2 {
		t.Fatalf("expected exactly 2 new records exported/synced in Run 2, got exported=%d, synced=%d",
			res2.ExportedRecords, res2.SyncedRecords)
	}
	if res2.PendingRemaining != 0 {
		t.Fatalf("expected 0 pending batches after Run 2, got %d", res2.PendingRemaining)
	}

	reqsAfterRun2 := server.totalRequests()
	ingestAfterRun2 := server.ingestRequests()

	// Run 3: unchanged input produces zero new exports, no ingest replay, and
	// only the empty-scan status report for both tools.
	res3, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Run 3 failed: %v", err)
	}
	if res3.ExportedBatches != 0 || res3.SyncedBatches != 0 {
		t.Fatalf("Run 3 should be no-op, got %#v", res3)
	}
	if got := server.ingestRequests(); got != ingestAfterRun2 {
		t.Fatalf("Run 3 must not replay any ingest upload: before=%d, after=%d", ingestAfterRun2, got)
	}
	if n := server.totalRequests(); n != reqsAfterRun2+3 {
		t.Fatalf("Run 3 must only add the grant-sync fetch and the empty-scan status report: before=%d, after=%d", reqsAfterRun2, n)
	}
}

// TestRunUpgradeFromLegacySourcesColdStart tests the first-time migration when
// only legacy sources.json exists without prior runs or grants.json.
func TestRunUpgradeFromLegacySourcesColdStart(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session-cold.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))

	codexDir := filepath.Join(t.TempDir(), "codex-sessions")
	writeCodexSession(t, codexDir, "rollout-cold.jsonl",
		codexTokenCount("2026-10-21T04:00:00Z", 100, 20, 5, 40),
		codexTokenCount("2026-10-21T04:01:00Z", 160, 30, 8, 80))

	// Write only legacy sources.json with authorized version 1 schema.
	writeLegacySourcesConfig(t, stateDir, grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: true},
			{Source: "codex-jsonl", Input: codexDir, Enabled: true},
		},
	})

	grantsPath := filepath.Join(stateDir, "grants.json")
	if _, err := os.Stat(grantsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("grants.json must not exist before first run: %v", err)
	}

	res1, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("first collection.Run failed: %v", err)
	}

	// Current grants.json must have been created.
	if _, err := os.Stat(grantsPath); err != nil {
		t.Fatalf("grants.json was not created on cold start: %v", err)
	}
	if res1.ExportedBatches != 2 || res1.SyncedBatches != 2 {
		t.Fatalf("expected 2 exported and synced batches on cold start, got %#v", res1)
	}
	reqsAfterFirst := server.totalRequests()
	ingestAfterFirst := server.ingestRequests()
	if reqsAfterFirst == 0 {
		t.Fatal("expected network calls for preflight and sync on cold start")
	}

	// Second run must be an idle no-op: no new exports, no ingest replay, and
	// only the empty-scan status report for both migrated tools.
	res2, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("second collection.Run failed: %v", err)
	}
	if res2.ExportedBatches != 0 || res2.SyncedBatches != 0 {
		t.Fatalf("second run must be no-op, got %#v", res2)
	}
	if got := server.ingestRequests(); got != ingestAfterFirst {
		t.Fatalf("second run must not replay any ingest upload: before=%d, after=%d", ingestAfterFirst, got)
	}
	if n := server.totalRequests(); n != reqsAfterFirst+3 {
		t.Fatalf("second run must only add the grant-sync fetch and the empty-scan status report: before=%d, after=%d", reqsAfterFirst, n)
	}
	if got := server.selfRequests(); got != 7 { // run 1: 2 drain + 2 receipt preflights + grant-sync; run 2: status preflight + grant-sync
		t.Fatalf("expected 5 total self preflights, got %d", got)
	}
	if got := server.toolStatusRequests(); got != 3 { // 2 synced receipts + 1 empty-scan POST
		t.Fatalf("expected 3 total tool-status POSTs, got %d", got)
	}
}

// TestRunUpgradeDisabledLegacyGrantsDoNotScanOrNetwork asserts that disabled
// grants in legacy sources.json are migrated as disabled and do not perform
// any input scanning or network traffic.
func TestRunUpgradeDisabledLegacyGrantsDoNotScanOrNetwork(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))

	codexDir := filepath.Join(t.TempDir(), "codex-sessions")
	writeCodexSession(t, codexDir, "rollout.jsonl",
		codexTokenCount("2026-10-21T04:00:00Z", 100, 20, 5, 40),
		codexTokenCount("2026-10-21T04:01:00Z", 160, 30, 8, 80))

	// All legacy grants are disabled.
	writeLegacySourcesConfig(t, stateDir, grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: false},
			{Source: "codex-jsonl", Input: codexDir, Enabled: false},
		},
	})

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("collection.Run with disabled legacy grants failed: %v", err)
	}
	if !res.NoGrants || res.Grants != 0 {
		t.Fatalf("expected NoGrants=true and Grants=0, got %#v", res)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("expected 0 exported and 0 synced batches, got %#v", res)
	}
	if n := server.totalRequests(); n != 1 {
		t.Fatalf("disabled legacy grants must only perform the grant-sync self fetch for the bound device, got %d requests", n)
	}

	// Verify grants.json was created and reflects disabled state.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load migrated grants: %v", err)
	}
	if len(cfg.Grants) != 2 {
		t.Fatalf("expected 2 grants in grants.json, got %d", len(cfg.Grants))
	}
	for _, g := range cfg.Grants {
		if g.Enabled {
			t.Fatalf("grant %s must be disabled: %#v", g.Source, g)
		}
	}
}

// TestRunUpgradeMalformedLegacySourcesYieldsErrorAndZeroNetwork asserts that
// corrupted or invalid legacy sources.json causes collection to fail fast with
// an error and produces zero exports and zero network requests.
func TestRunUpgradeMalformedLegacySourcesYieldsErrorAndZeroNetwork(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "syntax_error",
			payload: `{"version": 1, "grants": [bad-json`,
		},
		{
			name:    "unsupported_version",
			payload: `{"version": 999, "grants": []}`,
		},
		{
			name:    "unknown_source",
			payload: `{"version": 1, "grants": [{"source": "nonexistent-source", "input": "/tmp/valid", "enabled": true}]}`,
		},
		{
			name:    "relative_input_path",
			payload: `{"version": 1, "grants": [{"source": "claude-code-jsonl", "input": "relative/path/sessions", "enabled": true}]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			server := fakeServer(t)
			bindDevice(t, stateDir, server.URL)

			writeLegacySourcesRaw(t, stateDir, []byte(tc.payload))

			res, err := Run(t.Context(), Options{StateDir: stateDir})
			if err == nil {
				t.Fatalf("expected error for malformed legacy config %s, got nil", tc.name)
			}
			if n := server.totalRequests(); n != 0 {
				t.Fatalf("malformed legacy must not touch network, got %d requests", n)
			}
			if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
				t.Fatalf("malformed legacy must produce 0 exports and syncs, got %#v", res)
			}

			// Ensure outbox remains clean.
			outboxStore := outbox.New(stateDir)
			pending, err := countPending(outboxStore)
			if err != nil {
				t.Fatalf("failed to count pending outbox: %v", err)
			}
			if pending != 0 {
				t.Fatalf("expected 0 pending batches, got %d", pending)
			}
		})
	}
}

// TestRunUpgradeExplicitEmptyCurrentConfigWinsOverEnabledLegacy asserts that an
// explicit current grants.json (even when empty) takes precedence over any legacy
// sources.json and is never overwritten or backfilled by legacy grants.
func TestRunUpgradeExplicitEmptyCurrentConfigWinsOverEnabledLegacy(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))

	// Explicit empty current config: grants.json exists with 0 grants.
	writeEmptyGrantsConfig(t, stateDir)

	// Legacy sources.json exists with an enabled grant.
	writeLegacySourcesConfig(t, stateDir, grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: true},
		},
	})

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("collection.Run failed: %v", err)
	}

	// Current empty config wins: run treated as having no grants.
	if !res.NoGrants || res.Grants != 0 {
		t.Fatalf("expected explicit empty grants to win (NoGrants=true, Grants=0), got %#v", res)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("expected 0 exports and syncs, got %#v", res)
	}
	if n := server.totalRequests(); n != 1 {
		t.Fatalf("run with empty current config must only perform the grant-sync self fetch for the bound device, got %d requests", n)
	}

	// Verify current grants.json was untouched and still contains 0 grants.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		t.Fatalf("failed to load current grants: %v", err)
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("current grants.json must remain empty, got %d grants", len(cfg.Grants))
	}
}

// TestRunUpgradeLockBusyPreventsMigrationWrites asserts that when the runlock
// is held by another process, collection.Run fails fast with runlock.ErrBusy
// without performing legacy migration or writing grants.json.
func TestRunUpgradeLockBusyPreventsMigrationWrites(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)

	claudeDir := filepath.Join(t.TempDir(), "claude-sessions")
	writeClaudeSession(t, claudeDir, "session.jsonl",
		claudeLine(t, "2026-10-21T04:00:00Z", "s1", "msg_1", claudeUsage(10, 0, 0, 5)))

	// Write legacy sources.json; grants.json does NOT exist.
	writeLegacySourcesConfig(t, stateDir, grants.Config{
		Version: 1,
		Grants: []grants.Grant{
			{Source: "claude-code-jsonl", Input: claudeDir, Enabled: true},
		},
	})

	grantsPath := filepath.Join(stateDir, "grants.json")

	// Acquire lock to simulate concurrent run.
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, runlock.ErrBusy) {
		_ = lock.Close()
		t.Fatalf("expected runlock.ErrBusy, got %v", err)
	}

	// Migration must NOT have run: grants.json must not exist while locked.
	if _, err := os.Stat(grantsPath); !errors.Is(err, os.ErrNotExist) {
		_ = lock.Close()
		t.Fatalf("grants.json must not be created when lock is busy: %v", err)
	}
	if n := server.totalRequests(); n != 0 {
		_ = lock.Close()
		t.Fatalf("locked run must not make network requests, got %d", n)
	}

	// Release lock and run again; migration must now proceed safely.
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatalf("run after lock release failed: %v", err)
	}
	if res.ExportedBatches != 1 || res.SyncedBatches != 1 {
		t.Fatalf("expected 1 exported and synced batch, got %#v", res)
	}
	if _, err := os.Stat(grantsPath); err != nil {
		t.Fatalf("grants.json should now exist after successful run: %v", err)
	}
}
