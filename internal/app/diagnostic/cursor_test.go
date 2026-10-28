package diagnostic

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/statedir"
)

func queueCursorDiagnosticBatch(t *testing.T, dir string) cursoroutbox.Entry {
	t.Helper()
	in, out := "10", "2"
	batch := protocol.Batch{BatchID: "cursor-privacy-batch", SourceInstanceID: "source-1", Records: []protocol.Event{{EventKey: protocol.EventKeyPrefix + strings.Repeat("a", 64), Revision: 1, Kind: "event", OccurredAt: "2026-10-28T12:00:00Z", Tool: protocol.Tool, Input: &in, Output: &out, AdapterVersion: "cursor-v1", SourceType: protocol.SourceType}}}
	encoded, err := protocol.EncodeBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := cursoroutbox.New(dir).AddBatch(batch, 1, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestCursorPrivacyInspectsOnlyQueuedUsageLocally(t *testing.T) {
	dir := t.TempDir()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	const secret = "diagnostic-credential-sentinel"
	if err := statedir.New(dir).Save(statedir.DeviceState{ServerURL: server.URL, DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	queueCursorDiagnosticBatch(t, dir)
	reports, err := Privacy(PrivacyOptions{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("Cursor queue disappeared without local-file grants: %#v", reports)
	}
	r := reports[0]
	if r.Source != protocol.SourceType || r.OutboxPending != 1 || r.OutboxPendingRecords != 1 || r.RecordCount != 1 {
		t.Fatalf("wrong queue report: %#v", r)
	}
	if r.TokensInclude != nil || r.TokensExclude == nil || *r.TokensExclude != 12 {
		t.Fatalf("unknown cache counters became known: %#v", r)
	}
	if !strings.Contains(r.Input, "queued account usage") {
		t.Fatal("queued-only totals were not labeled")
	}
	if requests.Load() != 0 {
		t.Fatal("privacy report accessed network")
	}
	if strings.Contains(fmt.Sprintf("%+v", reports), secret) {
		t.Fatal("privacy report exposed device credential")
	}
}

func TestDoctorRecognizesCursorWithoutDirectoryGrants(t *testing.T) {
	dir := t.TempDir()
	if err := cursorsource.New(dir).Save(cursorsource.License{SourceInstanceID: "source-1", SourceType: protocol.SourceType, Status: cursorsource.StatusActive, ConfirmedAt: time.Now().UTC(), NextRevision: 1, AccountMatchID: "LOCAL-ACCOUNT-MATCH-SENTINEL"}); err != nil {
		t.Fatal(err)
	}
	report, err := Doctor(DoctorOptions{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if c := findCheck(t, report, "grants"); c.Status != CheckOK {
		t.Fatalf("Cursor-only device was classified as collecting nothing: %#v", c)
	}
	if c := findCheck(t, report, "cursor"); c.Status != CheckOK {
		t.Fatalf("missing local Cursor health check: %#v", c)
	}
	if strings.Contains(fmt.Sprintf("%+v", report), "LOCAL-ACCOUNT-MATCH-SENTINEL") {
		t.Fatal("doctor exposed local account identity metadata")
	}
}

func TestCursorPrivacyRefusesUnexpectedSecretFields(t *testing.T) {
	dir := t.TempDir()
	entry := queueCursorDiagnosticBatch(t, dir)
	raw, err := os.ReadFile(entry.File)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"batchId":`), []byte(`"cookie":"CURSOR-PRIVATE-SENTINEL","batchId":`), 1)
	if err = os.WriteFile(entry.File, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Privacy(PrivacyOptions{StateDir: dir})
	if err == nil {
		t.Fatal("unsafe queued payload passed privacy inspection")
	}
	if strings.Contains(err.Error(), "CURSOR-PRIVATE-SENTINEL") {
		t.Fatal("diagnostic error leaked payload contents")
	}
}
