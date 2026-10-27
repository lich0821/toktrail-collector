package syncclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
)

// serveSelfGrantProtocol answers GET /v1/devices/self with the grant
// protocol fields (grantProtocolVersion, paused, deviceGrantManaged).
func serveSelfGrantProtocol(w http.ResponseWriter, r *http.Request, revision int64, allowedTools []string, historyFrom *string) {
	device := map[string]any{
		"deviceId":             "dev-1",
		"consentRevision":      revision,
		"uploadAuthorized":     true,
		"revoked":              false,
		"paused":               false,
		"allowedTools":         allowedTools,
		"grantProtocolVersion": 1,
		"deviceGrantManaged":   true,
	}
	if historyFrom != nil {
		device["historyFrom"] = *historyFrom
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
}

// scopeGateServer is a grant-protocol server that records the record keys
// of every ingest POST body so tests can assert exactly what left the
// device.
func scopeGateServer(t *testing.T, revision int64, allowedTools []string, historyFrom *string) (*httptest.Server, *scopeGateCounters) {
	t.Helper()
	c := &scopeGateCounters{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.total.Add(1)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self":
			c.gets.Add(1)
			serveSelfGrantProtocol(w, r, revision, allowedTools, historyFrom)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ingest/batches":
			c.posts.Add(1)
			var body BatchRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid ingest body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			c.mu.Lock()
			for _, raw := range body.Records {
				key, err := recordKeyOf(raw)
				if err != nil {
					t.Errorf("invalid record: %v", err)
					continue
				}
				c.postedKeys = append(c.postedKeys, key)
			}
			c.mu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
				"batchId":         body.BatchID,
				"status":          "accepted",
				"acceptedRecords": len(body.Records),
				"rejectedRecords": 0,
				"replay":          false,
				"receivedAt":      "2026-10-27T08:00:00Z",
			}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, c
}

type scopeGateCounters struct {
	total      atomic.Int32
	gets       atomic.Int32
	posts      atomic.Int32
	mu         sync.Mutex
	postedKeys []string
}

func (c *scopeGateCounters) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.postedKeys...)
}

// The pre-POST scope gate under the grant protocol: narrowed-away records
// never leave the device. The ingest body provably contains only in-scope
// record keys; the out-of-scope ones are quarantined locally with the
// scope revision, and the legitimate remainder uploads and confirms.
func TestPrePostScopeGateNeverPostsOutOfScopeRecords(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-gate-mixed-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{
			{
				"recordKey": "keep-1", "kind": "delta",
				"occurredAt": "2026-10-26T10:00:00Z", "tool": "usage-json",
				"input": "10", "cacheRead": "0", "cacheWrite": "0", "output": "5",
				"adapterVersion": "gate-test-1", "sourceType": "fixture",
			},
			{
				"recordKey": "narrowed-tool", "kind": "delta",
				"occurredAt": "2026-10-26T10:01:00Z", "tool": "claude-code-jsonl",
				"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
				"adapterVersion": "gate-test-1", "sourceType": "fixture",
			},
			{
				"recordKey": "narrowed-history", "kind": "delta",
				"occurredAt": "2026-10-01T10:00:00Z", "tool": "usage-json",
				"input": "4", "cacheRead": "0", "cacheWrite": "0", "output": "3",
				"adapterVersion": "gate-test-1", "sourceType": "fixture",
			},
		},
	})
	if err := addPendingGateCounted(stateDir, batchID, batchFile, source, 3); err != nil {
		t.Fatal(err)
	}
	historyFrom := "2026-10-20T00:00:00Z"
	server, c := scopeGateServer(t, 21, []string{"usage-json"}, &historyFrom)

	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.AcceptedRecords != 1 {
		t.Fatalf("only the in-scope record may be accepted, got %#v", res.Receipt)
	}
	keys := c.keys()
	if len(keys) != 1 || keys[0] != "keep-1" {
		t.Fatalf("the ingest body must contain exactly the in-scope record, got %#v", keys)
	}
	for _, banned := range []string{"narrowed-tool", "narrowed-history"} {
		for _, k := range keys {
			if k == banned {
				t.Fatalf("out-of-scope record %s left the device", banned)
			}
		}
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 2 {
		t.Fatalf("expected the narrowed records quarantined locally, err=%v entries=%#v", qErr, qEntries)
	}
	for _, entry := range qEntries {
		if entry.ConsentRevision != 21 {
			t.Fatalf("quarantine must carry the live scope revision, got %#v", entry)
		}
	}
}

// A --file batch containing out-of-scope records is refused outright:
// zero network traffic, nothing quarantined, nothing moved.
func TestPrePostScopeGateRefusesFileBatchWithoutSending(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": "file-batch-1",
		"records": []map[string]any{
			{
				"recordKey": "file-out-1", "kind": "delta",
				"occurredAt": "2026-10-26T10:00:00Z", "tool": "claude-code-jsonl",
				"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
				"adapterVersion": "gate-test-1", "sourceType": "fixture",
			},
		},
	})
	historyFrom := "2026-10-20T00:00:00Z"
	server, c := scopeGateServer(t, 22, []string{"usage-json"}, &historyFrom)

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir, BatchFile: batchFile, BatchID: "file-batch-1"})
	if err == nil || !strings.Contains(err.Error(), "refusing to upload a --file batch") {
		t.Fatalf("expected the --file refusal, got %v", err)
	}
	if !errors.Is(err, ErrOutsideScope) && !strings.Contains(err.Error(), "outside the current consent scope") {
		t.Fatalf("the refusal must name the scope violation, got %v", err)
	}
	if got := c.posts.Load(); got != 0 {
		t.Fatalf("nothing may be posted for a refused --file batch, got %d POSTs", got)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 0 {
		t.Fatalf("a refused --file batch must not quarantine anything, err=%v entries=%#v", qErr, qEntries)
	}
}

// A fully out-of-scope outbox batch is quarantined locally with zero
// uploads; the outbox head is freed for later batches.
func TestPrePostScopeGateFullyOutOfScopeUploadsNothing(t *testing.T) {
	stateDir, store, _ := setupBoundState(t)
	const source = "usage-json"
	const batchID = "batch-gate-out-1"
	batchFile := writeBatchFile(t, map[string]any{
		"batchId": batchID,
		"records": []map[string]any{{
			"recordKey": "all-out-1", "kind": "delta",
			"occurredAt": "2026-10-26T10:00:00Z", "tool": "claude-code-jsonl",
			"input": "7", "cacheRead": "0", "cacheWrite": "0", "output": "2",
			"adapterVersion": "gate-test-1", "sourceType": "fixture",
		}},
	})
	if err := addPendingGateCounted(stateDir, batchID, batchFile, source, 1); err != nil {
		t.Fatal(err)
	}
	server, c := scopeGateServer(t, 23, []string{"usage-json"}, nil)

	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, StateDir: stateDir})
	if !errors.Is(err, ErrOutsideScope) || !strings.Contains(err.Error(), "fully quarantined locally") {
		t.Fatalf("expected the local full-quarantine refusal, got %v", err)
	}
	if got := c.posts.Load(); got != 0 {
		t.Fatalf("nothing may be posted, got %d POSTs", got)
	}
	if keys := c.keys(); len(keys) != 0 {
		t.Fatalf("no record may leave the device, got %#v", keys)
	}
	qEntries, qErr := quarantine.New(stateDir).Load()
	if qErr != nil || len(qEntries) != 1 || qEntries[0].RecordKey != "all-out-1" || qEntries[0].ConsentRevision != 23 {
		t.Fatalf("expected the record quarantined locally under revision 23, err=%v entries=%#v", qErr, qEntries)
	}
}

// addPendingGateCounted seeds one pending outbox batch with a record count.
func addPendingGateCounted(stateDir, batchID, file, source string, count int) error {
	_, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        file,
		Source:      source,
		Input:       file,
		RecordCount: count,
	})
	return err
}
