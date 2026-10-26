package syncclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestToolStatusReceiptDoesNotAdvanceUsageState(t *testing.T) {
	dir, store, secret := setupBoundState(t)
	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelf(t, w, r, 9) {
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices/tool-status" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("Authorization") != "Bearer dev-1."+secret || r.Header.Get("X-Consent-Revision") != "9" {
			t.Error("missing live authorization")
		}
		var body struct {
			Statuses []ToolStatus    `json:"statuses"`
			Records  json.RawMessage `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Statuses) != 1 || body.Statuses[0].Status != "no_new_records" || len(body.Records) > 0 {
			t.Errorf("bad receipt body: %+v", body)
		}
		posts++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	res, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: server.URL, ToolStatuses: []ToolStatus{{Tool: "Codex", Status: "no_new_records", Detail: "no new records since last confirmed baseline"}}})
	if err != nil || posts != 1 || res.Status != 202 {
		t.Fatalf("posts=%d result=%+v err=%v", posts, res, err)
	}
	after, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("status receipt changed device usage ACK state")
	}
}

func TestToolStatusFailsClosedAndSupportsOldServer(t *testing.T) {
	for _, mode := range []string{"invalid", "revoked", "scope", "old"} {
		t.Run(mode, func(t *testing.T) {
			dir, store, _ := setupBoundState(t)
			calls, posts := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/v1/devices/self" {
					writeJSON(w, 200, map[string]any{"device": map[string]any{"deviceId": "dev-1", "consentRevision": 2, "uploadAuthorized": mode != "revoked", "revoked": mode == "revoked", "allowedTools": []string{"Codex"}}})
					return
				}
				posts++
				w.WriteHeader(404)
			}))
			defer server.Close()
			item := ToolStatus{Tool: "Codex", Status: "no_new_records"}
			if mode == "invalid" {
				item.Detail = "/private/path"
			}
			if mode == "scope" {
				item.Tool = "Cursor"
			}
			res, err := ReportToolStatuses(t.Context(), store, Options{StateDir: dir, ServerURL: server.URL, ToolStatuses: []ToolStatus{item}})
			switch mode {
			case "invalid":
				if err == nil || calls != 0 {
					t.Fatalf("invalid status reached network: calls=%d err=%v", calls, err)
				}
			case "revoked":
				if !errors.Is(err, ErrDeviceRevoked) || posts != 0 {
					t.Fatalf("revoked status posted: %v", err)
				}
			case "scope":
				if !errors.Is(err, ErrOutsideScope) || posts != 0 {
					t.Fatalf("outside scope status posted: %v", err)
				}
			case "old":
				if err != nil || res.Status != 404 || posts != 1 {
					t.Fatalf("old server compatibility failed: %+v %v", res, err)
				}
			}
		})
	}
}
