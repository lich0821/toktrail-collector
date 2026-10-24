package status

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"toktrail-collector/internal/local/statedir"
)

func TestRunStatusUsesLocalCredentialAndPersistsServerState(t *testing.T) {
	store := statedir.New(t.TempDir())
	secret := strings.Repeat("a", 64)
	if err := store.Save(statedir.DeviceState{ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: secret}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/self" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-1."+secret {
			t.Fatalf("unexpected auth header %q", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     "leaderboard-local",
			"externalSubjectId": "user-1",
			"deviceName":        "MacBook",
			"platform":          "darwin-arm64",
			"consentRevision":   2,
			"uploadAuthorized":  true,
			"publicAuthorized":  false,
			"revoked":           false,
			"checkedAt":         "2026-10-20T10:11:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.ConsentRevision != 2 || !res.State.UploadAuthorized || res.State.PublicAuthorized || res.State.LastCheckedAt.IsZero() {
		t.Fatalf("unexpected status result: %#v", res.State)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.ConsentRevision != 2 || saved.ApplicationID != "leaderboard-local" || saved.DeviceSecret != secret {
		t.Fatalf("status was not persisted: %#v", saved)
	}
}

func TestRunStatusRequiresBoundDevice(t *testing.T) {
	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{})
	if err == nil {
		t.Fatal("expected unbound error")
	}
}

func TestRunStatusReturnsServerError(t *testing.T) {
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{DeviceID: "dev-1", DeviceSecret: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "unauthorized", "message": "bad credential"}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL})
	if err == nil {
		t.Fatal("expected server error")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
