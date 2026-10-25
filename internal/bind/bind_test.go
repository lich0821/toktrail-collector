package bind

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/statedir"
)

func TestRunBindGeneratesLocalSecretAndPersistsReceipt(t *testing.T) {
	var got bindRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/bind" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Ticket != "ticket-1" || got.DeviceSecret == "" || len(got.DeviceSecret) != 64 || got.RequestID == "" {
			t.Fatalf("unexpected bind request: %#v", got)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   1,
			"boundAt":           "2026-10-20T10:00:00Z",
			"replay":            false,
		}})
	}))
	defer server.Close()

	store := statedir.New(t.TempDir())
	res, err := Run(t.Context(), store, Options{
		ServerURL:         server.URL,
		Ticket:            "ticket-1",
		ApplicationID:     "leaderboard-local",
		ExternalSubjectID: "user-1",
		DeviceName:        "MacBook",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.DeviceID != "dev-1" || res.State.DeviceSecret == "" || res.State.BindRequestID == "" || res.Replay {
		t.Fatalf("unexpected result: %#v", res)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DeviceSecret != got.DeviceSecret || saved.BindRequestID != got.RequestID || saved.ConsentRevision != 1 {
		t.Fatalf("state was not persisted correctly: %#v", saved)
	}
}

func TestRunBindReusesRequestIDAndSecretForReplay(t *testing.T) {
	store := statedir.New(t.TempDir())
	initialSecret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initialRequest := "req-replay"
	if err := store.Save(statedir.DeviceState{DeviceSecret: initialSecret, BindRequestID: initialRequest}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DeviceSecret != initialSecret || got.RequestID != initialRequest {
			t.Fatalf("did not reuse local replay identity: %#v", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   1,
			"boundAt":           time.Now().UTC().Format(time.RFC3339),
			"replay":            true,
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, Ticket: "ticket-1", ExternalSubjectID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Replay || res.Status != http.StatusOK {
		t.Fatalf("expected replay OK, got %#v", res)
	}
}

func TestRunBindGeneratesFreshRequestIDAfterSuccessfulBind(t *testing.T) {
	store := statedir.New(t.TempDir())
	initialSecret := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initialRequest := "req-bound"
	if err := store.Save(statedir.DeviceState{DeviceID: "dev-old", DeviceSecret: initialSecret, BindRequestID: initialRequest}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DeviceSecret != initialSecret {
			t.Fatalf("expected existing device secret reuse, got %#v", got)
		}
		if got.RequestID == "" || got.RequestID == initialRequest {
			t.Fatalf("expected fresh request ID after prior successful bind, got %#v", got)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": map[string]any{
			"deviceId":          "dev-new",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   2,
			"boundAt":           time.Now().UTC().Format(time.RFC3339),
			"replay":            false,
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, Ticket: "ticket-2", ExternalSubjectID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.DeviceID != "dev-new" || res.State.BindRequestID == initialRequest {
		t.Fatalf("unexpected refreshed bind state: %#v", res.State)
	}
}

func TestRunBindReturnsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "unauthorized", "message": "bad ticket"}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), statedir.New(t.TempDir()), Options{ServerURL: server.URL, Ticket: "wrong", ExternalSubjectID: "user-1"})
	if err == nil {
		t.Fatal("expected bind error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLostBindResponsePersistsReplayIdentity(t *testing.T) {
	store := statedir.New(t.TempDir())
	var requests []bindRequest
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var request bindRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		saved, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.DeviceSecret != request.DeviceSecret || saved.BindRequestID != request.RequestID || saved.PendingBindFingerprint == "" {
			t.Fatal("replay identity was not durable before network request")
		}
		if len(requests) == 1 {
			return nil, errors.New("response lost after server accepted ticket")
		}
		body, _ := json.Marshal(map[string]any{"device": map[string]any{
			"deviceId": "dev-1", "applicationId": request.ApplicationID,
			"externalSubjectId": request.ExternalSubjectID, "replay": true,
		}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})}
	opt := Options{Ticket: "ticket-one", ExternalSubjectID: "user-1", HTTPClient: client}
	if _, err := Run(t.Context(), store, opt); err == nil {
		t.Fatal("expected lost response")
	}
	result, err := Run(t.Context(), store, opt)
	if err != nil {
		t.Fatal(err)
	}
	if requests[0] != requests[1] || !result.Replay {
		t.Fatal("retry changed bind payload")
	}
	if result.State.PendingBindFingerprint != "" {
		t.Fatal("confirmed bind retained pending marker")
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ticket-one") {
		t.Fatal("plaintext ticket persisted")
	}
}

func TestReplacementTicketGetsNewRequestAfterFailure(t *testing.T) {
	store := statedir.New(t.TempDir())
	var requests []bindRequest
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var request bindRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		return nil, errors.New("network unavailable")
	})}
	opt := Options{Ticket: "ticket-one", ExternalSubjectID: "user-1", HTTPClient: client}
	_, _ = Run(t.Context(), store, opt)
	opt.Ticket = "ticket-two"
	_, _ = Run(t.Context(), store, opt)
	if len(requests) != 2 || requests[0].RequestID == requests[1].RequestID || requests[0].DeviceSecret != requests[1].DeviceSecret {
		t.Fatal("replacement ticket did not get fresh request identity with existing device secret")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
