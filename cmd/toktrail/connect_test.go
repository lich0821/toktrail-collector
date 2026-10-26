package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/connect"
)

func TestRunConnectCLIValidation(t *testing.T) {
	t.Run("missing_args", func(t *testing.T) {
		err := runConnect([]string{})
		if err == nil || !strings.Contains(err.Error(), "usage: toktrail connect") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("too_many_args", func(t *testing.T) {
		err := runConnect([]string{"http://localhost:8080/connect#abc", "extra"})
		if err == nil || !strings.Contains(err.Error(), "usage: toktrail connect") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("invalid_flag", func(t *testing.T) {
		err := runConnect([]string{"--invalid-flag", "http://localhost:8080/connect#abc"})
		if err == nil {
			t.Fatalf("expected flag parsing error, got nil")
		}
	})
}

func TestPrintHelpIncludesConnect(t *testing.T) {
	// Capture printHelp output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printHelp()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "connect '<URL>'") {
		t.Fatalf("expected printHelp to document connect '<URL>', got:\n%s", output)
	}
}

type mockSchedulerRunner struct{}

func (mockSchedulerRunner) Run(name string, args ...string) error { return nil }

func TestRunConnectCLIIntegration(t *testing.T) {
	oldRunner := connectSchedulerRunner
	connectSchedulerRunner = mockSchedulerRunner{}
	defer func() { connectSchedulerRunner = oldRunner }()

	stateDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	validTicket := strings.Repeat("7", 64)

	// Mock toktrail-server
	toktrailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/devices/bind":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device": map[string]any{
					"deviceId":          "dev-cli-1",
					"applicationId":     "app-cli",
					"externalSubjectId": "sub-cli",
					"deviceName":        "dev-name",
					"platform":          "test-platform",
					"consentRevision":   1,
					"boundAt":           time.Now().UTC().Format(time.RFC3339),
				},
			})
		case "/v1/devices/self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceId":         "dev-cli-1",
				"consentRevision":  1,
				"uploadAuthorized": true,
				"publicAuthorized": true,
				"revoked":          false,
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer toktrailServer.Close()

	// Mock connect server
	connectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(connect.Config{
			SchemaVersion: 1,
			ServerURL:     toktrailServer.URL,
			ApplicationID: "app-cli",
			SubjectID:     "sub-cli",
			Tools:         []string{"Codex"},
			Days:          7,
			ExpiresAt:     time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer connectServer.Close()

	// Create local tool dir
	codexDir := filepath.Join(homeDir, ".codex", "sessions")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}

	connectURL := fmt.Sprintf("%s/api/collector/connect#%s", connectServer.URL, validTicket)
	err := runConnect([]string{"--state-dir", stateDir, connectURL})
	if err != nil {
		t.Fatalf("runConnect failed: %v", err)
	}
}
