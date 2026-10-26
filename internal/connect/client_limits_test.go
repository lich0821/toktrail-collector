package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectClientRejectsOversizedConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}` + strings.Repeat(" ", 1<<20)))
	}))
	defer server.Close()
	_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, strings.Repeat("a", 64), time.Now())
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MB") {
		t.Fatalf("oversized config error = %v", err)
	}
}

func TestSafeConnectClientPreservesTransportAndRejectsRedirect(t *testing.T) {
	original := &http.Client{Transport: http.DefaultTransport}
	safe := newSafeHTTPClient(original)
	if safe.Transport != original.Transport || safe.Timeout != 15*time.Second || original.Timeout != 0 {
		t.Fatal("safe client must preserve transport, enforce timeout, and leave original unchanged")
	}
	if safe.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect must be rejected")
	}
}

func TestServerURLRejectsQueryAndFragment(t *testing.T) {
	for _, url := range []string{"https://example.test?", "https://example.test?q=1", "https://example.test#secret"} {
		if err := validateServerURL(url); err == nil {
			t.Errorf("accepted ambiguous server URL %q", url)
		}
	}
}
