package installer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	secretUser     = "leaky-user-SECRET"
	secretQuery    = "token=query-SECRET"
	secretFragment = "frag-SECRET"
)

func secretMarkedURL(base string) string {
	return base + "/manifest.json?" + secretQuery + "#" + secretFragment
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func withFetchClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	old := httpFetchClient
	httpFetchClient = &http.Client{Transport: rt, Timeout: 5 * time.Second}
	t.Cleanup(func() { httpFetchClient = old })
}

func assertNoSecrets(t *testing.T, where string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", where)
	}
	msg := err.Error()
	for _, secret := range []string{secretUser, secretQuery, secretFragment, "://user@", "?token=", "#frag"} {
		if strings.Contains(msg, secret) {
			t.Errorf("%s: error message leaks URL part %q: %s", where, secret, msg)
		}
	}
}

func TestRedactURLStripsUserinfoQueryFragment(t *testing.T) {
	raw := "https://" + secretUser + ":pass-SECRET@example.test/some/path?" + secretQuery + "#" + secretFragment
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := redactURL(u)
	want := "https://example.test/some/path"
	if got != want {
		t.Errorf("redactURL = %q, want %q", got, want)
	}
	for _, secret := range []string{secretUser, "pass-SECRET", secretQuery, secretFragment} {
		if strings.Contains(got, secret) {
			t.Errorf("redactURL kept %q in %q", secret, got)
		}
	}
}

func TestFetchHTTPGetErrorNeverLeaksURL(t *testing.T) {
	withFetchClient(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}))
	_, err := Fetch(secretMarkedURL("https://host.invalid"), 1024)
	assertNoSecrets(t, "connection refused", err)
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("useful network cause lost: %s", err)
	}
	if !strings.Contains(err.Error(), "host.invalid") {
		t.Errorf("redacted host context lost: %s", err)
	}
}

func TestFetchHTTPTimeoutErrorCategory(t *testing.T) {
	withFetchClient(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}))
	_, err := Fetch(secretMarkedURL("https://host.invalid"), 1024)
	assertNoSecrets(t, "timeout", err)
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("timeout category lost: %s", err)
	}
}

func TestFetchHTTPCanceledErrorCategory(t *testing.T) {
	withFetchClient(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	}))
	_, err := Fetch(secretMarkedURL("https://host.invalid"), 1024)
	assertNoSecrets(t, "canceled", err)
	if !strings.Contains(err.Error(), "canceled") {
		t.Errorf("canceled category lost: %s", err)
	}
}

func TestFetchHTTPStatusErrorNeverLeaksURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer ts.Close()
	_, err := Fetch(secretMarkedURL(ts.URL), 1024)
	assertNoSecrets(t, "status error", err)
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("status code lost: %s", err)
	}
}

func TestFetchHTTPNestedURLErrorCauseDropped(t *testing.T) {
	// Redirect-style failures nest *url.Error inside *url.Error; the
	// wrappers' messages embed URLs, so only the deepest, URL-free
	// cause may survive.
	withFetchClient(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		inner := &url.Error{Op: "Get", URL: "https://redirect.invalid/next?" + secretQuery, Err: errors.New("stopped after 10 redirects")}
		return nil, &url.Error{Op: "Get", URL: "https://first.invalid/", Err: inner}
	}))
	_, err := Fetch(secretMarkedURL("https://host.invalid"), 1024)
	assertNoSecrets(t, "nested url.Error", err)
	if strings.Contains(err.Error(), "redirect.invalid") {
		t.Errorf("nested url.Error URL leaked: %s", err)
	}
	if !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Errorf("URL-free cause lost: %s", err)
	}
}

func TestFetchHTTPCauseContainingURLDropped(t *testing.T) {
	// Defense in depth: if the deepest non-url.Error cause itself embeds
	// a URL, the "://" guard must drop it entirely.
	withFetchClient(t, roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("Get \"https://deeper.invalid/x?" + secretQuery + "\": refused")
	}))
	_, err := Fetch(secretMarkedURL("https://host.invalid"), 1024)
	assertNoSecrets(t, "cause with url", err)
	if strings.Contains(err.Error(), "deeper.invalid") {
		t.Errorf("cause URL leaked: %s", err)
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Errorf("expected generic fallback, got: %s", err)
	}
}

func TestFetchHTTPStatusErrorUsesRedactedURL(t *testing.T) {
	// A real server answering non-200: the returned error must cite the
	// redacted scheme://host/path and never the query or fragment.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := Fetch(secretMarkedURL(srv.URL), 1024)
	assertNoSecrets(t, "status", err)
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("status lost from error: %s", err)
	}
	if !strings.Contains(err.Error(), srv.URL+"/manifest.json") {
		t.Errorf("redacted url context lost: %s", err)
	}
}

func TestFetchParseErrorRedacted(t *testing.T) {
	// Malformed URLs make url.Parse return a *url.ParseError that embeds
	// the raw input; the returned error must not echo it.
	raw := "https://" + secretUser + ":pass@" + strings.Repeat("%zz.", 4) + "invalid?" + secretQuery
	if _, err := url.Parse(raw); err == nil {
		t.Skip("url unexpectedly parsed")
	}
	_, err := Fetch(raw, 1024)
	assertNoSecrets(t, "parse", err)
}

func TestJoinBaseURLParseErrorRedacted(t *testing.T) {
	badBase := "https://" + strings.Repeat("%zz.", 8) + "host"
	_, err := joinBaseURL(badBase+"?"+secretQuery, "manifest.json")
	if err == nil {
		t.Skip("base url unexpectedly parsed")
	}
	msg := err.Error()
	if strings.Contains(msg, secretQuery) || strings.Contains(msg, "://") {
		t.Errorf("joinBaseURL parse error leaks input: %s", msg)
	}
}

func TestFetchHTTPBodyLimitExceededNeverLeaksURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(strings.Repeat("a", 2048)))
	}))
	defer ts.Close()
	_, err := Fetch(secretMarkedURL(ts.URL), 512)
	assertNoSecrets(t, "body limit exceeded", err)
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("limit notice lost: %s", err)
	}
}

func TestFetchFileScheme(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data with space #%.txt")
	if err := os.WriteFile(p, []byte("hello file scheme"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(fileURL(p), 1024)
	if err != nil {
		t.Fatalf("Fetch file: %v", err)
	}
	if string(got) != "hello file scheme" {
		t.Errorf("got %q, want %q", got, "hello file scheme")
	}
}

func TestFileURLConstruction(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/tmp/data.txt", "file:///tmp/data.txt"},
		{"C:\\Users\\runner\\data.txt", "file:///C:/Users/runner/data.txt"},
		{"C:/Users/runner/data.txt", "file:///C:/Users/runner/data.txt"},
		{"/C:/Users/runner/data.txt", "file:///C:/Users/runner/data.txt"},
		// '?' is forbidden in Windows filenames; cover its URL escaping
		// without creating a file on disk.
		{"C:/Users/runner/data with space #?%.txt", "file:///C:/Users/runner/data%20with%20space%20%23%3F%25.txt"},
	}
	for _, tc := range cases {
		got := fileURL(tc.input)
		if got != tc.want {
			t.Errorf("fileURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestResolveFilePathWindows(t *testing.T) {
	cases := []struct {
		rawURL string
		want   string
	}{
		{"file:///C:/path/to/file.txt", "C:\\path\\to\\file.txt"},
		{"file:///c:/path/to/file.txt", "c:\\path\\to\\file.txt"},
		{"file://localhost/C:/path/to/file.txt", "C:\\path\\to\\file.txt"},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.rawURL)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tc.rawURL, err)
		}
		got, err := resolveFilePathOS(u, "windows")
		if err != nil {
			t.Errorf("resolveFilePathOS(%q, windows) error: %v", tc.rawURL, err)
			continue
		}
		wantSlash := strings.ReplaceAll(tc.want, "\\", string(filepath.Separator))
		if got != wantSlash {
			t.Errorf("resolveFilePathOS(%q, windows) = %q, want %q", tc.rawURL, got, wantSlash)
		}
	}
}

func TestResolveFilePathRejectsRemoteHost(t *testing.T) {
	badURLs := []struct {
		rawURL   string
		wantHost string
	}{
		{"file://remotehost/share/data.txt", "remotehost"},
		{"file://example.com/data.txt", "example.com"},
		{"file://C:/Users/runner/data.txt", "C:"},
	}
	for _, tc := range badURLs {
		u, err := url.Parse(tc.rawURL)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tc.rawURL, err)
		}
		_, err = resolveFilePathOS(u, "windows")
		if err == nil {
			t.Errorf("resolveFilePathOS(%q) expected error for remote host", tc.rawURL)
			continue
		}
		wantMsg := fmt.Sprintf("file url with remote host %q is not supported", tc.wantHost)
		if err.Error() != wantMsg {
			t.Errorf("resolveFilePathOS(%q) error = %q, want %q", tc.rawURL, err.Error(), wantMsg)
		}
	}
}

func TestFetchRejectsUnknownScheme(t *testing.T) {
	_, err := Fetch("gopher://host.invalid/p", 1024)
	if err == nil {
		t.Fatal("accepted gopher scheme")
	}
	if !strings.Contains(err.Error(), "unsupported url scheme") {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestJoinBaseURLRejectsUnsafeNames(t *testing.T) {
	for _, bad := range []string{"..", "../evil", "a/b", "a\\b", "", "foo\x00bar"} {
		if _, err := joinBaseURL("https://example.test/r", bad); err == nil {
			t.Errorf("joinBaseURL accepted unsafe name %q", bad)
		}
	}
}

func TestJoinBaseURLParseErrorRedactsInput(t *testing.T) {
	badBase := "https://host.invalid/p?" + secretQuery + "\x7f"
	_, err := joinBaseURL(badBase, "file.bin")
	if err == nil {
		t.Skip("base url unexpectedly parsed")
	}
	msg := err.Error()
	if strings.Contains(msg, secretQuery) || strings.Contains(msg, "://") {
		t.Errorf("joinBaseURL parse error leaks input: %s", msg)
	}
}

func TestHTTPGetErrorDoesNotWrapURLError(t *testing.T) {
	_, err := url.Parse("https://host.invalid/p")
	if err != nil {
		t.Fatal(err)
	}
	raw := &url.Error{Op: "Get", URL: "https://host.invalid/p?" + secretQuery, Err: errors.New("boom")}
	got := httpGetError(&url.URL{Scheme: "https", Host: "host.invalid", Path: "/p"}, raw)
	var ue *url.Error
	if errors.As(got, &ue) {
		t.Errorf("httpGetError returned a *url.Error: %v", ue)
	}
	if strings.Contains(fmt.Sprint(got), secretQuery) {
		t.Errorf("httpGetError leaked query: %v", got)
	}
}
