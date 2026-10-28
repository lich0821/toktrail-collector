package connect

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// parseAndValidateConnectURL parses rawURL, extracts and validates the 64-hex ticket
// from the fragment, strips the fragment, and validates transport security.
func parseAndValidateConnectURL(rawURL string) (string, string, error) {
	baseURLStr, ticket, hasFragment := strings.Cut(rawURL, "#")
	if !hasFragment || strings.TrimSpace(ticket) == "" {
		return "", "", errors.New("missing connect ticket in URL fragment")
	}
	ticket = strings.TrimSpace(ticket)
	if len(ticket) != 64 {
		return "", "", errors.New("invalid connect ticket: must be 64-character hex")
	}
	if _, err := hex.DecodeString(ticket); err != nil {
		return "", "", errors.New("invalid connect ticket: must be 64-character hex")
	}

	u, err := url.Parse(baseURLStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid connect URL: %v", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("invalid connect URL scheme %q; only https (or http for loopback) allowed", scheme)
	}

	if u.User != nil {
		return "", "", errors.New("connect URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", errors.New("connect URL must not contain query parameters")
	}

	hostname := u.Hostname()
	if hostname == "" {
		return "", "", errors.New("missing host in connect URL")
	}

	if scheme == "http" && !isLoopbackHost(hostname) {
		return "", "", errors.New("insecure HTTP connect URL is only permitted for loopback hosts (localhost, 127.0.0.1, ::1); HTTPS is required")
	}

	u.Fragment = ""
	return u.String(), ticket, nil
}

// isLoopbackHost checks if host is localhost or an IPv4/IPv6 loopback address.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// validateServerURL validates the serverUrl provided in connect response.
func validateServerURL(serverURL string) error {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid server URL scheme %q; only https (or http for loopback) allowed", scheme)
	}
	if u.User != nil {
		return errors.New("server URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("server URL must not contain query parameters or fragment")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("missing host in server URL")
	}
	if scheme == "http" && !isLoopbackHost(hostname) {
		return errors.New("serverUrl must use HTTPS (HTTP only permitted for loopback)")
	}
	return nil
}

// fetchConnectConfig performs an HTTP GET to the stripped connect URL with Authorization: Bearer <ticket>,
// enforces redirect rejection, body size limits, and strictly validates the returned Config schema.
func fetchConnectConfig(ctx context.Context, client *http.Client, endpoint, ticket string, now time.Time) (Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Config{}, sanitizeError(err, ticket)
	}
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Accept", "application/json")

	safeClient := newSafeHTTPClient(client)

	resp, err := safeClient.Do(req)
	if err != nil {
		return Config{}, sanitizeError(err, ticket)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("connect failed: server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return Config{}, fmt.Errorf("read connect response body: %w", err)
	}
	if len(body) > 1<<20 {
		return Config{}, errors.New("connect response exceeds 1 MB limit")
	}

	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Config{}, fmt.Errorf("invalid connect response JSON: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return Config{}, errors.New("invalid connect response JSON: expected an object")
	}
	if cfg.SchemaVersion != 1 {
		return Config{}, fmt.Errorf("unsupported connect schemaVersion: %d (expected 1)", cfg.SchemaVersion)
	}
	if _, present := fields["days"]; !present {
		return Config{}, errors.New("missing days in connect response")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return Config{}, fmt.Errorf("invalid serverUrl in connect response: %w", err)
	}
	cfg.ApplicationID = strings.TrimSpace(cfg.ApplicationID)
	if cfg.ApplicationID == "" {
		return Config{}, errors.New("missing applicationId in connect response")
	}
	cfg.SubjectID = strings.TrimSpace(cfg.SubjectID)
	if cfg.SubjectID == "" {
		return Config{}, errors.New("missing subjectId in connect response")
	}
	if cfg.Days != nil && *cfg.Days != 7 && *cfg.Days != 30 && *cfg.Days != 90 {
		return Config{}, fmt.Errorf("invalid days %d in connect response (must be 7, 30, 90, or null)", *cfg.Days)
	}

	exp, err := time.Parse(time.RFC3339, cfg.ExpiresAt)
	if err != nil {
		exp, err = time.Parse(time.RFC3339Nano, cfg.ExpiresAt)
	}
	if err != nil {
		return Config{}, fmt.Errorf("invalid expiresAt format %q: %w", cfg.ExpiresAt, err)
	}
	if !exp.After(now) {
		return Config{}, fmt.Errorf("connect authorization expired at %s", cfg.ExpiresAt)
	}

	if len(cfg.Tools) == 0 {
		return Config{}, errors.New("no tools specified in connect response")
	}

	return cfg, nil
}

func newSafeHTTPClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	}
	if cloned.Timeout <= 0 || cloned.Timeout > 15*time.Second {
		cloned.Timeout = 15 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return &cloned
}

// sanitizeError ensures the ticket is never leaked in error messages.
func sanitizeError(err error, ticket string) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if idx := strings.IndexByte(urlErr.URL, '#'); idx != -1 {
			urlErr.URL = urlErr.URL[:idx]
		}
	}
	msg := err.Error()
	if ticket != "" {
		msg = strings.ReplaceAll(msg, ticket, "[REDACTED]")
	}
	return errors.New(msg)
}
