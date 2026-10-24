package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/distribution"
)

// maxFetchBytes is the hard ceiling for any single network download.
const maxFetchBytes = int64(1 << 30) // 1 GiB

// Fetch downloads url into memory with a hard size bound. Supported schemes
// are http, https (the update endpoint) and file (for local testing of the
// exact same code path). Any other scheme fails closed.
func Fetch(rawURL string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > maxFetchBytes {
		maxBytes = maxFetchBytes
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, sanitizedParseError(err)
	}
	switch u.Scheme {
	case "file":
		return fetchFile(u, maxBytes)
	case "http", "https":
		return fetchHTTP(rawURL, u, maxBytes)
	default:
		return nil, fmt.Errorf("unsupported url scheme %q (only http, https, file)", u.Scheme)
	}
}

// sanitizedParseError strips the raw input from a url.Parse failure.
func sanitizedParseError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return fmt.Errorf("parse url: %s (input redacted)", ue.Err)
	}
	return errors.New("parse url: invalid url (input redacted)")
}

func fetchFile(u *url.URL, maxBytes int64) ([]byte, error) {
	if u.Host != "" && u.Host != "localhost" {
		return nil, fmt.Errorf("file url with remote host %q is not supported", u.Host)
	}
	path := u.Path
	if path == "" {
		return nil, errors.New("file url has empty path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is %d bytes, exceeds limit %d", path, info.Size(), maxBytes)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

var httpFetchClient = &http.Client{Timeout: 10 * time.Minute}

func fetchHTTP(rawURL string, u *url.URL, maxBytes int64) ([]byte, error) {
	if u.Host == "" {
		return nil, errors.New("http url has empty host")
	}
	resp, err := httpFetchClient.Get(rawURL)
	if err != nil {
		return nil, httpGetError(u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get %s: status %s", redactURL(u), resp.Status)
	}
	if resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("http get %s: content length %d exceeds limit %d", redactURL(u), resp.ContentLength, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("http get %s: read body: %w", redactURL(u), err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("http get %s: body exceeds limit %d", redactURL(u), maxBytes)
	}
	return data, nil
}

func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.Fragment = ""
	return c.String()
}

func httpGetError(u *url.URL, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("http get %s: request canceled", redactURL(u))
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("http get %s: timed out", redactURL(u))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("http get %s: timed out", redactURL(u))
	}
	if cause := innermostHTTPCause(err); cause != "" {
		return fmt.Errorf("http get %s: %s", redactURL(u), cause)
	}
	return fmt.Errorf("http get %s: network error", redactURL(u))
}

func innermostHTTPCause(err error) string {
	for {
		var ue *url.Error
		if !errors.As(err, &ue) {
			break
		}
		err = ue.Err
	}
	msg := err.Error()
	if strings.Contains(msg, "://") {
		return ""
	}
	return msg
}

func joinBaseURL(base, name string) (string, error) {
	if !distribution.IsSafeFileName(name) {
		return "", fmt.Errorf("file name %q is not safe for url joining", name)
	}
	base = strings.TrimRight(base, "/")
	if base == "" {
		return "", errors.New("base url is empty")
	}
	u, err := url.Parse(base + "/" + name)
	if err != nil {
		return "", sanitizedParseError(err)
	}
	switch u.Scheme {
	case "http", "https", "file":
	default:
		return "", fmt.Errorf("base url scheme %q is not http, https, or file", u.Scheme)
	}
	return u.String(), nil
}

func readReleaseFile(distDir, baseURL, name string, maxBytes int64) ([]byte, error) {
	if distDir != "" {
		if !distribution.IsSafeFileName(name) {
			return nil, fmt.Errorf("file name %q is not safe", name)
		}
		return distribution.ReadBoundedFile(filepath.Join(distDir, name), maxBytes)
	}
	u, err := joinBaseURL(baseURL, name)
	if err != nil {
		return nil, err
	}
	return Fetch(u, maxBytes)
}
