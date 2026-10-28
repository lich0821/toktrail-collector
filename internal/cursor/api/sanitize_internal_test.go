package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestSanitizeTokenDropsSecretCause verifies the redaction contract: a
// secret-bearing error is redacted, its original cause becomes unreachable
// (Unwrap/As cannot surface it into logs), and only the cancellation
// sentinels stay detectable through errors.Is.
func TestSanitizeTokenDropsSecretCause(t *testing.T) {
	token := "user_secret1234%3A%3Ajwt.value"
	secret := fmt.Errorf("request to https://cursor.com/api with cookie %s failed: %w", token, context.DeadlineExceeded)

	sanitized := sanitizeToken(secret, token)

	if strings.Contains(sanitized.Error(), token) {
		t.Fatalf("message must be redacted: %q", sanitized.Error())
	}
	if !strings.Contains(sanitized.Error(), "[REDACTED]") {
		t.Fatalf("message must mark the redaction: %q", sanitized.Error())
	}
	if !errors.Is(sanitized, context.DeadlineExceeded) {
		t.Fatal("deadline sentinel must stay detectable through Is")
	}
	if errors.Is(sanitized, context.Canceled) {
		t.Fatal("a deadline error must not report cancellation")
	}
	if errors.Unwrap(sanitized) != nil {
		t.Fatal("the secret-bearing cause must be dropped, not kept behind Unwrap")
	}
	var urlErr *url.Error
	if errors.As(sanitized, &urlErr) {
		t.Fatal("the secret-bearing cause must not be reachable through As")
	}

	canceled := fmt.Errorf("post with %s: %w", token, context.Canceled)
	sanitizedCanceled := sanitizeToken(canceled, token)
	if !errors.Is(sanitizedCanceled, context.Canceled) {
		t.Fatal("cancellation sentinel must stay detectable through Is")
	}
	if errors.Is(sanitizedCanceled, context.DeadlineExceeded) {
		t.Fatal("a cancellation error must not report a deadline")
	}
	if errors.Unwrap(sanitizedCanceled) != nil {
		t.Fatal("the secret-bearing cause must be dropped, not kept behind Unwrap")
	}
}

// TestSanitizeTokenKeepsCleanChainsIntact verifies that errors carrying no
// token pass through untouched, preserving their full chain.
func TestSanitizeTokenKeepsCleanChainsIntact(t *testing.T) {
	clean := fmt.Errorf("request failed: %w", context.DeadlineExceeded)
	if got := sanitizeToken(clean, "user_secret1234%3A%3Ajwt.value"); got != clean {
		t.Fatal("a clean error must be returned unchanged")
	}
	if !errors.Is(clean, context.DeadlineExceeded) || errors.Unwrap(clean) == nil {
		t.Fatal("the clean chain must stay intact")
	}
}
