package auth

import (
	"encoding/base64"
	"testing"
	"time"
)

// syntheticJWT builds an unsigned three-segment JWS for tests. The signature
// segment is deliberately bogus: unverifiedTokenHint must never look at it.
func syntheticJWT(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".bogus-signature"
}

func TestUnverifiedTokenHintSubjectAndExpiry(t *testing.T) {
	sub, exp, ok := unverifiedTokenHint(syntheticJWT(t, `{"sub":"user_synthetic123","exp":1893456000}`))
	if !ok {
		t.Fatal("expected ok for a well-formed JWT payload")
	}
	if sub != "user_synthetic123" {
		t.Fatalf("subject: got %q, want %q", sub, "user_synthetic123")
	}
	if want := time.Unix(1893456000, 0).UTC(); !exp.Equal(want) {
		t.Fatalf("expiry: got %v, want %v", exp, want)
	}
}

func TestUnverifiedTokenHintSubjectOnly(t *testing.T) {
	sub, exp, ok := unverifiedTokenHint(syntheticJWT(t, `{"sub":"user_synthetic123"}`))
	if !ok || sub != "user_synthetic123" {
		t.Fatalf("unexpected result: ok=%v sub=%q", ok, sub)
	}
	if !exp.IsZero() {
		t.Fatalf("expected zero expiry, got %v", exp)
	}
}

func TestUnverifiedTokenHintExpiryOnly(t *testing.T) {
	sub, exp, ok := unverifiedTokenHint(syntheticJWT(t, `{"exp":1893456000}`))
	if !ok {
		t.Fatal("expected ok even without a subject claim")
	}
	if sub != "" {
		t.Fatalf("expected empty subject, got %q", sub)
	}
	if exp.Unix() != 1893456000 {
		t.Fatalf("unexpected expiry: %v", exp)
	}
}

func TestUnverifiedTokenHintPaddedSegment(t *testing.T) {
	payload := base64.URLEncoding.EncodeToString([]byte(`{"sub":"user_synthetic123"}`))
	token := "header." + payload + ".bogus-signature"
	sub, _, ok := unverifiedTokenHint(token)
	if !ok || sub != "user_synthetic123" {
		t.Fatalf("padded base64url payload should decode: ok=%v sub=%q", ok, sub)
	}
}

func TestUnverifiedTokenHintRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"not a jwt":        "synthetic-opaque-token",
		"two segments":     "header.body",
		"four segments":    "a.b.c.d",
		"empty payload":    "header..sig",
		"invalid base64":   "header.####.sig",
		"payload not json": syntheticJWT(t, `not-json`),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			sub, exp, ok := unverifiedTokenHint(token)
			if ok || sub != "" || !exp.IsZero() {
				t.Fatalf("expected rejection, got ok=%v sub=%q exp=%v", ok, sub, exp)
			}
		})
	}
}
