package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// unverifiedTokenHint extracts the subject and expiry claims from the JWT
// payload of token WITHOUT verifying its signature or any header claim.
//
// The result is an unverified hint only: a JWT payload is attacker-
// controlled data and parsing it proves nothing about identity. The
// authoritative account identity must come from the server identity
// endpoint. ok is false when token is not a JWS with three dot-separated
// segments or its payload cannot be decoded; that is not an error, because
// the token itself remains usable as a bearer credential.
func unverifiedTokenHint(token string) (sub string, expiresAt time.Time, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		return "", time.Time{}, false
	}
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return "", time.Time{}, false
	}
	var claims struct {
		Sub string  `json:"sub"`
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", time.Time{}, false
	}
	if claims.Exp > 0 {
		expiresAt = time.Unix(int64(claims.Exp), 0).UTC()
	}
	return claims.Sub, expiresAt, true
}

// decodeJWTSegment decodes a base64url JWT segment, with or without
// padding.
func decodeJWTSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}
