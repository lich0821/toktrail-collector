// Package identity derives opaque Cursor event identities without exposing
// Cursor account or request identifiers in upload records. Account ownership
// must be verified by the API client before callers use these functions.
package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"unicode"
)

var ErrIdentity = errors.New("cursor requires verified stable account and event identities")

// EventKey is stable within a TokTrail subject, across device replacement and
// source-instance recreation. Neither mutable token counts nor login tokens
// participate in the key. This is pseudonymization, not proof of ownership.
func EventKey(subjectID, accountID, eventID string) (string, error) {
	if !valid(subjectID) || !valid(accountID) || !valid(eventID) {
		return "", ErrIdentity
	}
	return "cursor-v1:" + digest("toktrail/cursor/event/v1", subjectID, accountID, eventID), nil
}

// SubjectNamespace disambiguates equal external subject ids used by different
// TokTrail applications. It stays stable when the collection device changes.
func SubjectNamespace(applicationID, externalSubjectID string) string {
	if !valid(applicationID) || !valid(externalSubjectID) {
		return ""
	}
	return digest("toktrail/cursor/subject/v1", applicationID, externalSubjectID)
}

// MatchAccount is local-only account-switch detection metadata. It must not
// appear in the upload payload, diagnostics, or ordinary log messages.
func MatchAccount(accountID string) string {
	if !valid(accountID) {
		return ""
	}
	return digest("toktrail/cursor/local-account/v1", accountID)
}

func valid(s string) bool {
	if len(s) == 0 || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func digest(domain string, parts ...string) string {
	h := sha256.New()
	frame(h, domain)
	for _, p := range parts {
		frame(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func frame(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}
