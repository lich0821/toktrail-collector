package identity

import (
	"strings"
	"testing"
)

func TestEventIdentityStabilityAndNamespaces(t *testing.T) {
	key, err := EventKey("subject-a", "user_cursor_1234567890", "event-1")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EventKey("subject-a", "user_cursor_1234567890", "event-1")
	if key != again || !strings.HasPrefix(key, "cursor-v1:") || len(key) != len("cursor-v1:")+64 {
		t.Fatalf("invalid stable key %q", key)
	}
	for _, args := range [][3]string{
		{"subject-b", "user_cursor_1234567890", "event-1"},
		{"subject-a", "user_cursor_0987654321", "event-1"},
		{"subject-a", "user_cursor_1234567890", "event-2"},
	} {
		other, err := EventKey(args[0], args[1], args[2])
		if err != nil || other == key {
			t.Fatalf("identity namespaces must be distinct: %q %v", other, err)
		}
	}
	if strings.Contains(key, "subject-a") || strings.Contains(key, "user_cursor") || strings.Contains(key, "event-1") {
		t.Fatal("event key exposes raw identifiers")
	}
}

func TestIdentityRejectsMissingAndMalformedInputs(t *testing.T) {
	for _, bad := range []string{"", " bad", "bad\nidentity", strings.Repeat("x", 257)} {
		if _, err := EventKey("subject", bad, "event"); err == nil {
			t.Fatal("accepted malformed account identity")
		}
		if MatchAccount(bad) != "" {
			t.Fatal("accepted malformed local account identity")
		}
	}
}

func TestVersionOneIdentityGoldenVector(t *testing.T) {
	ns := SubjectNamespace("app-a", "user-1")
	if ns != "7eba54f280590872b40bce55239a888c9b41046d420cd9278f07cd662176b95a" {
		t.Fatalf("subject namespace v1 drifted: %s", ns)
	}
	key, err := EventKey(ns, "user_cursor_1234567890", "event-1")
	if err != nil || key != "cursor-v1:675df42f14828e34277155b2b146b0e8c45fd26d534857119a985aaac554a73c" {
		t.Fatalf("event identity v1 drifted: %s %v", key, err)
	}
}

func TestSubjectNamespaceSeparatesApplications(t *testing.T) {
	a := SubjectNamespace("app-a", "same-external-user")
	b := SubjectNamespace("app-b", "same-external-user")
	if a == "" || a == b || a != SubjectNamespace("app-a", "same-external-user") {
		t.Fatal("subject namespace is not stable and application-isolated")
	}
	if SubjectNamespace("", "user") != "" {
		t.Fatal("missing application identity accepted")
	}
	ka, _ := EventKey(a, "cursor-account", "event")
	kb, _ := EventKey(b, "cursor-account", "event")
	if ka == kb {
		t.Fatal("equal external ids in different applications share event keys")
	}
}

func TestLengthFramingPreventsDelimiterCollisions(t *testing.T) {
	a, _ := EventKey("subject", "a|b", "c")
	b, _ := EventKey("subject", "a", "b|c")
	if a == b {
		t.Fatal("framing allowed identity collision")
	}
	if MatchAccount("account") == digest("toktrail/cursor/event/v1", "account") {
		t.Fatal("local and uploaded identities share a hash domain")
	}
}
