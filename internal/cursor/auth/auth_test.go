package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialJSONOmitsSecrets(t *testing.T) {
	c := Credential{
		AccessToken: "synthetic-secret-token",
		AccountID:   "synthetic-account-id",
		AccountHint: "synthetic-account-hint",
		Source:      SourceDesktopSQLite,
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(b)
	for _, secret := range []string{"synthetic-secret-token", "synthetic-account-id", "synthetic-account-hint"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("json marshaling leaked %q: %s", secret, rendered)
		}
	}
	if !strings.Contains(rendered, SourceDesktopSQLite) {
		t.Fatalf("expected non-secret source in json: %s", rendered)
	}
}

func TestCredentialFmtRedacted(t *testing.T) {
	c := Credential{
		AccessToken: "synthetic-secret-token",
		AccountID:   "synthetic-account-id",
		AccountHint: "synthetic-account-hint",
		Source:      SourceDesktopSQLite,
	}
	secrets := []string{"synthetic-secret-token", "synthetic-account-id", "synthetic-account-hint"}
	renderings := []string{
		c.String(),
		c.GoString(),
		fmt.Sprint(c),
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprintf("%v", &c),
		fmt.Sprintf("%#v", &c),
		fmt.Sprintf("wrapped: %v", c),
		fmt.Errorf("wrapped: %w", &ReadError{Code: CodeUnavailable, Op: "query"}).Error(),
	}
	for _, rendered := range renderings {
		for _, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Fatalf("fmt rendering leaked %q: %s", secret, rendered)
			}
		}
	}
}

func TestCredentialStringShowsPresenceOnly(t *testing.T) {
	present := Credential{AccessToken: "synthetic-secret-token", AccountID: "a", AccountHint: "h"}.String()
	if !strings.Contains(present, "HasToken:true") || !strings.Contains(present, "HasAccountID:true") || !strings.Contains(present, "HasAccountHint:true") {
		t.Fatalf("presence flags missing: %s", present)
	}
	absent := Credential{}.String()
	if !strings.Contains(absent, "HasToken:false") || !strings.Contains(absent, "HasAccountID:false") {
		t.Fatalf("absence flags missing: %s", absent)
	}
}

func TestReadErrorMatching(t *testing.T) {
	err := &ReadError{Code: CodeNoLogin, Op: "query"}
	if got, want := err.Error(), "cursor/auth: query: no_login"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrNoLogin) {
		t.Fatal("errors.Is(err, ErrNoLogin) failed")
	}
	if errors.Is(err, ErrPermission) {
		t.Fatal("errors.Is must not match a different code")
	}
	var re *ReadError
	if !errors.As(err, &re) || re.Code != CodeNoLogin {
		t.Fatalf("errors.As failed: %v", err)
	}
	wrapped := fmt.Errorf("outer: %w", err)
	if !errors.Is(wrapped, ErrNoLogin) {
		t.Fatal("errors.Is through wrapping failed")
	}
}

func TestProviderInterfaceCompliance(t *testing.T) {
	var _ Provider = DesktopProvider(Options{HomeDir: "/synthetic-home"})
	var _ Provider = desktopProvider{}
}
