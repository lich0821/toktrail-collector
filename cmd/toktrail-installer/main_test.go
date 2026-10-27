package main

import (
	"strings"
	"testing"
)

// The upgrade command's full pipeline (discovery, verification, replacement)
// is tested in internal/installer and the gated release E2E. These tests
// cover the CLI surface: required flags, option validation order, and the
// fail-closed hint when no existing installation is present.

func TestRunUpgradeRequiresSourceAndVersion(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no flags", nil, "-base-url or -dist-dir"},
		{"no version", []string{"-dist-dir", "/nonexistent-dist"}, "-version is required"},
		{"both sources", []string{"-dist-dir", "/a", "-base-url", "https://x.invalid", "-version", "v0.2.0"}, "mutually exclusive"},
		{"latest", []string{"-dist-dir", "/nonexistent-dist", "-version", "latest"}, "-version"},
	}
	for _, tc := range cases {
		err := runUpgrade(tc.args)
		if err == nil {
			t.Errorf("%s: expected an error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not contain %q", tc.name, err.Error(), tc.want)
		}
	}
}

func TestRunUpgradeRequiresExistingInstallation(t *testing.T) {
	// A valid-looking invocation against an empty directory must fail with
	// the fresh-install hint instead of creating anything.
	dir := t.TempDir()
	err := runUpgrade([]string{
		"-dist-dir", "/nonexistent-dist",
		"-version", "v0.2.0",
		"-pubkey", "/nonexistent.pem",
		"-install-dir", dir,
	})
	if err == nil {
		t.Fatal("expected an error for a missing existing binary")
	}
	if !strings.Contains(err.Error(), "no existing") || !strings.Contains(err.Error(), "install command") {
		t.Fatalf("error should point at the install command for fresh installs, got %q", err.Error())
	}
}

func TestUsageDocumentsUpgradeBoundaries(t *testing.T) {
	for _, want := range []string{
		"upgrade -base-url",
		"no \"latest\" channel",
		"no automatic rollback",
		"unverified snapshot",
		"only that path was upgraded",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage text is missing %q", want)
		}
	}
}
