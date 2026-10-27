package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLegacyBuildDelegatesWithCallerRelativePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX build compatibility is exercised on Linux/macOS")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	repo := filepath.Join(t.TempDir(), "checkout with spaces")
	if err := os.MkdirAll(filepath.Join(repo, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "arguments")
	t.Setenv("TOKTRAIL_TEST_BUILD_CAPTURE", capture)
	spy := "#!/bin/sh\nset -eu\npwd > \"$TOKTRAIL_TEST_BUILD_CAPTURE\"\nprintf '%s\\n' \"$@\" >> \"$TOKTRAIL_TEST_BUILD_CAPTURE\"\n"
	if err := os.WriteFile(filepath.Join(repo, "scripts", "release.sh"), []byte(spy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdBuild([]string{"-version", "v0.1.0-test.1", "-repo", repo, "-dist", "output with spaces", "-key", "keys/test key.pem"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	dist, _ := filepath.Abs("output with spaces")
	key, _ := filepath.Abs("keys/test key.pem")
	// Check the child cwd using SameFile: macOS can resolve /var to /private/var.
	gotDir, err := os.Stat(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	wantDir, _ := os.Stat(repo)
	if !os.SameFile(gotDir, wantDir) {
		t.Fatalf("wrong script cwd: %s", lines[0])
	}
	if len(lines) != 9 || strings.Join(lines[1:6], "\n") != strings.Join([]string{"build", "v0.1.0-test.1", "--dist", dist, "--go"}, "\n") || !filepath.IsAbs(lines[6]) || lines[7] != "--key" || lines[8] != key {
		t.Fatalf("unexpected script arguments: %q", lines)
	}
}

func TestLegacyBuildRejectsInvalidVersionBeforeScript(t *testing.T) {
	if err := cmdBuild([]string{"-version", "../../unsafe", "-repo", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "build version") {
		t.Fatalf("expected version validation before checkout access, got %v", err)
	}
}

func TestLegacyBuildRequiresCheckout(t *testing.T) {
	if err := cmdBuild([]string{"-version", "v0.1.0", "-repo", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "source checkout") {
		t.Fatalf("expected a clear checkout requirement, got %v", err)
	}
}

func TestCmdUpgradeValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no flags", nil, "-base-url or -dist-dir"},
		{"no version", []string{"-dist-dir", "/nonexistent-dist"}, "-version is required"},
		{"latest", []string{"-dist-dir", "/nonexistent-dist", "-version", "latest"}, "-version"},
	}
	for _, tc := range cases {
		if err := cmdUpgrade(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
	// A missing existing installation must fail closed with a hint.
	if err := cmdUpgrade([]string{"-dist-dir", "/nonexistent-dist", "-version", "v0.2.0", "-install-dir", t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "no existing") {
		t.Errorf("expected missing-installation refusal, got %v", err)
	}
}
