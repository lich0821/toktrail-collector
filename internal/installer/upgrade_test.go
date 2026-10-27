package installer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
)

// fakeVersionScript returns a POSIX shell script that impersonates a
// toktrail binary reporting the given version. Existing-binary tests that
// execute it are skipped on Windows, matching the install downgrade tests.
func fakeVersionScript(v string) string {
	return "#!/bin/sh\necho 'toktrail " + v + "'\n"
}

// withLookPath overrides the PATH-discovery seam for one test.
func withLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	old := lookPath
	lookPath = fn
	t.Cleanup(func() { lookPath = old })
}

// canonicalPath resolves symlinks the same way discovery does, so tests can
// compare paths on macOS where t.TempDir() reports /var but the filesystem
// resolves it to /private/var.
func canonicalPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func writeExistingScript(t *testing.T, dir, version string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "toktrail"+distribution.BinaryExt(runtime.GOOS))
	if err := os.WriteFile(p, []byte(fakeVersionScript(version)), 0o755); err != nil {
		t.Fatal(err)
	}
	return canonicalPath(t, p)
}

func TestUpgradeHappyPathViaPATHDiscovery(t *testing.T) {
	binDir := t.TempDir()
	existing := writeExistingScript(t, binDir, "v0.1.0")
	fd := newFakeDistBinary(t, "v0.2.0", fakeVersionScript("v0.2.0"))

	withLookPath(t, func(name string) (string, error) {
		if name != "toktrail"+distribution.BinaryExt(runtime.GOOS) {
			return "", fmt.Errorf("unexpected lookup %q", name)
		}
		return existing, nil
	})

	res, err := Upgrade(UpgradeOptions{
		DistDir:    fd.versionDir,
		Version:    "v0.2.0",
		PubKeyPath: fd.pubPath,
		KeepOld:    true,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.FromVersion != "v0.1.0" || res.Version != "v0.2.0" {
		t.Errorf("unexpected result: %+v", res)
	}
	if !res.DiscoveredViaPATH {
		t.Error("expected DiscoveredViaPATH for PATH discovery")
	}
	if res.BinaryPath != existing {
		t.Errorf("binary path = %s, want the original %s", res.BinaryPath, existing)
	}
	if res.KeptOldPath != existing+previousBinarySuffix {
		t.Errorf("kept old path = %s", res.KeptOldPath)
	}
	cur, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != fakeVersionScript("v0.2.0") {
		t.Error("existing path does not contain the new binary")
	}
	old, err := os.ReadFile(res.KeptOldPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != fakeVersionScript("v0.1.0") {
		t.Error(".previous does not contain the replaced binary")
	}
	// Only the binary and its kept copy exist in the install directory.
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("install dir has unexpected entries: %v", names)
	}
}

func TestUpgradeExplicitInstallDirBypassesPATH(t *testing.T) {
	binDir := t.TempDir()
	existing := writeExistingScript(t, binDir, "v0.1.0")
	fd := newFakeDistBinary(t, "v0.2.0", fakeVersionScript("v0.2.0"))

	// PATH discovery is unavailable; the explicit directory must win.
	withLookPath(t, func(string) (string, error) {
		return "", errors.New("not found")
	})

	res, err := Upgrade(UpgradeOptions{
		DistDir:    fd.versionDir,
		Version:    "v0.2.0",
		PubKeyPath: fd.pubPath,
		InstallDir: binDir,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.DiscoveredViaPATH {
		t.Error("explicit -install-dir must not be reported as PATH discovery")
	}
	if res.BinaryPath != existing {
		t.Errorf("binary path = %s, want %s", res.BinaryPath, existing)
	}
}

func TestUpgradeRequiresExistingInstallation(t *testing.T) {
	fd := newFakeDist(t, "v0.2.0")

	// PATH discovery finds nothing.
	withLookPath(t, func(string) (string, error) {
		return "", errors.New("not found")
	})
	_, err := Upgrade(upgradeOpts(fd, ""))
	if err == nil || !strings.Contains(err.Error(), "install command") {
		t.Fatalf("expected a clear fresh-install hint, got %v", err)
	}

	// An explicit directory without the binary is also refused.
	empty := t.TempDir()
	opts := upgradeOpts(fd, empty)
	withLookPath(t, func(string) (string, error) {
		return "", errors.New("not found")
	})
	if _, err := Upgrade(opts); err == nil || !strings.Contains(err.Error(), "no existing") {
		t.Fatalf("expected missing-binary refusal, got %v", err)
	}
}

func TestUpgradeRefusesSameVersionAndDowngrade(t *testing.T) {
	binDir := t.TempDir()
	existing := writeExistingScript(t, binDir, "v0.2.0")
	fdSame := newFakeDistBinary(t, "v0.2.0", fakeVersionScript("v0.2.0"))
	fdOlder := newFakeDistBinary(t, "v0.1.0", fakeVersionScript("v0.1.0"))

	same := upgradeOpts(fdSame, binDir)
	if _, err := Upgrade(same); err == nil || !strings.Contains(err.Error(), "already at") {
		t.Fatalf("same-version upgrade must refuse, got %v", err)
	}
	down := upgradeOpts(fdOlder, binDir)
	if _, err := Upgrade(down); err == nil || !strings.Contains(err.Error(), "refusing to downgrade") {
		t.Fatalf("downgrade must refuse, got %v", err)
	}

	// -allow-downgrade permits both a reinstall and a downgrade.
	same.AllowDowngrade = true
	if res, err := Upgrade(same); err != nil || res.FromVersion != "v0.2.0" {
		t.Fatalf("same-version reinstall with -allow-downgrade failed: %v", err)
	}
	down.AllowDowngrade = true
	if res, err := Upgrade(down); err != nil || res.FromVersion != "v0.2.0" || res.Version != "v0.1.0" {
		t.Fatalf("downgrade with -allow-downgrade failed: %v", err)
	}
	if cur, err := os.ReadFile(existing); err != nil || string(cur) != fakeVersionScript("v0.1.0") {
		t.Errorf("downgrade did not install the older binary")
	}
}

func TestUpgradeRefusesUnidentifiableExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is not a runnable Windows executable")
	}
	binDir := t.TempDir()
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(binDir, "toktrail")
	if err := os.WriteFile(junk, []byte("definitely not a toktrail binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fd := newFakeDist(t, "v0.2.0")
	_, err := Upgrade(upgradeOpts(fd, binDir))
	if err == nil || !strings.Contains(err.Error(), "cannot determine the version") {
		t.Fatalf("expected refusal to replace an unknown file, got %v", err)
	}
	if cur, err := os.ReadFile(junk); err != nil || string(cur) != "definitely not a toktrail binary\n" {
		t.Error("refusal must leave the existing file untouched")
	}
}

func TestUpgradeKeepOldChainAndDisable(t *testing.T) {
	binDir := canonicalPath(t, t.TempDir())
	writeExistingScript(t, binDir, "v0.1.0")
	fd2 := newFakeDistBinary(t, "v0.2.0", fakeVersionScript("v0.2.0"))
	fd3 := newFakeDistBinary(t, "v0.3.0", fakeVersionScript("v0.3.0"))
	target := filepath.Join(binDir, "toktrail")
	prev := target + previousBinarySuffix

	res, err := Upgrade(UpgradeOptions{DistDir: fd2.versionDir, Version: "v0.2.0", PubKeyPath: fd2.pubPath, InstallDir: binDir, KeepOld: true})
	if err != nil {
		t.Fatalf("first upgrade: %v", err)
	}
	if got := readOrFail(t, prev); got != fakeVersionScript("v0.1.0") {
		t.Errorf("after first upgrade .previous = %q", got)
	}

	// The second upgrade overwrites .previous with the then-current binary
	// (one-step rollback chain).
	res, err = Upgrade(UpgradeOptions{DistDir: fd3.versionDir, Version: "v0.3.0", PubKeyPath: fd3.pubPath, InstallDir: binDir, KeepOld: true})
	if err != nil {
		t.Fatalf("second upgrade: %v", err)
	}
	if got := readOrFail(t, target); got != fakeVersionScript("v0.3.0") {
		t.Errorf("target = %q after second upgrade", got)
	}
	if got := readOrFail(t, prev); got != fakeVersionScript("v0.2.0") {
		t.Errorf(".previous = %q after second upgrade, want the v0.2.0 binary", got)
	}
	if res.KeptOldPath != prev {
		t.Errorf("KeptOldPath = %s", res.KeptOldPath)
	}

	// KeepOld=false neither creates nor removes an existing .previous.
	fd4 := newFakeDistBinary(t, "v0.4.0", fakeVersionScript("v0.4.0"))
	res, err = Upgrade(UpgradeOptions{DistDir: fd4.versionDir, Version: "v0.4.0", PubKeyPath: fd4.pubPath, InstallDir: binDir})
	if err != nil {
		t.Fatalf("third upgrade without keep-old: %v", err)
	}
	if res.KeptOldPath != "" {
		t.Errorf("KeptOldPath = %s, want empty", res.KeptOldPath)
	}
	if got := readOrFail(t, prev); got != fakeVersionScript("v0.2.0") {
		t.Errorf(".previous must be left untouched when keep-old is disabled, got %q", got)
	}
}

func TestUpgradeConflictHandling(t *testing.T) {
	fd := newFakeDist(t, "v0.2.0")

	// Target path is a directory.
	dirTarget := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirTarget, "toktrail"+distribution.BinaryExt(runtime.GOOS)), 0o755); err != nil {
		t.Fatal(err)
	}
	withLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
	if _, err := Upgrade(upgradeOpts(fd, dirTarget)); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected non-regular refusal, got %v", err)
	}

	// .previous exists but is a directory (POSIX-only: needs an
	// identifiable existing binary first).
	if runtime.GOOS != "windows" {
		binDir := t.TempDir()
		target := filepath.Join(binDir, "toktrail")
		if err := os.WriteFile(target, []byte(fakeVersionScript("v0.1.0")), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(target+previousBinarySuffix, 0o755); err != nil {
			t.Fatal(err)
		}
		opts := upgradeOpts(fd, binDir)
		opts.KeepOld = true
		if _, err := Upgrade(opts); err == nil || !strings.Contains(err.Error(), previousBinarySuffix) {
			t.Fatalf("expected .previous conflict refusal, got %v", err)
		}
		if cur, err := os.ReadFile(target); err != nil || string(cur) != fakeVersionScript("v0.1.0") {
			t.Error("conflict refusal must leave the existing binary untouched")
		}
	}
}

func TestUpgradeResolvesSymlinkToRealFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	realDir, linkDir := t.TempDir(), t.TempDir()
	writeExistingScript(t, realDir, "v0.1.0")
	link := filepath.Join(linkDir, "toktrail")
	if err := os.Symlink(filepath.Join(realDir, "toktrail"), link); err != nil {
		t.Fatal(err)
	}
	fd := newFakeDistBinary(t, "v0.2.0", fakeVersionScript("v0.2.0"))

	withLookPath(t, func(string) (string, error) { return link, nil })

	res, err := Upgrade(UpgradeOptions{DistDir: fd.versionDir, Version: "v0.2.0", PubKeyPath: fd.pubPath})
	if err != nil {
		t.Fatalf("Upgrade through symlink: %v", err)
	}
	want := canonicalPath(t, filepath.Join(realDir, "toktrail"))
	if res.BinaryPath != want {
		t.Errorf("binary path = %s, want resolved %s", res.BinaryPath, want)
	}
	if got := readOrFail(t, want); got != fakeVersionScript("v0.2.0") {
		t.Error("resolved real file was not upgraded")
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink itself must remain a symlink")
	}
}

func TestUpgradeRefusesNonCanonicalResolvedName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	realDir, linkDir := t.TempDir(), t.TempDir()
	real := filepath.Join(realDir, "toktrail-backup")
	if err := os.WriteFile(real, []byte(fakeVersionScript("v0.1.0")), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "toktrail")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fd := newFakeDist(t, "v0.2.0")

	withLookPath(t, func(string) (string, error) { return link, nil })

	if _, err := Upgrade(UpgradeOptions{DistDir: fd.versionDir, Version: "v0.2.0", PubKeyPath: fd.pubPath}); err == nil ||
		!strings.Contains(err.Error(), "canonical") {
		t.Fatalf("expected canonical-name refusal, got %v", err)
	}
	if got := readOrFail(t, real); got != fakeVersionScript("v0.1.0") {
		t.Error("refusal must leave the real file untouched")
	}
}

func TestUpgradeOptionValidation(t *testing.T) {
	fd := newFakeDist(t, "v0.2.0")
	binDir := t.TempDir()

	// Option validation happens before any discovery or download.
	cases := []struct {
		name string
		opts UpgradeOptions
		want string
	}{
		{"no source", UpgradeOptions{Version: "v0.2.0", PubKeyPath: fd.pubPath}, "-base-url or -dist-dir"},
		{"both sources", UpgradeOptions{DistDir: fd.versionDir, BaseURL: "https://x.invalid", Version: "v0.2.0", PubKeyPath: fd.pubPath}, "mutually exclusive"},
		{"no version", UpgradeOptions{DistDir: fd.versionDir, PubKeyPath: fd.pubPath, InstallDir: binDir}, "-version is required"},
		{"latest", UpgradeOptions{DistDir: fd.versionDir, Version: "latest", PubKeyPath: fd.pubPath, InstallDir: binDir}, "-version"},
	}
	for _, tc := range cases {
		if _, err := Upgrade(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
}

func TestUpgradeWrongTrustRootLeavesBinaryInPlace(t *testing.T) {
	fd := newFakeDist(t, "v0.2.0")
	binDir := t.TempDir()
	writeExistingScript(t, binDir, "v0.1.9")

	// A wrong trust root is rejected by the shared verification pipeline.
	_, otherPub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := distribution.PublicKeyPEM(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub := filepath.Join(t.TempDir(), "wrong.pem")
	if err := os.WriteFile(wrongPub, []byte(otherPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := upgradeOpts(fd, binDir)
	opts.PubKeyPath = wrongPub
	if _, err := Upgrade(opts); err == nil || !strings.Contains(err.Error(), "signature verification") {
		t.Fatalf("expected verification failure under the wrong key, got %v", err)
	}
	// The existing binary must be untouched after the failed upgrade.
	if got := readOrFail(t, filepath.Join(binDir, "toktrail"+distribution.BinaryExt(runtime.GOOS))); got != fakeVersionScript("v0.1.9") {
		t.Error("failed upgrade must leave the existing binary in place")
	}
}

func upgradeOpts(fd *fakeDist, installDir string) UpgradeOptions {
	return UpgradeOptions{
		DistDir:    fd.versionDir,
		Version:    fd.version,
		PubKeyPath: fd.pubPath,
		InstallDir: installDir,
	}
}

func readOrFail(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
