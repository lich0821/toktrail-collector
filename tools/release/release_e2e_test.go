package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

// TestEndToEndRelease exercises the full pipeline against real go builds:
// keygen -> build all 6 platforms via scripts/release.sh -> verify the whole dist
// -> install via the generated bootstrap script (file:// base URL) -> run the
// installed collector. It is slow (12 cross-compiles) and therefore gated behind
// TOKTRAIL_RELEASE_E2E=1.
func TestEndToEndRelease(t *testing.T) {
	if os.Getenv("TOKTRAIL_RELEASE_E2E") != "1" {
		t.Skip("set TOKTRAIL_RELEASE_E2E=1 to run the slow end-to-end release test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap script execution test is POSIX-only")
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	version := "v0.1.0-test.1"

	// 1. Key generation with an explicitly labeled TEST key.
	keyPath := filepath.Join(work, "TEST-release-key.pem")
	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := distribution.WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(work, "pinned-pub.pem")
	if err := os.WriteFile(pinPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Build release via scripts/release.sh
	distRoot := filepath.Join(work, "dist")
	releaseScript := filepath.Join(repoRoot, "scripts", "release.sh")
	buildCmd := exec.Command("sh", releaseScript, "build", version, "--dist", distRoot, "--key", keyPath)
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "GOPROXY=off", "GOCACHE="+filepath.Join(repoRoot, ".gocache"))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/release.sh failed: %v\n%s", err, out)
	}

	distDir := filepath.Join(distRoot, version)
	manifestPath := filepath.Join(distDir, distribution.ManifestFileName)
	sigPath := filepath.Join(distDir, distribution.ManifestSignatureFileName)

	// 3. Verify the whole dist directory against the pinned key.
	m, err := installer.Verify(installer.VerifyOptions{
		ManifestPath:    manifestPath,
		SignaturePath:   sigPath,
		PubKeyPath:      pinPath,
		DistDir:         distDir,
		ExpectedVersion: version,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(m.Artifacts) != len(distribution.ReleasePlatforms) {
		t.Fatalf("built %d artifacts, want %d", len(m.Artifacts), len(distribution.ReleasePlatforms))
	}

	// 4. Install via the generated bootstrap script with a file:// base URL.
	installDir := filepath.Join(work, "install-target")
	scriptPath := filepath.Join(distDir, "install-"+version+".sh")
	cmd := exec.Command("sh", scriptPath, "file://"+distDir, installDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap script failed: %v\n%s", err, out)
	}

	// 5. The installed collector must run and report the release version.
	installed := filepath.Join(installDir, "toktrail")
	out, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed toktrail failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("installed toktrail reports %q, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}

	// 6. A second run must refuse to clobber in no-clobber mode via the
	//    underlying installer (the script itself always replaces).
	tool := distribution.InstallerBinaryName(version, runtime.GOOS, runtime.GOARCH)
	toolPath := filepath.Join(distDir, tool)
	if out, err := exec.Command(toolPath, "install",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
		"-install-dir", installDir,
		"-no-replace",
	).CombinedOutput(); err == nil {
		t.Fatalf("second install with -no-replace succeeded\n%s", out)
	}

	// 7. In-place upgrade, same version: must fail closed without
	//    -allow-downgrade, leaving the binary untouched.
	upEnv := append(os.Environ(), "PATH="+installDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	upgRefuse := exec.Command(toolPath, "upgrade",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
	)
	upgRefuse.Env = upEnv
	if out, err := upgRefuse.CombinedOutput(); err == nil {
		t.Fatalf("same-version upgrade without -allow-downgrade succeeded\n%s", out)
	} else if !strings.Contains(string(out), "already at") {
		t.Fatalf("same-version upgrade should explain the refusal, got: %s", out)
	}

	// 8. In-place upgrade with -allow-downgrade reinstalls at the original
	//    path (PATH discovery), keeps .previous, and the binary still runs.
	upgRun := exec.Command(toolPath, "upgrade",
		"-base-url", "file://"+distDir,
		"-version", version,
		"-pubkey", pinPath,
		"-allow-downgrade",
	)
	upgRun.Env = upEnv
	if out, err := upgRun.CombinedOutput(); err != nil {
		t.Fatalf("upgrade with -allow-downgrade failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(installed + ".previous"); err != nil {
		t.Fatalf("expected the previous binary to be kept: %v", err)
	}
	out, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("upgraded toktrail failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("upgraded toktrail reports %q, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}
	prev, err := exec.Command(installed+".previous", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("kept .previous binary failed: %v\n%s", err, prev)
	}
	if strings.TrimSpace(string(prev)) != "toktrail "+version {
		t.Errorf("kept .previous reports %q, want %q", strings.TrimSpace(string(prev)), "toktrail "+version)
	}

	// 9. Bootstrap script --upgrade also fails closed on the same version
	//    and must leave the installed binary untouched.
	scriptUpg := exec.Command("sh", scriptPath, "file://"+distDir, "--upgrade")
	scriptUpg.Env = upEnv
	if out, err := scriptUpg.CombinedOutput(); err == nil {
		t.Fatalf("bootstrap --upgrade on the same version succeeded\n%s", out)
	}
	out, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("toktrail failed after refused script upgrade: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "toktrail "+version {
		t.Errorf("toktrail reports %q after refused script upgrade, want %q", strings.TrimSpace(string(out)), "toktrail "+version)
	}
}
