package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
)

func generateTestPubKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, pem
}

func testManifest(version string) *distribution.Manifest {
	return &distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: "2026-10-24T00:00:00Z",
		Artifacts: []distribution.Artifact{
			{
				OS:                    "darwin",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-darwin-arm64",
				InstallerBinarySha256: strings.Repeat("a", 64),
			},
			{
				OS:                    "darwin",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-darwin-amd64",
				InstallerBinarySha256: strings.Repeat("b", 64),
			},
			{
				OS:                    "linux",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-linux-arm64",
				InstallerBinarySha256: strings.Repeat("c", 64),
			},
			{
				OS:                    "linux",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-linux-amd64",
				InstallerBinarySha256: strings.Repeat("d", 64),
			},
			{
				OS:                    "windows",
				Arch:                  "amd64",
				InstallerBinary:       "toktrail-release-" + version + "-windows-amd64.exe",
				InstallerBinarySha256: strings.Repeat("e", 64),
			},
			{
				OS:                    "windows",
				Arch:                  "arm64",
				InstallerBinary:       "toktrail-release-" + version + "-windows-arm64.exe",
				InstallerBinarySha256: strings.Repeat("f", 64),
			},
		},
	}
}

func TestScriptStaticInvariants(t *testing.T) {
	dir := t.TempDir()
	_, pubPEM := generateTestPubKey(t)
	m := testManifest("v1.2.3")

	paths, err := EmitInstallScripts(dir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}

	var shPath, ps1Path string
	for _, p := range paths {
		if strings.HasSuffix(p, ".sh") {
			shPath = p
		} else if strings.HasSuffix(p, ".ps1") {
			ps1Path = p
		}
	}
	if shPath == "" || ps1Path == "" {
		t.Fatalf("expected both .sh and .ps1 scripts, got %v", paths)
	}

	shContent, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}
	shStr := string(shContent)

	// POSIX script invariants:
	// 1. Must NOT use exec before installer (so EXIT trap cleanup runs).
	if strings.Contains(shStr, "exec \"$TMP") || strings.Contains(shStr, "exec $TMP") {
		t.Errorf("POSIX install script still uses exec to run installer, preventing cleanup trap")
	}
	// 2. Must register EXIT trap for cleanup.
	if !strings.Contains(shStr, "trap cleanup EXIT") {
		t.Errorf("POSIX install script missing 'trap cleanup EXIT'")
	}
	// 3. Must guard TMP against empty and non-absolute before rm -rf.
	if !strings.Contains(shStr, "/*)") || !strings.Contains(shStr, "rm -rf \"$TMP\"") {
		t.Errorf("POSIX install script missing guarded rm -rf for absolute TMP")
	}
	// 4. Must pin the public key.
	if !strings.Contains(shStr, pubPEM) {
		t.Errorf("POSIX install script missing pinned public key")
	}

	ps1Content, err := os.ReadFile(ps1Path)
	if err != nil {
		t.Fatal(err)
	}
	ps1Str := string(ps1Content)

	// PowerShell script invariants:
	// 1. Must have try / finally block.
	if !strings.Contains(ps1Str, "try {") || !strings.Contains(ps1Str, "finally {") {
		t.Errorf("PowerShell install script missing try / finally block")
	}
	// 2. Finally block must remove $tmp.
	if !strings.Contains(ps1Str, "Remove-Item -Recurse -Force $tmp") {
		t.Errorf("PowerShell install script missing cleanup in finally block")
	}
	// 3. Must propagate installer and curl failure exit codes.
	if !strings.Contains(ps1Str, "$LASTEXITCODE") {
		t.Errorf("PowerShell install script missing $LASTEXITCODE propagation")
	}
}

func TestPOSIXScriptBehavioralCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell execution test on Windows")
	}

	dir := t.TempDir()
	serverDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}

	version := "v0.9.9"
	_, pubPEM := generateTestPubKey(t)

	// Determine tool file name for current test runner host.
	var osName, archName string
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		t.Skipf("unsupported test OS: %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "arm64":
		archName = "arm64"
	case "amd64":
		archName = "amd64"
	default:
		t.Skipf("unsupported test ARCH: %s", runtime.GOARCH)
	}

	toolFile := fmt.Sprintf("toktrail-release-%s-%s-%s", version, osName, archName)
	fakeToolPath := filepath.Join(serverDir, toolFile)
	recordTmpFile := filepath.Join(dir, "recorded_tmp.txt")

	// Fake installer: writes the directory containing itself (TMP) to recordTmpFile and exits.
	fakeScript := fmt.Sprintf(`#!/bin/sh
set -eu
MY_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "$MY_DIR" > %q
if [ "${FAIL_INSTALLER:-0}" = "1" ]; then
  exit 42
fi
exit 0
`, recordTmpFile)

	if err := os.WriteFile(fakeToolPath, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Calculate hash of fakeToolPath.
	h := sha256.Sum256([]byte(fakeScript))
	toolHash := hex.EncodeToString(h[:])

	m := testManifest(version)
	for i := range m.Artifacts {
		if m.Artifacts[i].OS == osName && m.Artifacts[i].Arch == archName {
			m.Artifacts[i].InstallerBinarySha256 = toolHash
		}
	}

	scriptPaths, err := EmitInstallScripts(serverDir, m, pubPEM)
	if err != nil {
		t.Fatalf("EmitInstallScripts: %v", err)
	}

	var installScript string
	for _, p := range scriptPaths {
		if strings.HasSuffix(p, ".sh") {
			installScript = p
			break
		}
	}
	if installScript == "" {
		t.Fatal("install.sh not emitted")
	}

	// 1. Success case: verify installer runs, returns 0, and TMP directory is cleaned up.
	baseURL := "file://" + filepath.ToSlash(serverDir)
	cmd := exec.Command("/bin/sh", installScript, baseURL, filepath.Join(dir, "install_target"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh failed: %v\nOutput: %s", err, out)
	}

	recBytes, err := os.ReadFile(recordTmpFile)
	if err != nil {
		t.Fatalf("fake installer was not invoked: %v", err)
	}
	recordedTmp := strings.TrimSpace(string(recBytes))
	if recordedTmp == "" {
		t.Fatal("recordedTmp is empty")
	}
	if _, err := os.Stat(recordedTmp); !os.IsNotExist(err) {
		t.Errorf("TMP directory %s still exists after successful installer run; cleanup trap failed", recordedTmp)
	}

	// 2. Failure case: verify installer failure propagates exit code, and TMP directory is STILL cleaned up.
	os.Remove(recordTmpFile)
	cmdFail := exec.Command("/bin/sh", installScript, baseURL, filepath.Join(dir, "install_target"))
	cmdFail.Env = append(os.Environ(), "FAIL_INSTALLER=1")
	outFail, errFail := cmdFail.CombinedOutput()
	if errFail == nil {
		t.Fatalf("expected install.sh to fail with exit 42, but succeeded. Output: %s", outFail)
	}
	if exitErr, ok := errFail.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 42 {
			t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
		}
	} else {
		t.Errorf("unexpected error type: %v", errFail)
	}

	recBytesFail, err := os.ReadFile(recordTmpFile)
	if err != nil {
		t.Fatalf("fake installer was not invoked on failure test: %v", err)
	}
	recordedTmpFail := strings.TrimSpace(string(recBytesFail))
	if _, err := os.Stat(recordedTmpFail); !os.IsNotExist(err) {
		t.Errorf("TMP directory %s still exists after failed installer run; cleanup trap failed", recordedTmpFail)
	}
}
