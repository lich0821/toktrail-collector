package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

func createFakePlatformBinaries(t *testing.T, dir, version string, platforms []distribution.Platform) {
	t.Helper()
	for _, p := range platforms {
		osName, arch := p.OS, p.Arch
		rawName := distribution.CollectorRawBinaryName(version, osName, arch)
		if err := os.WriteFile(filepath.Join(dir, rawName), []byte("fake collector "+osName+"-"+arch), 0o755); err != nil {
			t.Fatal(err)
		}
		toolName := distribution.InstallerBinaryName(version, osName, arch)
		if err := os.WriteFile(filepath.Join(dir, toolName), []byte("fake tool "+osName+"-"+arch), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRepeatAssembleRefusesExistingManifest(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	platforms := distribution.ReleasePlatforms
	createFakePlatformBinaries(t, dir, ver, platforms)

	// First assemble.
	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir}); err != nil {
		t.Fatalf("first assemble failed: %v", err)
	}

	manifestPath := filepath.Join(dir, distribution.ManifestFileName)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest not found: %v", err)
	}

	// Second assemble must fail and refuse to overwrite.
	err := runAssemble([]string{"-version", ver, "-dist-dir", dir})
	if err == nil {
		t.Fatal("second assemble should have failed because manifest already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestAssembleRefusesStaleOutputsBeforeWriting(t *testing.T) {
	const ver = "v0.1.0"
	for _, name := range []string{
		distribution.CollectorArchiveName(ver, "darwin", "amd64"),
		"install-" + ver + ".sh",
		"install-" + ver + ".ps1",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			createFakePlatformBinaries(t, dir, ver, distribution.ReleasePlatforms)
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("preserve stale output"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := runAssemble([]string{"-version", ver, "-dist-dir", dir}); err == nil {
				t.Fatal("assembly accepted a stale output")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "preserve stale output" {
				t.Fatalf("existing output changed: %q, %v", got, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 13 {
				t.Fatalf("assembly wrote files before rejecting stale output: %d entries", len(entries))
			}
		})
	}
}

func TestIncompletePlatformInputFails(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	platforms := distribution.ReleasePlatforms
	// Only create 5 of the 6 platforms.
	incomplete := platforms[:5]
	createFakePlatformBinaries(t, dir, ver, incomplete)

	err := runAssemble([]string{"-version", ver, "-dist-dir", dir})
	if err == nil {
		t.Fatal("assemble with incomplete platform inputs should have failed")
	}
	missingPlatform := platforms[5]
	if !strings.Contains(err.Error(), missingPlatform.OS) && !strings.Contains(err.Error(), missingPlatform.Arch) {
		t.Errorf("error should mention missing platform, got: %v", err)
	}

	// Verify no manifest was written.
	manifestPath := filepath.Join(dir, distribution.ManifestFileName)
	if _, err := os.Stat(manifestPath); err == nil {
		t.Fatal("manifest should not be written when platform inputs are incomplete")
	}
}

func TestSigningFailureCannotSilentlyYieldValidLookingRelease(t *testing.T) {
	dir := t.TempDir()
	ver := "v0.1.0"
	platforms := distribution.ReleasePlatforms
	createFakePlatformBinaries(t, dir, ver, platforms)

	badKeyPath := filepath.Join(dir, "bad-key.pem")
	if err := os.WriteFile(badKeyPath, []byte("NOT A VALID KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runAssemble([]string{"-version", ver, "-dist-dir", dir, "-key", badKeyPath})
	if err == nil {
		t.Fatal("assemble with bad signing key should have failed")
	}

	// Verify neither manifest.json nor manifest.json.sig was created.
	manifestPath := filepath.Join(dir, distribution.ManifestFileName)
	if _, err := os.Stat(manifestPath); err == nil {
		t.Fatal("manifest.json must not exist after signing failure")
	}
	sigPath := filepath.Join(dir, distribution.ManifestSignatureFileName)
	if _, err := os.Stat(sigPath); err == nil {
		t.Fatal("manifest.json.sig must not exist after signing failure")
	}
}

func TestAssembleAndVerifyHappyPath(t *testing.T) {
	dir := t.TempDir()
	ver := "v1.2.3"
	platforms := distribution.ReleasePlatforms
	createFakePlatformBinaries(t, dir, ver, platforms)

	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "priv.pem")
	if err := distribution.WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pubPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runAssemble([]string{"-version", ver, "-dist-dir", dir, "-key", keyPath}); err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// Verify using installer.Verify.
	manifestPath := filepath.Join(dir, distribution.ManifestFileName)
	sigPath := filepath.Join(dir, distribution.ManifestSignatureFileName)
	m, err := installer.Verify(installer.VerifyOptions{
		ManifestPath:    manifestPath,
		SignaturePath:   sigPath,
		PubKeyPath:      pubPath,
		DistDir:         dir,
		ExpectedVersion: ver,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if m.Version != ver || len(m.Artifacts) != 6 {
		t.Errorf("unexpected manifest: %+v", m)
	}

	// Check scripts were emitted.
	shPath := filepath.Join(dir, "install-"+ver+".sh")
	if _, err := os.Stat(shPath); err != nil {
		t.Errorf("missing shell install script: %v", err)
	}
	ps1Path := filepath.Join(dir, "install-"+ver+".ps1")
	if _, err := os.Stat(ps1Path); err != nil {
		t.Errorf("missing powershell install script: %v", err)
	}
}

func TestValidateVersion(t *testing.T) {
	valid := []string{"v0.1.0", "v1.0.0-rc.1", "v2.3.4-alpha"}
	for _, v := range valid {
		if err := runValidateVersion([]string{"-version", v}); err != nil {
			t.Errorf("expected valid version %q, got: %v", v, err)
		}
	}

	invalid := []string{"", "0.1.0", "v1", "latest", "v1.2.3/evil"}
	for _, v := range invalid {
		if err := runValidateVersion([]string{"-version", v}); err == nil {
			t.Errorf("expected invalid version %q to fail", v)
		}
	}
}
