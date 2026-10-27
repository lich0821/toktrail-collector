package installer

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/distribution"
)

type fakeDist struct {
	version    string
	distDir    string
	versionDir string
	pubPath    string
	binContent string
	binSha     string
	binSize    int64
	priv       ed25519.PrivateKey
}

func newFakeDist(t *testing.T, version string) *fakeDist {
	t.Helper()
	return newFakeDistBinary(t, version, "fake collector binary for "+version)
}

// newFakeDistBinary builds a fake signed dist whose collector "binary" is
// binContent. Tests use a version-reporting shell script as binContent to
// exercise in-place upgrade preconditions.
func newFakeDistBinary(t *testing.T, version, binContent string) *fakeDist {
	t.Helper()
	dir := t.TempDir()
	fd := &fakeDist{version: version, distDir: dir, versionDir: filepath.Join(dir, version), binContent: binContent}
	if err := os.MkdirAll(fd.versionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fd.priv = priv
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	fd.pubPath = filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(fd.pubPath, []byte(pubPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	osName, arch := runtime.GOOS, runtime.GOARCH
	ext := distribution.BinaryExt(osName)
	binPath := filepath.Join(fd.versionDir, "toktrail"+ext)
	if err := os.WriteFile(binPath, []byte(fd.binContent), 0o755); err != nil {
		t.Fatal(err)
	}
	fd.binSha, fd.binSize, err = distribution.SHA256File(binPath)
	if err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(fd.versionDir, distribution.CollectorRawBinaryName(version, osName, arch))
	if err := os.WriteFile(rawPath, []byte(fd.binContent), 0o755); err != nil {
		t.Fatal(err)
	}

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfSha, selfSize, err := distribution.SHA256File(selfExe)
	if err != nil {
		t.Fatal(err)
	}

	archiveName := distribution.CollectorArchiveName(version, osName, arch)
	archivePath := filepath.Join(fd.versionDir, archiveName)
	if strings.HasSuffix(archiveName, ".tar.gz") {
		if err := buildTarGz(archivePath, []tarEntry{{name: "toktrail" + ext, typ: '0', content: fd.binContent}}); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := buildZip(archivePath, []zipEntry{{name: "toktrail" + ext, content: fd.binContent}}); err != nil {
			t.Fatal(err)
		}
	}
	arcSha, arcSize, err := distribution.SHA256File(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	toolFile := distribution.InstallerBinaryName(version, osName, arch)
	if err := os.WriteFile(filepath.Join(fd.versionDir, toolFile), mustReadFile(t, selfExe), 0o755); err != nil {
		t.Fatal(err)
	}

	m := &distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Artifacts: []distribution.Artifact{{
			OS:                    osName,
			Arch:                  arch,
			Binary:                "toktrail" + ext,
			BinarySha256:          fd.binSha,
			BinarySize:            fd.binSize,
			Archive:               archiveName,
			ArchiveSha256:         arcSha,
			ArchiveSize:           arcSize,
			InstallerBinary:       toolFile,
			InstallerBinarySha256: selfSha,
			InstallerBinarySize:   selfSize,
		}},
	}
	manifestBytes, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(priv, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	return fd
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (fd *fakeDist) installOpts(t *testing.T) InstallOptions {
	t.Helper()
	return InstallOptions{
		DistDir:    fd.versionDir,
		Version:    fd.version,
		PubKeyPath: fd.pubPath,
		InstallDir: filepath.Join(t.TempDir(), "bin"),
	}
}

func TestInstallHappyPath(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	res, err := Install(fd.installOpts(t))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Version != "v0.1.0" || res.Replaced {
		t.Errorf("unexpected result: %+v", res)
	}
	data, err := os.ReadFile(res.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fd.binContent {
		t.Error("installed binary content mismatch")
	}
	info, err := os.Stat(res.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary not executable: %v", info.Mode())
	}
	entries, err := os.ReadDir(filepath.Dir(res.BinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("install dir has extra entries: %v", names)
	}
}

func TestInstallFromBaseURLFileScheme(t *testing.T) {
	fd := newFakeDist(t, "v0.2.0")
	opts := fd.installOpts(t)
	opts.DistDir = ""
	opts.BaseURL = fileURL(fd.versionDir)
	res, err := Install(opts)
	if err != nil {
		t.Fatalf("Install via file:// base url: %v", err)
	}
	if res.Version != "v0.2.0" {
		t.Errorf("version = %s", res.Version)
	}
}

func TestInstallRefusesTamperedManifest(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	manifestPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	data := mustReadFile(t, manifestPath)
	tampered := strings.Replace(string(data), `"schema": 1`, `"schema": 1 `, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not apply")
	}
	if err := os.WriteFile(manifestPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(fd.installOpts(t)); err == nil {
		t.Fatal("tampered manifest installed")
	}
}

func TestInstallRefusesWrongKey(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	_, otherPub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := distribution.PublicKeyPEM(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	opts := fd.installOpts(t)
	wrongPub := filepath.Join(t.TempDir(), "wrong.pem")
	if err := os.WriteFile(wrongPub, []byte(otherPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	opts.PubKeyPath = wrongPub
	if _, err := Install(opts); err == nil {
		t.Fatal("install under wrong pinned key succeeded")
	}
}

func TestInstallRefusesMissingTrustRoot(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	opts.PubKeyPath = filepath.Join(t.TempDir(), "does-not-exist.pem")
	if _, err := Install(opts); err == nil {
		t.Fatal("install without a trust root succeeded")
	}
	opts.PubKeyPath = ""
	if _, err := Install(opts); err == nil {
		t.Fatal("install with empty trust root succeeded")
	}
}

func TestInstallRefusesWrongVersion(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	opts.Version = "v0.2.0"
	if _, err := Install(opts); err == nil {
		t.Fatal("version mismatch accepted")
	}
	opts.Version = "latest"
	if _, err := Install(opts); err == nil {
		t.Fatal("non-semver version accepted")
	}
}

func TestInstallRefusesWrongPlatform(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	opts.OS, opts.Arch = "windows", "riscv"
	_, err := Install(opts)
	if err == nil {
		t.Fatal("unsupported platform accepted")
	}
	if !strings.Contains(err.Error(), "windows/riscv") {
		t.Errorf("error should name the requested platform: %v", err)
	}
}

func TestInstallRefusesSignedButMalformedManifest(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	manifestPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	data := mustReadFile(t, manifestPath)
	tampered := strings.Replace(string(data), `"schema": 1`, `"schema": 1, "extra": 1`, 1)
	sig, err := distribution.SignDetached(fd.priv, []byte(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(fd.installOpts(t)); err == nil {
		t.Fatal("signed but malformed manifest installed")
	}
}

func TestInstallRefusesTamperedArchive(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	osName, arch := runtime.GOOS, runtime.GOARCH
	binPath := filepath.Join(fd.versionDir, "toktrail"+distribution.BinaryExt(osName))
	if err := os.WriteFile(binPath, []byte(fd.binContent+"tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	arcPath := filepath.Join(fd.versionDir, distribution.CollectorArchiveName(fd.version, osName, arch))
	if err := os.Remove(arcPath); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(arcPath, ".tar.gz") {
		if err := buildTarGz(arcPath, []tarEntry{{name: "toktrail" + distribution.BinaryExt(osName), typ: '0', content: fd.binContent + "tampered"}}); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := buildZip(arcPath, []zipEntry{{name: "toktrail" + distribution.BinaryExt(osName), content: fd.binContent + "tampered"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(fd.installOpts(t)); err == nil {
		t.Fatal("tampered archive installed")
	}
}

func TestInstallNoReplace(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	if _, err := Install(opts); err != nil {
		t.Fatal(err)
	}
	opts.NoReplace = true
	if _, err := Install(opts); err == nil {
		t.Fatal("no-clobber mode replaced an existing binary")
	}
}

func TestInstallSelfCheck(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	mPath := filepath.Join(fd.versionDir, distribution.ManifestFileName)
	m, err := distribution.ParseManifest(mustReadFile(t, mPath))
	if err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].InstallerBinarySha256 = strings.Repeat("0", 64)
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(fd.priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(opts); err == nil {
		t.Fatal("install succeeded despite self-check mismatch")
	}
	opts.SkipSelfCheck = true
	if _, err := Install(opts); err != nil {
		t.Fatalf("install with -skip-self-check failed: %v", err)
	}
}

func TestInstallDowngradeProtection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake existing binary is a POSIX shell script")
	}
	fd := newFakeDist(t, "v0.1.0")
	opts := fd.installOpts(t)
	existing := filepath.Join(opts.InstallDir, "toktrail")
	if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho 'toktrail v9.0.0'\n"
	if err := os.WriteFile(existing, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(opts); err == nil {
		t.Fatal("downgrade installed without -allow-downgrade")
	}
	opts.AllowDowngrade = true
	res, err := Install(opts)
	if err != nil {
		t.Fatalf("downgrade with -allow-downgrade failed: %v", err)
	}
	if !res.Replaced {
		t.Error("expected replacement")
	}
	data, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fd.binContent {
		t.Error("downgrade did not install the new binary")
	}
}

func TestInstallKeepOld(t *testing.T) {
	fd1 := newFakeDist(t, "v0.1.0")
	opts := fd1.installOpts(t)
	if _, err := Install(opts); err != nil {
		t.Fatal(err)
	}
	fd2 := newFakeDist(t, "v0.2.0")
	opts2 := fd2.installOpts(t)
	opts2.InstallDir = opts.InstallDir
	opts2.KeepOld = true
	res, err := Install(opts2)
	if err != nil {
		t.Fatalf("upgrade install: %v", err)
	}
	if !res.Replaced || res.KeptOldPath == "" {
		t.Fatalf("expected replacement with kept old: %+v", res)
	}
	old, err := os.ReadFile(res.KeptOldPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != fd1.binContent {
		t.Error(".previous does not contain the old binary")
	}
	cur, err := os.ReadFile(res.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != fd2.binContent {
		t.Error("new binary not installed")
	}
}

func TestInstallArgumentValidation(t *testing.T) {
	fd := newFakeDist(t, "v0.1.0")
	cases := []InstallOptions{
		{Version: "v0.1.0", PubKeyPath: fd.pubPath, InstallDir: "/tmp/x"},
		{DistDir: fd.versionDir, BaseURL: "https://x.invalid", Version: "v0.1.0", PubKeyPath: fd.pubPath, InstallDir: "/tmp/x"},
		{DistDir: fd.versionDir, PubKeyPath: fd.pubPath, InstallDir: "/tmp/x"},
		{DistDir: fd.versionDir, Version: "v0.1.0", PubKeyPath: fd.pubPath},
	}
	for i, opts := range cases {
		if _, err := Install(opts); err == nil {
			t.Errorf("case %d accepted invalid options", i)
		}
	}
}

func TestVerifyDistDir(t *testing.T) {
	fd := newFakeDist(t, "v0.3.0")
	m, err := Verify(VerifyOptions{
		ManifestPath:    filepath.Join(fd.versionDir, distribution.ManifestFileName),
		SignaturePath:   filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName),
		PubKeyPath:      fd.pubPath,
		DistDir:         fd.versionDir,
		ExpectedVersion: "v0.3.0",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if m.Version != "v0.3.0" {
		t.Errorf("version = %s", m.Version)
	}
	osName, arch := runtime.GOOS, runtime.GOARCH
	bin := filepath.Join(fd.versionDir, distribution.CollectorRawBinaryName("v0.3.0", osName, arch))
	if err := os.WriteFile(bin, []byte("corrupted"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyOptions{
		ManifestPath:  filepath.Join(fd.versionDir, distribution.ManifestFileName),
		SignaturePath: filepath.Join(fd.versionDir, distribution.ManifestSignatureFileName),
		PubKeyPath:    fd.pubPath,
		DistDir:       fd.versionDir,
	}); err == nil {
		t.Fatal("verify accepted corrupted dist file")
	}
}
