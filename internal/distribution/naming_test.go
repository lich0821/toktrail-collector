package distribution

import (
	"strings"
	"testing"
)

func TestNamingConventions(t *testing.T) {
	if len(ReleasePlatforms) != 6 {
		t.Fatalf("expected 6 release platforms, got %d", len(ReleasePlatforms))
	}

	for _, p := range ReleasePlatforms {
		binExt := BinaryExt(p.OS)
		if p.OS == "windows" && binExt != ".exe" {
			t.Errorf("expected .exe for windows, got %q", binExt)
		}
		if p.OS != "windows" && binExt != "" {
			t.Errorf("expected empty binExt for %s, got %q", p.OS, binExt)
		}

		arcExt := ArchiveExt(p.OS)
		if p.OS == "windows" && arcExt != ".zip" {
			t.Errorf("expected .zip for windows, got %q", arcExt)
		}
		if p.OS != "windows" && arcExt != ".tar.gz" {
			t.Errorf("expected .tar.gz for %s, got %q", p.OS, arcExt)
		}

		archiveName := CollectorArchiveName("v1.0.0", p.OS, p.Arch)
		if !strings.HasPrefix(archiveName, "toktrail-v1.0.0-"+p.OS+"-"+p.Arch) {
			t.Errorf("unexpected archive name: %s", archiveName)
		}

		installerName := InstallerBinaryName("v1.0.0", p.OS, p.Arch)
		if !strings.HasPrefix(installerName, "toktrail-release-v1.0.0-"+p.OS+"-"+p.Arch) {
			t.Errorf("unexpected installer name: %s", installerName)
		}

		rawName := CollectorRawBinaryName("v1.0.0", p.OS, p.Arch)
		if !strings.HasPrefix(rawName, "toktrail-v1.0.0-"+p.OS+"-"+p.Arch) {
			t.Errorf("unexpected raw collector name: %s", rawName)
		}
	}

	goos, goarch := RuntimePlatform()
	if goos == "" || goarch == "" {
		t.Errorf("RuntimePlatform returned empty: %s/%s", goos, goarch)
	}
}

func TestSafeFileName(t *testing.T) {
	valid := []string{
		"toktrail",
		"toktrail.exe",
		"toktrail-v1.0.0-darwin-arm64.tar.gz",
		"toktrail-release-v1.0.0-windows-amd64.exe",
		"manifest.json",
		"manifest.json.sig",
	}
	for _, s := range valid {
		if !IsSafeFileName(s) {
			t.Errorf("expected %q to be safe file name", s)
		}
	}

	invalid := []string{
		"",
		"../foo",
		"foo/bar",
		`foo\bar`,
		"foo..bar",
		" spaces ",
		"-startwithdash",
		".startwithdot",
	}
	for _, s := range invalid {
		if IsSafeFileName(s) {
			t.Errorf("expected %q to be invalid safe file name", s)
		}
	}
}
