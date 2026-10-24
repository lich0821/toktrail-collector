package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"toktrail-collector/internal/distribution"
)

//go:embed templates/install.sh.tmpl
var unixScriptTemplate string

//go:embed templates/install.ps1.tmpl
var windowsScriptTemplate string

type unixPin struct {
	Match    string // uname -s / uname -m pattern
	OS       string
	Arch     string
	ToolFile string
	Sha256   string
}

type winPin struct {
	Arch   string
	Sha256 string
}

type scriptData struct {
	Version      string
	PublicKeyPEM string
	UnixPins     []unixPin
	WinPins      []winPin
}

func unixMatch(osName, arch string) (string, bool) {
	switch {
	case osName == "darwin" && arch == "arm64":
		return "Darwin/arm64", true
	case osName == "darwin" && arch == "amd64":
		return "Darwin/x86_64", true
	case osName == "linux" && arch == "arm64":
		return "Linux/aarch64", true
	case osName == "linux" && arch == "amd64":
		return "Linux/x86_64", true
	}
	return "", false
}

// EmitInstallScripts renders the per-release bootstrap install scripts into
// distDir with the pinned public key and installer hashes. It returns the
// written script paths.
func EmitInstallScripts(distDir string, m *distribution.Manifest, pubPEM string) ([]string, error) {
	if pubPEM == "" || !strings.Contains(pubPEM, "BEGIN PUBLIC KEY") {
		return nil, fmt.Errorf("refusing to emit install scripts without a pinned public key")
	}
	data := scriptData{Version: m.Version, PublicKeyPEM: pubPEM}
	hasUnix, hasWin := false, false
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if match, ok := unixMatch(a.OS, a.Arch); ok {
			data.UnixPins = append(data.UnixPins, unixPin{
				Match:    match,
				OS:       a.OS,
				Arch:     a.Arch,
				ToolFile: a.InstallerBinary,
				Sha256:   a.InstallerBinarySha256,
			})
			hasUnix = true
		}
		if a.OS == "windows" {
			data.WinPins = append(data.WinPins, winPin{
				Arch:   a.Arch,
				Sha256: a.InstallerBinarySha256,
			})
			hasWin = true
		}
	}

	var written []string
	if hasUnix {
		p := filepath.Join(distDir, "install-"+m.Version+".sh")
		if err := renderScript(unixScriptTemplate, data, p, 0o755); err != nil {
			return nil, err
		}
		written = append(written, p)
	}
	if hasWin {
		p := filepath.Join(distDir, "install-"+m.Version+".ps1")
		if err := renderScript(windowsScriptTemplate, data, p, 0o644); err != nil {
			return nil, err
		}
		written = append(written, p)
	}
	return written, nil
}

func renderScript(tmpl string, data scriptData, path string, mode os.FileMode) error {
	t, err := template.New("script").Parse(tmpl)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := t.Execute(f, data); err != nil {
		return err
	}
	return f.Close()
}
