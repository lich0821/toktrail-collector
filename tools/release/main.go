// Command release provides maintainer-side release tools: validating version
// strings, assembling release artifacts into signed distribution packages,
// and generating pinned bootstrap install scripts.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"toktrail-collector/internal/distribution"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <assemble|validate-version> [flags]\n", os.Args[0])
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "assemble":
		err = runAssemble(os.Args[2:])
	case "validate-version":
		err = runValidateVersion(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runValidateVersion(args []string) error {
	fs := flag.NewFlagSet("validate-version", flag.ContinueOnError)
	ver := fs.String("version", "", "version to validate (e.g. v0.1.0)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ver == "" {
		return fmt.Errorf("-version is required")
	}
	v, err := distribution.ParseVersion(*ver)
	if err != nil {
		return fmt.Errorf("invalid version %q: %w", *ver, err)
	}
	fmt.Println(v.String())
	return nil
}

func runAssemble(args []string) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	ver := fs.String("version", "", "release version, e.g. v0.1.0 (required)")
	distDir := fs.String("dist-dir", "", "path to directory containing built binaries (required)")
	keyPath := fs.String("key", "", "path to Ed25519 private key PEM for signing manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *ver == "" || *distDir == "" {
		return fmt.Errorf("-version and -dist-dir are required")
	}

	if _, err := distribution.ParseVersion(*ver); err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}

	absDistDir, err := filepath.Abs(*distDir)
	if err != nil {
		return fmt.Errorf("resolve dist dir: %w", err)
	}

	manifestPath := filepath.Join(absDistDir, distribution.ManifestFileName)
	sigPath := filepath.Join(absDistDir, distribution.ManifestSignatureFileName)
	outputs := []string{manifestPath, sigPath,
		filepath.Join(absDistDir, "install-"+*ver+".sh"),
		filepath.Join(absDistDir, "install-"+*ver+".ps1")}
	for _, p := range distribution.ReleasePlatforms {
		outputs = append(outputs, filepath.Join(absDistDir, distribution.CollectorArchiveName(*ver, p.OS, p.Arch)))
	}
	for _, output := range outputs {
		if _, err := os.Lstat(output); err == nil {
			return fmt.Errorf("release output already exists at %s; refusing to overwrite or reuse", output)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect release output %s: %w", output, err)
		}
	}

	// Validate signing key up-front before creating any files or archives.
	// Signing failure must never silently leave a valid-looking release behind.
	var priv ed25519.PrivateKey
	var pubPEM string
	if *keyPath != "" {
		loadedPriv, err := distribution.LoadPrivateKeyPEM(*keyPath)
		if err != nil {
			return fmt.Errorf("load signing key: %w", err)
		}
		priv = loadedPriv
		pubKey, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("extract public key: invalid key type")
		}
		pemStr, err := distribution.PublicKeyPEM(pubKey)
		if err != nil {
			return fmt.Errorf("format public key: %w", err)
		}
		pubPEM = pemStr
	}

	platforms := distribution.ReleasePlatforms
	if len(platforms) != 6 {
		return fmt.Errorf("expected exactly 6 supported platforms, got %d", len(platforms))
	}

	// Check all required inputs exist for all platforms first.
	type platformFiles struct {
		osName      string
		arch        string
		rawBinPath  string
		toolBinPath string
		archiveName string
		archivePath string
		entryName   string
	}

	var toProcess []platformFiles
	for _, p := range platforms {
		osName, arch := p.OS, p.Arch
		ext := distribution.BinaryExt(osName)
		rawName := distribution.CollectorRawBinaryName(*ver, osName, arch)
		rawPath := filepath.Join(absDistDir, rawName)
		if _, err := os.Stat(rawPath); err != nil {
			return fmt.Errorf("missing collector binary for %s/%s at %s: %w", osName, arch, rawPath, err)
		}

		toolName := distribution.InstallerBinaryName(*ver, osName, arch)
		toolPath := filepath.Join(absDistDir, toolName)
		if _, err := os.Stat(toolPath); err != nil {
			return fmt.Errorf("missing installer binary for %s/%s at %s: %w", osName, arch, toolPath, err)
		}

		arcName := distribution.CollectorArchiveName(*ver, osName, arch)
		arcPath := filepath.Join(absDistDir, arcName)
		entryName := distribution.CollectorBinaryName + ext

		toProcess = append(toProcess, platformFiles{
			osName:      osName,
			arch:        arch,
			rawBinPath:  rawPath,
			toolBinPath: toolPath,
			archiveName: arcName,
			archivePath: arcPath,
			entryName:   entryName,
		})
	}

	var artifacts []distribution.Artifact
	for _, pf := range toProcess {
		binSha, binSize, err := distribution.SHA256File(pf.rawBinPath)
		if err != nil {
			return fmt.Errorf("hash collector binary %s: %w", pf.rawBinPath, err)
		}

		if err := CreateArchive(pf.archivePath, pf.rawBinPath, pf.entryName); err != nil {
			return fmt.Errorf("create archive %s: %w", pf.archivePath, err)
		}

		arcSha, arcSize, err := distribution.SHA256File(pf.archivePath)
		if err != nil {
			return fmt.Errorf("hash archive %s: %w", pf.archivePath, err)
		}

		toolSha, toolSize, err := distribution.SHA256File(pf.toolBinPath)
		if err != nil {
			return fmt.Errorf("hash installer binary %s: %w", pf.toolBinPath, err)
		}

		artifacts = append(artifacts, distribution.Artifact{
			OS:                    pf.osName,
			Arch:                  pf.arch,
			Binary:                pf.entryName,
			BinarySha256:          binSha,
			BinarySize:            binSize,
			Archive:               pf.archiveName,
			ArchiveSha256:         arcSha,
			ArchiveSize:           arcSize,
			InstallerBinary:       filepath.Base(pf.toolBinPath),
			InstallerBinarySha256: toolSha,
			InstallerBinarySize:   toolSize,
		})
	}

	m := &distribution.Manifest{
		Schema:      distribution.ManifestSchema,
		Product:     distribution.ProductName,
		Version:     *ver,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Artifacts:   artifacts,
	}

	manifestBytes, err := m.Marshal()
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	var sigBytes []byte
	if priv != nil {
		sig, err := distribution.SignDetached(priv, manifestBytes)
		if err != nil {
			return fmt.Errorf("sign manifest: %w", err)
		}
		sigBytes = sig
	}

	// Write manifest.json atomically with O_EXCL.
	mf, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if _, err := mf.Write(manifestBytes); err != nil {
		mf.Close()
		return fmt.Errorf("write manifest content: %w", err)
	}
	if err := mf.Close(); err != nil {
		return fmt.Errorf("close manifest file: %w", err)
	}

	// Write signature if signed.
	if len(sigBytes) > 0 {
		sf, err := os.OpenFile(sigPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
		if _, err := sf.Write(sigBytes); err != nil {
			sf.Close()
			return fmt.Errorf("write signature content: %w", err)
		}
		if err := sf.Close(); err != nil {
			return fmt.Errorf("close signature file: %w", err)
		}

		// Emit bootstrap install scripts.
		if _, err := EmitInstallScripts(absDistDir, m, pubPEM); err != nil {
			return fmt.Errorf("emit install scripts: %w", err)
		}
	}

	fmt.Printf("Assembled release %s for %d platforms at %s\n", *ver, len(artifacts), absDistDir)
	return nil
}
