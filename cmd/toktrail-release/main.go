// Command toktrail-release provides maintainer key/sign/verify commands.
// Legacy build delegates to scripts/release.sh; install remains compatible.
// User release artifacts are built from cmd/toktrail-installer instead.
// See docs/RELEASE.md for ownership and trust boundaries.
//
// The tool uses only the Go standard library and standard cryptography
// (Ed25519 signatures, SHA-256 hashes). Private keys are only ever read
// from an explicit -key path and are never logged.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	release "toktrail-collector/internal/distribution"
	"toktrail-collector/internal/installer"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `toktrail-release - build, sign, verify, and install toktrail-collector releases

Usage:
  toktrail-release keygen  -out <private-key.pem>
  toktrail-release build   -version v0.1.0 [-dist dist] [-repo .] [-key <private-key.pem>]
  toktrail-release sign    -manifest <manifest.json> -key <private-key.pem> [-out <manifest.json.sig>]
  toktrail-release verify  -manifest <manifest.json> -signature <manifest.json.sig> -pubkey <pub.pem>
                          [-dist-dir <dir>] [-version <v>] [-platform <os>/<arch>]
  toktrail-release install -base-url <download-root> -version <v> -pubkey <pub.pem> -install-dir <dir>
                          [-allow-downgrade] [-no-replace] [-keep-old] [-skip-self-check]
                          (or: -dist-dir <dir> instead of -base-url, for local files)
  toktrail-release version

Trust model: verification always requires an explicitly pinned public key
(-pubkey). Missing trust root, invalid signature, malformed manifest,
hash/size mismatch, unsupported platform, or version mismatch all abort
before anything is installed. The installer only places the binary: it
never changes upload consent, collector state, or scheduler registration,
and never contacts the upload (sync) endpoint - -base-url is the separate
download/update endpoint.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "build":
		err = cmdBuild(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "version":
		fmt.Printf("toktrail-release %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "toktrail-release %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "output path for the private key (required; must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	priv, pub, err := release.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := release.WritePrivateKeyPEM(*out, priv); err != nil {
		return err
	}
	pubPEM, err := release.PublicKeyPEM(pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Private key written to %s (mode 0600). %s.\n", *out,
		"Never commit it, never paste it into logs, tickets, or chat")
	fmt.Printf("%s", pubPEM)
	fmt.Fprintln(os.Stderr, "The block above is the PUBLIC key: pin it (docs/RELEASE.md) and distribute it via a channel independent of the download endpoint.")
	return nil
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	ver := fs.String("version", "", "release version, e.g. v0.1.0 (required)")
	dist := fs.String("dist", "dist", "output root; artifacts land in <dist>/<version>/")
	repo := fs.String("repo", ".", "module root (working directory for go build)")
	key := fs.String("key", "", "Ed25519 private key PEM; when set the manifest is signed and bootstrap install scripts are emitted")
	goBin := fs.String("go", "go", "go executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := release.ParseVersion(*ver); err != nil {
		return fmt.Errorf("build version: %w", err)
	}
	repoRoot, err := filepath.Abs(*repo)
	if err != nil {
		return fmt.Errorf("resolve -repo: %w", err)
	}
	if *dist == "" {
		*dist = "dist"
	}
	// Resolve paths before changing the child's working directory. The old
	// build command interprets -dist and -key relative to its caller.
	distRoot, err := filepath.Abs(*dist)
	if err != nil {
		return fmt.Errorf("resolve -dist: %w", err)
	}
	if *goBin == "" {
		*goBin = "go"
	}
	compiler, err := exec.LookPath(*goBin)
	if err != nil {
		return fmt.Errorf("find Go executable: %w", err)
	}
	compiler, err = filepath.Abs(compiler)
	if err != nil {
		return err
	}
	script := filepath.Join(repoRoot, "scripts", "release.sh")
	if info, err := os.Stat(script); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("build requires a source checkout containing scripts/release.sh under -repo %q", repoRoot)
	}
	scriptArgs := []string{script, "build", *ver, "--dist", distRoot, "--go", compiler}
	if *key != "" {
		keyPath, err := filepath.Abs(*key)
		if err != nil {
			return fmt.Errorf("resolve -key: %w", err)
		}
		scriptArgs = append(scriptArgs, "--key", keyPath)
	}
	cmd := exec.Command("sh", scriptArgs...)
	cmd.Dir = repoRoot
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scripts/release.sh: %w", err)
	}
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "manifest.json to sign (required)")
	key := fs.String("key", "", "Ed25519 private key PEM (required, explicit input; never logged)")
	out := fs.String("out", "", "signature output path (default <manifest>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *key == "" {
		return fmt.Errorf("-manifest and -key are required")
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	// The manifest must parse before we sign it: never sign garbage.
	m, err := release.ParseManifest(data)
	if err != nil {
		return fmt.Errorf("refusing to sign invalid manifest: %w", err)
	}
	priv, err := release.LoadPrivateKeyPEM(*key)
	if err != nil {
		return err
	}
	sig, err := release.SignDetached(priv, data)
	if err != nil {
		return err
	}
	outPath := *out
	if outPath == "" {
		outPath = *manifest + ".sig"
	}
	if err := os.WriteFile(outPath, sig, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s (%s) -> %s\n", *manifest, m.Version, outPath)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "manifest.json (required)")
	signature := fs.String("signature", "", "manifest.json.sig (required)")
	pubkey := fs.String("pubkey", "", "pinned public key PEM (required; may contain several PUBLIC KEY blocks for rotation)")
	distDir := fs.String("dist-dir", "", "also verify every artifact file in this directory")
	ver := fs.String("version", "", "require this exact version")
	platform := fs.String("platform", "", "require an artifact for os/arch, e.g. darwin/arm64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *signature == "" || *pubkey == "" {
		return fmt.Errorf("-manifest, -signature and -pubkey are required")
	}
	opts := installer.VerifyOptions{
		ManifestPath:    *manifest,
		SignaturePath:   *signature,
		PubKeyPath:      *pubkey,
		DistDir:         *distDir,
		ExpectedVersion: *ver,
	}
	if *platform != "" {
		osName, arch, ok := splitPlatform(*platform)
		if !ok {
			return fmt.Errorf("-platform must be <os>/<arch>, e.g. darwin/arm64")
		}
		opts.OS, opts.Arch = osName, arch
	}
	m, err := installer.Verify(opts)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s %s, %d platform(s)", m.Product, m.Version, len(m.Artifacts))
	if *distDir != "" {
		fmt.Printf(", all artifact files verified against the signed manifest")
	}
	fmt.Println()
	for _, a := range m.Artifacts {
		fmt.Printf("  %s/%s %s\n", a.OS, a.Arch, a.Archive)
	}
	return nil
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "release download/update endpoint root (http/https/file)")
	distDir := fs.String("dist-dir", "", "install from a local dist directory instead of a URL")
	ver := fs.String("version", "", "exact version to install (required)")
	pubkey := fs.String("pubkey", "", "pinned public key PEM (required trust root)")
	installDir := fs.String("install-dir", "", "directory to install the binary into (required)")
	allowDowngrade := fs.Bool("allow-downgrade", false, "allow installing an older version than currently installed")
	noReplace := fs.Bool("no-replace", false, "refuse to replace an existing binary (no-clobber)")
	keepOld := fs.Bool("keep-old", false, "keep the previous binary as <binary>.previous")
	skipSelfCheck := fs.Bool("skip-self-check", false, "skip check that this tool matches the signed manifest (only for locally compiled tools)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := installer.Install(installer.InstallOptions{
		BaseURL:        *baseURL,
		DistDir:        *distDir,
		Version:        *ver,
		PubKeyPath:     *pubkey,
		InstallDir:     *installDir,
		AllowDowngrade: *allowDowngrade,
		NoReplace:      *noReplace,
		KeepOld:        *keepOld,
		SkipSelfCheck:  *skipSelfCheck,
	})
	if err != nil {
		return err
	}
	action := "installed"
	if res.Replaced {
		action = "replaced"
	}
	fmt.Printf("%s toktrail %s (%s) at %s\n", action, res.Version, res.Platform, res.BinaryPath)
	if res.KeptOldPath != "" {
		fmt.Printf("previous binary kept at %s\n", res.KeptOldPath)
	}
	fmt.Println("note: nothing else was changed - no state, no upload consent, no scheduler registration")
	return nil
}

func splitPlatform(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			osName, arch := s[:i], s[i+1:]
			if osName != "" && arch != "" && !containsSlash(osName) && !containsSlash(arch) {
				return osName, arch, true
			}
			return "", "", false
		}
	}
	return "", "", false
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
