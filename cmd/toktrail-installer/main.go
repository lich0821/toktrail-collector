// Command toktrail-installer verifies and installs toktrail-collector releases.
// It verifies the cryptographic manifest, checks all hashes and platform
// requirements, and atomically places the collector binary.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"toktrail-collector/internal/installer"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `toktrail-installer - verify and install toktrail-collector releases

Usage:
  toktrail-installer install -base-url <download-root> -version <v> -pubkey <pub.pem> -install-dir <dir>
                             [-allow-downgrade] [-no-replace] [-keep-old] [-skip-self-check]
                             (or: -dist-dir <dir> instead of -base-url, for local files)
  toktrail-installer verify  -manifest <manifest.json> -signature <manifest.json.sig> -pubkey <pub.pem>
                             [-dist-dir <dir>] [-version <v>] [-platform <os>/<arch>]
  toktrail-installer version

Trust model: verification always requires an explicitly pinned public key
(-pubkey). Missing trust root, invalid signature, malformed manifest,
hash/size mismatch, unsupported platform, or version mismatch all abort
before anything is installed. The installer only places the binary: it
never changes upload consent, collector state, or scheduler registration,
and never contacts the upload (sync) endpoint.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// If invoked directly with flags (e.g. -version ... -install-dir ...), treat as install.
	if strings.HasPrefix(cmd, "-") {
		cmd = "install"
		args = os.Args[1:]
	}

	var err error
	switch cmd {
	case "install":
		err = runInstall(args)
	case "verify":
		err = runVerify(args)
	case "version":
		fmt.Printf("toktrail-installer %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "toktrail-installer %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func runInstall(args []string) error {
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

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "path to manifest.json (required)")
	signature := fs.String("signature", "", "path to manifest.json.sig (required)")
	pubkey := fs.String("pubkey", "", "path to pinned public key PEM (required)")
	distDir := fs.String("dist-dir", "", "verify every artifact on disk in this directory against the manifest")
	ver := fs.String("version", "", "require this exact version in the manifest")
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
		parts := strings.Split(*platform, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("-platform must be <os>/<arch>, e.g. darwin/arm64")
		}
		opts.OS, opts.Arch = parts[0], parts[1]
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
