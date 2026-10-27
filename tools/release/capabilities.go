package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/source/registry"
)

// Capabilities metadata constants. The capabilities document is a small,
// strictly fixed-format, version-bound statement of which developer tools a
// release can collect. It is generated exactly once per release by the
// assembler from the single canonical tool registry
// (internal/source/registry.SupportedTools) - the same registry that is
// compiled into every platform binary - so all platforms of a version share
// one identical document. There is no per-platform variant and therefore no
// possibility of conflicting platform capabilities.
const (
	// CapabilitiesSchema is the only capabilities schema this code accepts.
	CapabilitiesSchema = 1
	// CapabilitiesFileName is the canonical capabilities metadata filename.
	CapabilitiesFileName = "capabilities.json"
	// CapabilitiesSignatureFileName is the detached Ed25519 signature of the
	// capabilities document. It is produced with the same release signing
	// key and the same raw 64-byte detached format as manifest.json.sig.
	CapabilitiesSignatureFileName = "capabilities.json.sig"

	// MaxCapabilitiesBytes bounds the capabilities document on read.
	MaxCapabilitiesBytes = 1 << 16 // 64 KiB
	// MaxCapabilityTools bounds the tools array length.
	MaxCapabilityTools = 64
	// MaxCapabilityToolNameLen bounds one tool name (ASCII pattern below).
	MaxCapabilityToolNameLen = 64
)

// CapabilityToolNameRegex is the exact tool-name pattern the website and
// receipts accept: ASCII-only, starting with an alphanumeric, allowing
// alphanumerics, space, dot, underscore, plus and hyphen, at most 64
// characters. The capability generator enforces the same rule so a release
// can never advertise a tool name the server would reject (fail closed at
// assembly time, not at upload time). In particular this excludes path
// separators, path-traversal elements, control characters and non-ASCII.
var CapabilityToolNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$`)

// Capabilities is the signed, version-bound capability statement of a
// release. The field set is closed and fixed: {schema, product, version,
// tools}. Unknown fields, wrong types, or trailing data are all rejected,
// mirroring the strictness of the release manifest.
type Capabilities struct {
	Schema  int      `json:"schema"`
	Product string   `json:"product"`
	Version string   `json:"version"`
	Tools   []string `json:"tools"`
}

// BuildCapabilities derives the capability statement for version from the
// one canonical tool registry. The version is validated and embedded in the
// document, binding the capability statement to that release version.
func BuildCapabilities(version string) (*Capabilities, error) {
	if _, err := distribution.ParseVersion(version); err != nil {
		return nil, fmt.Errorf("capabilities version: %w", err)
	}
	specs := registry.SupportedTools()
	if len(specs) == 0 {
		return nil, errors.New("tool registry is empty; refusing to emit an empty capability statement")
	}
	if len(specs) > MaxCapabilityTools {
		return nil, fmt.Errorf("tool registry has %d entries, exceeds limit %d", len(specs), MaxCapabilityTools)
	}
	tools := make([]string, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		if err := validateCapabilityToolName(spec.Tool); err != nil {
			return nil, fmt.Errorf("registry tool name: %w", err)
		}
		key := strings.ToLower(spec.Tool)
		if seen[key] {
			return nil, fmt.Errorf("registry tool name %q duplicates another entry case-insensitively", spec.Tool)
		}
		seen[key] = true
		tools = append(tools, spec.Tool)
	}
	return &Capabilities{
		Schema:  CapabilitiesSchema,
		Product: distribution.ProductName,
		Version: version,
		Tools:   tools,
	}, nil
}

// validateCapabilityToolName enforces the server-accepted ASCII tool-name
// pattern (CapabilityToolNameRegex). Tool names legitimately contain spaces
// ("Claude Code"), so the stricter bare-file-name rules used for release
// artifacts do not apply here; the pattern still excludes path separators,
// "..", whitespace edges at the start, control characters and non-ASCII.
func validateCapabilityToolName(name string) error {
	if !CapabilityToolNameRegex.MatchString(name) {
		return fmt.Errorf("tool name %q does not match the accepted ASCII pattern ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$", name)
	}
	if len(name) > MaxCapabilityToolNameLen {
		return fmt.Errorf("tool name %q exceeds max length %d", name, MaxCapabilityToolNameLen)
	}
	return nil
}

// ParseCapabilities strictly parses and validates capabilities bytes. It
// fails closed on: oversized input, malformed JSON, unknown fields, trailing
// data, wrong schema/product, invalid version, and an empty, duplicate,
// oversized or unsafe tools array.
func ParseCapabilities(data []byte) (*Capabilities, error) {
	if int64(len(data)) > MaxCapabilitiesBytes {
		return nil, fmt.Errorf("capabilities document is %d bytes, exceeds limit %d", len(data), MaxCapabilitiesBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("capabilities document is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Capabilities
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("capabilities JSON: %w", err)
	}
	// Reject trailing content after the first JSON value.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("capabilities document has trailing data after JSON object")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Capabilities) validate() error {
	if c.Schema != CapabilitiesSchema {
		return fmt.Errorf("capabilities schema %d, want %d", c.Schema, CapabilitiesSchema)
	}
	if c.Product != distribution.ProductName {
		return fmt.Errorf("capabilities product %q, want %q", c.Product, distribution.ProductName)
	}
	if _, err := distribution.ParseVersion(c.Version); err != nil {
		return fmt.Errorf("capabilities version: %w", err)
	}
	if len(c.Tools) == 0 {
		return errors.New("capabilities has no tools")
	}
	if len(c.Tools) > MaxCapabilityTools {
		return fmt.Errorf("capabilities has %d tools, exceeds limit %d", len(c.Tools), MaxCapabilityTools)
	}
	seen := make(map[string]bool, len(c.Tools))
	for i, name := range c.Tools {
		if err := validateCapabilityToolName(name); err != nil {
			return fmt.Errorf("tools[%d]: %w", i, err)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("tools[%d] %q duplicates another entry case-insensitively", i, name)
		}
		seen[key] = true
	}
	return nil
}

// Marshal renders the capabilities document deterministically (2-space
// indent, fixed field order), matching the manifest rendering style.
func (c *Capabilities) Marshal() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeNewFile writes data to path with O_EXCL so an accidental rerun can
// never overwrite an already published release file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// VerifyCapabilitiesOptions configures standalone verification of the
// signed capabilities document.
type VerifyCapabilitiesOptions struct {
	CapabilitiesPath string
	SignaturePath    string
	PubKeyPath       string
	ExpectedVersion  string
}

// VerifyCapabilities checks the capabilities document signature (raw 64-byte
// detached Ed25519, verified against an explicitly pinned public key that may
// contain several PUBLIC KEY blocks for rotation) and its strict content,
// optionally requiring an exact version. It fails closed on any
// inconsistency. The signature is verified before parsing, mirroring the
// manifest verification order.
func VerifyCapabilities(opts VerifyCapabilitiesOptions) (*Capabilities, error) {
	pubs, err := distribution.LoadPublicKeysPEM(opts.PubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("trust root: %w", err)
	}
	doc, err := distribution.ReadBoundedFile(opts.CapabilitiesPath, MaxCapabilitiesBytes)
	if err != nil {
		return nil, fmt.Errorf("read capabilities: %w", err)
	}
	sig, err := distribution.ReadBoundedFile(opts.SignaturePath, distribution.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("read capabilities signature: %w", err)
	}
	if len(sig) != distribution.SignatureSize {
		return nil, fmt.Errorf("capabilities signature: %d bytes, want %d", len(sig), distribution.SignatureSize)
	}
	if err := distribution.VerifyDetachedAny(pubs, doc, sig); err != nil {
		return nil, fmt.Errorf("capabilities signature verification: %w", err)
	}
	c, err := ParseCapabilities(doc)
	if err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	if opts.ExpectedVersion != "" {
		if _, err := distribution.ParseVersion(opts.ExpectedVersion); err != nil {
			return nil, fmt.Errorf("expected version: %w", err)
		}
		if c.Version != opts.ExpectedVersion {
			return nil, fmt.Errorf("capabilities version %s does not match expected %s", c.Version, opts.ExpectedVersion)
		}
	}
	return c, nil
}

// capabilitiesPaths returns the canonical capabilities document and
// signature paths inside distDir.
func capabilitiesPaths(distDir string) (string, string) {
	return filepath.Join(distDir, CapabilitiesFileName),
		filepath.Join(distDir, CapabilitiesSignatureFileName)
}
