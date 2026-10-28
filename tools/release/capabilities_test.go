package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/distribution"
	"toktrail-collector/internal/source/registry"
)

// capabilitiesDocJSON renders a capabilities document from raw parts so
// tests can feed structurally invalid variants to the strict parser.
func capabilitiesDocJSON(schema int, product, version string, tools string) []byte {
	return []byte("{\n  \"schema\": " + itoa(schema) + ",\n  \"product\": " + jsonString(product) +
		",\n  \"version\": " + jsonString(version) + ",\n  \"tools\": [" + tools + "]\n}\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func mustBuildCapabilities(t *testing.T, version string) *Capabilities {
	t.Helper()
	c, err := BuildCapabilities(version)
	if err != nil {
		t.Fatalf("BuildCapabilities(%q): %v", version, err)
	}
	return c
}

// TestBuildCapabilitiesMatchesRegistry verifies the document content: the
// tools list is exactly the canonical registry tool names, in registry
// order, and the identity fields are fixed.
func TestBuildCapabilitiesMatchesRegistry(t *testing.T) {
	const ver = "v1.2.3"
	c := mustBuildCapabilities(t, ver)

	if c.Schema != CapabilitiesSchema || CapabilitiesSchema != 2 {
		t.Errorf("schema = %d, want 2", c.Schema)
	}
	if c.Product != distribution.ProductName {
		t.Errorf("product = %q, want %q", c.Product, distribution.ProductName)
	}
	if c.Version != ver {
		t.Errorf("version = %q, want %q", c.Version, ver)
	}

	specs := registry.SupportedTools()
	if len(specs) == 0 {
		t.Fatal("registry.SupportedTools is empty; test cannot assert content")
	}
	if len(c.Tools) != len(specs) {
		t.Fatalf("tools length = %d, want %d (registry size)", len(c.Tools), len(specs))
	}
	for i, spec := range specs {
		if c.Tools[i] != spec.Tool {
			t.Errorf("tools[%d] = %q, want registry canonical name %q", i, c.Tools[i], spec.Tool)
		}
	}
	// The known registry entries must be advertised.
	for _, want := range []string{"Codex", "Claude Code", "DeepSeek Harness"} {
		found := false
		for _, got := range c.Tools {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tools %q missing known registry tool %q", c.Tools, want)
		}
	}
}

func TestBuildCapabilitiesRejectsInvalidVersion(t *testing.T) {
	for _, ver := range []string{"", "1.0.0", "latest", "v1", "v1.2.3/evil"} {
		if _, err := BuildCapabilities(ver); err == nil {
			t.Errorf("BuildCapabilities(%q) should fail", ver)
		}
	}
}

// TestCapabilitiesMarshalFixedFormat pins the exact wire format: exactly the
// four fields schema/product/version/tools, deterministic rendering, and a
// faithful round trip.
func TestCapabilitiesMarshalFixedFormat(t *testing.T) {
	c := mustBuildCapabilities(t, "v0.1.0")

	data, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Deterministic: two marshals are byte-identical.
	again, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal (2nd): %v", err)
	}
	if string(data) != string(again) {
		t.Fatalf("Marshal is not deterministic:\n%s\n---\n%s", data, again)
	}

	// Exactly five top-level keys with the required names and types.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("marshal produced invalid JSON: %v\n%s", err, data)
	}
	if len(raw) != 5 {
		t.Fatalf("document has %d top-level fields, want exactly 5: %v", len(raw), raw)
	}
	for _, key := range []string{"schema", "product", "version", "tools", "sources"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("document missing required field %q: %s", key, data)
		}
	}
	var schema int
	if err := json.Unmarshal(raw["schema"], &schema); err != nil || schema != 2 {
		t.Errorf("schema = %d (err %v), want number 2", schema, err)
	}
	var product string
	if err := json.Unmarshal(raw["product"], &product); err != nil || product != "toktrail-collector" {
		t.Errorf("product = %q (err %v), want \"toktrail-collector\"", product, err)
	}
	var version string
	if err := json.Unmarshal(raw["version"], &version); err != nil || version != "v0.1.0" {
		t.Errorf("version = %q (err %v), want \"v0.1.0\"", version, err)
	}
	var tools []string
	if err := json.Unmarshal(raw["tools"], &tools); err != nil {
		t.Fatalf("tools is not an array of strings: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("tools array is empty")
	}
	specs := registry.SupportedTools()
	if len(tools) != len(specs) {
		t.Fatalf("tools length = %d, want %d", len(tools), len(specs))
	}

	// Round trip: parse( Marshal(c) ) == c.
	parsed, err := ParseCapabilities(data)
	if err != nil {
		t.Fatalf("ParseCapabilities(round trip): %v\n%s", err, data)
	}
	if parsed.Schema != c.Schema || parsed.Product != c.Product || parsed.Version != c.Version {
		t.Errorf("round trip identity mismatch: %+v vs %+v", parsed, c)
	}
	if strings.Join(parsed.Tools, "\x00") != strings.Join(c.Tools, "\x00") {
		t.Errorf("round trip tools mismatch: %q vs %q", parsed.Tools, c.Tools)
	}
	if len(parsed.Sources) != len(c.Sources) {
		t.Fatalf("round trip sources length = %d, want %d", len(parsed.Sources), len(c.Sources))
	}
	for i := range c.Sources {
		if parsed.Sources[i] != c.Sources[i] {
			t.Errorf("round trip sources[%d] = %+v, want %+v", i, parsed.Sources[i], c.Sources[i])
		}
	}
}

// TestParseCapabilitiesAcceptsLegacySchema1 pins that already-published
// schema-1 documents (tools only, every source implicitly local) stay
// readable, while the same document with a sources field fails closed.
func TestParseCapabilitiesAcceptsLegacySchema1(t *testing.T) {
	legacy := capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Codex", "Cursor"`)
	c, err := ParseCapabilities(legacy)
	if err != nil {
		t.Fatalf("legacy schema 1 document must parse: %v\n%s", err, legacy)
	}
	if c.Schema != 1 || len(c.Sources) != 0 || len(c.Tools) != 2 {
		t.Fatalf("unexpected legacy parse: %+v", c)
	}
	withSources := []byte(strings.Replace(string(legacy), `"tools": [`, `"sources": [{"tool":"Codex","source":"codex-jsonl","mode":"local","protocol":1}], "tools": [`, 1))
	if _, err := ParseCapabilities(withSources); err == nil {
		t.Fatal("schema 1 document carrying sources must fail closed")
	}
}

// TestParseCapabilitiesRejectsInvalidSources pins the closed schema-2
// sources set: only known modes, protocol 1, registered tool names and
// adapter-shaped source ids are accepted.
func TestParseCapabilitiesRejectsInvalidSources(t *testing.T) {
	base := func(sources string) []byte {
		return []byte("{\n  \"schema\": 2,\n  \"product\": \"toktrail-collector\",\n  \"version\": \"v0.1.0\",\n  \"tools\": [\"Codex\", \"Cursor\"],\n  \"sources\": [" + sources + "]\n}\n")
	}
	valid := base(`{"tool":"Codex","source":"codex-jsonl","mode":"local","protocol":1},{"tool":"Cursor","source":"cursor-dashboard-api","mode":"account-network","protocol":1}`)
	if _, err := ParseCapabilities(valid); err != nil {
		t.Fatalf("valid schema 2 document rejected: %v\n%s", err, valid)
	}
	for name, doc := range map[string][]byte{
		"empty sources":       base(``),
		"unknown mode":        base(`{"tool":"Codex","source":"codex-jsonl","mode":"remote","protocol":1}`),
		"unknown protocol":    base(`{"tool":"Codex","source":"codex-jsonl","mode":"local","protocol":2}`),
		"tool not in tools":   base(`{"tool":"Other","source":"codex-jsonl","mode":"local","protocol":1}`),
		"duplicate tool":      base(`{"tool":"Codex","source":"codex-jsonl","mode":"local","protocol":1},{"tool":"codex","source":"codex-jsonl","mode":"local","protocol":1}`),
		"bad source id":       base(`{"tool":"Codex","source":"../evil","mode":"local","protocol":1}`),
		"uppercase source id": base(`{"tool":"Codex","source":"Codex-JSONL","mode":"local","protocol":1}`),
		"bad tool name":       base(`{"tool":"../evil","source":"codex-jsonl","mode":"local","protocol":1}`),
	} {
		if _, err := ParseCapabilities(doc); err == nil {
			t.Errorf("%s: schema 2 sources accepted, want rejected:\n%s", name, doc)
		}
	}
}

// TestValidateCapabilityToolNameMatchesServerPattern pins the generator's
// fail-closed rule to the exact ASCII pattern the website and receipts
// accept: ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$. A registry name outside this
// set must stop assembly instead of producing a rejected artifact.
func TestValidateCapabilityToolNameMatchesServerPattern(t *testing.T) {
	valid := []string{
		"Codex",
		"Claude Code",
		"DeepSeek Harness",
		"A1",                    // minimal length
		strings.Repeat("a", 64), // max length
		"Tool v1.2+3_beta-rc",   // every allowed extra character
	}
	for _, name := range valid {
		if err := validateCapabilityToolName(name); err != nil {
			t.Errorf("validateCapabilityToolName(%q) = %v, want accepted", name, err)
		}
	}
	invalid := []string{
		"",                      // empty
		" Codex",                // leading space
		"Co dex\t",              // tab is not an allowed character
		"codex\n",               // newline
		"../evil",               // path traversal
		"../../etc/passwd",      // path traversal
		"Co/dex",                // path separator
		`C:\Users\chuck`,        // windows path
		".codex",                // leading dot
		"-codex",                // leading hyphen
		"_codex",                // leading underscore
		"+codex",                // leading plus
		"Cödex",                 // non-ASCII
		"工具",                    // non-ASCII
		strings.Repeat("a", 65), // one over the max length
		"Codex\x00",             // NUL byte
	}
	for _, name := range invalid {
		if err := validateCapabilityToolName(name); err == nil {
			t.Errorf("validateCapabilityToolName(%q) accepted, want rejected", name)
		}
	}
	// Every canonical registry name must pass the server pattern today;
	// otherwise assembly would fail closed on the real registry.
	for _, spec := range registry.SupportedTools() {
		if err := validateCapabilityToolName(spec.Tool); err != nil {
			t.Errorf("registry tool %q fails the accepted pattern: %v", spec.Tool, err)
		}
	}
}

// TestParseCapabilitiesRejectsInvalid feeds structurally invalid documents
// to the strict parser; every case must fail closed.
func TestParseCapabilitiesRejectsInvalid(t *testing.T) {
	valid := `"Codex", "Claude Code"`
	cases := []struct {
		name string
		doc  []byte
	}{
		{"wrong schema 0", capabilitiesDocJSON(0, "toktrail-collector", "v0.1.0", valid)},
		{"wrong schema 2", capabilitiesDocJSON(2, "toktrail-collector", "v0.1.0", valid)},
		{"wrong product", capabilitiesDocJSON(1, "other-product", "v0.1.0", valid)},
		{"empty product", capabilitiesDocJSON(1, "", "v0.1.0", valid)},
		{"missing version", capabilitiesDocJSON(1, "toktrail-collector", "", valid)},
		{"invalid version", capabilitiesDocJSON(1, "toktrail-collector", "1.0.0", valid)},
		{"unknown field", []byte(`{"schema":1,"product":"toktrail-collector","version":"v0.1.0","tools":["Codex"],"extra":true}`)},
		{"trailing data", append(capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", valid), []byte("{}\n")...)},
		{"not json", []byte("this is not json")},
		{"empty document", []byte("   \n")},
		{"empty tools", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", "")},
		{"null tools", []byte(`{"schema":1,"product":"toktrail-collector","version":"v0.1.0","tools":null}`)},
		{"empty tool name", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Codex", ""`)},
		{"duplicate tool", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Codex", "Codex"`)},
		{"case-insensitive duplicate tool", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Codex", "codex"`)},
		{"tool with leading whitespace", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `" Codex"`)},
		{"tool with control character", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Codex\u0000"`)},
		{"tool with tab", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Co\tdex"`)},
		{"path-like tool name", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"../evil"`)},
		{"tool name with slash", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Co/dex"`)},
		{"tool name with backslash", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"C:\\Users"`)},
		{"non-ascii tool name", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"Cödex"`)},
		{"tool name starting with dot", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `".codex"`)},
		{"tool name starting with hyphen", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", `"-codex"`)},
		{"tool name too long", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", jsonString(strings.Repeat("x", MaxCapabilityToolNameLen+1)))},
		{"too many tools", capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0",
			`"`+strings.Repeat("a,", MaxCapabilityTools)+`a"`)},
		{"oversized document", append(capabilitiesDocJSON(1, "toktrail-collector", "v0.1.0", valid),
			make([]byte, MaxCapabilitiesBytes)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCapabilities(tc.doc); err == nil {
				t.Fatalf("ParseCapabilities accepted invalid document:\n%s", tc.doc)
			}
		})
	}
}

// writeCapabilitiesFixture writes a signed capabilities document pair plus
// the pinned public key into dir and returns the three paths.
func writeCapabilitiesFixture(t *testing.T, dir, version string) (capsPath, sigPath, pubPath string) {
	t.Helper()
	c := mustBuildCapabilities(t, version)
	doc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := distribution.SignDetached(priv, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != distribution.SignatureSize {
		t.Fatalf("signature length = %d, want raw %d bytes", len(sig), distribution.SignatureSize)
	}
	pubPEM, err := distribution.PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	capsPath = filepath.Join(dir, CapabilitiesFileName)
	sigPath = filepath.Join(dir, CapabilitiesSignatureFileName)
	pubPath = filepath.Join(dir, "pin.pem")
	for _, w := range []struct {
		path string
		data []byte
	}{
		{capsPath, doc},
		{sigPath, sig},
		{pubPath, []byte(pubPEM)},
	} {
		if err := os.WriteFile(w.path, w.data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return capsPath, sigPath, pubPath
}

// TestVerifyCapabilitiesSignatureAndVersionBinding covers the signature
// (raw 64-byte detached Ed25519 over the exact document bytes, verified
// against an independently pinned public key), the strict content, and the
// version binding.
func TestVerifyCapabilitiesSignatureAndVersionBinding(t *testing.T) {
	dir := t.TempDir()
	const ver = "v2.0.0"
	capsPath, sigPath, pubPath := writeCapabilitiesFixture(t, dir, ver)

	base := VerifyCapabilitiesOptions{
		CapabilitiesPath: capsPath,
		SignaturePath:    sigPath,
		PubKeyPath:       pubPath,
	}

	// Happy path: signature verifies, content parses, version matches.
	c, err := VerifyCapabilities(base)
	if err != nil {
		t.Fatalf("VerifyCapabilities: %v", err)
	}
	if c.Version != ver || c.Product != distribution.ProductName || len(c.Tools) == 0 {
		t.Errorf("unexpected verified capabilities: %+v", c)
	}
	specs := registry.SupportedTools()
	if len(c.Tools) != len(specs) {
		t.Errorf("verified tools length = %d, want %d", len(c.Tools), len(specs))
	}

	// Version binding: the document must match the expected version exactly.
	wrongVer := base
	wrongVer.ExpectedVersion = "v2.0.1"
	if _, err := VerifyCapabilities(wrongVer); err == nil {
		t.Fatal("VerifyCapabilities accepted a version mismatch")
	} else if !strings.Contains(err.Error(), "does not match expected") {
		t.Errorf("version mismatch error should explain the mismatch, got: %v", err)
	}

	// Tampered document: signature must fail.
	doc, err := os.ReadFile(capsPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(doc), ver, "v2.0.1", 1)
	if tampered == string(doc) {
		t.Fatal("test bug: tampering did not change the document")
	}
	if err := os.WriteFile(capsPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapabilities(base); err == nil {
		t.Fatal("VerifyCapabilities accepted a tampered document")
	}
	if err := os.WriteFile(capsPath, doc, 0o644); err != nil {
		t.Fatal(err)
	}

	// Wrong trust root: an unrelated pinned key must fail.
	_, otherPub, err := distribution.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := distribution.PublicKeyPEM(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	otherPin := filepath.Join(dir, "other-pin.pem")
	if err := os.WriteFile(otherPin, []byte(otherPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	wrongKey := base
	wrongKey.PubKeyPath = otherPin
	if _, err := VerifyCapabilities(wrongKey); err == nil {
		t.Fatal("VerifyCapabilities accepted a signature from the wrong key")
	}

	// Truncated signature must fail.
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig[:len(sig)-1], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapabilities(base); err == nil {
		t.Fatal("VerifyCapabilities accepted a truncated signature")
	}

	// A valid document signed over different content fails (the restored
	// document no longer matches the truncated-signature state is already
	// covered; restore and verify the happy path still passes end-to-end).
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapabilities(base); err != nil {
		t.Fatalf("VerifyCapabilities happy path broke after restore: %v", err)
	}
}

func TestRunVerifyCapabilitiesCommand(t *testing.T) {
	dir := t.TempDir()
	const ver = "v3.1.4"
	capsPath, sigPath, pubPath := writeCapabilitiesFixture(t, dir, ver)

	ok := []string{
		"-capabilities", capsPath,
		"-signature", sigPath,
		"-pubkey", pubPath,
		"-version", ver,
	}
	if err := runVerifyCapabilities(ok); err != nil {
		t.Fatalf("runVerifyCapabilities: %v", err)
	}

	// Missing required flags.
	if err := runVerifyCapabilities([]string{"-capabilities", capsPath}); err == nil {
		t.Fatal("runVerifyCapabilities accepted missing -signature/-pubkey")
	}

	// Version mismatch via the CLI path.
	mismatch := []string{
		"-capabilities", capsPath,
		"-signature", sigPath,
		"-pubkey", pubPath,
		"-version", "v3.1.5",
	}
	if err := runVerifyCapabilities(mismatch); err == nil {
		t.Fatal("runVerifyCapabilities accepted a version mismatch")
	}

	// Bad signature via the CLI path.
	badSig := filepath.Join(dir, "bad.sig")
	if err := os.WriteFile(badSig, make([]byte, distribution.SignatureSize), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"-capabilities", capsPath,
		"-signature", badSig,
		"-pubkey", pubPath,
	}
	if err := runVerifyCapabilities(bad); err == nil {
		t.Fatal("runVerifyCapabilities accepted an invalid signature")
	}
}
