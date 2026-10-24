package distribution

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeygenWriteLoadSignVerify(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "release-key.pem")

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := WritePrivateKeyPEM(keyPath, priv); err != nil {
		t.Fatalf("WritePrivateKeyPEM: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %o, want 0600", info.Mode().Perm())
	}

	// No-clobber: a second write to the same path must fail.
	if err := WritePrivateKeyPEM(keyPath, priv); err == nil {
		t.Error("second WritePrivateKeyPEM succeeded; want refuse-to-overwrite")
	}

	loaded, err := LoadPrivateKeyPEM(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Error("loaded private key differs")
	}

	pubPEM, err := PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pubPEM, "BEGIN PUBLIC KEY") {
		t.Errorf("public key PEM missing header: %q", pubPEM)
	}

	msg := []byte("manifest bytes")
	sig, err := SignDetached(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
	if err := VerifyDetached(pub, msg, sig); err != nil {
		t.Errorf("VerifyDetached: %v", err)
	}
	// Tampered message must fail.
	if err := VerifyDetached(pub, []byte("manifest bytez"), sig); err == nil {
		t.Error("tampered message verified")
	}
	// Tampered signature must fail.
	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0xff
	if err := VerifyDetached(pub, msg, bad); err == nil {
		t.Error("tampered signature verified")
	}
}

func TestMultiKeyPinRotation(t *testing.T) {
	dir := t.TempDir()
	oldPriv, oldPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	newPriv, newPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pins, err := PublicKeyPEM(oldPub)
	if err != nil {
		t.Fatal(err)
	}
	pins2, err := PublicKeyPEM(newPub)
	if err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pinPath, []byte(pins+pins2), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPublicKeysPEM(pinPath)
	if err != nil {
		t.Fatalf("LoadPublicKeysPEM: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d keys, want 2", len(loaded))
	}

	msg := []byte("signed during transition with the new key")
	sig, err := SignDetached(newPriv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetachedAny(loaded, msg, sig); err != nil {
		t.Errorf("verify under any pinned key: %v", err)
	}
	// A release still signed with the OLD key must also verify while both
	// keys are pinned (the transition window).
	oldSig, err := SignDetached(oldPriv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetachedAny(loaded, msg, oldSig); err != nil {
		t.Errorf("old-key signature rejected during rotation window: %v", err)
	}
	// A third, unpinned key must not verify.
	otherPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherSig, err := SignDetached(otherPriv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetachedAny(loaded, msg, otherSig); err == nil {
		t.Error("signature from unpinned key verified")
	}
	// Empty trust list must fail closed.
	if err := VerifyDetachedAny(nil, msg, sig); err == nil {
		t.Error("verification with no pinned keys succeeded")
	}
}

func TestLoadPublicKeysFailClosed(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"empty":       "",
		"garbage":     "not a pem file",
		"wrong-block": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPublicKeysPEM(p); err == nil {
			t.Errorf("LoadPublicKeysPEM(%s) accepted invalid content", name)
		}
	}
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "priv.pem")
	if err := WritePrivateKeyPEM(privPath, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeysPEM(privPath); err == nil {
		t.Error("private key PEM accepted as pinned public key")
	}
	if _, err := LoadPublicKeysPEM(""); err == nil {
		t.Error("empty pubkey path accepted (missing trust root must fail closed)")
	}
}

func TestPrivateKeyExplicitPathOnly(t *testing.T) {
	if _, err := LoadPrivateKeyPEM(""); err == nil {
		t.Error("empty key path accepted; key input must be explicit")
	}
}
