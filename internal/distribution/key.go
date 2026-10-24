package distribution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxKeyFileBytes = 1 << 16 // 64 KiB is far more than any PEM key needs
	privateKeyMode  = 0o600
	SignatureSize   = ed25519.SignatureSize
	privateKeyType  = "PRIVATE KEY"
	publicKeyType   = "PUBLIC KEY"
	keygenHint      = "keep this file secret; never commit it or paste it into logs, tickets, or chat"
)

// GenerateKeyPair generates a fresh Ed25519 key pair using crypto/rand.
// No key material is ever persisted by this function.
func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 key generation: %w", err)
	}
	return priv, pub, nil
}

// WritePrivateKeyPEM writes an Ed25519 private key as a PKCS#8 PEM file with
// 0600 permissions. It refuses to overwrite an existing file so an accidental
// rerun can never destroy a release key.
func WritePrivateKeyPEM(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key has unexpected size %d", len(priv))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{Type: privateKeyType, Bytes: der}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateKeyMode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("private key file %s already exists; refusing to overwrite (%s)", path, keygenHint)
		}
		return fmt.Errorf("create private key file: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

// LoadPrivateKeyPEM reads an Ed25519 private key from an explicit path.
// The path is the only supported key input; keys are never read from
// the environment, a network source, or a default location.
func LoadPrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private key path is required (explicit -key input)")
	}
	data, err := ReadBoundedFile(path, maxKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != privateKeyType {
		return nil, errors.New("private key file is not a PEM PRIVATE KEY block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an Ed25519 key")
	}
	return priv, nil
}

// PublicKeyPEM encodes an Ed25519 public key as a PKIX PEM string.
// Public keys are the only key material that may be published or pinned.
func PublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("public key has unexpected size %d", len(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: publicKeyType, Bytes: der}); err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	return buf.String(), nil
}

// LoadPublicKeysPEM reads one or more Ed25519 public keys from a PEM file.
// Multiple PUBLIC KEY blocks are allowed so that key rotation can pin the
// old and new key simultaneously during a transition window.
// An empty, malformed, or wrong-algorithm file is an error (fail closed).
func LoadPublicKeysPEM(path string) ([]ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("public key path is required: verification without an explicitly trusted public key is refused")
	}
	data, err := ReadBoundedFile(path, maxKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	var pubs []ed25519.PublicKey
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != publicKeyType {
			return nil, fmt.Errorf("unexpected PEM block %q in public key file", block.Type)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("pinned public key is not an Ed25519 key")
		}
		pubs = append(pubs, pub)
	}
	if len(pubs) == 0 {
		return nil, errors.New("public key file contains no PUBLIC KEY PEM block")
	}
	return pubs, nil
}

// SignDetached produces a raw 64-byte Ed25519 signature over message.
func SignDetached(priv ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key")
	}
	return ed25519.Sign(priv, message), nil
}

// VerifyDetached checks a raw 64-byte Ed25519 signature over message.
// All inputs are length-checked first; any failure is an error (fail closed).
func VerifyDetached(pub ed25519.PublicKey, message, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("signature has length %d, want %d", len(signature), SignatureSize)
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// VerifyDetachedAny checks the signature against any one of the pinned
// public keys; it fails closed when the list is empty.
func VerifyDetachedAny(pubs []ed25519.PublicKey, message, signature []byte) error {
	if len(pubs) == 0 {
		return errors.New("no pinned public key: refusing to verify without a trust root")
	}
	var firstErr error
	for _, pub := range pubs {
		if err := VerifyDetached(pub, message, signature); err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("signature verification failed")
	}
	return fmt.Errorf("signature does not match any pinned public key: %w", firstErr)
}

// ReadBoundedFile reads up to maxBytes from path, failing if oversized.
func ReadBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is %d bytes, exceeds limit %d", path, info.Size(), maxBytes)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
