package distribution

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256File computes the lowercase hex SHA-256 digest and byte size of a file.
func SHA256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SHA256Bytes computes the lowercase hex SHA-256 digest of a byte slice.
func SHA256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
