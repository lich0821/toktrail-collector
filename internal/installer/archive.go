package installer

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"toktrail-collector/internal/distribution"
)

const (
	maxArchiveEntries = 256
	executableMode    = 0o755
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ExtractBinaryEntry extracts exactly one named regular-file entry from an
// archive into dstPath, verifying its size and SHA-256 while streaming.
//
// Path-traversal defenses: every entry name in the archive is validated
// (bare relative names only; absolute paths, "..", and separators rejected),
// and only TypeReg entries are accepted anywhere — symlinks, hardlinks,
// devices, and directories make the whole archive invalid. Extraction is
// bounded by maxBytes to defend against decompression bombs.
func ExtractBinaryEntry(archivePath, entryName, dstPath string, expectedSize int64, expectedSha string) error {
	if !distribution.IsSafeFileName(entryName) {
		return fmt.Errorf("requested entry name %q is not a safe bare file name", entryName)
	}
	if expectedSize <= 0 || expectedSize > distribution.MaxBinarySize {
		return fmt.Errorf("expected entry size %d out of bounds", expectedSize)
	}
	if !hex64.MatchString(expectedSha) {
		return errors.New("expected entry sha256 is not 64 hex characters")
	}
	switch {
	case strings.HasSuffix(archivePath, ".zip"):
		return extractZipEntry(archivePath, entryName, dstPath, expectedSize, expectedSha)
	case strings.HasSuffix(archivePath, ".tar.gz"):
		return extractTarEntry(archivePath, entryName, dstPath, expectedSize, expectedSha)
	default:
		return fmt.Errorf("archive path %q must end with .tar.gz or .zip", archivePath)
	}
}

func extractTarEntry(archivePath, entryName, dstPath string, expectedSize int64, expectedSha string) error {
	// Pass 1: validate every entry in the archive. The whole archive is
	// rejected if any member is a symlink/hardlink/directory or has an
	// unsafe name, even one appearing after the wanted entry.
	if err := validateTarEntries(archivePath); err != nil {
		return err
	}
	// Pass 2: extract the wanted entry.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Name != entryName {
			continue
		}
		if err := streamVerified(tr, dstPath, expectedSize, expectedSha); err != nil {
			return fmt.Errorf("extract %q: %w", entryName, err)
		}
		return nil
	}
	return fmt.Errorf("entry %q not found in archive", entryName)
}

func validateTarEntries(archivePath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
		}
		if err := checkEntryName(hdr.Name); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive entry %q has non-regular type (symlinks, hardlinks, and directories are rejected)", hdr.Name)
		}
	}
	return nil
}

func extractZipEntry(archivePath, entryName, dstPath string, expectedSize int64, expectedSha string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > distribution.MaxBinarySize {
		return fmt.Errorf("archive is %d bytes, exceeds limit %d", info.Size(), distribution.MaxBinarySize)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	if len(zr.File) > maxArchiveEntries {
		return fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
	}
	for _, zf := range zr.File {
		if err := checkEntryName(zf.Name); err != nil {
			return err
		}
		if zf.FileInfo().IsDir() {
			return fmt.Errorf("archive entry %q is a directory", zf.Name)
		}
		mode := zf.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			return fmt.Errorf("archive entry %q is not a regular file", zf.Name)
		}
		if zf.Name != entryName {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("open zip entry: %w", err)
		}
		err = streamVerified(rc, dstPath, expectedSize, expectedSha)
		rc.Close()
		if err != nil {
			return fmt.Errorf("extract %q: %w", entryName, err)
		}
		return nil
	}
	return fmt.Errorf("entry %q not found in archive", entryName)
}

func checkEntryName(name string) error {
	if name == "" {
		return errors.New("archive contains an empty entry name")
	}
	if !distribution.IsSafeFileName(name) {
		return fmt.Errorf("archive entry name %q is unsafe (path separators, '..', absolute paths, or invalid characters are rejected)", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("archive entry name %q contains '..'", name)
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("archive entry name %q is absolute", name)
	}
	return nil
}

func streamVerified(r io.Reader, dstPath string, expectedSize int64, expectedSha string) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, executableMode)
	if err != nil {
		return err
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > expectedSize {
				out.Close()
				return fmt.Errorf("entry is larger than expected %d bytes", expectedSize)
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return werr
			}
			h.Write(buf[:n])
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if total != expectedSize {
		return fmt.Errorf("entry is %d bytes, expected %d", total, expectedSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedSha {
		return fmt.Errorf("entry sha256 %s, expected %s", got, expectedSha)
	}
	return nil
}
