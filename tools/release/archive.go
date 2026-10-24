package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"toktrail-collector/internal/distribution"
)

const executableMode = 0o755

// CreateArchive packs srcPath into dstPath under entryName.
// Unix platforms get a reproducible tar.gz; windows gets a zip.
// Both embed the executable mode bit for the binary.
func CreateArchive(dstPath, srcPath, entryName string) error {
	if !distribution.IsSafeFileName(entryName) {
		return fmt.Errorf("archive entry name %q is not a safe bare file name", entryName)
	}
	switch {
	case strings.HasSuffix(dstPath, ".zip"):
		return createZip(dstPath, srcPath, entryName)
	case strings.HasSuffix(dstPath, ".tar.gz"):
		return createTarGz(dstPath, srcPath, entryName)
	default:
		return fmt.Errorf("archive path %q must end with .tar.gz or .zip", dstPath)
	}
}

func createTarGz(dstPath, srcPath, entryName string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	// Zero ModTime and USTAR format keep archives byte-reproducible.
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     entryName,
		Size:     info.Size(),
		Mode:     executableMode,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, in); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return out.Close()
}

func createZip(dstPath, srcPath, entryName string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	hdr := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	hdr.SetMode(executableMode)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}
