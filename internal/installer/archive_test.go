package installer

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type tarEntry struct {
	name     string
	typ      byte
	linkname string
	content  string
}

func buildTarGz(path string, entries []tarEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, e := range entries {
		hdr := &tar.Header{
			Typeflag: e.typ,
			Name:     e.name,
			Size:     int64(len(e.content)),
			Mode:     0o755,
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(e.content)); err != nil {
			return err
		}
	}
	return nil
}

type zipEntry struct {
	name    string
	content string
}

func buildZip(path string, entries []zipEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			return err
		}
	}
	return nil
}

func TestExtractBinaryEntryTarGz(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "out.tar.gz")
	content := "#!/bin/sh\necho collector\n"
	if err := buildTarGz(tgz, []tarEntry{{name: "toktrail", typ: tar.TypeReg, content: content}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "extracted")
	if err := ExtractBinaryEntry(tgz, "toktrail", out, int64(len(content)), sha256Hex(content)); err != nil {
		t.Fatalf("ExtractBinaryEntry tar.gz: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("tar.gz content mismatch")
	}
}

func TestExtractBinaryEntryZip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "out.zip")
	content := "#!/bin/sh\necho collector\n"
	if err := buildZip(zp, []zipEntry{{name: "toktrail", content: content}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "extracted-zip")
	if err := ExtractBinaryEntry(zp, "toktrail", out, int64(len(content)), sha256Hex(content)); err != nil {
		t.Fatalf("ExtractBinaryEntry zip: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("zip content mismatch")
	}
}

func TestExtractRejectsTraversalTar(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, "evil.tar.gz")
	if err := buildTarGz(evil, []tarEntry{{name: "../evil", typ: tar.TypeReg, content: "bad"}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	err := ExtractBinaryEntry(evil, "toktrail", out, 2, strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("traversal entry accepted")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evil")); statErr == nil {
		t.Error("file was written outside the extraction root")
	}
}

func TestExtractRejectsSymlinkTar(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, "evil.tar.gz")
	entries := []tarEntry{
		{name: "toktrail", typ: tar.TypeReg, content: "good"},
		{name: "extra", typ: tar.TypeSymlink, linkname: "/etc/passwd"},
	}
	if err := buildTarGz(evil, entries); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	err := ExtractBinaryEntry(evil, "toktrail", out, 4, sha256Hex("good"))
	if err == nil {
		t.Fatal("symlink entry accepted")
	}
}

func TestExtractRejectsDirectoryEntriesAndNestedNames(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, "evil.tar.gz")
	entries := []tarEntry{{name: "sub/dir/toktrail", typ: tar.TypeReg, content: "x"}}
	if err := buildTarGz(evil, entries); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinaryEntry(evil, "toktrail", filepath.Join(dir, "o"), 1, sha256Hex("x")); err == nil {
		t.Error("nested entry name accepted")
	}

	evil2 := filepath.Join(dir, "evil2.tar.gz")
	entries2 := []tarEntry{{name: "sub", typ: tar.TypeDir}}
	if err := buildTarGz(evil2, entries2); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinaryEntry(evil2, "toktrail", filepath.Join(dir, "o2"), 1, sha256Hex("x")); err == nil {
		t.Error("directory entry accepted")
	}
}

func TestExtractRejectsSizeAndHashMismatch(t *testing.T) {
	dir := t.TempDir()
	src := "collector-binary"
	sha := sha256Hex(src)
	size := int64(len(src))
	arc := filepath.Join(dir, "a.tar.gz")
	if err := buildTarGz(arc, []tarEntry{{name: "toktrail", typ: tar.TypeReg, content: src}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := ExtractBinaryEntry(arc, "toktrail", out, size+1, sha); err == nil {
		t.Error("wrong expected size accepted")
	}
	if err := ExtractBinaryEntry(arc, "toktrail", out, size, strings.Repeat("0", 64)); err == nil {
		t.Error("wrong expected hash accepted")
	}
	if err := ExtractBinaryEntry(arc, "toktrail", out, size, sha); err != nil {
		t.Errorf("correct extraction failed: %v", err)
	}
}

func TestExtractRejectsSizeBomb(t *testing.T) {
	dir := t.TempDir()
	content := string(bytes.Repeat([]byte{0}, 1<<20))
	arc := filepath.Join(dir, "bomb.tar.gz")
	if err := buildTarGz(arc, []tarEntry{{name: "toktrail", typ: tar.TypeReg, content: content}}); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinaryEntry(arc, "toktrail", filepath.Join(dir, "out"), 100, strings.Repeat("a", 64)); err == nil {
		t.Error("oversized content accepted (decompression bomb)")
	}
}

func TestExtractZipRejectsTraversalAndSymlink(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "evil.zip")
	if err := buildZip(zp, []zipEntry{
		{name: "../evil", content: "x"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinaryEntry(zp, "toktrail", filepath.Join(dir, "o"), 1, sha256Hex("x")); err == nil {
		t.Error("zip traversal entry accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
		t.Error("file written outside extraction root")
	}
}
