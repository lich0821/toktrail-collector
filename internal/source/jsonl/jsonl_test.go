package jsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedHelpers(t *testing.T) {
	dir := t.TempDir()
	visible := filepath.Join(dir, "visible.jsonl")
	hidden := filepath.Join(dir, ".hidden.jsonl")
	ignored := filepath.Join(dir, "ignored.txt")
	for _, path := range []string{visible, hidden, ignored} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	all, err := Files(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all, []string{hidden, visible}) {
		t.Fatalf("unexpected JSONL files: got %#v", all)
	}

	nonHidden, err := Files(dir, Options{SkipHiddenFiles: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nonHidden, []string{visible}) {
		t.Fatalf("unexpected non-hidden JSONL files: got %#v", nonHidden)
	}

	decoded, err := DecodeObject(`{"n": 9007199254740993}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["n"].(json.Number); !ok {
		t.Fatalf("expected json.Number, got %T", decoded["n"])
	}
	if _, err := DecodeObject(`{} {}`); err == nil {
		t.Fatal("expected trailing JSON data to fail")
	}
}
