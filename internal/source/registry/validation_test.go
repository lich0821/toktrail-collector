package registry

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/claudecodejsonl"
	"toktrail-collector/internal/source/codexjsonl"
	"toktrail-collector/internal/source/usagejson"
)

func dummyLoader(opt adapter.Options) (adapter.LoadResult, error) {
	return adapter.LoadResult{}, nil
}

func TestRegistryRejectsInvalidAdapters(t *testing.T) {
	tests := []struct {
		name        string
		adapters    []adapter.Adapter
		errContains string
	}{
		{
			name: "empty source string",
			adapters: []adapter.Adapter{
				{Source: "", Load: dummyLoader},
			},
			errContains: "adapter source is empty",
		},
		{
			name: "whitespace only source string",
			adapters: []adapter.Adapter{
				{Source: "   \t\n", Load: dummyLoader},
			},
			errContains: "adapter source is empty",
		},
		{
			name: "duplicate source string",
			adapters: []adapter.Adapter{
				{Source: "custom-source", Load: dummyLoader},
				{Source: "custom-source", Load: dummyLoader},
			},
			errContains: `duplicate adapter source "custom-source"`,
		},
		{
			name: "duplicate source string with whitespace variation",
			adapters: []adapter.Adapter{
				{Source: "custom-source", Load: dummyLoader},
				{Source: "  custom-source  ", Load: dummyLoader},
			},
			errContains: `duplicate adapter source "custom-source"`,
		},
		{
			name: "nil loader function",
			adapters: []adapter.Adapter{
				{Source: "custom-source", Load: nil},
			},
			errContains: `adapter "custom-source" has no loader`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := New(tc.adapters...)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (registry: %+v)", tc.errContains, reg)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
			}
		})
	}
}

func TestRegistryCopiesInputAndAll(t *testing.T) {
	src1 := adapter.Adapter{Source: "src-1", Load: dummyLoader}
	src2 := adapter.Adapter{Source: "src-2", Load: dummyLoader}

	input := []adapter.Adapter{src1, src2}
	reg, err := New(input...)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Mutating the slice passed to New must not affect the Registry.
	input[0].Source = "mutated-after-new"
	if _, ok := reg.Lookup("mutated-after-new"); ok {
		t.Fatal("registry was mutated by changing the slice passed into New")
	}
	if _, ok := reg.Lookup("src-1"); !ok {
		t.Fatal("registry lost original source after slice passed into New was mutated")
	}

	// All() must return a slice copy so mutating the return value doesn't mutate internal state.
	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(all))
	}
	all[0].Source = "mutated-from-all"
	if got := reg.All()[0].Source; got != "src-1" {
		t.Fatalf("registry internal adapters mutated through All(): got %q, want %q", got, "src-1")
	}
}

func TestValidateCommitDispatch(t *testing.T) {
	var hookCalledWith string
	hookErr := errors.New("hook validation error")

	adapterWithHookSuccess := adapter.Adapter{
		Source: "hook-success-source",
		Load:   dummyLoader,
		ValidateCommit: func(stateDir string) error {
			hookCalledWith = stateDir
			return nil
		},
	}
	adapterWithHookError := adapter.Adapter{
		Source: "hook-error-source",
		Load:   dummyLoader,
		ValidateCommit: func(stateDir string) error {
			hookCalledWith = stateDir
			return hookErr
		},
	}
	adapterWithNilHook := adapter.Adapter{
		Source:         "nil-hook-source",
		Load:           dummyLoader,
		ValidateCommit: nil,
	}

	reg, err := New(adapterWithHookSuccess, adapterWithHookError, adapterWithNilHook)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// 1. Unknown source ID fails closed with error.
	err = reg.ValidateCommit("unknown-source-id", "/tmp/state")
	if err == nil {
		t.Fatal("expected error for unknown source ID, got nil")
	}
	if !strings.Contains(err.Error(), `unsupported source "unknown-source-id"`) {
		t.Fatalf("unexpected error message for unknown source: %v", err)
	}

	// Package-level ValidateCommit also fails for unknown source.
	err = ValidateCommit("unknown-source-id", "/tmp/state")
	if err == nil || !strings.Contains(err.Error(), `unsupported source "unknown-source-id"`) {
		t.Fatalf("expected package-level ValidateCommit to fail for unknown source, got %v", err)
	}

	// 2. Nil hook succeeds without error.
	hookCalledWith = ""
	if err := reg.ValidateCommit("nil-hook-source", "/tmp/state"); err != nil {
		t.Fatalf("expected nil error for nil ValidateCommit hook, got: %v", err)
	}
	if hookCalledWith != "" {
		t.Fatalf("hook should not have been called, but was called with %q", hookCalledWith)
	}

	// 3. Non-nil hook returns success and receives correct stateDir.
	hookCalledWith = ""
	if err := reg.ValidateCommit("hook-success-source", "/path/to/custom-state"); err != nil {
		t.Fatalf("expected nil error for successful ValidateCommit hook, got: %v", err)
	}
	if hookCalledWith != "/path/to/custom-state" {
		t.Fatalf("hook called with %q, want %q", hookCalledWith, "/path/to/custom-state")
	}

	// 4. Non-nil hook returns failure.
	hookCalledWith = ""
	err = reg.ValidateCommit("hook-error-source", "/path/to/failing-state")
	if !errors.Is(err, hookErr) {
		t.Fatalf("expected hookErr %v, got %v", hookErr, err)
	}
	if hookCalledWith != "/path/to/failing-state" {
		t.Fatalf("hook called with %q, want %q", hookCalledWith, "/path/to/failing-state")
	}
}

func TestInjectableFourthSourceRegistryIntegration(t *testing.T) {
	fourthSourceID := "synthetic-fourth-source"
	fourthLoaderCalls := 0
	syntheticRec := adapter.Record{
		"recordKey":      "rec-001",
		"groupKey":       "grp-1",
		"resetKey":       "rst-1",
		"kind":           "delta",
		"occurredAt":     "2026-10-24T00:00:00Z",
		"tool":           "FourthTool",
		"model":          "unknown",
		"input":          "100",
		"cacheRead":      "20",
		"cacheWrite":     "10",
		"output":         "50",
		"adapterVersion": "v1.0.0",
		"sourceType":     fourthSourceID,
	}
	if !adapter.RecordIsUploadSafe(syntheticRec) {
		t.Fatalf("synthetic test record is not upload-safe: %+v", syntheticRec)
	}

	fourthAdapter := adapter.Adapter{
		Source:      fourthSourceID,
		Description: "Synthetic fourth source for testing",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			fourthLoaderCalls++
			return adapter.LoadResult{
				Records: []adapter.Record{syntheticRec},
			}, nil
		},
		ValidateCommit: func(stateDir string) error {
			if stateDir == "" {
				return errors.New("state dir cannot be empty")
			}
			return nil
		},
	}

	// Construct actual registry with the 3 production adapters + the fourth source
	reg, err := New(
		usagejson.Adapter(),
		codexjsonl.Adapter(),
		claudecodejsonl.Adapter(),
		fourthAdapter,
	)
	if err != nil {
		t.Fatalf("failed to construct registry with 4th source: %v", err)
	}

	// Verify All has 4 adapters in order
	all := reg.All()
	if len(all) != 4 {
		t.Fatalf("expected 4 adapters, got %d", len(all))
	}
	expectedSources := []string{
		adapter.UsageJSONSource,
		adapter.CodexJSONLSource,
		adapter.ClaudeCodeJSONLSource,
		fourthSourceID,
	}
	var actualSources []string
	for _, a := range all {
		actualSources = append(actualSources, a.Source)
	}
	if !reflect.DeepEqual(actualSources, expectedSources) {
		t.Fatalf("unexpected adapter sources: got %v, want %v", actualSources, expectedSources)
	}

	// Verify KnownSources
	if !reflect.DeepEqual(reg.KnownSources(), expectedSources) {
		t.Fatalf("unexpected KnownSources(): got %v, want %v", reg.KnownSources(), expectedSources)
	}

	// Verify IsKnownSource
	if !reg.IsKnownSource(fourthSourceID) {
		t.Fatalf("expected IsKnownSource(%q) to be true", fourthSourceID)
	}
	if reg.IsKnownSource("unregistered-source") {
		t.Fatal("expected IsKnownSource for unregistered source to be false")
	}

	// Verify Lookup
	lookedUp, ok := reg.Lookup(fourthSourceID)
	if !ok {
		t.Fatalf("failed to lookup %q", fourthSourceID)
	}
	if lookedUp.Description != "Synthetic fourth source for testing" {
		t.Fatalf("unexpected description: %q", lookedUp.Description)
	}

	// Verify LoadRecordsForSource dispatches to fourthLoader
	res, err := reg.LoadRecordsForSource(adapter.Options{
		Source: fourthSourceID,
		Input:  "/path/to/synthetic.json",
	})
	if err != nil {
		t.Fatalf("LoadRecordsForSource failed: %v", err)
	}
	if fourthLoaderCalls != 1 {
		t.Fatalf("expected fourthLoaderCalls to be 1, got %d", fourthLoaderCalls)
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	if key := adapter.StringField(res.Records[0], "recordKey"); key != "rec-001" {
		t.Fatalf("expected recordKey rec-001, got %q", key)
	}
	if !adapter.RecordIsUploadSafe(res.Records[0]) {
		t.Fatalf("record from LoadRecordsForSource is not upload-safe: %+v", res.Records[0])
	}

	// Verify LoadRecordsForSource fails for unsupported source
	_, err = reg.LoadRecordsForSource(adapter.Options{Source: "unsupported"})
	if err == nil || !strings.Contains(err.Error(), `unsupported source "unsupported"`) {
		t.Fatalf("expected unsupported source error, got: %v", err)
	}

	// Verify ValidateCommit dispatch for fourth source
	if err := reg.ValidateCommit(fourthSourceID, "/state/dir"); err != nil {
		t.Fatalf("expected ValidateCommit to succeed, got: %v", err)
	}
	if err := reg.ValidateCommit(fourthSourceID, ""); err == nil {
		t.Fatal("expected ValidateCommit to fail with empty state dir, got nil")
	}
}
