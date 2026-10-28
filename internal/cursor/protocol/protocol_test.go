package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func fixture() Batch {
	in, out, model := "10", "2", "test-model"
	return Batch{
		BatchID: "cursor-batch-1", SourceInstanceID: "source-1",
		Records: []Event{{EventKey: EventKeyPrefix + strings.Repeat("a", 64), Revision: 1, Kind: "event", OccurredAt: "2026-10-28T12:00:00Z", Tool: Tool, Model: &model, Input: &in, Output: &out, AdapterVersion: "cursor-dashboard-api-v1", SourceType: SourceType}},
	}
}

func TestNarrowAccountBatchRoundTrip(t *testing.T) {
	encoded, err := EncodeBatch(fixture())
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeBatch(encoded)
	if err != nil || b.Records[0].EventKey != fixture().Records[0].EventKey {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if b.Records[0].CacheRead != nil || b.Records[0].CacheWrite != nil {
		t.Fatal("unknown counts became zero")
	}
}

func TestOutboxRejectsExtraPrivateFieldsAndTrailingData(t *testing.T) {
	encoded, _ := EncodeBatch(fixture())
	for _, body := range [][]byte{
		bytes.Replace(encoded, []byte(`"batchId":`), []byte(`"cookie":"SECRET","batchId":`), 1),
		bytes.Replace(encoded, []byte(`"eventKey":`), []byte(`"accountId":"PRIVATE","eventKey":`), 1),
		append(append([]byte(nil), encoded...), []byte(` {"token":"SECRET"}`)...),
	} {
		if _, err := DecodeBatch(body); err == nil {
			t.Fatal("unsafe batch accepted")
		} else if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("error leaked source payload")
		}
	}
}

func TestBatchValidationProtectsEventIdentityAndCounters(t *testing.T) {
	for _, mutate := range []func(*Batch){
		func(b *Batch) { b.Records = append(b.Records, b.Records[0]) },
		func(b *Batch) { b.Records[0].EventKey = "raw-account-event" },
		func(b *Batch) { b.Records[0].Revision = 0 },
		func(b *Batch) { b.Records[0].Revision = 1<<53 - 1 },
		func(b *Batch) { b.Records[0].Tool = "Codex" },
		func(b *Batch) { b.Records[0].Kind = "delta" },
		func(b *Batch) { v := "-2"; b.Records[0].Input = &v },
		func(b *Batch) { v := "1.5"; b.Records[0].Output = &v },
		func(b *Batch) { v := "bad\nmodel"; b.Records[0].Model = &v },
		func(b *Batch) { b.Records[0].OccurredAt = "tomorrow" },
	} {
		b := fixture()
		mutate(&b)
		if _, err := EncodeBatch(b); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
}
