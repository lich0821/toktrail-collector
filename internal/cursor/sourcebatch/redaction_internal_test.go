package sourcebatch

import "testing"

func TestRecordErrorsRejectUnknownInvalidPrefix(t *testing.T) {
	got := sanitizeRecordErrors([]RecordError{{Index: 0, Code: "invalid_PRIVATE_SENTINEL"}, {Index: 1, Code: "invalid_decimal"}})
	if got[0].Code != "record_rejected" || got[1].Code != "invalid_decimal" {
		t.Fatal("record error codes do not follow the exact protocol allowlist")
	}
}
