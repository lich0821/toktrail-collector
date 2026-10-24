package syncclient

import (
	"encoding/json"
	"fmt"

	"toktrail-collector/internal/source/adapter"
)

// privacyGateError is the static, value-free failure the send path returns
// when a pre-existing batch file does not conform to the upload whitelist.
// It never echoes record contents (field names, model strings, values): the
// batch stays on disk exactly as it is, and the user must re-export it from
// its source or recover it through quarantine.
type privacyGateError struct {
	BatchID string
	Reason  string
}

func (e *privacyGateError) Error() string {
	return fmt.Sprintf(
		"batch %s %s; refusing to upload: re-export the batch from its source or recover it through quarantine; the batch file was not uploaded and no HTTP request was made",
		e.BatchID, e.Reason)
}

// requireUploadPrivacy fail-closes every send path (explicit --file, the
// automatic outbox, and batches re-created by scope reorganization or
// quarantine recovery on a later run) before any state change or HTTP
// traffic: each record must already conform to the upload whitelist the
// fixed exporters produce. A batch that predates the privacy fix is never
// rewritten and never uploaded verbatim; the file, outbox entry, attempt
// accounting, and ACK state all stay untouched because this check runs
// before the batch is even marked as attempted.
func requireUploadPrivacy(batch BatchRequest) error {
	for idx, raw := range batch.Records {
		var record adapter.Record
		if err := json.Unmarshal(raw, &record); err != nil || record == nil {
			return &privacyGateError{BatchID: batch.BatchID, Reason: fmt.Sprintf("record %d is not a record object", idx)}
		}
		if !adapter.RecordIsUploadSafe(record) {
			return &privacyGateError{BatchID: batch.BatchID, Reason: fmt.Sprintf("record %d carries fields or a model outside the upload whitelist", idx)}
		}
	}
	return nil
}
