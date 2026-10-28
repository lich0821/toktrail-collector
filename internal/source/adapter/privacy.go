package adapter

import "reflect"

// usageJSONExportFields is the exact field whitelist of the server ingest
// record schema. Free-form inputs can contain sensitive non-protocol fields.
var usageJSONExportFields = []string{
	"recordKey", "groupKey", "resetKey", "kind", "occurredAt", "tool", "model",
	"input", "cacheRead", "cacheWrite", "output", "adapterVersion", "sourceType", "mutationType",
}

// sanitizeUsageJSONRecord copies only protocol fields without changing their
// values. Invalid model values remain present so validation reports them.
func sanitizeUsageJSONRecord(record Record) Record {
	out := make(Record, len(record))
	for _, field := range usageJSONExportFields {
		if value, ok := record[field]; ok {
			out[field] = value
		}
	}
	return out
}

func SanitizeUsageJSONRecords(records []Record) []Record {
	sanitized := make([]Record, len(records))
	for idx, record := range records {
		sanitized[idx] = sanitizeUsageJSONRecord(record)
	}
	return sanitized
}

// RecordIsUploadSafe rejects extra fields and malformed model values before
// a previously saved batch can be sent.
func RecordIsUploadSafe(record Record) bool {
	if record == nil || ValidateModel(record["model"]) != nil {
		return false
	}
	sanitized := sanitizeUsageJSONRecord(record)
	if len(sanitized) != len(record) {
		return false
	}
	for field, value := range record {
		projected, ok := sanitized[field]
		if !ok || !reflect.DeepEqual(value, projected) {
			return false
		}
	}
	return true
}
