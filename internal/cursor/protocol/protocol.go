// Package protocol defines the narrow, credential-free wire format for Cursor
// account usage. It is separate from device-local usage batches.
package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"toktrail-collector/internal/source/adapter"
)

const (
	SourceType      = "cursor-dashboard-api"
	Tool            = "Cursor"
	EventKeyPrefix  = "cursor-v1:"
	MaxBatchRecords = 500
	MaxBatchBytes   = 1 << 20
)

// Source contains server-authorized metadata, never a Cursor account id.
type Source struct {
	SourceInstanceID string `json:"sourceInstanceId"`
	SourceType       string `json:"sourceType"`
	State            string `json:"state"`
	FenceVersion     int64  `json:"fenceVersion"`
	NextRevision     int64  `json:"nextRevision"`
}

type Event struct {
	EventKey       string  `json:"eventKey"`
	Revision       int64   `json:"revision"`
	Kind           string  `json:"kind"`
	OccurredAt     string  `json:"occurredAt"`
	Tool           string  `json:"tool"`
	Model          *string `json:"model"`
	Input          *string `json:"input"`
	CacheRead      *string `json:"cacheRead"`
	CacheWrite     *string `json:"cacheWrite"`
	Output         *string `json:"output"`
	AdapterVersion string  `json:"adapterVersion"`
	SourceType     string  `json:"sourceType"`
}

type Batch struct {
	BatchID          string  `json:"batchId"`
	SourceInstanceID string  `json:"sourceInstanceId"`
	Records          []Event `json:"records"`
}

var ErrUnsafeBatch = errors.New("invalid cursor account usage batch")

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func (e Event) Validate() error {
	if !strings.HasPrefix(e.EventKey, EventKeyPrefix) || len(e.EventKey) != len(EventKeyPrefix)+64 {
		return ErrUnsafeBatch
	}
	suffix := strings.TrimPrefix(e.EventKey, EventKeyPrefix)
	if _, err := hex.DecodeString(suffix); err != nil || suffix != strings.ToLower(suffix) {
		return ErrUnsafeBatch
	}
	if e.Revision < 1 || e.Revision >= 1<<53-1 || e.Kind != "event" || e.Tool != Tool || e.SourceType != SourceType || !validLabel(e.AdapterVersion) {
		return ErrUnsafeBatch
	}
	if _, err := time.Parse(time.RFC3339Nano, e.OccurredAt); err != nil {
		return ErrUnsafeBatch
	}
	if err := adapter.ValidateModel(optional(e.Model)); err != nil {
		return ErrUnsafeBatch
	}
	for _, n := range []*string{e.Input, e.CacheRead, e.CacheWrite, e.Output} {
		if n != nil {
			if _, ok := adapter.ParseUint(*n); !ok {
				return ErrUnsafeBatch
			}
		}
	}
	return nil
}

func optional(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func ValidateBatch(b Batch) error {
	if !validLabel(b.BatchID) || !validLabel(b.SourceInstanceID) || len(b.Records) == 0 || len(b.Records) > MaxBatchRecords {
		return ErrUnsafeBatch
	}
	seen := make(map[string]bool, len(b.Records))
	for _, e := range b.Records {
		if e.Validate() != nil || seen[e.EventKey] {
			return ErrUnsafeBatch
		}
		seen[e.EventKey] = true
	}
	return nil
}

// DecodeBatch checks immutable outbox bytes again before upload. Unknown
// fields, including accidentally persisted credentials, fail closed.
func DecodeBatch(data []byte) (Batch, error) {
	var b Batch
	if len(data) > MaxBatchBytes {
		return b, ErrUnsafeBatch
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Batch{}, ErrUnsafeBatch
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Batch{}, ErrUnsafeBatch
	}
	if err := ValidateBatch(b); err != nil {
		return Batch{}, err
	}
	return b, nil
}

func EncodeBatch(b Batch) ([]byte, error) {
	if err := ValidateBatch(b); err != nil {
		return nil, err
	}
	data, err := json.Marshal(b)
	if err != nil || len(data) > MaxBatchBytes {
		return nil, ErrUnsafeBatch
	}
	return data, nil
}
