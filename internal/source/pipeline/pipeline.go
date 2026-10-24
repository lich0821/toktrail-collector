package pipeline

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/registry"
)

type ScanResult struct {
	Source              string
	Input               string
	Records             []adapter.Record
	RecordCount         int
	ValidRecords        int
	InvalidRecords      int
	KnownIncludeRecords int
	KnownExcludeRecords int
	TokensInclude       *uint64
	TokensExclude       *uint64
	Tools               map[string]int
	EarliestOccurredAt  *time.Time
	LatestOccurredAt    *time.Time
	// Quarantined counts input lines skipped because they were invalid;
	// quarantined lines never block the remaining valid usage.
	Quarantined int
	// Issues lists the first quarantined lines with reasons (capped).
	Issues []adapter.LineIssue
}

type PreviewRow struct {
	Index     int
	RecordKey string
	Tool      string
	Kind      string
	Occurred  string
	Include   *uint64
	Exclude   *uint64
	Valid     bool
	Error     string
}

type ExportResult struct {
	BatchID string
	Output  string
	Records int
}

func (p *Pipeline) Scan(opt adapter.Options) (ScanResult, error) {
	opt = withDefaults(opt)
	if err := p.validateInput(opt); err != nil {
		return ScanResult{}, err
	}
	loaded, err := p.registry.LoadRecordsForSource(opt)
	if err != nil {
		return ScanResult{}, err
	}
	records, issues, quarantined := loaded.Records, loaded.Issues, loaded.Quarantined
	res := ScanResult{Source: opt.Source, Input: opt.Input, Records: records, RecordCount: len(records), Tools: map[string]int{}, Quarantined: quarantined, Issues: issues}
	for _, record := range records {
		err := adapter.ValidateRecord(record)
		if err != nil {
			res.InvalidRecords++
		} else {
			res.ValidRecords++
		}
		tool := adapter.StringField(record, "tool")
		if tool == "" {
			tool = "<unknown>"
		}
		res.Tools[tool]++
		if t, ok := adapter.OccurredAt(record); ok {
			if res.EarliestOccurredAt == nil || t.Before(*res.EarliestOccurredAt) {
				v := t
				res.EarliestOccurredAt = &v
			}
			if res.LatestOccurredAt == nil || t.After(*res.LatestOccurredAt) {
				v := t
				res.LatestOccurredAt = &v
			}
		}
		if include, ok := adapter.IncludeTokens(record); ok {
			res.KnownIncludeRecords++
			if err := adapter.AddUint64(&res.TokensInclude, include); err != nil {
				return ScanResult{}, fmt.Errorf("include token total overflow: %w", err)
			}
		}
		if exclude, ok := adapter.ExcludeTokens(record); ok {
			res.KnownExcludeRecords++
			if err := adapter.AddUint64(&res.TokensExclude, exclude); err != nil {
				return ScanResult{}, fmt.Errorf("exclude token total overflow: %w", err)
			}
		}
	}
	return res, nil
}
func (p *Pipeline) Preview(opt adapter.Options) ([]PreviewRow, error) {
	opt = withDefaults(opt)
	if err := p.validateInput(opt); err != nil {
		return nil, err
	}
	if opt.Limit <= 0 {
		opt.Limit = 10
	}
	loaded, err := p.registry.LoadRecordsForSource(opt)
	if err != nil {
		return nil, err
	}
	records := loaded.Records
	if len(records) > opt.Limit {
		records = records[:opt.Limit]
	}
	rows := make([]PreviewRow, 0, len(records))
	for idx, record := range records {
		var errText string
		valid := true
		if err := adapter.ValidateRecord(record); err != nil {
			valid = false
			errText = err.Error()
		}
		rows = append(rows, PreviewRow{
			Index:     idx,
			RecordKey: adapter.StringField(record, "recordKey"),
			Tool:      adapter.StringField(record, "tool"),
			Kind:      adapter.StringField(record, "kind"),
			Occurred:  adapter.StringField(record, "occurredAt"),
			Include:   adapter.OptionalInclude(record),
			Exclude:   adapter.OptionalExclude(record),
			Valid:     valid,
			Error:     errText,
		})
	}
	return rows, nil
}
func (p *Pipeline) Export(opt adapter.Options) (ExportResult, error) {
	prepared, err := p.PrepareExport(opt)
	if err != nil {
		return ExportResult{}, err
	}
	if err := p.WritePreparedExport(prepared); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{BatchID: prepared.BatchID, Output: prepared.Output, Records: prepared.Records}, nil
}
func withDefaults(o adapter.Options) adapter.Options {
	o.Source = strings.TrimSpace(o.Source)
	if o.Source == "" {
		o.Source = adapter.UsageJSONSource
	}
	o.Input = strings.TrimSpace(o.Input)
	o.Output = strings.TrimSpace(o.Output)
	o.BatchID = strings.TrimSpace(o.BatchID)
	return o
}

type Pipeline struct{ registry *registry.Registry }

func New(reg *registry.Registry) *Pipeline {
	if reg == nil {
		reg = registry.Production()
	}
	return &Pipeline{registry: reg}
}

var production = New(registry.Production())

func (p *Pipeline) validateInput(opt adapter.Options) error {
	if !p.registry.IsKnownSource(opt.Source) {
		return fmt.Errorf("unsupported source %q", opt.Source)
	}
	if opt.Input == "" {
		return errors.New("missing input path")
	}
	return nil
}
func Scan(opt adapter.Options) (ScanResult, error)      { return production.Scan(opt) }
func Preview(opt adapter.Options) ([]PreviewRow, error) { return production.Preview(opt) }
func Export(opt adapter.Options) (ExportResult, error)  { return production.Export(opt) }
