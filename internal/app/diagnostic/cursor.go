package diagnostic

import (
	"fmt"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/source/adapter"
)

// cursorPrivacy inspects only TokTrail's own pending account batch files.
// It never opens Cursor's database, resolves credentials, or calls an API.
// Totals describe this queue, not the entire Cursor account history.
func cursorPrivacy(stateDir string) (*PrivacyReport, error) {
	_, hasPermit, err := cursorsource.New(stateDir).Load()
	if err != nil {
		return nil, fmt.Errorf("Cursor local permit is unreadable")
	}
	ledger := cursoroutbox.New(stateDir)
	entries, err := ledger.Load()
	if err != nil {
		return nil, fmt.Errorf("Cursor usage queue is unreadable")
	}
	r := &PrivacyReport{Source: protocol.SourceType, Input: "<local queued account usage; not account history>", Tools: map[string]int{}}
	var include, exclude uint64
	includeKnown, excludeKnown := true, true
	for _, entry := range entries {
		if entry.Status != cursoroutbox.StatusPending {
			continue
		}
		batch, err := ledger.LoadBatchBytes(entry)
		if err != nil {
			return nil, fmt.Errorf("Cursor pending batch is invalid; upload refused")
		}
		r.OutboxPending++
		for _, event := range batch.Records {
			r.RecordCount++
			r.ValidRecords++
			r.UploadSafeRecords++
			r.OutboxPendingRecords++
			r.Tools[protocol.Tool]++
			record := adapter.Record{"input": diagnosticCount(event.Input), "cacheRead": diagnosticCount(event.CacheRead), "cacheWrite": diagnosticCount(event.CacheWrite), "output": diagnosticCount(event.Output)}
			if n, ok := adapter.IncludeTokens(record); !ok || n > ^uint64(0)-include {
				includeKnown = false
			} else {
				include += n
			}
			if n, ok := adapter.ExcludeTokens(record); !ok || n > ^uint64(0)-exclude {
				excludeKnown = false
			} else {
				exclude += n
			}
			at, _ := time.Parse(time.RFC3339Nano, event.OccurredAt)
			if r.Earliest == nil || at.Before(*r.Earliest) {
				v := at
				r.Earliest = &v
			}
			if r.Latest == nil || at.After(*r.Latest) {
				v := at
				r.Latest = &v
			}
		}
	}
	if !hasPermit && r.OutboxPending == 0 {
		return nil, nil
	}
	if includeKnown {
		r.TokensInclude = &include
	}
	if excludeKnown {
		r.TokensExclude = &exclude
	}
	return r, nil
}

func diagnosticCount(n *string) any {
	if n == nil {
		return nil
	}
	return *n
}

func cursorDoctor(stateDir string) (Check, bool) {
	license, exists, err := cursorsource.New(stateDir).Load()
	if err != nil {
		return Check{Name: "cursor", Status: CheckFail, Detail: "local Cursor permit unreadable; no credential inspection performed"}, false
	}
	report, err := cursorPrivacy(stateDir)
	if err != nil {
		return Check{Name: "cursor", Status: CheckFail, Detail: err.Error()}, false
	}
	if report == nil {
		return Check{Name: "cursor", Status: CheckSkipped, Detail: "Cursor account source is not locally enabled"}, false
	}
	status, detail := CheckWarn, "no local Cursor permit; pending account usage remains local"
	if exists {
		detail = fmt.Sprintf("local Cursor permit status=%s; %d pending account batch(es); login not inspected", license.Status, report.OutboxPending)
		if license.Collectable() {
			status = CheckOK
		}
	}
	return Check{Name: "cursor", Status: status, Detail: detail}, exists && license.Collectable()
}
