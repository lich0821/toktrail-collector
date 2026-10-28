package api

import "fmt"

// CollapseReason explains why a snapshot was dropped when collapsing.
type CollapseReason string

const (
	// CollapseReasonSmallerSnapshot: the row lost to another snapshot of the
	// same event under the token-total competition.
	CollapseReasonSmallerSnapshot CollapseReason = "smaller-snapshot"
)

// DroppedSnapshot records one collapsed-away row so callers can log
// anomalies (duplicate snapshots inside a single response are unexpected on
// a healthy upstream) without losing the evidence.
type DroppedSnapshot struct {
	// Index is the row's position in the input slice.
	Index int
	// UsageEventID is the event key the row competed under. Programmatic
	// use only: String never renders it, so raw ids stay out of logs.
	UsageEventID string
	// Model and TimestampMS identify the competing group.
	Model       string
	TimestampMS int64
	Reason      CollapseReason
}

// String renders a dropped snapshot for anomaly logs without the event id.
func (d DroppedSnapshot) String() string {
	return fmt.Sprintf("cursor snapshot collapsed: index=%d reason=%s", d.Index, d.Reason)
}

// CollapseResult is the outcome of collapsing event snapshots.
type CollapseResult struct {
	// Events holds one survivor per UsageEventID, in source order, plus
	// every id-less row unchanged.
	Events []UsageEvent
	// Dropped records every collapsed-away snapshot with its reason.
	Dropped []DroppedSnapshot
}

// CollapseSnapshots resolves duplicate snapshots within one response (or one
// stored document) WITHOUT ever summing them, mirroring tokscale's
// generation-2 collapse (cursor_event_snapshot_keep_mask,
// crates/tokscale-core/src/sessions/cursor.rs @ 39ecb83):
//
//   - A row carrying a UsageEventID is keyed by that id alone. The winner
//     per key is the row with the largest token total, with the earliest row
//     winning exact ties; survivors retain source order.
//   - A row with no UsageEventID has no stable identity, so its identity is
//     never guessed: it is kept unmerged and uncounted. The reference joins
//     id-less rows to identified events by (conversation, model,
//     timestamp); TokTrail deliberately does not, and the Normalizer skips
//     id-less rows when counting so a large id-less snapshot cannot pollute
//     any event's total.
//
// TokTrail v1 also deviates from the reference rank: cost fields are not
// uploaded, so the competition ranks by token total only, and a row whose
// total is unknown (any token count nil) ranks below every row with a known
// total rather than being coerced to zero. Unknown-total ties keep the
// earliest row in arrival order — the newest snapshot, since the dashboard
// lists events newest-first — which matches the replace-by-newest semantics
// the sync layer applies across pulls.
//
// Collapse resolves duplicates within one document only. Across successful
// pulls, the sync layer must REPLACE the stored event for a usageEventId
// with the freshly fetched snapshot (the reference's
// merge_cursor_usage_events semantics) so server-side downward corrections
// apply; a local historical maximum must never be treated as authoritative
// against newer data.
func CollapseSnapshots(events []UsageEvent) CollapseResult {
	result := CollapseResult{}
	// survivor[usageEventID] is the index of the current winning row.
	survivor := make(map[string]int)
	for i := range events {
		id := events[i].UsageEventID
		if id == "" {
			continue
		}
		current, ok := survivor[id]
		if !ok {
			survivor[id] = i
			continue
		}
		loser := current
		if snapshotRank(&events[i]) > snapshotRank(&events[current]) {
			survivor[id] = i
		} else {
			loser = i
		}
		result.Dropped = append(result.Dropped, DroppedSnapshot{
			Index:        loser,
			UsageEventID: id,
			Model:        events[loser].Model,
			TimestampMS:  events[loser].TimestampMS,
			Reason:       CollapseReasonSmallerSnapshot,
		})
	}

	for i := range events {
		if id := events[i].UsageEventID; id == "" || survivor[id] == i {
			result.Events = append(result.Events, events[i])
		}
	}
	return result
}

// snapshotRank is the competition rank: the token total, with an unknown
// total (any count nil) ranking below every known non-negative total.
func snapshotRank(e *UsageEvent) int64 {
	if total, ok := e.TokenTotal(); ok {
		return total
	}
	return -1
}
