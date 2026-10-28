package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/cursor/api"
)

const (
	testAccountID = "user_testuser1234"
	testJWT       = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdXRoMHx1c2VyX3Rlc3R1c2VyMTIzNCJ9.c2lnbmF0dXJl"
	testToken     = testAccountID + "%3A%3A" + testJWT
)

func newMockServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func newTestClient(t *testing.T, baseURL string, mutate func(*api.Options)) *api.Client {
	t.Helper()
	opts := api.Options{BaseURL: baseURL}
	if mutate != nil {
		mutate(&opts)
	}
	client, err := api.New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func summaryOKHandler(t *testing.T, requests *[]capturedRequest) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requests != nil {
			*requests = append(*requests, capturedRequest{
				Method: r.Method,
				Path:   r.URL.Path,
				Cookie: r.Header.Get("Cookie"),
			})
		}
		_, _ = io.WriteString(w, `{"membershipType":"pro","billingCycleStart":"2026-10-01","billingCycleEnd":"2026-11-01"}`)
	}
}

type capturedRequest struct {
	Method string
	Path   string
	Cookie string
	Origin string
	CType  string
	Body   string
}

func snapshotRow(id, conversation, model string, timestampMS int64, input, output, cacheRead int64) string {
	return fmt.Sprintf(`{
		"timestamp": %q,
		"model": %q,
		"usageEventId": %q,
		"chargedCents": 1.5,
		"tokenUsage": {"inputTokens": %d, "outputTokens": %d, "cacheReadTokens": %d, "cacheWriteTokens": 1, "totalCents": 1.5},
		"conversationId": %q
	}`, strconv.FormatInt(timestampMS, 10), model, id, input, output, cacheRead, conversation)
}

func eventsHandler(t *testing.T, requests *[]capturedRequest, pages [][]string, total *int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if requests != nil {
			*requests = append(*requests, capturedRequest{
				Method: r.Method,
				Path:   r.URL.Path,
				Cookie: r.Header.Get("Cookie"),
				Origin: r.Header.Get("Origin"),
				CType:  r.Header.Get("Content-Type"),
				Body:   string(body),
			})
		}
		var parsed struct {
			Page int `json:"page"`
		}
		_ = json.Unmarshal(body, &parsed)
		page := parsed.Page
		if page < 1 || page > len(pages) {
			page = len(pages)
		}
		rows := make([]json.RawMessage, 0, len(pages[page-1]))
		for _, row := range pages[page-1] {
			rows = append(rows, json.RawMessage(row))
		}
		response := map[string]any{"usageEventsDisplay": rows}
		if total != nil {
			response["totalUsageEventsCount"] = *total
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func TestSessionNeverLeaksCredential(t *testing.T) {
	sess := api.Session{Token: testToken}
	rendered := fmt.Sprintf("%v", sess)
	if strings.Contains(rendered, testToken) || strings.Contains(rendered, testJWT) {
		t.Fatalf("String() leaked the token: %q", rendered)
	}
	if goStr := fmt.Sprintf("%#v", sess); strings.Contains(goStr, testJWT) {
		t.Fatalf("GoString() leaked the token: %q", goStr)
	}
	encoded, err := json.Marshal(sess)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testJWT) {
		t.Fatalf("JSON marshal leaked the token: %s", encoded)
	}
}

func TestNewEnforcesHostAllowlist(t *testing.T) {
	cases := []struct {
		baseURL string
		wantErr string
	}{
		{"", ""},
		{"https://cursor.com", ""},
		{"http://127.0.0.1:1", ""},
		{"http://localhost:1", ""},
		{"https://example.com", "host is not allowed"},
		{"http://cursor.com", "must use https"},
		{"https://cursor.com:8443", "default port"},
		{"https://user:pass@cursor.com", "user info"},
		{"https://cursor.com/?x=1", "query"},
		{"https://cursor.com/#frag", "fragment"},
		{"https://cursor.com/path", "path"},
		{"ftp://cursor.com", "must use https"},
		{"://bad url", "invalid base URL"},
	}
	for _, tc := range cases {
		_, err := api.New(api.Options{BaseURL: tc.baseURL})
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("New(%q): unexpected error %v", tc.baseURL, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("New(%q): want error containing %q, got %v", tc.baseURL, tc.wantErr, err)
		}
	}
}

func TestNewAppliesHardCaps(t *testing.T) {
	// Construction with oversized bounds must clamp rather than fail or
	// accept the loosening.
	if _, err := api.New(api.Options{
		PageSize:     100000,
		MaxPages:     100000,
		MaxBodyBytes: 1 << 30,
		Timeout:      24 * time.Hour,
	}); err != nil {
		t.Fatalf("hard-cap construction must succeed: %v", err)
	}
}

func TestFetchUsageEventsSendsVerifiedProtocol(t *testing.T) {
	var requests []capturedRequest
	now := time.UnixMilli(1792841120156)
	total := int64(1)
	server := newMockServer(t, eventsHandler(t, &requests, [][]string{{snapshotRow("e-1", "c-1", "gemini-3.8-flash-high", 1792841120000, 10, 5, 2)}}, &total))
	client, err := api.New(api.Options{BaseURL: server, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events.Events))
	}
	req := requests[0]
	if req.Method != http.MethodPost || req.Path != "/api/dashboard/get-filtered-usage-events" {
		t.Fatalf("want POST /api/dashboard/get-filtered-usage-events, got %s %s", req.Method, req.Path)
	}
	if req.Cookie != "WorkosCursorSessionToken="+testToken {
		t.Fatalf("cookie header mismatch: %q", req.Cookie)
	}
	if req.Origin != "https://cursor.com" || req.CType != "application/json" {
		t.Fatalf("CSRF headers missing: Origin=%q Content-Type=%q", req.Origin, req.CType)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	if body["startDate"] != "0" || body["endDate"] != "1792841120156" {
		t.Fatalf("window must be ms strings: %v", body)
	}
	if body["page"] != float64(1) || body["pageSize"] != float64(500) {
		t.Fatalf("page/pageSize mismatch: %v", body)
	}
}

func TestFetchUsageEventsWalksPagesUntilAdvertisedTotal(t *testing.T) {
	total := int64(4)
	pages := [][]string{
		{snapshotRow("e-1", "c", "m", 3000, 1, 1, 0), snapshotRow("e-2", "c", "m", 2000, 1, 1, 0)},
		{snapshotRow("e-3", "c", "m", 1000, 1, 1, 0), snapshotRow("e-4", "c", "m", 500, 1, 1, 0)},
	}
	server := newMockServer(t, eventsHandler(t, nil, pages, &total))
	client := newTestClient(t, server, func(o *api.Options) { o.PageSize = 2 })
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 4 || !events.HasTotalCount || events.TotalUsageEventsCount != 4 {
		t.Fatalf("want 4 events with total 4, got %d events, total=%d(%v)", len(events.Events), events.TotalUsageEventsCount, events.HasTotalCount)
	}
	if events.PagesFetched != 2 {
		t.Fatalf("want 2 pages, got %d", events.PagesFetched)
	}
	if events.Events[0].UsageEventID != "e-1" || events.Events[3].UsageEventID != "e-4" {
		t.Fatal("events must keep arrival order (newest first from the server)")
	}
}

func TestFetchUsageEventsShortPageWithoutTotalKeepsWalkingUntilEmpty(t *testing.T) {
	// A short page is not a reliable end: the server may clamp the page
	// size, so the walk must continue to the empty page.
	pages := [][]string{
		{snapshotRow("e-1", "c", "m", 1000, 1, 1, 0)},
		{},
	}
	server := newMockServer(t, eventsHandler(t, nil, pages, nil))
	client := newTestClient(t, server, nil)
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.PagesFetched != 2 || events.HasTotalCount {
		t.Fatalf("the walk must continue past the short page to the empty one: events=%d pages=%d hasTotal=%v",
			len(events.Events), events.PagesFetched, events.HasTotalCount)
	}
}

func TestFetchUsageEventsStopsOnExplicitHasNextFalse(t *testing.T) {
	row := json.RawMessage(snapshotRow("e-1", "c", "m", 1000, 1, 1, 0))
	requests := 0
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"usageEventsDisplay": []json.RawMessage{row},
			"hasNext":            false,
		})
	})
	client := newTestClient(t, server, nil)
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || requests != 1 {
		t.Fatalf("hasNext:false must end the walk after one short page: events=%d requests=%d", len(events.Events), requests)
	}
}

func TestFetchUsageEventsRefusesSilentTruncationWithoutReliableEnd(t *testing.T) {
	// No total and no hasNext: a server that keeps returning short, non-empty
	// pages (page-size clamping) must not silently truncate history.
	row := json.RawMessage(snapshotRow("e-1", "c", "m", 1000, 1, 1, 0))
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"usageEventsDisplay": []json.RawMessage{row}})
	})
	client := newTestClient(t, server, func(o *api.Options) { o.MaxPages = 2 })
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "partial history") {
		t.Fatalf("no reliable end signal must fail loudly, got %v", err)
	}
}

func TestFetchUsageEventsRejectsEmptyPageBeforeAdvertisedTotal(t *testing.T) {
	total := int64(4)
	pages := [][]string{{snapshotRow("e-1", "c", "m", 1000, 1, 1, 0)}, {}}
	server := newMockServer(t, eventsHandler(t, nil, pages, &total))
	client := newTestClient(t, server, func(o *api.Options) { o.PageSize = 2 })
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "empty page") {
		t.Fatalf("empty page before total must fail, got %v", err)
	}
}

func TestFetchUsageEventsRejectsMissingDisplayArray(t *testing.T) {
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"totalUsageEventsCount": 5}`)
	})
	client := newTestClient(t, server, nil)
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "usageEventsDisplay") {
		t.Fatalf("missing array must fail (WAF guard), got %v", err)
	}
}

func TestFetchUsageEventsRejectsInvalidEventRows(t *testing.T) {
	rows := []string{`{"timestamp":"1000","model":"m","tokenUsage":{"inputTokens":-5}}`}
	server := newMockServer(t, eventsHandler(t, nil, [][]string{rows}, nil))
	client := newTestClient(t, server, nil)
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "invalid event row") {
		t.Fatalf("strict parsing must reject negative counts, got %v", err)
	}
}

func TestFetchUsageEventsSessionExpired(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})
		client := newTestClient(t, server, nil)
		_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
		if !errors.Is(err, api.ErrSessionExpired) {
			t.Fatalf("status %d must map to ErrSessionExpired, got %v", status, err)
		}
	}
}

func TestFetchUsageEventsEnforcesByteCap(t *testing.T) {
	row := snapshotRow("e-1", "c", "m", 1000, 1, 1, 0)
	server := newMockServer(t, eventsHandler(t, nil, [][]string{{row}}, nil))
	client := newTestClient(t, server, func(o *api.Options) { o.MaxBodyBytes = 10 })
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("byte cap must fail, got %v", err)
	}
}

func TestFetchUsageEventsRefusesPartialHistoryAtHardPageCap(t *testing.T) {
	// The server clamps its page size to one row while advertising an
	// unreachable total; the hard page cap must refuse the partial walk.
	total := int64(100000)
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"totalUsageEventsCount": total,
			"usageEventsDisplay":    []json.RawMessage{json.RawMessage(snapshotRow("e", "c", "m", 1000, 1, 1, 0))},
		})
	})
	client := newTestClient(t, server, func(o *api.Options) { o.MaxPages = 2 })
	_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "partial history") {
		t.Fatalf("hard page cap must refuse partial history, got %v", err)
	}
}

func TestFetchUsageEventsStartDateFiltersAndStopsAtCrossedPage(t *testing.T) {
	start := int64(1500)
	pages := [][]string{
		{snapshotRow("e-1", "c", "m", 2000, 1, 1, 0), snapshotRow("e-2", "c", "m", 1600, 1, 1, 0)},
		{snapshotRow("e-3", "c", "m", 1400, 1, 1, 0), snapshotRow("e-4", "c", "m", 1000, 1, 1, 0)},
		{snapshotRow("e-5", "c", "m", 500, 1, 1, 0)},
	}
	requestCount := 0
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		page := requestCount
		if page > len(pages) {
			page = len(pages)
		}
		var body struct {
			StartDate string `json:"startDate"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.StartDate != "1500" {
			t.Errorf("startDate must be forwarded as string, got %q", body.StartDate)
		}
		rows := make([]json.RawMessage, 0, len(pages[page-1]))
		for _, row := range pages[page-1] {
			rows = append(rows, json.RawMessage(row))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"usageEventsDisplay": rows})
	})
	client := newTestClient(t, server, func(o *api.Options) { o.PageSize = 2 })
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{StartDateMS: &start})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 2 || events.Events[0].UsageEventID != "e-1" || events.Events[1].UsageEventID != "e-2" {
		t.Fatalf("events older than the window must be dropped: %+v", events.Events)
	}
	if requestCount != 2 {
		t.Fatalf("walk must stop at the crossed page, requests=%d", requestCount)
	}
	if events.StartDateMS != start {
		t.Fatalf("result window start mismatch: %d", events.StartDateMS)
	}
}

func TestFetchUsageEventsReturnsRawSnapshotsWithoutSumming(t *testing.T) {
	rows := []string{
		snapshotRow("same-id", "c", "m", 1792841120000, 100, 10, 50),
		snapshotRow("same-id", "c", "m", 1792841120000, 90, 9, 45),
		snapshotRow("same-id", "c", "m", 1792841120000, 4, 1, 4),
	}
	total := int64(3)
	server := newMockServer(t, eventsHandler(t, nil, [][]string{rows}, &total))
	client := newTestClient(t, server, nil)
	events, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 3 {
		t.Fatalf("the fetch must return every raw snapshot (3), got %d", len(events.Events))
	}
	collapsed := api.CollapseSnapshots(events.Events)
	if len(collapsed.Events) != 1 {
		t.Fatalf("collapse must keep one snapshot, got %d", len(collapsed.Events))
	}
	kept := collapsed.Events[0]
	if kept.InputTokens == nil || *kept.InputTokens != 100 {
		t.Fatalf("largest snapshot must survive, got %+v", kept)
	}
	if len(collapsed.Dropped) != 2 {
		t.Fatalf("two snapshots must be recorded as dropped, got %d", len(collapsed.Dropped))
	}
}

func TestFetchUsageEventsRejectsAllRedirects(t *testing.T) {
	for _, location := range []string{
		"https://example.com/api/dashboard/get-filtered-usage-events",
		"/api/dashboard/get-filtered-usage-events?elsewhere=1",
	} {
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, location, http.StatusFound)
		})
		client := newTestClient(t, server, nil)
		_, err := client.FetchUsageEvents(context.Background(), api.Session{Token: testToken}, api.FetchOptions{})
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("redirect %q must be rejected, got %v", location, err)
		}
		if err != nil && (strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), testJWT)) {
			t.Fatal("error must not leak the session token")
		}
	}
}

func TestFetchUsageEventsRejectsEmptyToken(t *testing.T) {
	client := newTestClient(t, newMockServer(t, func(w http.ResponseWriter, r *http.Request) {}), nil)
	if _, err := client.FetchUsageEvents(context.Background(), api.Session{}, api.FetchOptions{}); err == nil {
		t.Fatal("empty token must fail")
	}
}

func TestFetchUsageSummaryVerifiesSession(t *testing.T) {
	var requests []capturedRequest
	server := newMockServer(t, summaryOKHandler(t, &requests))
	client := newTestClient(t, server, nil)
	summary, err := client.FetchUsageSummary(context.Background(), api.Session{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	if summary.MembershipType != "pro" || summary.BillingCycleStart != "2026-10-01" || summary.BillingCycleEnd != "2026-11-01" {
		t.Fatalf("summary mismatch: %+v", summary)
	}
	req := requests[0]
	if req.Method != http.MethodGet || req.Path != "/api/usage-summary" {
		t.Fatalf("want GET /api/usage-summary, got %s %s", req.Method, req.Path)
	}
	if req.Cookie != "WorkosCursorSessionToken="+testToken {
		t.Fatalf("cookie mismatch: %q", req.Cookie)
	}
}

func TestFetchUsageSummaryRejectsInvalidShapes(t *testing.T) {
	cases := map[string]string{
		"missing window": `{"membershipType":"pro"}`,
		"not an object":  `[]`,
	}
	for name, payload := range cases {
		server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, payload)
		})
		client := newTestClient(t, server, nil)
		if _, err := client.FetchUsageSummary(context.Background(), api.Session{Token: testToken}); err == nil {
			t.Fatalf("%s must fail", name)
		}
	}
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := newTestClient(t, server, nil)
	if _, err := client.FetchUsageSummary(context.Background(), api.Session{Token: testToken}); !errors.Is(err, api.ErrSessionExpired) {
		t.Fatalf("401 must map to ErrSessionExpired, got %v", err)
	}
}

func TestVerifySessionFullFlow(t *testing.T) {
	var requests []capturedRequest
	server := newMockServer(t, summaryOKHandler(t, &requests))
	client := newTestClient(t, server, nil)

	result, err := client.VerifySession(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountID != testAccountID {
		t.Fatalf("account id mismatch: %q", result.AccountID)
	}
	if result.SessionToken != testToken {
		t.Fatalf("session token must be normalized to the %%3A%%3A form: %q", result.SessionToken)
	}
	if result.Summary == nil || result.Summary.BillingCycleStart != "2026-10-01" {
		t.Fatalf("summary proof missing: %+v", result.Summary)
	}
	if requests[0].Cookie != "WorkosCursorSessionToken="+testToken {
		t.Fatalf("verification must send the assembled cookie, got %q", requests[0].Cookie)
	}
	if rendered := fmt.Sprintf("%v", result); strings.Contains(rendered, testJWT) {
		t.Fatalf("VerifyResult.String() leaked the token: %q", rendered)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), testJWT) {
		t.Fatalf("VerifyResult JSON leaked the token: %s", encoded)
	}
}

func TestVerifySessionAcceptsBareJWTAndLiteralSeparator(t *testing.T) {
	server := newMockServer(t, summaryOKHandler(t, nil))
	client := newTestClient(t, server, nil)

	bare, err := client.VerifySession(context.Background(), testJWT)
	if err != nil {
		t.Fatal(err)
	}
	if bare.AccountID != testAccountID || bare.SessionToken != testToken {
		t.Fatalf("bare JWT must assemble the cookie: %+v", bare)
	}

	literal, err := client.VerifySession(context.Background(), testAccountID+"::"+testJWT)
	if err != nil {
		t.Fatal(err)
	}
	if literal.AccountID != testAccountID || literal.SessionToken != testToken {
		t.Fatalf("literal '::' must normalize to %%3A%%3A: %+v", literal)
	}
}

func TestVerifySessionRejectsPrefixMismatchWithoutNetwork(t *testing.T) {
	requests := 0
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
	})
	client := newTestClient(t, server, nil)
	_, err := client.VerifySession(context.Background(), "user_otheruser9999%3A%3A"+testJWT)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("prefix mismatch must be rejected, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("mismatch must be rejected before any network call, made %d", requests)
	}
}

func TestVerifySessionRejectsInvalidCredentials(t *testing.T) {
	server := newMockServer(t, summaryOKHandler(t, nil))
	client := newTestClient(t, server, nil)
	badJWT := func(claims string) string {
		return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2ln"
	}
	cases := map[string]string{
		"empty":             "",
		"not a jwt":         "not-a-jwt",
		"no sub":            badJWT(`{"other":"x"}`),
		"sub without user_": badJWT(`{"sub":"auth0|someone"}`),
		"weak id":           badJWT(`{"sub":"auth0|user_ab1"}`),
		"payload not json":  "eyJhbGciOiJIUzI1NiJ9.%%%%.c2ln",
		"sub not a string":  badJWT(`{"sub":42}`),
	}
	for name, credential := range cases {
		if _, err := client.VerifySession(context.Background(), credential); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestVerifySessionMapsExpiredSessions(t *testing.T) {
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := newTestClient(t, server, nil)
	_, err := client.VerifySession(context.Background(), testToken)
	if !errors.Is(err, api.ErrSessionExpired) {
		t.Fatalf("expired credential must surface ErrSessionExpired, got %v", err)
	}
}

func TestParseUsageEventStrictShapes(t *testing.T) {
	raw := json.RawMessage(`{
		"timestamp": "1792841120156",
		"model": " gemini-3.8-flash-high ",
		"usageEventId": " 452fb2c1-0000-0000-0000-000000000000 ",
		"chargedCents": "$1,234.5",
		"tokenUsage": {"inputTokens": "10", "outputTokens": 2, "cacheReadTokens": 3, "cacheWriteTokens": 4, "totalCents": 1234.5},
		"conversationId": "c-1",
		"unknownFutureField": {"nested": true}
	}`)
	event, err := api.ParseUsageEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.TimestampMS != 1792841120156 || event.Model != "gemini-3.8-flash-high" {
		t.Fatalf("core fields mismatch: %+v", event)
	}
	if event.UsageEventID != "452fb2c1-0000-0000-0000-000000000000" || event.ConversationID != "c-1" {
		t.Fatalf("id fields must be trimmed: %+v", event)
	}
	if event.InputTokens == nil || *event.InputTokens != 10 || event.OutputTokens == nil || *event.OutputTokens != 2 ||
		event.CacheReadTokens == nil || *event.CacheReadTokens != 3 || event.CacheWriteTokens == nil || *event.CacheWriteTokens != 4 {
		t.Fatalf("token coercion mismatch: %+v", event)
	}
	if total, ok := event.TokenTotal(); !ok || total != 19 {
		t.Fatalf("token total mismatch: %d %v", total, ok)
	}

	partial, err := api.ParseUsageEvent(json.RawMessage(`{"timestamp":"1792841120156","model":"m","tokenUsage":{"inputTokens":10,"outputTokens":2,"cacheReadTokens":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	if partial.CacheWriteTokens != nil {
		t.Fatal("absent cacheWriteTokens must stay nil")
	}
	if total, ok := partial.TokenTotal(); ok {
		t.Fatalf("a total with an unknown component must be unknown, got %d", total)
	}

	iso, err := api.ParseUsageEvent(json.RawMessage(`{"timestamp":"2026-10-20T01:02:03Z","model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	if iso.TimestampMS != time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC).UnixMilli() {
		t.Fatalf("ISO timestamp must parse: %+v", iso)
	}

	positional, err := api.ParseUsageEvent(json.RawMessage(`["c-9","1700000000000","claude-4.5-sonnet",12.5,{"inputTokens":7}]`))
	if err != nil {
		t.Fatal(err)
	}
	if positional.ConversationID != "c-9" || positional.TimestampMS != 1700000000000 || positional.Model != "claude-4.5-sonnet" ||
		positional.InputTokens == nil || *positional.InputTokens != 7 {
		t.Fatalf("positional coercion mismatch: %+v", positional)
	}

	invalid := map[string]string{
		"empty row":         ``,
		"null row":          `null`,
		"scalar row":        `"just a string"`,
		"negative count":    `{"timestamp":"1000","model":"m","tokenUsage":{"inputTokens":-5}}`,
		"fractional count":  `{"timestamp":"1000","model":"m","tokenUsage":{"inputTokens":2.9}}`,
		"fractional string": `{"timestamp":"1000","model":"m","tokenUsage":{"inputTokens":"2.9"}}`,
		"overflow count":    `{"timestamp":"1000","model":"m","tokenUsage":{"inputTokens":9223372036854775808}}`,
		"missing model":     `{"timestamp":"1000"}`,
		"empty model":       `{"timestamp":"1000","model":"  "}`,
		"missing timestamp": `{"model":"m"}`,
		"zero timestamp":    `{"timestamp":"0","model":"m"}`,
		"negative time":     `{"timestamp":"-5","model":"m"}`,
		"bad tokenUsage":    `{"timestamp":"1000","model":"m","tokenUsage":[1,2]}`,
		"non-string id":     `{"timestamp":"1000","model":"m","conversationId":7}`,
	}
	for name, row := range invalid {
		if _, err := api.ParseUsageEvent(json.RawMessage(row)); err == nil {
			t.Fatalf("%s must be rejected, not coerced", name)
		}
	}
}

func TestCollapseSnapshotsMirrorsReferenceRules(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	mk := func(id string, ts int64, input *int64) api.UsageEvent {
		e := api.UsageEvent{
			ConversationID: "conv",
			Model:          "m",
			TimestampMS:    ts,
			InputTokens:    input,
		}
		if id != "" {
			e.UsageEventID = id
		}
		return e
	}
	complete := func(id string, ts int64, input int64) api.UsageEvent {
		e := mk(id, ts, i64(input))
		e.OutputTokens = i64(0)
		e.CacheReadTokens = i64(0)
		e.CacheWriteTokens = i64(0)
		return e
	}

	t.Run("largest snapshot wins and source order is kept", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			complete("id-1", 1000, 10),
			complete("id-1", 1000, 20),
			complete("id-1", 1000, 15),
		})
		if len(got.Events) != 1 || got.Events[0].InputTokens == nil || *got.Events[0].InputTokens != 20 {
			t.Fatalf("largest snapshot must survive: %+v", got.Events)
		}
		if len(got.Dropped) != 2 {
			t.Fatalf("both smaller snapshots must be recorded: %+v", got.Dropped)
		}
	})

	t.Run("exact tie keeps the earliest row", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			complete("id-1", 1000, 10),
			complete("id-1", 1000, 10),
		})
		if len(got.Events) != 1 || len(got.Dropped) != 1 || got.Dropped[0].Index != 1 {
			t.Fatalf("the later row must be dropped: events=%d dropped=%+v", len(got.Events), got.Dropped)
		}
	})

	t.Run("later lower snapshot does not replace a larger one", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			complete("id-1", 1000, 20),
			complete("id-1", 1000, 10),
		})
		if len(got.Events) != 1 || *got.Events[0].InputTokens != 20 {
			t.Fatalf("the larger earlier snapshot must survive: %+v", got.Events)
		}
	})

	t.Run("idless rows stay unmerged beside identified events", func(t *testing.T) {
		// Same conversation, model, and timestamp: two identified events plus
		// a large id-less snapshot. Identity is never guessed, so the id-less
		// row must not join either event and its count must not pollute
		// theirs; the Normalizer skips it when counting.
		idless := mk("", 1000, i64(30))
		idless.OutputTokens = i64(0)
		idless.CacheReadTokens = i64(0)
		idless.CacheWriteTokens = i64(0)
		got := api.CollapseSnapshots([]api.UsageEvent{
			complete("id-a", 1000, 10),
			complete("id-b", 1000, 20),
			idless,
		})
		if len(got.Events) != 3 || len(got.Dropped) != 0 {
			t.Fatalf("idless rows must stay unmerged and undropped: events=%d dropped=%d", len(got.Events), len(got.Dropped))
		}
		byID := map[string]int64{}
		for _, e := range got.Events {
			if e.InputTokens == nil {
				t.Fatalf("event lost its input count: %+v", e)
			}
			byID[e.UsageEventID] = *e.InputTokens
		}
		if byID["id-a"] != 10 || byID["id-b"] != 20 || byID[""] != 30 {
			t.Fatalf("no event's count may be polluted by the idless row: %v", byID)
		}
	})

	t.Run("unknown total ranks below every known total", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			mk("id-1", 1000, nil),
			complete("id-1", 1000, 1),
		})
		if len(got.Events) != 1 || got.Events[0].InputTokens == nil || *got.Events[0].InputTokens != 1 {
			t.Fatalf("unknown total must not win: %+v", got.Events)
		}
	})

	t.Run("different timestamps stay separate", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			complete("id-1", 1000, 10),
			complete("id-2", 2000, 10),
		})
		if len(got.Events) != 2 {
			t.Fatalf("distinct events must remain distinct: %+v", got.Events)
		}
	})

	t.Run("unmatched idless rows are all kept", func(t *testing.T) {
		got := api.CollapseSnapshots([]api.UsageEvent{
			mk("", 1000, i64(10)),
			mk("", 1000, i64(10)),
		})
		if len(got.Events) != 2 || len(got.Dropped) != 0 {
			t.Fatalf("repeated idless billable rows are legitimate: events=%d dropped=%d", len(got.Events), len(got.Dropped))
		}
	})
}

func TestDroppedSnapshotStringOmitsEventID(t *testing.T) {
	dropped := api.DroppedSnapshot{
		Index:        7,
		UsageEventID: "452fb2c1-secret-event-id",
		Model:        "m",
		TimestampMS:  1792841120156,
		Reason:       api.CollapseReasonSmallerSnapshot,
	}
	rendered := dropped.String()
	if strings.Contains(rendered, "452fb2c1-secret-event-id") {
		t.Fatalf("String must not render the raw event id: %q", rendered)
	}
	if !strings.Contains(rendered, "index=7") || !strings.Contains(rendered, "smaller-snapshot") {
		t.Fatalf("String must carry the index and reason: %q", rendered)
	}
}

func TestFetchUsageEventsPreservesContextErrors(t *testing.T) {
	row := json.RawMessage(snapshotRow("e-1", "c", "m", 1000, 1, 1, 0))
	server := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"usageEventsDisplay": []json.RawMessage{row}})
	})
	client := newTestClient(t, server, nil)

	t.Run("cancellation survives sanitization", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.FetchUsageEvents(ctx, api.Session{Token: testToken}, api.FetchOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context.Canceled must stay detectable, got %v", err)
		}
	})

	t.Run("deadline survives sanitization", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err := client.FetchUsageEvents(ctx, api.Session{Token: testToken}, api.FetchOptions{})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("context.DeadlineExceeded must stay detectable, got %v", err)
		}
	})
}
