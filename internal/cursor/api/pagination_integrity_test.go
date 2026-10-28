package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"toktrail-collector/internal/cursor/api"
)

func integrityRow(id string) map[string]any {
	row := map[string]any{"timestamp": "1000", "model": "test-model", "tokenUsage": map[string]any{"inputTokens": "10", "outputTokens": "2"}}
	if id != "" {
		row["usageEventId"] = id
	}
	return row
}

func TestUsagePaginationRejectsRepeatedIdentifiedPage(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"totalUsageEventsCount": 2, "usageEventsDisplay": []any{integrityRow("private-event-sentinel")}})
	}))
	defer s.Close()
	client, err := api.New(api.Options{BaseURL: s.URL, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.FetchUsageEvents(context.Background(), api.Session{Token: "synthetic-session"}, api.FetchOptions{EndDateMS: 2000})
	if err == nil || result != nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("repeated page was accepted as complete: %v", err)
	}
	if requests != 2 || strings.Contains(err.Error(), "private-event-sentinel") {
		t.Fatal("duplicate detection leaked event identity or kept walking")
	}
}

func TestUsagePaginationDoesNotGuessIdlessPageIdentity(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		rows := []any{integrityRow("")}
		if requests == 3 {
			rows = nil
		}
		if rows == nil {
			rows = []any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"usageEventsDisplay": rows})
	}))
	defer s.Close()
	client, err := api.New(api.Options{BaseURL: s.URL, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.FetchUsageEvents(context.Background(), api.Session{Token: "synthetic-session"}, api.FetchOptions{EndDateMS: 2000})
	if err != nil || result == nil || len(result.Events) != 2 || requests != 3 {
		t.Fatalf("distinct idless rows incorrectly merged: %#v %v", result, err)
	}
}

func TestUsagePaginationRejectsInvalidTotalsAndExcessRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"negative-total", map[string]any{"totalUsageEventsCount": -1, "usageEventsDisplay": []any{integrityRow("one")}}},
		{"excessive-total", map[string]any{"totalUsageEventsCount": 3, "usageEventsDisplay": []any{integrityRow("one")}}},
		{"excessive-rows", map[string]any{"usageEventsDisplay": []any{integrityRow("one"), integrityRow("two"), integrityRow("three")}, "hasNext": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(tc.body) }))
			defer s.Close()
			client, err := api.New(api.Options{BaseURL: s.URL, MaxEvents: 2})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.FetchUsageEvents(context.Background(), api.Session{Token: "synthetic-session"}, api.FetchOptions{EndDateMS: 2000})
			if err == nil || result != nil {
				t.Fatalf("invalid history returned as complete: %#v %v", result, err)
			}
		})
	}
}
