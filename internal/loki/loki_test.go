package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 18, 6, 0, 0, 0, time.UTC)

type line struct {
	stream map[string]string
	ts     int64
	text   string
}

// fakeLoki answers query_range like Loki does: the earliest `limit` entries
// at or after start, before end, grouped by stream.
func fakeLoki(t *testing.T, lines []line, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		q := r.URL.Query()
		if r.URL.Path != "/loki/api/v1/query_range" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if q.Get("direction") != "forward" {
			t.Errorf("direction = %q, want forward", q.Get("direction"))
		}
		if q.Get("query") == "" {
			t.Errorf("no query")
		}
		start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))

		var hit []line
		for _, l := range lines {
			if l.ts >= start && l.ts < end {
				hit = append(hit, l)
			}
		}
		sort.SliceStable(hit, func(i, j int) bool { return hit[i].ts < hit[j].ts })
		if len(hit) > limit {
			hit = hit[:limit]
		}
		type stream struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		}
		byKey := map[string]*stream{}
		var order []string
		for _, l := range hit {
			k := fmt.Sprint(l.stream)
			if byKey[k] == nil {
				byKey[k] = &stream{Stream: l.stream}
				order = append(order, k)
			}
			byKey[k].Values = append(byKey[k].Values, []string{strconv.FormatInt(l.ts, 10), l.text})
		}
		res := []*stream{}
		for _, k := range order {
			res = append(res, byKey[k])
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "streams", "result": res},
		})
	}))
}

func at(d time.Duration) int64 { return t0.Add(d).UnixNano() }

func TestFetchPaginates(t *testing.T) {
	a := map[string]string{"namespace": "monitoring", "container": "loki", "level": "warn"}
	b := map[string]string{"job": "journal", "node": "rke2-worker-01", "unit": "garage.service", "level": "error"}
	var lines []line
	for i := range 10 {
		lines = append(lines, line{a, at(time.Duration(i) * time.Minute), fmt.Sprintf("a%d", i)})
	}
	// Two streams with lines at the same nanosecond, straddling a page edge.
	lines = append(lines, line{b, at(2 * time.Minute), "b-same-ns"})
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, PageLimit: 3}
	got, truncated, err := c.Fetch(context.Background(), `{level="warn"}`, t0, t0.Add(time.Hour), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
	if len(got) != 11 {
		t.Fatalf("got %d entries, want 11 (no duplicates, none lost)", len(got))
	}
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e.Line] {
			t.Errorf("duplicate %q", e.Line)
		}
		seen[e.Line] = true
	}
	if !seen["b-same-ns"] {
		t.Error("lost the entry sharing a nanosecond with the page edge")
	}
	if got[0].Labels["container"] != "loki" || !got[0].Time.Equal(t0) {
		t.Errorf("first entry = %+v", got[0])
	}
	if calls < 4 {
		t.Errorf("calls = %d, want pagination", calls)
	}
}

func TestFetchCapsLines(t *testing.T) {
	s := map[string]string{"namespace": "x", "container": "y", "level": "warn"}
	var lines []line
	for i := range 20 {
		lines = append(lines, line{s, at(time.Duration(i) * time.Second), fmt.Sprint(i)})
	}
	calls := 0
	srv := fakeLoki(t, lines, &calls)
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, PageLimit: 5}
	got, truncated, err := c.Fetch(context.Background(), `{}`, t0, t0.Add(time.Hour), 12)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(got) != 12 {
		t.Errorf("got %d entries, truncated=%v; want 12, true", len(got), truncated)
	}

	got, truncated, _ = c.Fetch(context.Background(), `{}`, t0, t0.Add(time.Hour), 20)
	if truncated || len(got) != 20 {
		t.Errorf("exactly at the cap: got %d, truncated=%v; want 20, false", len(got), truncated)
	}
}

func TestFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "max entries limit per query exceeded", http.StatusBadRequest)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	_, _, err := c.Fetch(context.Background(), `{}`, t0, t0.Add(time.Hour), 10)
	if err == nil {
		t.Fatal("want error")
	}
	if want := "max entries limit"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q lacks %q", err, want)
	}
}

func TestParseFile(t *testing.T) {
	f, err := os.Open("../../testdata/loki.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no entries in fixture")
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.Before(got[i-1].Time) {
			t.Fatalf("entries not in time order at %d", i)
		}
	}
}
