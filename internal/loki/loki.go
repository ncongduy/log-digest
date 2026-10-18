// Package loki reads log lines from Loki's query_range API.
package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ncongduy/log-digest/internal/digest"
)

// DefaultPageLimit is Loki's default max_entries_limit_per_query.
const DefaultPageLimit = 5000

// Client queries one Loki. With auth_enabled: false there is no tenant header.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	PageLimit int
}

// Fetch returns every line matching query in [start, end), oldest first, up
// to maxLines. truncated reports that more lines were left in the window.
//
// Loki pages by count, not by cursor: each page is the oldest PageLimit lines
// at or after start. The next page starts at the last page's newest
// timestamp, inclusive, and skips the lines at that timestamp it already has,
// so lines from two streams sharing a nanosecond are neither lost nor doubled.
func (c *Client) Fetch(ctx context.Context, query string, start, end time.Time, maxLines int) ([]digest.Entry, bool, error) {
	limit := c.PageLimit
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	var out []digest.Entry
	from := start
	var edge map[string]bool
	for {
		page, err := c.page(ctx, query, from, end, limit)
		if err != nil {
			return nil, false, err
		}
		fresh := 0
		for _, e := range page {
			if edge[key(e)] {
				continue
			}
			out = append(out, e)
			fresh++
			if len(out) > maxLines {
				return out[:maxLines], true, nil
			}
		}
		if len(page) < limit {
			return out, false, nil
		}
		last := page[len(page)-1].Time
		if fresh == 0 {
			// A full page of lines at one nanosecond, all seen: step past it.
			from, edge = last.Add(time.Nanosecond), nil
			continue
		}
		from, edge = last, map[string]bool{}
		for _, e := range page {
			if e.Time.Equal(last) {
				edge[key(e)] = true
			}
		}
	}
}

func (c *Client) page(ctx context.Context, query string, from, end time.Time, limit int) ([]digest.Entry, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(from.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "forward")
	u := strings.TrimRight(c.BaseURL, "/") + "/loki/api/v1/query_range?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("loki: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return Parse(resp.Body)
}

type response struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			// [ts, line] or, with categorize-labels, [ts, line, metadata].
			Values [][]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// Parse decodes one query_range response into entries, oldest first. It also
// reads a saved response for --input.
func Parse(r io.Reader) ([]digest.Entry, error) {
	var resp response
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("loki: decode: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("loki: status %q", resp.Status)
	}
	if t := resp.Data.ResultType; t != "streams" {
		return nil, fmt.Errorf("loki: result type %q, want streams", t)
	}
	var out []digest.Entry
	for _, s := range resp.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				return nil, fmt.Errorf("loki: value with %d fields", len(v))
			}
			var ts, line string
			if err := json.Unmarshal(v[0], &ts); err != nil {
				return nil, fmt.Errorf("loki: timestamp: %w", err)
			}
			if err := json.Unmarshal(v[1], &line); err != nil {
				return nil, fmt.Errorf("loki: line: %w", err)
			}
			n, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("loki: timestamp %q: %w", ts, err)
			}
			out = append(out, digest.Entry{Time: time.Unix(0, n).UTC(), Labels: s.Stream, Line: line})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// key identifies a line within one timestamp: its stream and its text.
func key(e digest.Entry) string {
	names := make([]string, 0, len(e.Labels))
	for k := range e.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k + "=" + e.Labels[k] + "\x00")
	}
	b.WriteString(strconv.FormatInt(e.Time.UnixNano(), 10) + "\x00" + e.Line)
	return b.String()
}
