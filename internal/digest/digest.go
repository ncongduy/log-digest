// Package digest folds a window of log lines into groups of the same message
// and renders them as a prompt that fits a byte budget.
package digest

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// MaxSamples is the number of distinct example lines kept per group.
	MaxSamples = 3
	// MaxSampleRunes cuts one example line.
	MaxSampleRunes = 500
	// MaxPods is the number of pod names kept per group.
	MaxPods = 3
	// MaxGroupsPerSource keeps one chatty source from filling the prompt.
	MaxGroupsPerSource = 15
	maxTemplateRunes   = 300
)

// Entry is one log line with its Loki stream labels. Line must already be
// sanitized.
type Entry struct {
	Time   time.Time
	Labels map[string]string
	Line   string
}

// Group is every line from one source at one level with the same template.
type Group struct {
	Source   string
	Level    string
	Template string
	Count    int
	First    time.Time
	Last     time.Time
	Samples  []string
	Pods     []string
}

// SourceTotal counts one source's lines by level.
type SourceTotal struct {
	Source  string
	ByLevel map[string]int
	Total   int
}

// Digest is a window's worth of grouped lines.
type Digest struct {
	Start, End time.Time
	Lines      int
	// Truncated: the line cap was reached and the rest of the window is missing.
	Truncated bool
	// Redacted: values the sanitizer replaced.
	Redacted int
	Groups   []*Group
	Sources  []*SourceTotal
}

var levelRank = map[string]int{"critical": 0, "error": 1, "warn": 2}

func rank(level string) int {
	if r, ok := levelRank[level]; ok {
		return r
	}
	return len(levelRank)
}

// Source names where a line came from: a container, or a node's unit.
func Source(labels map[string]string) string {
	if ns := labels["namespace"]; ns != "" {
		return "pod " + ns + "/" + labels["container"]
	}
	if labels["job"] == "journal" {
		return "node " + labels["node"] + " " + labels["unit"]
	}
	return "other " + labels["job"]
}

// Build groups entries by source, level and template.
func Build(entries []Entry, start, end time.Time) *Digest {
	d := &Digest{Start: start, End: end, Lines: len(entries)}
	groups := map[string]*Group{}
	sources := map[string]*SourceTotal{}
	for _, e := range entries {
		src, lvl := Source(e.Labels), e.Labels["level"]
		tpl := Template(e.Line)
		key := src + "\x00" + lvl + "\x00" + tpl
		g := groups[key]
		if g == nil {
			g = &Group{Source: src, Level: lvl, Template: tpl, First: e.Time, Last: e.Time}
			groups[key] = g
		}
		g.Count++
		if e.Time.Before(g.First) {
			g.First = e.Time
		}
		if e.Time.After(g.Last) {
			g.Last = e.Time
		}
		if s := sample(e.Line); len(g.Samples) < MaxSamples && !contains(g.Samples, s) {
			g.Samples = append(g.Samples, s)
		}
		if p := e.Labels["pod"]; p != "" && len(g.Pods) < MaxPods && !contains(g.Pods, p) {
			g.Pods = append(g.Pods, p)
		}

		st := sources[src]
		if st == nil {
			st = &SourceTotal{Source: src, ByLevel: map[string]int{}}
			sources[src] = st
		}
		st.ByLevel[lvl]++
		st.Total++
	}

	for _, g := range groups {
		d.Groups = append(d.Groups, g)
	}
	sort.Slice(d.Groups, func(i, j int) bool {
		a, b := d.Groups[i], d.Groups[j]
		if rank(a.Level) != rank(b.Level) {
			return rank(a.Level) < rank(b.Level)
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Template < b.Template
	})

	for _, s := range sources {
		d.Sources = append(d.Sources, s)
	}
	sort.Slice(d.Sources, func(i, j int) bool {
		a, b := d.Sources[i], d.Sources[j]
		if ra, rb := worst(a), worst(b); ra != rb {
			return ra < rb
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		return a.Source < b.Source
	})
	return d
}

func worst(s *SourceTotal) int {
	r := len(levelRank)
	for lvl := range s.ByLevel {
		r = min(r, rank(lvl))
	}
	return r
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sample(line string) string {
	line = strings.TrimSpace(strings.ReplaceAll(line, "\n", " ⏎ "))
	if r := []rune(line); len(r) > MaxSampleRunes {
		return string(r[:MaxSampleRunes]) + "…"
	}
	return line
}

// LevelCounts returns the number of lines per level.
func (d *Digest) LevelCounts() map[string]int {
	c := map[string]int{}
	for _, g := range d.Groups {
		c[g.Level] += g.Count
	}
	return c
}

// Top returns the n most severe, most frequent groups.
func (d *Digest) Top(n int) []*Group {
	return d.Groups[:min(n, len(d.Groups))]
}

// Template replaces the parts of a line that vary between occurrences of the
// same message, so they group together. Used for grouping only; samples keep
// the original text.
func Template(line string) string {
	for _, r := range templateRules {
		line = r(line)
	}
	line = strings.TrimSpace(line)
	if r := []rune(line); len(r) > maxTemplateRunes {
		line = string(r[:maxTemplateRunes])
	}
	return line
}

func sub(re, repl string) func(string) string {
	rx := regexp.MustCompile(re)
	return func(s string) string { return rx.ReplaceAllString(s, repl) }
}

// Hex runs of 8 or more with a digit in them: chunk IDs, hashes, addresses.
// The digit keeps words like "deadbeef" and "accepted" out.
var hexRx = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{8,}\b`)

func hex(s string) string {
	return hexRx.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(strings.TrimPrefix(m, "0x"), "0123456789") {
			return "<hex>"
		}
		return m
	})
}

var templateRules = []func(string) string{
	// klog header: W1018 06:00:01.005434       1 file.go:12]
	sub(`^[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+`, ""),
	sub(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`, "<ts>"),
	sub(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`, "<ts>"),
	sub(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, "<uuid>"),
	// Pod name suffixes: <deployment>-<pod-template-hash>-<5>, <daemonset>-<5>.
	// Kubernetes' random alphabet has no vowels and no 0, 1, 3.
	sub(`-[bcdfghjklmnpqrstvwxz2456789]{8,10}-[bcdfghjklmnpqrstvwxz2456789]{5}\b`, "-<pod>"),
	sub(`-[bcdfghjklmnpqrstvwxz2456789]{5}\b`, "-<pod>"),
	// MAC before IPv6: ufw's MAC= field is 14 octets, which the IPv6 rule
	// would only half match.
	sub(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5,}\b`, "<mac>"),
	// IPv6, compressed or not. Also catches hh:mm:ss, harmless here.
	sub(`\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b`, "<ip6>"),
	sub(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`, "<ip>"),
	hex,
	sub(`\b(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+\b`, "<dur>"),
	sub(`\d+(?:\.\d+)?`, "<n>"),
	sub(`\s+`, " "),
}

// Prompt renders the digest in at most budget bytes, as long as the header and
// the per-source totals fit: those are always complete. Groups follow, most
// severe first, until the budget is spent; the rest are counted per source
// under "Not shown".
func (d *Digest) Prompt(budget int) string {
	var head strings.Builder
	fmt.Fprintf(&head, "Window: %s\n", d.Window())
	fmt.Fprintf(&head, "Lines: %d lines at WARN or worse (%s) from %d sources in %d groups.\n",
		d.Lines, levelList(d.LevelCounts()), len(d.Sources), len(d.Groups))
	if d.Truncated {
		head.WriteString("Truncated: Loki returned more lines than the cap; the end of the window is missing.\n")
	}
	fmt.Fprintf(&head, "Redacted values: %d\n", d.Redacted)
	head.WriteString("\n## Sources (lines by level)\n")
	for _, s := range d.Sources {
		fmt.Fprintf(&head, "%s: %s\n", s.Source, levelList(s.ByLevel))
	}
	head.WriteString("\n## Groups (most severe first, then most frequent)\n")

	// What stays out, per source, kept up to date as groups go in, so the
	// "Not shown" section's size is known at every step.
	type rest struct{ groups, lines int }
	left := map[string]*rest{}
	var order []string
	for _, g := range d.Groups {
		r := left[g.Source]
		if r == nil {
			r = &rest{}
			left[g.Source] = r
			order = append(order, g.Source)
		}
		r.groups++
		r.lines += g.Count
	}
	restLine := func(src string, r *rest) string {
		if r.groups == 0 {
			return ""
		}
		return fmt.Sprintf("%s: %d groups, %d lines\n", src, r.groups, r.lines)
	}
	const restHeader = "\n## Not shown (prompt budget)\n"
	restLen := 0
	for src, r := range left {
		restLen += len(restLine(src, r))
	}

	var body strings.Builder
	shown := map[string]int{}
	for _, g := range d.Groups {
		if shown[g.Source] >= MaxGroupsPerSource {
			continue
		}
		block := g.render()
		r := left[g.Source]
		after := restLen - len(restLine(g.Source, r))
		r.groups--
		r.lines -= g.Count
		after += len(restLine(g.Source, r))
		total := head.Len() + body.Len() + len(block)
		if after > 0 {
			total += len(restHeader) + after
		}
		if total > budget {
			r.groups++
			r.lines += g.Count
			break
		}
		body.WriteString(block)
		restLen = after
		shown[g.Source]++
	}

	out := head.String() + body.String()
	if restLen > 0 {
		out += restHeader
		for _, src := range order {
			out += restLine(src, left[src])
		}
	}
	return out
}

func (g *Group) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### [%s] %s ×%d (%s–%s UTC", g.Level, g.Source, g.Count,
		g.First.UTC().Format("15:04:05"), g.Last.UTC().Format("15:04:05"))
	if len(g.Pods) > 0 {
		fmt.Fprintf(&b, ", pods: %s", strings.Join(g.Pods, ", "))
	}
	b.WriteString(")\n")
	for _, s := range g.Samples {
		b.WriteString("| " + s + "\n")
	}
	return b.String()
}

// Window describes the time span, e.g. "2026-10-18 06:00 – 12:00 UTC (6h)".
func (d *Digest) Window() string {
	s, e := d.Start.UTC(), d.End.UTC()
	endFmt := "15:04"
	if s.YearDay() != e.YearDay() || s.Year() != e.Year() {
		endFmt = "2006-01-02 15:04"
	}
	dur := e.Sub(s)
	ds := dur.String()
	if dur%time.Hour == 0 {
		ds = fmt.Sprintf("%dh", int(dur.Hours()))
	}
	return fmt.Sprintf("%s – %s UTC (%s)", s.Format("2006-01-02 15:04"), e.Format(endFmt), ds)
}

func levelList(c map[string]int) string {
	levels := make([]string, 0, len(c))
	for l := range c {
		levels = append(levels, l)
	}
	sort.Slice(levels, func(i, j int) bool {
		if rank(levels[i]) != rank(levels[j]) {
			return rank(levels[i]) < rank(levels[j])
		}
		return levels[i] < levels[j]
	})
	parts := make([]string, 0, len(levels))
	for _, l := range levels {
		if c[l] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", l, c[l]))
		}
	}
	return strings.Join(parts, ", ")
}
