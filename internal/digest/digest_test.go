package digest

import (
	"fmt"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"
)

var (
	t0    = time.Date(2026, 10, 18, 6, 0, 0, 0, time.UTC)
	start = t0
	end   = t0.Add(6 * time.Hour)
)

func pod(ns, container, podName, level, line string, at time.Duration) Entry {
	return Entry{
		Time:   t0.Add(at),
		Labels: map[string]string{"namespace": ns, "container": container, "pod": podName, "level": level},
		Line:   line,
	}
}

func journal(node, unit, level, line string, at time.Duration) Entry {
	return Entry{
		Time:   t0.Add(at),
		Labels: map[string]string{"job": "journal", "node": node, "unit": unit, "level": level},
		Line:   line,
	}
}

func TestTemplate(t *testing.T) {
	same := [][2]string{
		{
			`2026-10-18T06:00:01.123Z level=warn msg="retrying" attempt=3 after=1.5s`,
			`2026-10-18T07:12:44.9Z level=warn msg="retrying" attempt=11 after=250ms`,
		},
		{
			`W1018 06:00:01.005434       1 reflector.go:561] dial tcp 10.43.0.1:443: i/o timeout`,
			`W1018 09:41:22.115000       1 reflector.go:561] dial tcp 10.43.0.9:443: i/o timeout`,
		},
		{
			`volume pvc-0d3f2a64-9b1c-4d6e-8f00-123456789abc degraded`,
			`volume pvc-11111111-2222-4333-8444-555555555555 degraded`,
		},
		{
			`pod monitoring/grafana-7d9f8b6c5-x7k2p not ready`,
			`pod monitoring/grafana-6c8d7f9b4-q2w8z not ready`,
		},
		{
			`[UFW BLOCK] IN=enp0s31f6 OUT= MAC=01:00:5e:00:00:01:a4:91:b1:2c:3d:4e:08:00 SRC=192.168.0.1 DST=224.0.0.1 LEN=36 TTL=1 PROTO=UDP`,
			`[UFW BLOCK] IN=enp0s31f6 OUT= MAC=ff:ff:ff:ff:ff:ff:bc:de:f0:12:34:56:08:00 SRC=192.168.0.27 DST=239.255.255.250 LEN=200 TTL=4 PROTO=UDP`,
		},
		{
			`[UFW BLOCK] SRC=fe80:0000:0000:0000:1234:abcd:ef01:2345 DST=ff02:0000:0000:0000:0000:0000:0000:00fb PROTO=UDP`,
			`[UFW BLOCK] SRC=fe80::a1b2:c3d4 DST=ff02::fb PROTO=UDP`,
		},
		{
			`chunk 0xdeadbeef01 flushed`,
			`chunk 0xcafebabe99 flushed`,
		},
	}
	for _, p := range same {
		if a, b := Template(p[0]), Template(p[1]); a != b {
			t.Errorf("want same template:\n %s\n %s\ngot:\n %s\n %s", p[0], p[1], a, b)
		}
	}
	if a, b := Template("disk full on /var"), Template("disk slow on /var"); a == b {
		t.Errorf("different text gave the same template %q", a)
	}
}

func TestBuildGroups(t *testing.T) {
	entries := []Entry{
		pod("monitoring", "loki", "loki-0", "warn", "level=warn msg=\"slow query\" took=3s", 1*time.Minute),
		pod("monitoring", "loki", "loki-0", "warn", "level=warn msg=\"slow query\" took=7s", 2*time.Hour),
		pod("monitoring", "loki", "loki-0", "warn", "level=warn msg=\"slow query\" took=9s", 3*time.Hour),
		pod("monitoring", "loki", "loki-0", "warn", "level=warn msg=\"slow query\" took=9s", 4*time.Hour),
		pod("monitoring", "loki", "loki-0", "warn", "level=warn msg=\"slow query\" took=1s", 5*time.Hour),
		pod("monitoring", "loki", "loki-0", "error", "level=error msg=\"flush failed\"", 10*time.Minute),
		journal("rke2-worker-01", "garage.service", "critical", "PANIC disk gone", 30*time.Minute),
	}
	d := Build(entries, start, end)

	if d.Lines != 7 {
		t.Errorf("Lines = %d, want 7", d.Lines)
	}
	if len(d.Groups) != 3 {
		t.Fatalf("groups = %d, want 3: %+v", len(d.Groups), d.Groups)
	}
	// Most severe first, then most frequent.
	order := []string{"critical", "error", "warn"}
	for i, g := range d.Groups {
		if g.Level != order[i] {
			t.Errorf("group %d level = %s, want %s", i, g.Level, order[i])
		}
	}
	if g := d.Groups[0]; g.Source != "node rke2-worker-01 garage.service" {
		t.Errorf("journal source = %q", g.Source)
	}
	w := d.Groups[2]
	if w.Source != "pod monitoring/loki" || w.Count != 5 {
		t.Errorf("warn group = %q ×%d, want pod monitoring/loki ×5", w.Source, w.Count)
	}
	if !w.First.Equal(t0.Add(time.Minute)) || !w.Last.Equal(t0.Add(5*time.Hour)) {
		t.Errorf("first/last = %v / %v", w.First, w.Last)
	}
	if len(w.Samples) != MaxSamples {
		t.Errorf("samples = %d, want %d (distinct only): %q", len(w.Samples), MaxSamples, w.Samples)
	}
	if len(w.Pods) != 1 || w.Pods[0] != "loki-0" {
		t.Errorf("pods = %q", w.Pods)
	}

	if len(d.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(d.Sources))
	}
	if s := d.Sources[0]; s.Source != "node rke2-worker-01 garage.service" || s.ByLevel["critical"] != 1 {
		t.Errorf("first source = %+v", s)
	}
	if s := d.Sources[1]; s.Total != 6 || s.ByLevel["warn"] != 5 || s.ByLevel["error"] != 1 {
		t.Errorf("loki source = %+v", s)
	}
	lc := d.LevelCounts()
	if lc["critical"] != 1 || lc["error"] != 1 || lc["warn"] != 5 {
		t.Errorf("LevelCounts = %v", lc)
	}
}

func TestSampleTruncated(t *testing.T) {
	long := strings.Repeat("é", MaxSampleRunes+50)
	d := Build([]Entry{pod("a", "b", "c", "warn", long, 0)}, start, end)
	s := d.Groups[0].Samples[0]
	if n := len([]rune(s)); n != MaxSampleRunes+1 { // + the ellipsis
		t.Errorf("sample runes = %d, want %d", n, MaxSampleRunes+1)
	}
}

func TestPrompt(t *testing.T) {
	entries := []Entry{
		pod("monitoring", "loki", "loki-0", "error", "flush failed: disk full", time.Minute),
		journal("rke2-server-02", "rke2-server.service", "warn", "etcd slow apply took 210ms", time.Hour),
	}
	d := Build(entries, start, end)
	d.Redacted = 4
	p := d.Prompt(60_000)
	for _, want := range []string{
		"2026-10-18 06:00 – 12:00 UTC (6h)",
		"2 lines",
		"error 1, warn 1",
		"Redacted values: 4",
		"pod monitoring/loki",
		"node rke2-server-02 rke2-server.service",
		"| flush failed: disk full",
		"| etcd slow apply took 210ms",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "Not shown") {
		t.Errorf("nothing should be cut at this budget:\n%s", p)
	}
}

func TestPromptBudget(t *testing.T) {
	var entries []Entry
	for i := range 200 {
		entries = append(entries, pod("ns", fmt.Sprintf("c%03d", i), "p", "warn",
			fmt.Sprintf("distinct failure kind %s %s", strings.Repeat("x", i%7+1), strings.Repeat("y", 200)), 0))
	}
	d := Build(entries, start, end)
	full := d.Prompt(1 << 30)
	budget := len(full) / 3
	p := d.Prompt(budget)
	if len(p) > budget {
		t.Errorf("prompt is %d bytes, budget %d", len(p), budget)
	}
	if !strings.Contains(p, "Not shown") {
		t.Errorf("cut groups must be listed under Not shown")
	}
	// Every source keeps its total, even when its groups are cut.
	if !strings.Contains(p, "pod ns/c199") {
		t.Errorf("source totals must survive the budget")
	}
}

func TestTop(t *testing.T) {
	var entries []Entry
	for i := range 5 {
		entries = append(entries, pod("ns", fmt.Sprintf("c%d", i), "p", "warn", fmt.Sprintf("kind %c", 'a'+i), 0))
	}
	d := Build(entries, start, end)
	if got := len(d.Top(3)); got != 3 {
		t.Errorf("Top(3) = %d groups", got)
	}
	if got := len(d.Top(10)); got != 5 {
		t.Errorf("Top(10) = %d groups", got)
	}
}

func TestWindow(t *testing.T) {
	for _, c := range []struct {
		start, end time.Time
		want       string
	}{
		{start, end, "2026-10-18 06:00 – 12:00 UTC (6h)"},
		{t0.Add(14 * time.Minute), t0.Add(24 * time.Minute), "2026-10-18 06:14 – 06:24 UTC (10m)"},
		{t0.Add(-90 * time.Minute), t0, "2026-10-18 04:30 – 06:00 UTC (1h30m)"},
		{t0.Add(-7 * time.Hour), t0, "2026-10-17 23:00 – 2026-10-18 06:00 UTC (7h)"},
	} {
		d := Build(nil, c.start, c.end)
		if got := d.Window(); got != c.want {
			t.Errorf("Window() = %q, want %q", got, c.want)
		}
	}
}

func TestWindowInLocation(t *testing.T) {
	helsinki, err := time.LoadLocation("Europe/Helsinki")
	if err != nil {
		t.Fatal(err)
	}
	// Helsinki falls back from EEST to EET at 01:00 UTC on 2026-10-25.
	fallBack := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		start, end time.Time
		want       string
	}{
		{t0.Add(14 * time.Minute), t0.Add(24 * time.Minute), "2026-10-18 09:14 – 09:24 EEST (10m)"},
		{fallBack.Add(-5 * time.Minute), fallBack.Add(5 * time.Minute), "2026-10-25 03:55 EEST – 03:05 EET (10m)"},
	} {
		d := Build(nil, c.start, c.end)
		d.Loc = helsinki
		if got := d.Window(); got != c.want {
			t.Errorf("Window() = %q, want %q", got, c.want)
		}
	}
}

func TestPromptInLocation(t *testing.T) {
	helsinki, err := time.LoadLocation("Europe/Helsinki")
	if err != nil {
		t.Fatal(err)
	}
	d := Build([]Entry{
		pod("monitoring", "loki", "loki-0", "error", "flush failed: disk full", time.Minute),
		pod("monitoring", "loki", "loki-0", "error", "flush failed: disk full", 2*time.Hour),
	}, start, end)
	d.Loc = helsinki
	p := d.Prompt(60_000)
	for _, want := range []string{
		"Window: 2026-10-18 09:00 – 15:00 EEST (6h)",
		"pod monitoring/loki ×2 (09:01:00–11:00:00 EEST",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
}
