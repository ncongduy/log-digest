// Command log-digest reads the last window of WARN-and-worse lines from Loki,
// redacts secrets, has Claude analyse them through the Claude Code CLI, and
// posts the report to Slack.
//
// Exit status: 0 when a report was posted (a fallback without Claude's
// analysis included), 1 when Loki or Slack failed, 2 on bad configuration.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ncongduy/log-digest/internal/claude"
	"github.com/ncongduy/log-digest/internal/digest"
	"github.com/ncongduy/log-digest/internal/loki"
	"github.com/ncongduy/log-digest/internal/sanitize"
	"github.com/ncongduy/log-digest/internal/slack"
)

//go:embed system.md
var systemPrompt string

// version is set at build time: -ldflags "-X main.version=…".
var version = "dev"

// The same selectors as the log alerts (loki-rules-homelab.yaml in
// k8s-homelab), so the digest and the alerts count the same lines.
const (
	podQuery     = `{namespace=~".+", level=~"warn|error|critical"}`
	journalQuery = `{job="journal", level=~"warn|error|critical"}`
)

const fallbackGroups = 10

type config struct {
	lokiURL       string
	window        time.Duration
	maxLines      int
	budget        int
	claudeBin     string
	model         string
	claudeTimeout time.Duration
	dryRun        bool
	input         string
	// From the environment only: a flag would show in the process list.
	webhook string
	context string
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, now time.Time) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		log.Error("bad configuration", "err", err)
		return 2
	}
	if cfg == nil { // --version
		fmt.Fprintln(stdout, version)
		return 0
	}

	// The window ends at the minute the run started: a run started by hand
	// right after a change reads the last WINDOW of lines, up to now.
	end := now.UTC().Truncate(time.Minute)
	start := end.Add(-cfg.window)

	var entries []digest.Entry
	var truncated bool
	if cfg.input != "" {
		entries, err = readInput(cfg.input)
		if err != nil {
			log.Error("read input", "err", err)
			return 1
		}
		if len(entries) > 0 {
			start = entries[0].Time.Truncate(time.Hour)
			end = start.Add(cfg.window)
		}
	} else {
		entries, truncated, err = fetch(ctx, cfg, start, end)
		if err != nil {
			log.Error("fetch from Loki", "err", err)
			return 1
		}
	}

	san := sanitize.New()
	for i := range entries {
		entries[i].Line = san.Line(entries[i].Line)
	}
	d := digest.Build(entries, start, end)
	d.Truncated = truncated
	d.Redacted = san.Total()
	prompt := d.Prompt(cfg.budget)
	log.Info("digest built", "window", d.Window(), "lines", d.Lines, "sources", len(d.Sources),
		"groups", len(d.Groups), "redacted", d.Redacted, "truncated", truncated, "prompt_bytes", len(prompt))

	if cfg.dryRun {
		fmt.Fprint(stdout, prompt)
		return 0
	}

	title := "Log digest · " + d.Window()
	var body, usage string
	if d.Lines == 0 {
		body = ":large_green_circle: No WARN or worse lines in this window."
	} else {
		r := &claude.Runner{
			Bin:          cfg.claudeBin,
			Model:        cfg.model,
			SystemPrompt: system(cfg.context),
			Timeout:      cfg.claudeTimeout,
		}
		res, err := r.Analyze(ctx, prompt)
		if err != nil {
			log.Error("claude failed; posting the digest without analysis", "err", err)
			body = fallback(d, err)
		} else {
			log.Info("claude answered", "input_tokens", res.InputTokens, "output_tokens", res.OutputTokens,
				"duration", res.Duration)
			body = slack.Escape(res.Text)
			usage = fmt.Sprintf("%s in / %s out tokens", kilo(res.InputTokens), kilo(res.OutputTokens))
		}
	}

	if err := slack.Post(ctx, cfg.webhook, slack.NewMessage(title, body, footer(d, cfg.model, usage))); err != nil {
		log.Error("post to Slack", "err", err)
		return 1
	}
	log.Info("report posted")
	return 0
}

func parse(args []string, stderr io.Writer) (*config, error) {
	fs := flag.NewFlagSet("log-digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := &config{}
	fs.StringVar(&cfg.lokiURL, "loki-url", env("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100"), "Loki base URL (LOKI_URL)")
	fs.DurationVar(&cfg.window, "window", envDuration("WINDOW", 10*time.Minute), "how far back to read (WINDOW)")
	fs.IntVar(&cfg.maxLines, "max-lines", envInt("MAX_LINES", 50_000), "most lines to read from Loki (MAX_LINES)")
	fs.IntVar(&cfg.budget, "prompt-budget", envInt("PROMPT_BUDGET", 60_000), "most bytes of digest sent to Claude (PROMPT_BUDGET)")
	fs.StringVar(&cfg.claudeBin, "claude-bin", env("CLAUDE_BIN", "claude"), "Claude Code CLI (CLAUDE_BIN)")
	fs.StringVar(&cfg.model, "model", env("CLAUDE_MODEL", "sonnet"), "model alias or ID (CLAUDE_MODEL)")
	fs.DurationVar(&cfg.claudeTimeout, "claude-timeout", envDuration("CLAUDE_TIMEOUT", 20*time.Minute), "longest wait for Claude (CLAUDE_TIMEOUT)")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "print the prompt; call neither Claude nor Slack")
	fs.StringVar(&cfg.input, "input", "", "read a saved Loki query_range response instead of querying Loki")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *showVersion {
		return nil, nil
	}
	cfg.webhook = os.Getenv("SLACK_WEBHOOK_URL")
	cfg.context = strings.TrimSpace(os.Getenv("DIGEST_CONTEXT"))
	switch {
	case cfg.window <= 0:
		return nil, errors.New("window must be positive")
	case cfg.maxLines <= 0 || cfg.budget <= 0:
		return nil, errors.New("max-lines and prompt-budget must be positive")
	case !cfg.dryRun && cfg.webhook == "":
		return nil, errors.New("SLACK_WEBHOOK_URL is not set")
	}
	return cfg, nil
}

// fetch reads the journal first, then pods with what is left of the line
// cap: a flood of pod warnings must not hide a node's.
func fetch(ctx context.Context, cfg *config, start, end time.Time) ([]digest.Entry, bool, error) {
	c := &loki.Client{BaseURL: cfg.lokiURL}
	nodes, tn, err := c.Fetch(ctx, journalQuery, start, end, cfg.maxLines/2)
	if err != nil {
		return nil, false, err
	}
	pods, tp, err := c.Fetch(ctx, podQuery, start, end, cfg.maxLines-len(nodes))
	if err != nil {
		return nil, false, err
	}
	return append(nodes, pods...), tn || tp, nil
}

func readInput(path string) ([]digest.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return loki.Parse(f)
}

func system(clusterContext string) string {
	if clusterContext == "" {
		return systemPrompt
	}
	return systemPrompt + "\nAbout this cluster:\n" + clusterContext + "\n"
}

// fallback is the report when Claude could not write one: the reason, then
// the most severe groups as they are.
func fallback(d *digest.Digest, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, ":warning: *Claude unavailable:* %s\n\nTop groups, not analysed:\n", slack.Escape(err.Error()))
	for _, g := range d.Top(fallbackGroups) {
		sample := ""
		if len(g.Samples) > 0 {
			sample = g.Samples[0]
			if r := []rune(sample); len(r) > 200 {
				sample = string(r[:200]) + "…"
			}
			sample = " — `" + slack.Escape(strings.ReplaceAll(sample, "`", "'")) + "`"
		}
		fmt.Fprintf(&b, "• *[%s]* `%s` ×%d%s\n", g.Level, slack.Escape(g.Source), g.Count, sample)
	}
	if n := len(d.Groups) - fallbackGroups; n > 0 {
		fmt.Fprintf(&b, "…and %d more groups.\n", n)
	}
	return b.String()
}

func footer(d *digest.Digest, model, usage string) string {
	parts := []string{
		fmt.Sprintf("%d lines", d.Lines),
		fmt.Sprintf("%d sources", len(d.Sources)),
		fmt.Sprintf("%d groups", len(d.Groups)),
		fmt.Sprintf("%d values redacted", d.Redacted),
	}
	if d.Truncated {
		parts = append(parts, "truncated: the line cap was hit")
	}
	if usage != "" {
		parts = append(parts, model, usage)
	}
	return strings.Join(parts, " · ")
}

func kilo(n int) string {
	if n < 1000 {
		return strconv.Itoa(n)
	}
	return fmt.Sprintf("%.1fk", float64(n)/1000)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
