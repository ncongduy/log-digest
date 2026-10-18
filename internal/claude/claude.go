// Package claude runs the Claude Code CLI in print mode.
//
// The CLI, not the HTTP API: a Claude Pro or Max subscription authenticates
// only the unmodified claude binary (CLAUDE_CODE_OAUTH_TOKEN from
// `claude setup-token`). Calling the Messages API with that token is not
// permitted, so this package never does.
package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner runs one claude -p call per Analyze.
type Runner struct {
	Bin          string
	Model        string
	SystemPrompt string
	Timeout      time.Duration
}

// Result is claude's answer and what it cost.
type Result struct {
	Text         string
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	Duration     time.Duration
}

// Variables claude has no use for. It gets no tools, so it could not use
// them anyway; leaving them out keeps it that way if that ever changes.
var dropEnv = []string{"SLACK_WEBHOOK_URL"}

// Args returns the claude command line, without the binary.
//
// --tools "" leaves the model no tools, so a prompt injection in a log line
// can at worst bend the text of the report. --tools takes a list, so a flag
// must follow its empty value, or the next argument becomes a tool name.
// --safe-mode skips CLAUDE.md, skills, plugins, hooks and auto memory. Not
// --bare: bare mode ignores CLAUDE_CODE_OAUTH_TOKEN.
func Args(model, systemPrompt string) []string {
	return []string{
		"-p",
		"--output-format", "json",
		"--model", model,
		"--system-prompt", systemPrompt,
		"--tools", "",
		"--strict-mcp-config",
		"--safe-mode",
		"--no-session-persistence",
		"--permission-prompts", "none",
		"--max-turns", "1",
	}
}

type output struct {
	Subtype      string  `json:"subtype"`
	IsError      bool    `json:"is_error"`
	Result       string  `json:"result"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	DurationMS   int64   `json:"duration_ms"`
	Usage        struct {
		InputTokens              int `json:"input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
}

// Analyze sends prompt on stdin and returns claude's reply.
func (r *Runner) Analyze(ctx context.Context, prompt string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.Bin, Args(r.Model, r.SystemPrompt)...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = childEnv(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// After the context ends, give claude a moment, then stop waiting for
	// any child that still holds stdout.
	cmd.WaitDelay = 2 * time.Second

	runErr := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Result{}, fmt.Errorf("claude: timed out after %s", r.Timeout)
	}

	var out output
	parseErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &out)
	switch {
	case parseErr == nil && out.IsError:
		return Result{}, fmt.Errorf("claude: %s", firstLine(out.Result, out.Subtype))
	case parseErr == nil && out.Subtype != "" && out.Subtype != "success":
		return Result{}, fmt.Errorf("claude: %s", out.Subtype)
	case runErr != nil:
		return Result{}, fmt.Errorf("claude: %v: %s", runErr, firstLine(tail(stderr.String()), tail(stdout.String())))
	case parseErr != nil:
		return Result{}, fmt.Errorf("claude: unreadable output: %v: %s", parseErr, tail(stdout.String()))
	case strings.TrimSpace(out.Result) == "":
		return Result{}, errors.New("claude: empty result")
	}
	return Result{
		Text:         strings.TrimSpace(out.Result),
		InputTokens:  out.Usage.InputTokens + out.Usage.CacheCreationInputTokens + out.Usage.CacheReadInputTokens,
		OutputTokens: out.Usage.OutputTokens,
		CostUSD:      out.TotalCostUSD,
		Duration:     time.Duration(out.DurationMS) * time.Millisecond,
	}, nil
}

func childEnv(env []string) []string {
	out := make([]string, 0, len(env))
next:
	for _, kv := range env {
		for _, k := range dropEnv {
			if strings.HasPrefix(kv, k+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// firstLine returns the first non-empty line of s, or of fallback.
func firstLine(s, fallback string) string {
	for _, v := range []string{s, fallback} {
		for _, l := range strings.Split(v, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				return l
			}
		}
	}
	return "no output"
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = "…" + s[len(s)-300:]
	}
	return s
}
