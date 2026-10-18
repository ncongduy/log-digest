package claude

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake writes a stand-in for the claude binary. It saves its arguments,
// stdin and environment next to itself, then behaves as FAKE_MODE says.
func fake(t *testing.T) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "claude")
	script := `#!/bin/sh
d=$(dirname "$0")
printf '%s\n' "$@" > "$d/args"
cat > "$d/stdin"
env > "$d/env"
case "$FAKE_MODE" in
ok)
  echo '{"type":"result","subtype":"success","is_error":false,"result":"*Verdict*: all good","total_cost_usd":0.012,"duration_ms":4200,"usage":{"input_tokens":100,"cache_creation_input_tokens":20,"cache_read_input_tokens":30,"output_tokens":40}}' ;;
is_error)
  echo '{"type":"result","subtype":"success","is_error":true,"result":"Claude AI usage limit reached"}' ;;
exit_json)
  echo '{"type":"result","subtype":"success","is_error":true,"result":"Invalid bearer token"}'; exit 1 ;;
exit_plain)
  echo 'boom: something broke' >&2; exit 2 ;;
max_turns)
  echo '{"type":"result","subtype":"error_max_turns","is_error":false}' ;;
slow)
  sleep 5 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAnalyzeOK(t *testing.T) {
	bin, dir := fake(t)
	t.Setenv("FAKE_MODE", "ok")
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.example/should-not-pass")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "fake-oauth")

	r := &Runner{Bin: bin, Model: "sonnet", SystemPrompt: "You are an SRE.", Timeout: 10 * time.Second}
	res, err := r.Analyze(context.Background(), "the digest")
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "*Verdict*: all good" {
		t.Errorf("Text = %q", res.Text)
	}
	if res.InputTokens != 150 || res.OutputTokens != 40 {
		t.Errorf("tokens = %d in / %d out, want 150 / 40", res.InputTokens, res.OutputTokens)
	}
	if read(t, filepath.Join(dir, "stdin")) != "the digest" {
		t.Error("digest not passed on stdin")
	}

	args := strings.Split(strings.TrimSuffix(read(t, filepath.Join(dir, "args")), "\n"), "\n")
	want := map[string]string{
		"--output-format":      "json",
		"--model":              "sonnet",
		"--system-prompt":      "You are an SRE.",
		"--tools":              "",
		"--permission-prompts": "none",
		"--max-turns":          "1",
	}
	for flag, val := range want {
		i := index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] != val {
			t.Errorf("want %s %q in %q", flag, val, args)
		}
	}
	for _, flag := range []string{"-p", "--strict-mcp-config", "--safe-mode", "--no-session-persistence"} {
		if index(args, flag) < 0 {
			t.Errorf("missing %s in %q", flag, args)
		}
	}
	// --tools takes a list: the next argument must be a flag, never text
	// it could swallow as a tool name.
	if i := index(args, "--tools"); i+2 < len(args) && !strings.HasPrefix(args[i+2], "-") {
		t.Errorf("argument after --tools \"\" is %q, want a flag", args[i+2])
	}

	env := read(t, filepath.Join(dir, "env"))
	if strings.Contains(env, "SLACK_WEBHOOK_URL") {
		t.Error("the Slack webhook leaked into claude's environment")
	}
	if !strings.Contains(env, "CLAUDE_CODE_OAUTH_TOKEN=fake-oauth") {
		t.Error("the OAuth token must reach claude")
	}
}

func TestAnalyzeErrors(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"is_error", "usage limit reached"},
		{"exit_json", "Invalid bearer token"},
		{"exit_plain", "boom: something broke"},
		{"max_turns", "error_max_turns"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			bin, _ := fake(t)
			t.Setenv("FAKE_MODE", tt.mode)
			r := &Runner{Bin: bin, Model: "sonnet", SystemPrompt: "x", Timeout: 10 * time.Second}
			_, err := r.Analyze(context.Background(), "d")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestAnalyzeTimeout(t *testing.T) {
	bin, _ := fake(t)
	t.Setenv("FAKE_MODE", "slow")
	r := &Runner{Bin: bin, Model: "sonnet", SystemPrompt: "x", Timeout: 200 * time.Millisecond}
	begin := time.Now()
	_, err := r.Analyze(context.Background(), "d")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want timed out", err)
	}
	if time.Since(begin) > 3*time.Second {
		t.Errorf("took %v; the timeout did not stop claude", time.Since(begin))
	}
}

func index(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}
