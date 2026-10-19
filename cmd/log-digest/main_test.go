package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixture = "../../testdata/loki.json"

// 12:30 UTC. The fixture fills 06:00–12:00, so the --input tests pass
// --window 6h.
var now = time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)

func fixtureSecrets(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func assertNoSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range fixtureSecrets(t) {
		if strings.Contains(text, s) {
			t.Errorf("%s contains the secret %q", where, s)
		}
	}
}

// fakeClaude records its stdin and answers as FAKE_MODE says.
func fakeClaude(t *testing.T) (bin, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "claude")
	stdinFile = filepath.Join(dir, "stdin")
	script := `#!/bin/sh
cat > "` + stdinFile + `"
case "$FAKE_MODE" in
ok) echo '{"type":"result","subtype":"success","is_error":false,"result":"*Verdict*: flashcard cannot reach <its> database.","usage":{"input_tokens":1200,"output_tokens":300}}' ;;
fail) echo '{"type":"result","subtype":"success","is_error":true,"result":"Claude AI usage limit reached"}'; exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, stdinFile
}

func fakeSlack(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posts = append(posts, string(b))
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

func TestDryRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--dry-run", "--input", fixture, "--window", "6h"}, &stdout, &stderr, now)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	p := stdout.String()
	for _, want := range []string{
		"Window: 2026-10-18 06:00 – 12:00 UTC (6h)",
		"[critical] node rke2-agent-01 kernel",
		"[error] pod flashcard/web ×2",
		"[warn] pod monitoring/loki ×3",
		"Redacted values: 6",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
	assertNoSecrets(t, "dry-run prompt", p)
	assertNoSecrets(t, "logs", stderr.String())
}

func TestRunPostsReport(t *testing.T) {
	bin, stdinFile := fakeClaude(t)
	srv, posts := fakeSlack(t)
	t.Setenv("FAKE_MODE", "ok")
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)
	t.Setenv("DIGEST_CONTEXT", "RKE2 homelab, four nodes.")

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--input", fixture, "--window", "6h", "--claude-bin", bin}, &stdout, &stderr, now)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(*posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(*posts))
	}
	post := (*posts)[0]
	var msg struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(post), &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(msg.Text, "Log digest · 2026-10-18 06:00 – 12:00 UTC") {
		t.Errorf("title = %q", msg.Text)
	}
	if blocks := fmt.Sprint(msg.Blocks); !strings.Contains(blocks, "flashcard cannot reach &lt;its&gt; database") {
		t.Errorf("report missing or not escaped: %s", blocks)
	}
	for _, want := range []string{"12 lines", "9 sources", "6 values redacted", "sonnet", "1.2k in"} {
		if !strings.Contains(post, want) {
			t.Errorf("footer lacks %q: %s", want, post)
		}
	}
	sent, _ := os.ReadFile(stdinFile)
	if !strings.Contains(string(sent), "[error] pod flashcard/web") {
		t.Errorf("claude did not get the digest: %s", sent)
	}
	assertNoSecrets(t, "claude's stdin", string(sent))
	assertNoSecrets(t, "Slack post", post)
	assertNoSecrets(t, "logs", stderr.String())
}

func TestRunFallsBackWhenClaudeFails(t *testing.T) {
	bin, _ := fakeClaude(t)
	srv, posts := fakeSlack(t)
	t.Setenv("FAKE_MODE", "fail")
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--input", fixture, "--window", "6h", "--claude-bin", bin}, &stdout, &stderr, now)
	if code != 0 {
		t.Fatalf("exit %d, want 0: the fallback post is the signal", code)
	}
	if len(*posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(*posts))
	}
	post := (*posts)[0]
	for _, want := range []string{"Claude unavailable", "usage limit reached", "pod flashcard/web"} {
		if !strings.Contains(post, want) {
			t.Errorf("fallback lacks %q: %s", want, post)
		}
	}
	assertNoSecrets(t, "fallback post", post)
	if !strings.Contains(stderr.String(), "level=ERROR") {
		t.Errorf("the failure must be logged at ERROR: %s", stderr.String())
	}
}

func TestRunQuietWindow(t *testing.T) {
	srv, posts := fakeSlack(t)
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"success","data":{"resultType":"streams","result":[]}}`)
	}))
	defer loki.Close()
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	// No claude binary at all: a quiet window must not need it.
	code := run(context.Background(), []string{"--loki-url", loki.URL, "--claude-bin", "/nonexistent"}, &stdout, &stderr, now)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(*posts) != 1 || !strings.Contains((*posts)[0], "No WARN or worse lines") {
		t.Errorf("posts = %q", *posts)
	}
}

func TestRunWindowEndsAtTheMinute(t *testing.T) {
	srv, posts := fakeSlack(t)
	var queries []url.Values
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query())
		io.WriteString(w, `{"status":"success","data":{"resultType":"streams","result":[]}}`)
	}))
	defer loki.Close()
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)
	t.Setenv("WINDOW", "")

	// Run by hand at 12:30:45, the default window is 12:20–12:30.
	at := time.Date(2026, 10, 18, 12, 30, 45, 0, time.UTC)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--loki-url", loki.URL}, &stdout, &stderr, at)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	wantStart := fmt.Sprint(time.Date(2026, 10, 18, 12, 20, 0, 0, time.UTC).UnixNano())
	wantEnd := fmt.Sprint(time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC).UnixNano())
	if len(queries) == 0 {
		t.Fatal("Loki was not queried")
	}
	for _, q := range queries {
		if q.Get("start") != wantStart || q.Get("end") != wantEnd {
			t.Errorf("query %q: start=%s end=%s, want %s and %s", q.Get("query"), q.Get("start"), q.Get("end"), wantStart, wantEnd)
		}
	}
	if len(*posts) != 1 || !strings.Contains((*posts)[0], "2026-10-18 12:20 – 12:30 UTC (10m)") {
		t.Errorf("posts = %q", *posts)
	}
}

func TestRunLokiDown(t *testing.T) {
	srv, posts := fakeSlack(t)
	t.Setenv("SLACK_WEBHOOK_URL", srv.URL)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--loki-url", "http://127.0.0.1:1"}, &stdout, &stderr, now)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if len(*posts) != 0 {
		t.Errorf("nothing should be posted when Loki is down")
	}
}

func TestRunNeedsWebhook(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--input", fixture}, &stdout, &stderr, now); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}
