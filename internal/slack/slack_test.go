package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEscape(t *testing.T) {
	got := Escape("a < b && c > d <!channel>")
	want := "a &lt; b &amp;&amp; c &gt; d &lt;!channel&gt;"
	if got != want {
		t.Errorf("Escape = %q, want %q", got, want)
	}
}

func TestSplit(t *testing.T) {
	para := strings.Repeat("word ", 100) // 500 chars
	text := strings.Join([]string{para, para, para, para, para, para, para}, "\n\n")
	chunks := Split(text, 1200)
	for i, c := range chunks {
		if n := utf8.RuneCountInString(c); n > 1200 {
			t.Errorf("chunk %d has %d runes", i, n)
		}
	}
	if got := strings.Join(chunks, "\n\n"); got != text {
		t.Error("paragraph chunks do not rejoin to the original")
	}
	if len(chunks) != 4 {
		t.Errorf("chunks = %d, want 4 (two 500-char paragraphs each)", len(chunks))
	}

	long := strings.Repeat("é", 7000)
	chunks = Split(long, 3000)
	if len(chunks) != 3 {
		t.Fatalf("hard cut: chunks = %d, want 3", len(chunks))
	}
	if strings.Join(chunks, "") != long {
		t.Error("hard-cut chunks lose text")
	}
	if Split("", 3000) != nil {
		t.Error("empty text should give no chunks")
	}
}

func TestNewMessage(t *testing.T) {
	body := strings.Repeat(strings.Repeat("x", 2900)+"\n\n", 60)
	m := NewMessage(strings.Repeat("T", 200), body, "12 lines · sonnet")
	if len(m.Blocks) > MaxBlocks {
		t.Fatalf("blocks = %d, max %d", len(m.Blocks), MaxBlocks)
	}
	if m.Blocks[0]["type"] != "header" {
		t.Errorf("first block = %v", m.Blocks[0]["type"])
	}
	h := m.Blocks[0]["text"].(map[string]any)["text"].(string)
	if utf8.RuneCountInString(h) > 150 {
		t.Errorf("header is %d runes", utf8.RuneCountInString(h))
	}
	last := m.Blocks[len(m.Blocks)-1]
	if last["type"] != "context" {
		t.Errorf("last block = %v, want context footer", last["type"])
	}
	beforeLast := m.Blocks[len(m.Blocks)-2]["text"].(map[string]any)["text"].(string)
	if !strings.HasSuffix(beforeLast, "_(truncated)_") {
		t.Errorf("an overlong report must say it was truncated")
	}
	if m.Text == "" {
		t.Error("no notification text")
	}
}

func TestPost(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	if err := Post(context.Background(), srv.URL, NewMessage("t", "body", "f")); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "t" || len(got["blocks"].([]any)) != 3 {
		t.Errorf("payload = %v", got)
	}
}

func TestPostErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid_blocks", http.StatusBadRequest)
	}))
	err := Post(context.Background(), srv.URL+"/services/T0/B0/SECRETPART", NewMessage("t", "b", "f"))
	if err == nil || !strings.Contains(err.Error(), "invalid_blocks") {
		t.Errorf("err = %v, want Slack's reason", err)
	}
	srv.Close()

	// Nothing listening: the transport error must not carry the URL, which
	// is the credential.
	err = Post(context.Background(), srv.URL+"/services/T0/B0/SECRETPART", NewMessage("t", "b", "f"))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "SECRETPART") {
		t.Errorf("webhook URL leaked into the error: %v", err)
	}
}
