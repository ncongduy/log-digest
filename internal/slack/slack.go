// Package slack posts a report to an incoming webhook as Block Kit.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Slack's limits: 50 blocks a message, 150 characters a header, 3000 a
// section.
const (
	MaxBlocks  = 50
	maxHeader  = 150
	maxSection = 3000
	truncNote  = "\n_(truncated)_"
)

// Block is one Block Kit block.
type Block map[string]any

// Message is an incoming-webhook payload. Text is the notification and the
// fallback for clients that cannot show blocks.
type Message struct {
	Text   string  `json:"text"`
	Blocks []Block `json:"blocks"`
}

// Escape makes text safe for mrkdwn: no links, no <!channel> mentions, which
// a log line repeated by the model could otherwise smuggle in.
func Escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// NewMessage builds header, sections and a context footer. body is mrkdwn,
// already escaped; title and footer are plain.
func NewMessage(title, body, footer string) Message {
	blocks := []Block{{
		"type": "header",
		"text": map[string]any{"type": "plain_text", "text": cut(title, maxHeader), "emoji": true},
	}}
	room := MaxBlocks - 2
	chunks := Split(body, maxSection-len(truncNote))
	if len(chunks) > room {
		chunks = chunks[:room]
		chunks[room-1] += truncNote
	}
	for _, c := range chunks {
		blocks = append(blocks, Block{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": c}})
	}
	blocks = append(blocks, Block{
		"type":     "context",
		"elements": []any{map[string]any{"type": "mrkdwn", "text": cut(Escape(footer), maxSection)}},
	})
	return Message{Text: title, Blocks: blocks}
}

// Split cuts text into chunks of at most max runes: at blank lines when it
// can, at line ends when a paragraph is too long, mid-line as a last resort.
func Split(text string, max int) []string {
	if text == "" {
		return nil
	}
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	add := func(piece, sep string) {
		switch {
		case cur == "":
			cur = piece
		case utf8.RuneCountInString(cur)+utf8.RuneCountInString(sep)+utf8.RuneCountInString(piece) <= max:
			cur += sep + piece
		default:
			flush()
			cur = piece
		}
	}
	for _, para := range strings.Split(text, "\n\n") {
		if utf8.RuneCountInString(para) <= max {
			add(para, "\n\n")
			continue
		}
		flush()
		for _, line := range strings.Split(para, "\n") {
			for utf8.RuneCountInString(line) > max {
				r := []rune(line)
				flush()
				out = append(out, string(r[:max]))
				line = string(r[max:])
			}
			add(line, "\n")
		}
		flush()
	}
	flush()
	return out
}

func cut(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// Post sends m to the webhook. Errors never contain the URL: it is the
// credential.
func Post(ctx context.Context, webhook string, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return errors.New("slack: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("slack: %v", err)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: %s: %s", resp.Status, strings.TrimSpace(string(reply)))
	}
	return nil
}
