// Package sanitize redacts credentials and email addresses from log lines
// before they leave the cluster.
//
// Rules run in order, most specific first, so a token that has a known shape
// is named in its placeholder ([REDACTED:github-token]) before the generic
// key=value and blob rules see it. Over-redaction is the accepted failure
// mode: a lost value costs a little context, a leaked one costs a rotation.
package sanitize

import (
	"regexp"
	"strings"
)

const marker = "[REDACTED"

type rule struct {
	name  string
	apply func(string) (string, int)
}

// Sanitizer redacts lines and counts what each rule replaced. Not safe for
// concurrent use.
type Sanitizer struct {
	rules  []rule
	counts map[string]int
}

// New returns a Sanitizer with the full rule set.
func New() *Sanitizer {
	return &Sanitizer{rules: rules, counts: map[string]int{}}
}

// Line returns line with every match replaced by a placeholder.
func (s *Sanitizer) Line(line string) string {
	for _, r := range s.rules {
		var n int
		line, n = r.apply(line)
		if n > 0 {
			s.counts[r.name] += n
		}
	}
	return line
}

// Counts returns the number of replacements per rule name.
func (s *Sanitizer) Counts() map[string]int { return s.counts }

// Total returns the number of replacements across all rules.
func (s *Sanitizer) Total() int {
	t := 0
	for _, n := range s.counts {
		t += n
	}
	return t
}

// replace builds a rule that substitutes every match of re with repl, which
// may reference groups ($1).
func replace(name, re, repl string) rule {
	rx := regexp.MustCompile(re)
	return rule{name, func(s string) (string, int) {
		n := len(rx.FindAllStringIndex(s, -1))
		if n == 0 {
			return s, 0
		}
		return rx.ReplaceAllString(s, repl), n
	}}
}

// Key names whose value is a credential. Long cores may follow any prefix
// (accessToken, DB_PASSWORD); short ones must be a whole segment, so that
// bypass=, passed= and author= survive.
const (
	longCore  = `password|passwd|passphrase|secret|token|apikey|api[_-]key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|signature|cookie|session[_-]?id`
	shortCore = `pass|pwd|sig|auth|authorization|session`
	keyRe     = `\b(?:[a-z0-9]+[_.-])*(?:[a-z0-9]*(?:` + longCore + `)|(?:` + shortCore + `))(?:[_.-][a-z0-9]+)*`
)

var kvRx = regexp.MustCompile(`(?i)(` + keyRe + `["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&"'}\]]+)`)

// An auth scheme left in front of a value the bearer rule already redacted.
var schemeRx = regexp.MustCompile(`(?i)^(?:bearer|basic|digest|token)$`)

func keyValue(s string) (string, int) {
	idx := kvRx.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, m := range idx {
		vs, ve := m[4], m[5]
		val := s[vs:ve]
		inner := val
		quote := ""
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') {
			quote, inner = val[:1], val[1:len(val)-1]
		}
		if inner == "" || strings.HasPrefix(inner, marker) || schemeRx.MatchString(inner) {
			continue
		}
		b.WriteString(s[last:vs])
		b.WriteString(quote + marker + "]" + quote)
		last = ve
		n++
	}
	b.WriteString(s[last:])
	return b.String(), n
}

// Long runs of base64-ish characters with upper case, lower case and digits
// mixed: keys, app passwords, session blobs. Kubernetes names, paths and
// UUIDs lack upper case and survive.
var blobRx = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)

func blob(s string) (string, int) {
	n := 0
	out := blobRx.ReplaceAllStringFunc(s, func(m string) string {
		var up, lo, dig int
		for _, c := range m {
			switch {
			case c >= 'A' && c <= 'Z':
				up++
			case c >= 'a' && c <= 'z':
				lo++
			case c >= '0' && c <= '9':
				dig++
			}
		}
		if up < 2 || lo < 2 || dig < 2 {
			return m
		}
		n++
		return marker + ":blob]"
	})
	return out, n
}

var rules = []rule{
	replace("private-key", `-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z ]*PRIVATE KEY-----|$)`, marker+":private-key]"),
	replace("cookie", `(?i)(\b(?:set-)?cookie:\s*)\S.*`, "${1}"+marker+"]"),
	replace("bearer", `(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`, "$1 "+marker+"]"),
	replace("jwt", `\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`, marker+":jwt]"),
	replace("slack-webhook", `https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+`, "https://hooks.slack.com/"+marker+"]"),
	replace("slack-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}`, marker+":slack-token]"),
	replace("github-token", `\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`, marker+":github-token]"),
	replace("api-key", `\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`, marker+":api-key]"),
	replace("aws-key", `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, marker+":aws-key]"),
	replace("garage-key", `\bGK[0-9a-f]{24}\b`, marker+":garage-key]"),
	replace("tailscale-key", `\btskey-[A-Za-z0-9-]{10,}`, marker+":tailscale-key]"),
	replace("url-userinfo", `([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+):[^\s@/]+@`, "$1:"+marker+"]@"),
	{"key-value", keyValue},
	replace("hex", `\b[0-9a-fA-F]{40,}\b`, marker+":hex]"),
	{"blob", blob},
	replace("email", `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, "[EMAIL]"),
}
