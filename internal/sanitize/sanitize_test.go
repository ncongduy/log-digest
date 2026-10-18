package sanitize

import (
	"strings"
	"testing"
)

// Fake secrets are assembled at run time so the repository never contains a
// string a secret scanner would flag.
var (
	fakeGitHub    = "gh" + "p_" + strings.Repeat("A1b2", 9)
	fakeGitHubPAT = "github" + "_pat_" + strings.Repeat("Z9y8", 10)
	fakeSlackHook = "https://hooks.slack.com/" + "services/T0000/B0000/" + strings.Repeat("x", 24)
	fakeSlackTok  = "xox" + "b-" + "1234567890-" + strings.Repeat("a", 24)
	fakeAnthropic = "sk-" + "ant-" + "oat01-" + strings.Repeat("Q", 40)
	fakeAWS       = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGarage    = "GK" + strings.Repeat("0a", 12)
	fakeTailscale = "tskey-" + "auth-" + strings.Repeat("k", 20)
	fakeJWT       = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0In0" + ".c2lnbmF0dXJlMTIz"
	fakeBlob      = "Ab3" + strings.Repeat("xY7z", 10)
	fakeHex       = strings.Repeat("deadbeef", 8)
	fakePEM       = "-----BEGIN RSA " + "PRIVATE KEY-----MIIEow" + strings.Repeat("A", 30) + "-----END RSA PRIVATE KEY-----"
)

func TestLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"pem block", "key: " + fakePEM + " done", "key: [REDACTED:private-key] done"},
		{"pem without end", "loaded " + fakePEM[:40], "loaded [REDACTED:private-key]"},
		{"cookie header", "req Cookie: sid=abc; theme=dark", "req Cookie: [REDACTED]"},
		{"set-cookie header", "Set-Cookie: oc_sessionPassphrase=xyz; path=/", "Set-Cookie: [REDACTED]"},
		{"bearer", "Authorization: Bearer abcdefghijkl.mnop", "Authorization: Bearer [REDACTED]"},
		{"basic", "header authorization: Basic dXNlcjpwYXNz", "header authorization: Basic [REDACTED]"},
		{"jwt", "token was " + fakeJWT + " for user", "token was [REDACTED:jwt] for user"},
		{"slack webhook", "posting to " + fakeSlackHook, "posting to https://hooks.slack.com/[REDACTED]"},
		{"slack token", "auth with " + fakeSlackTok + " ok", "auth with [REDACTED:slack-token] ok"},
		{"github token", "clone " + fakeGitHub + " ok", "clone [REDACTED:github-token] ok"},
		{"github pat", "pat " + fakeGitHubPAT, "pat [REDACTED:github-token]"},
		{"anthropic key", "using " + fakeAnthropic, "using [REDACTED:api-key]"},
		{"aws key", "id " + fakeAWS + " denied", "id [REDACTED:aws-key] denied"},
		{"garage key", "key " + fakeGarage + " not found", "key [REDACTED:garage-key] not found"},
		{"tailscale key", "login " + fakeTailscale, "login [REDACTED:tailscale-key]"},
		{"url userinfo", "dial postgres://app:s3cr3t@pg-rw.databases:5432/app failed", "dial postgres://app:[REDACTED]@pg-rw.databases:5432/app failed"},
		{"kv equals", "connect password=hunter2 host=db", "connect password=[REDACTED] host=db"},
		{"kv prefixed", "env DB_PASSWORD=hunter2", "env DB_PASSWORD=[REDACTED]"},
		{"kv camel", "accessToken=abc123 user=bob", "accessToken=[REDACTED] user=bob"},
		{"kv json", `{"client_secret":"abc def","user":"bob"}`, `{"client_secret":"[REDACTED]","user":"bob"}`},
		{"kv json escaped quote", `{"password":"a\"b","n":1}`, `{"password":"[REDACTED]","n":1}`},
		{"kv colon", "secret: topsecret", "secret: [REDACTED]"},
		{"kv single quotes", "token='abc def' end", "token='[REDACTED]' end"},
		{"kv query string", "GET /s3?X-Amz-Signature=abcd1234&X-Amz-Date=20261018 200", "GET /s3?X-Amz-Signature=[REDACTED]&X-Amz-Date=20261018 200"},
		{"kv api key", "api_key=zzz", "api_key=[REDACTED]"},
		{"hex blob", "hash " + fakeHex + " end", "hash [REDACTED:hex] end"},
		{"opaque blob", "value " + fakeBlob + " end", "value [REDACTED:blob] end"},
		{"email", "login failed for alice.smith@example.com from 10.0.0.5", "login failed for [EMAIL] from 10.0.0.5"},
		// The k8s-homelab runbook's drill (infra/monitoring/install.md §14).
		{"runbook drill",
			`level=warn msg="digest drill" password=hunter2-DRILL dsn=postgres://app:pg-DRILL@db:5432/x user=drill@example.com`,
			`level=warn msg="digest drill" password=[REDACTED] dsn=postgres://app:[REDACTED]@db:5432/x user=[EMAIL]`},

		// Must survive: the analysis needs them.
		{"uuid kept", "pod 0d3f2a64-9b1c-4d6e-8f00-123456789abc evicted", "pod 0d3f2a64-9b1c-4d6e-8f00-123456789abc evicted"},
		{"ip kept", "dial tcp 100.64.0.7:9100: i/o timeout", "dial tcp 100.64.0.7:9100: i/o timeout"},
		{"pod name kept", "monitoring/kube-prometheus-stack-grafana-7d9f8b6c5-x7k2p restarted", "monitoring/kube-prometheus-stack-grafana-7d9f8b6c5-x7k2p restarted"},
		{"k8s key kept", `msg="Reconciler error" key=default/foo`, `msg="Reconciler error" key=default/foo`},
		{"passed kept", "tests passed=3 bypass=true", "tests passed=3 bypass=true"},
		{"author kept", "author=bob authentication failed", "author=bob authentication failed"},
		{"tokens count kept", "tokens=5 secretary=ann", "tokens=5 secretary=ann"},
		{"path kept", "open /var/log/pods/monitoring_loki-0_0d3f2a64/loki/0.log: no such file", "open /var/log/pods/monitoring_loki-0_0d3f2a64/loki/0.log: no such file"},
		{"plain url kept", "GET http://loki.monitoring.svc.cluster.local:3100/ready 503", "GET http://loki.monitoring.svc.cluster.local:3100/ready 503"},
		{"short hex kept", "commit 9b1dfd3 deployed", "commit 9b1dfd3 deployed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New().Line(tt.in)
			if got != tt.want {
				t.Errorf("\n in: %s\ngot: %s\nwant: %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestCounts(t *testing.T) {
	s := New()
	s.Line("password=a token=b")
	s.Line("mail bob@example.com")
	s.Line("nothing here")
	if got := s.Counts()["key-value"]; got != 2 {
		t.Errorf("key-value count = %d, want 2", got)
	}
	if got := s.Counts()["email"]; got != 1 {
		t.Errorf("email count = %d, want 1", got)
	}
	if got := s.Total(); got != 3 {
		t.Errorf("Total = %d, want 3", got)
	}
}

func TestAlreadyRedactedNotCountedTwice(t *testing.T) {
	s := New()
	got := s.Line("Authorization: Bearer abcdefghijklmnop")
	if got != "Authorization: Bearer [REDACTED]" {
		t.Fatalf("got %q", got)
	}
	if s.Total() != 1 {
		t.Errorf("Total = %d, want 1: %v", s.Total(), s.Counts())
	}
}

func TestNoSecretSurvives(t *testing.T) {
	secrets := []string{fakeGitHub, fakeGitHubPAT, fakeSlackHook, fakeSlackTok, fakeAnthropic,
		fakeAWS, fakeGarage, fakeTailscale, fakeJWT, fakeBlob, fakeHex, "hunter2"}
	line := strings.Join([]string{
		"a=" + fakeGitHub, `"b":"` + fakeGitHubPAT + `"`, fakeSlackHook, fakeSlackTok,
		fakeAnthropic, fakeAWS, fakeGarage, fakeTailscale, fakeJWT, fakeBlob, fakeHex,
		"password=hunter2",
	}, " ")
	got := New().Line(line)
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Errorf("secret %q survived in %q", s, got)
		}
	}
}
