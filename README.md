# log-digest

It reads the last 10 minutes' WARN-and-worse log lines from Loki, redacts
secrets, has Claude analyse them through the Claude Code CLI, and posts the
report to Slack. It runs when started by hand, as a Job created from a
suspended Kubernetes CronJob. Deployed by
[k8s-homelab](https://github.com/ncongduy/k8s-homelab), `infra/monitoring/`
§14.

```
Loki ─▶ redact ─▶ group by source, level and message ─▶ digest ─▶ claude -p ─▶ Slack
```

## Why the CLI

It runs on a Claude **Pro or Max subscription**, without an API key.
`claude setup-token` prints a one-year OAuth token. With it set as
`CLAUDE_CODE_OAUTH_TOKEN`, the unmodified `claude` binary runs headless. The
subscription may not be used against the Messages API directly, so this program
runs `claude -p` as a subprocess and never calls the API itself. Every run counts
toward the subscription's usage limits.

`claude` runs with no tools (`--tools ""`), no MCP servers, no customisations
(`--safe-mode`), one turn, and no saved session. A log line crafted to instruct
the model can at worst change the report's wording; it cannot run anything.
The Slack webhook is removed from `claude`'s environment.

## Configuration

| Env | Flag | Default | |
|---|---|---|---|
| `LOKI_URL` | `--loki-url` | `http://loki.monitoring.svc.cluster.local:3100` | |
| `WINDOW` | `--window` | `10m` | ends at the current minute |
| `MAX_LINES` | `--max-lines` | `50000` | half reserved for journal lines |
| `PROMPT_BUDGET` | `--prompt-budget` | `60000` | bytes of digest sent to Claude |
| `CLAUDE_BIN` | `--claude-bin` | `claude` | |
| `CLAUDE_MODEL` | `--model` | `sonnet` | |
| `CLAUDE_TIMEOUT` | `--claude-timeout` | `20m` | |
| `TZ` | `--tz` | `UTC` | time zone of the report's times, an IANA name such as `Europe/Helsinki`; the zone data is built in |
| `DIGEST_CONTEXT` | — | — | facts about the cluster, appended to the system prompt |
| `SLACK_WEBHOOK_URL` | — | — | required unless `--dry-run` |
| `CLAUDE_CODE_OAUTH_TOKEN` | — | — | read by `claude` itself |

`--dry-run` prints the exact digest Claude would get, and calls neither Claude
nor Slack. `--input FILE` reads a saved Loki `query_range` response instead of
querying Loki.

Exit status: 0 when a report was posted, including the fallback posted when
Claude fails (`Claude unavailable: <reason>` plus the top groups, not analysed);
1 when Loki or Slack failed; 2 on bad configuration.

## What is redacted

Applied in order, before grouping, so nothing downstream ever sees the original
values (`internal/sanitize`):

- private key blocks, `Cookie:` / `Set-Cookie:` headers, `Bearer` / `Basic`
  credentials, JWTs
- Slack webhooks and tokens, GitHub tokens, `sk-…` API keys, AWS-style and
  Garage `GK…` key IDs, Tailscale `tskey-…` keys
- `user:password@` in URLs
- values of keys like password, secret, token, api_key, access_key,
  client_secret, auth, cookie, session id, signature, credential, in `k=v`,
  `"k":"v"`, `k: v` and query strings
- long opaque strings: 40+ hex characters, or 32+ base64-like characters
  mixing upper case, lower case and digits
- email addresses

IPs, hostnames, pod names and UUIDs stay. The rules match patterns, so a
secret in a shape none of them knows, such as a bare password in prose, gets
through.

## Develop

```bash
go test ./...
go run ./cmd/log-digest --dry-run --input testdata/loki.json
# against the cluster, with `kubectl -n monitoring port-forward svc/loki 3100`:
go run ./cmd/log-digest --dry-run --loki-url http://localhost:3100
```

Fake secrets in tests are assembled at run time, so no string in the repository
trips a secret scanner. `testdata/secrets.txt` lists the fixture's, and CI
fails if any of them survives the dry run.

## Image

`ghcr.io/ncongduy/log-digest:sha-<short>`, built and smoke-tested by
`.github/workflows/image.yml` on every push to `main`. It holds the static Go
binary and the native Claude Code binary from Anthropic's installer, pinned by
`CLAUDE_CODE_VERSION` in the `Dockerfile`. It runs as uid 65532 on a read-only
root, with `HOME=/tmp`.
