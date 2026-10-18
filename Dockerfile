# log-digest plus the Claude Code CLI it runs. Pinned versions: Go here and
# in go.mod, Claude Code in CLAUDE_CODE_VERSION; k8s-homelab infra/versions.md
# records both.

FROM golang:1.26.3-trixie AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/log-digest ./cmd/log-digest

# The native Claude Code binary from Anthropic's installer, unmodified: the
# only way a Pro or Max subscription may be used outside the terminal. The
# installer checks the download against its published checksum.
FROM debian:trixie-slim AS claude
ARG CLAUDE_CODE_VERSION=2.1.300
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl \
 && curl -fsSL https://claude.ai/install.sh | bash -s "${CLAUDE_CODE_VERSION}" \
 && mkdir /out && cp -L /root/.local/bin/claude /out/claude \
 && /out/claude --version | grep -qF "${CLAUDE_CODE_VERSION}"

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=claude /out/claude /usr/local/bin/claude
COPY --from=build /out/log-digest /usr/local/bin/log-digest
# HOME on /tmp: Claude Code writes ~/.claude.json and ~/.claude/, and the
# root filesystem is read-only in the CronJob.
ENV HOME=/tmp \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/log-digest"]
