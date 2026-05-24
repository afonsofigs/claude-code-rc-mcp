# CLAUDE.md

## What is this?

A self-hosted MCP server that launches `claude remote-control` sessions on a remote
development server over SSH. Four tools: `start_session`, `list_sessions`,
`stop_session`, `list_projects`. Protected by OAuth 2.1 with credentials derived
from `MCP_SECRET`.

## Stack

- Node.js (ESM), single file: `server.js`
- `@modelcontextprotocol/sdk` — MCP protocol, OAuth handlers, Streamable HTTP transport
- `ssh2` — SSH client
- `express` — HTTP server
- `zod` — schema validation

## Project structure

```
server.js          — All server code (OAuth provider, SSH helper, MCP tools, Express app)
package.json       — Dependencies
Dockerfile         — Container build
k8s/deployment.yaml — Example Kubernetes manifest
.github/workflows/ — CI/CD to ghcr.io
```

## Running locally

```bash
cp .env.example .env   # fill it in
node --env-file=.env server.js
```

## Key design decisions

- **SSH, not a sidecar / `kubectl exec`** — the MCP is a standalone deployment that
  reaches the dev server over SSH, which keeps it portable to any host (VM,
  bare-metal, pod with sshd), not just Kubernetes.
- **tmux workaround** — `claude remote-control` requires a TTY and has no headless
  mode. Each session runs as `claude remote-control … 2>&1 | tee /tmp/rc-<id>.log`
  inside a detached `tmux` session named `rc-<id>`.
- **Sessions auto-terminate** — because the pane runs the `claude | tee` pipeline
  directly, the `tmux` session ends when `claude` exits. So `list_sessions` only
  ever shows live sessions; there are no zombie tmux sessions to reap. The logfile
  outlives the session, so `list_sessions` lazily deletes orphan `/tmp/rc-*.log`.
- **Logfile, not `capture-pane`** — `start_session` polls the logfile, which
  survives even if the session dies on a startup error; `capture-pane` would not.
- **Unique session ids** — `start_session` appends a random suffix
  (`rc-<name>-<random>`) so reusing the same `name` never collides.
- **OAuth 2.1 file-persisted** — tokens stored in `TOKEN_STORE_PATH` via `TokenStore`.
  Single-instance store; clients survive pod restarts if the path is on a volume.
- **Fixed client credentials** — `client_id` / `client_secret` derived from
  `MCP_SECRET` via SHA-256. No dynamic registration from unknown clients.
- **Shell-injection hardening** — `name`, `path` and `id` are strictly validated
  before being interpolated into SSH commands.
- **Opt-in bypass permissions** — `start_session` accepts a `bypass_permissions`
  flag that appends `--dangerously-skip-permissions` to the `claude remote-control`
  invocation. It is off by default and must be set explicitly per call; the
  response header surfaces `bypass: on` so the choice is visible.

## Common tasks

### Add a new tool
Add another `server.tool()` call inside `createMcpServer()`.

### Change OAuth token expiry
In `OAuthProvider.exchangeAuthorizationCode()`, change `expiresIn` (default 86400 = 24h).

### Test locally
```bash
curl http://localhost:3000/health
curl http://localhost:3000/.well-known/oauth-authorization-server
```

## CI/CD

Push to `main` triggers GitHub Actions: builds the Docker image and pushes it to
`ghcr.io/afonsofigs/claude-code-rc-mcp:latest` + an SHA tag.
