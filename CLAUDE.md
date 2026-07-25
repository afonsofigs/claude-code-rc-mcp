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
- **Two launch shapes** — `claude remote-control` takes no initial prompt (its
  usage is `[options]` only). So when `start_session` is given a `prompt`, it
  launches `claude --rc <name> "<prompt>"` instead: a single interactive session
  with Remote Control enabled, which does accept a positional prompt. The
  trade-off is `--spawn` — it exists only on the server form, so `worktree` is
  ignored in prompt mode. The session stays open after the task completes.
- **Prompt never touches a shell parser** — it is base64-encoded in Node,
  decoded into `/tmp/rc-<id>.prompt` on the server, and read back inside the
  tmux command as `"$(cat …)"`. That is why prompts can hold quotes, `$(…)`,
  backticks and newlines without any escaping logic, and why the `NAME_RE`-style
  validation used for `name`/`path`/`id` is not needed for it.
- **pipe-pane, not `tee`, in prompt mode** — an interactive session checks
  whether stdout is a TTY; behind `| tee` it falls back to `--print` and exits
  with "Input must be provided…". So the pane runs `claude` directly and the log
  is captured with `tmux pipe-pane`. The pipe is detached once the session is up:
  it mirrors every TUI redraw and would otherwise grow without bound.
- **URL source differs per mode** — the interactive TUI draws the URL in chunks
  split by cursor-positioning escapes, so `stripAnsi` on the raw log yields a
  mangled URL (a dropped character); `tmux capture-pane` renders it correctly.
  The Remote Control server is the mirror image: its `tee` log is clean line
  output, while its pane wraps the (longer) environment URL across two rows.
  Hence `pollSession({fromPane})` — pane first for prompt mode only. The
  resolved URL is then written to `/tmp/rc-<id>.url` so `list_sessions` reports
  exactly what `start_session` returned instead of re-parsing the log.
- **Sessions auto-terminate** — because the pane runs the `claude | tee` pipeline
  directly, the `tmux` session ends when `claude` exits. So `list_sessions` only
  ever shows live sessions; there are no zombie tmux sessions to reap. The logfile
  outlives the session, so `list_sessions` lazily deletes orphan `/tmp/rc-*.log`.
- **Logfile, not `capture-pane`, for diagnostics** — `start_session` polls the
  logfile, which survives even if the session dies on a startup error;
  `capture-pane` would not. (`capture-pane` is used only to read the URL of a
  live interactive session — see below.)
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
- **Server-level instructions** — the `McpServer` is constructed with an
  `instructions` string (`SERVER_INSTRUCTIONS`) that the SDK delivers to the
  client at `initialize` time. It tells the model when to reach for these tools
  (trigger phrasings, ordering rules: `list_projects` → `start_session`,
  `list_sessions` before reusing/duplicating, etc.) and which behaviours need
  explicit user consent (`bypass_permissions`, `stop_session`). Tool
  descriptions echo the same cues so they fire even if the client truncates the
  server instructions.

## Common tasks

### Add a new tool
Add another `server.tool()` call inside `createMcpServer()`. Write the tool
description with *trigger phrasings* the user might say, not just what the tool
does — that is what the model reads to decide when to invoke it. If the new
tool changes the recommended order of operations, update `SERVER_INSTRUCTIONS`
too so the guidance stays consistent.

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
