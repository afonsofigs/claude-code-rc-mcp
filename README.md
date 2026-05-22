# claude-code-rc-mcp

Self-hosted [MCP](https://modelcontextprotocol.io/) server that launches **[Claude Code Remote Control](https://code.claude.com/docs/en/remote-control)** sessions on a remote development server, over SSH. Designed as a remote connector for [Claude.ai](https://claude.ai), so you can start a coding session on your server from the web or the mobile app — without opening a terminal.

## Why?

`claude remote-control` needs an interactive terminal (TTY) on the server. Without this MCP you have to SSH in by hand, start `tmux`, run the command, and only then connect from the app. With it, you just ask Claude.ai *"start a Claude Code session in project X"* and the MCP does the rest.

Sessions are **ephemeral by design**: created on demand, alive while in use, gone when finished. The only permanent component is this lightweight MCP server itself.

## How it works

```
Claude.ai / Mobile app / Scheduled tasks
        |
        v  HTTPS + OAuth 2.1 + Streamable HTTP
  claude-code-rc-mcp  (this server)
        |
        v  SSH (key-based auth)
  Remote dev server with Claude Code installed
        |
        v  tmux new-session -d 'claude remote-control'
  Remote Control session (ephemeral)
        |
        v  the session phones home to the Anthropic API
  Session shows up at claude.ai/code  ->  you attach to it
```

The Remote Control connection itself is **outbound-only** (the server connects to the Anthropic API; no inbound ports). SSH is only the channel this MCP uses to *launch* the process.

> **Note on `tmux`.** `claude remote-control` still requires a TTY — there is no `--headless`/`--daemon` mode yet. Running it inside a detached `tmux` session provides the TTY, survives the SSH connection closing, and gives `list`/`kill` of sessions for free. When a headless mode lands, the `tmux` layer can be dropped.

## Features

- **4 tools**: `start_session`, `list_sessions`, `stop_session`, `list_projects`
- **OAuth 2.1**: fixed client credentials derived from `MCP_SECRET` — no separate user database
- **Persistent OAuth tokens**: issued tokens are written to disk so they survive container/pod restarts
- **Streamable HTTP**: `/mcp` endpoint for remote MCP connections
- **Stateless**: all session state lives in `tmux` on the remote server, so the MCP can be restarted or scaled freely
- **Docker**: ready to deploy on Kubernetes, Fly.io, Railway, etc.

## MCP Tools

### `start_session`

SSHes to the server and launches `claude remote-control` inside a detached `tmux` session in the chosen project directory, then returns the session URL.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Short label, shown in claude.ai/code (1-41 chars, `[a-zA-Z0-9_-]`) |
| `path` | string | Yes | Project directory, relative to `PROJECTS_BASE_DIR` |
| `worktree` | boolean | No | Spawn on-demand work in isolated git worktrees. Defaults to `SPAWN_WORKTREE`. |

The `tmux` session is named `rc-<name>-<random>`; the random suffix avoids collisions when the same `name` is reused.

### `list_sessions`

Lists the active `rc-*` `tmux` sessions and their URLs. Also cleans up orphan log files left by sessions that already ended.

### `stop_session`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id from `start_session` / `list_sessions` (e.g. `my-project-a1b2c3`) |

### `list_projects`

Lists directories under `PROJECTS_BASE_DIR` that look like projects (contain a `.git` or `.claude` entry). Use the names as the `path` input of `start_session`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_SECRET` | Yes | Secret used to derive the OAuth credentials (e.g. `openssl rand -hex 32`) |
| `SERVER_URL` | Yes | Public HTTPS URL of this server (OAuth issuer) |
| `SSH_HOST` | Yes | Hostname/IP of the development server |
| `SSH_USER` | Yes | SSH user |
| `SSH_PRIVATE_KEY` | Yes | SSH private key **content** (PEM block). If the value is a path to an existing file, it is read instead. |
| `PROJECTS_BASE_DIR` | Yes | Base directory on the server; the `path` input is relative to it |
| `SSH_PORT` | No | SSH port (default: `22`) |
| `SSH_PASSPHRASE` | No | Passphrase for an encrypted SSH key |
| `CLAUDE_BIN` | No | `claude` binary on the server; set to an absolute path if not on the non-interactive SSH `PATH` (default: `claude`) |
| `SPAWN_WORKTREE` | No | Boolean (default `false`). Default for the per-call `worktree` input |
| `TOKEN_STORE_PATH` | No | Where issued OAuth tokens are persisted (default: `/data/oauth-tokens.json`) |
| `PORT` | No | Server port (default: `3000`) |

## Quick Start

### Server prerequisites

The remote development server must have:

- **Claude Code installed and pre-authenticated** — run `claude` once and complete `/login` (Pro/Max/Team/Enterprise). This MCP does **not** handle Claude Code authentication; it only launches `remote-control`.
- **`tmux`** installed.
- **SSH key-based access** for the configured user. Use a dedicated key for a non-root user; `AllowUsers` and a restricted shell are recommended.

### Run with Docker

```bash
docker run -d \
  -e MCP_SECRET=$(openssl rand -hex 32) \
  -e SERVER_URL=https://your-domain.com \
  -e SSH_HOST=devserver.example.com \
  -e SSH_USER=youruser \
  -e SSH_PRIVATE_KEY="$(cat ~/.ssh/rc_mcp_key)" \
  -e PROJECTS_BASE_DIR=/home/youruser/projects \
  -p 3000:3000 \
  ghcr.io/afonsofigs/claude-code-rc-mcp:latest
```

### Run with Node.js

```bash
git clone https://github.com/afonsofigs/claude-code-rc-mcp.git
cd claude-code-rc-mcp
npm install
cp .env.example .env   # fill it in
node --env-file=.env server.js
```

## Claude.ai Connector Setup

1. Deploy with HTTPS (e.g. behind a Cloudflare Tunnel or any reverse proxy).
2. Check the server logs for `client_id` and `client_secret` (printed on startup).
3. Go to [claude.ai/settings/connectors](https://claude.ai/settings/connectors) → **Add custom connector**.
4. Enter the URL `https://your-domain.com/mcp` and the `client_id` / `client_secret`.
5. The connector links automatically and is available in conversations and scheduled tasks.

## Authentication & Security

OAuth 2.1, same model as a small set of self-hosted MCP connectors:

- **Fixed client credentials** — `client_id` / `client_secret` derived deterministically from `MCP_SECRET` via SHA-256. No registration page, no user database.
- **Auto-approve `/authorize`** — security comes from the fixed credentials: only someone with `MCP_SECRET` can derive valid ones.
- **PKCE (S256)** — mandatory for every authorization flow.
- **Redirect URI lockdown** — only `claude.ai` / `claude.com` callback URLs are accepted.
- **HTTPS** — deploy behind TLS; the OAuth proxy is the only entry point.

> **Blast radius.** Anyone who can invoke this MCP can run arbitrary code on the development server through Claude Code — that is the whole point. Treat the OAuth layer as the only access barrier: keep `MCP_SECRET` secret, give the SSH key a dedicated **non-root** user, and do not share credentials.

## Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | No | Health check |
| `GET /.well-known/oauth-authorization-server` | No | OAuth metadata (RFC 8414) |
| `GET /.well-known/oauth-protected-resource` | No | Protected resource metadata (RFC 9728) |
| `POST /register` | No | Client registration (returns the fixed client) |
| `GET /authorize` | No | OAuth authorization (auto-approve) |
| `POST /token` | No | Token exchange |
| `POST /mcp` · `GET /mcp` · `DELETE /mcp` | Bearer | Streamable HTTP MCP transport |

## Kubernetes Deployment

A complete example manifest is in [`k8s/deployment.yaml`](k8s/deployment.yaml): Namespace + Secret + PVC + Deployment + Service. Mount the SSH private key and `MCP_SECRET` as a `Secret`, never bake them into the image. Expose via a ClusterIP Service + Cloudflare Tunnel (or any HTTPS reverse proxy). The PVC is what lets OAuth tokens survive pod restarts.

## Dependencies

- [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) — official MCP TypeScript SDK (OAuth + Streamable HTTP)
- [ssh2](https://github.com/mscdex/ssh2) — SSH client for Node.js
- [express](https://expressjs.com/) — HTTP server
- [zod](https://zod.dev/) — schema validation

## License

MIT
