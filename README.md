# claude-code-rc-mcp

Self-hosted [MCP](https://modelcontextprotocol.io/) server that launches **[Claude Code Remote Control](https://code.claude.com/docs/en/remote-control)** sessions on a remote development server, over SSH. Designed as a remote connector for [Claude.ai](https://claude.ai), so you can start a coding session on your server from the web or the mobile app — without opening a terminal.

## Why?

`claude remote-control` needs an interactive terminal (TTY) on the server. Without this MCP you have to SSH in by hand, start `tmux`, run the command, and only then connect from the app. With it, you just ask Claude.ai *"start a Claude Code session in project X"* and the MCP does the rest.

Sessions are created on demand and live while in use. When one stops (a dev server restart, a crash, `stop_session`), its conversation is kept, and the next `send_prompt` or `get_reply` brings it back as it was. The only permanent component is this lightweight MCP server itself.

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

Once a conversational session is up, `send_prompt` / `get_reply` drive it over the same SSH channel — the prompt goes in through the `tmux` paste buffer, the final answer comes back out of the session's JSONL transcript.

The Remote Control connection itself is **outbound-only** (the server connects to the Anthropic API; no inbound ports). SSH is only the channel this MCP uses to *launch* the process.

> **Note on `tmux`.** `claude remote-control` still requires a TTY — there is no `--headless`/`--daemon` mode yet. Running it inside a detached `tmux` session provides the TTY, survives the SSH connection closing, and gives `list`/`kill` of sessions for free. When a headless mode lands, the `tmux` layer can be dropped.

## Features

- **8 tools**: `start_session`, `send_prompt`, `get_reply`, `interrupt_session`, `resume_session`, `list_sessions`, `stop_session`, `list_projects`
- **Two-way**: prompt a session that is already running and get its final answer back, without leaving the chat
- **Resumable**: sessions that stopped (dev server restart, crash) are listed and picked up again with their full conversation, under the same id and URL
- **Session system prompt**: `APPEND_SYSTEM_PROMPT` adds house rules to every conversational session, e.g. "never use interactive widgets"
- **OAuth 2.1**: fixed client credentials derived from `MCP_SECRET` — no separate user database
- **Persistent OAuth tokens**: issued tokens are written to disk so they survive container/pod restarts
- **Streamable HTTP**: `/mcp` endpoint for remote MCP connections
- **Stateless**: all session state lives on the remote server (`tmux`, plus `~/.claude-rc-mcp`), so the MCP can be restarted or scaled freely
- **Docker**: ready to deploy on Kubernetes, Fly.io, Railway, etc.

## MCP Tools

### `start_session`

SSHes to the server and launches Claude Code Remote Control inside a detached `tmux` session in the chosen project directory, then returns the session URL.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Short label, shown in claude.ai/code (1-41 chars, `[a-zA-Z0-9_-]`) |
| `path` | string | Yes | Project directory, relative to `PROJECTS_BASE_DIR` |
| `prompt` | string | No | Initial prompt or slash command to run as soon as the session opens |
| `interactive` | boolean | No | Open an empty conversational session, ready for `send_prompt`. Implied by `prompt` |
| `worktree` | boolean | No | Spawn on-demand work in isolated git worktrees. Defaults to `SPAWN_WORKTREE`. Ignored for conversational sessions |
| `bypass_permissions` | boolean | No | Launch with `--dangerously-skip-permissions`, so the session never waits for tool approvals |

The `tmux` session is named `rc-<name>-<random>`; the random suffix avoids collisions when the same `name` is reused.

**Two launch modes.** Plain, the session is the persistent Remote Control *server* (`claude remote-control`) — it accepts multiple concurrent sessions and honours `--spawn`. With `prompt` or `interactive`, it is a single **conversational** session started as `claude --rc <name> ["<prompt>"]`: the only form that takes an initial instruction, and the only one you can send further prompts to. `worktree`/spawn does not apply there. Either way the session stays open when the task finishes, so you can pick it up from claude.ai/code:

> *"Start a session on `my-project` and run `/security-review`"* → the review is already running by the time you open the link.

The prompt is never interpolated into a shell command: it is base64-encoded, decoded into `~/.claude-rc-mcp/<id>.prompt` on the server, and read back with `"$(cat …)"`, so no part of it reaches a shell parser.

Conversational sessions also get `--append-system-prompt` with a short note from this server (see [Session system prompt](#session-system-prompt)) followed by `APPEND_SYSTEM_PROMPT`, and `--session-id` with a conversation id chosen here, which is how their transcript is found and how they are resumed later.

### `send_prompt`

Sends a follow-up prompt to a conversational session, and returns its **final answer** - so you can hold a whole conversation with a remote session from Claude.ai, not just start one.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id from `start_session` / `list_sessions` |
| `prompt` | string | Yes | What to ask. Slash commands and multi-line text both work |
| `wait_seconds` | number | No | How long to wait for the answer before returning (default `90`, max `240`) |

The prompt is typed into the live conversation, so the session keeps its full context and the exchange stays visible at claude.ai/code. Turns that outlast `wait_seconds` are not lost — the call returns "still working" and [`get_reply`](#get_reply) collects the answer afterwards.

Two things happen first when needed:

- **The session is not running** (it shows as *not running* in `list_sessions`): it is resumed, with its conversation, before the prompt goes in.
- **The session is busy** with a previous turn, or has a question, approval prompt or dialog open: that is interrupted with Esc first. One turn at a time. A prompt pasted into a running turn is folded into it as a queued attachment, so it would never get an answer of its own, and a dialog would swallow the paste.

Only conversational sessions accept it; against a Remote Control *server* session it returns an explanatory error, because that process spawns its sessions as separate children and has no conversation of its own.

### `get_reply`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id |
| `wait_seconds` | number | No | How long to wait if the turn is still running (default `90`, max `240`, `0` to peek) |

Collects the final answer of the session's current turn: the reply to the last `send_prompt`, or - if no prompt was ever sent through the MCP - the reply to the `prompt` the session was started with. That second case is the useful one for *"start a session on X and run the tests"*: come back later and read the result. A session that is not running is resumed first.

Besides an answer, it can report that the turn ran a slash command (with the command's output, e.g. `/compact`), was interrupted, ended with an API error, was cut short (the session stopped mid-turn, e.g. a server restart), or is waiting on a question, approval prompt or dialog.

#### How the answer is read back

Not by scraping the terminal. Claude Code writes every conversation to a JSONL transcript under `~/.claude/projects/<project>/<uuid>.jsonl`, and each assistant entry carries an explicit `stop_reason` - so the end of a turn is a fact to be read, not a guess about whether the pane has stopped changing. The reply comes out as clean text: no ANSI escapes, no box-drawing, nothing truncated to the terminal width. Slash commands such as `/compact` or `/model` end differently: with no assistant message at all, on an entry holding the command's output.

The transcript is found by name: `start_session` picks the conversation id itself (`--session-id`), so there is no directory-slug to rebuild. A `/clear` moves the session on to a new conversation. That is tracked through the small status file Claude Code keeps per process (`~/.claude/sessions/<pid>.json`), which also says whether the session is busy, idle, or waiting on a dialog.

Two things follow from this that are worth knowing:

- **Questions and approval prompts block the turn.** A session running without `bypass_permissions` stops mid-turn on the tool-approval box, and one that uses `AskUserQuestion` stops on the question, so neither reaches a final answer. `send_prompt` and `get_reply` detect it and say so, with the session URL, instead of waiting out the timeout. Answer it at claude.ai/code, or dismiss it with `interrupt_session`. Sessions you intend to drive this way are best started with `bypass_permissions`, and told through `APPEND_SYSTEM_PROMPT` to ask their questions in plain text.
- **The reply is anchored to the prompt, not to the clock.** An older turn's answer, which may also land after the prompt was sent, is not mistaken for it.

### `interrupt_session`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id |

Stops what the session is doing right now, like pressing Esc or the stop button: a running turn, or an open question, approval prompt or dialog. The session stays open with its context, ready for the next `send_prompt`.

### `resume_session`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id from `list_sessions` |
| `bypass_permissions` | boolean | No | Override the permission mode the session was started with. Omitted, it is kept |

Relaunches a conversational session that is no longer running as `claude --rc <name> --resume <conversation>`, in the same `tmux` session name, so the id stays the same, and so does the claude.ai/code URL. `send_prompt` and `get_reply` do this on their own; this tool is for when you only want the session back.

This works because the per-session state lives in `~/.claude-rc-mcp/` on the dev server, next to the transcripts under `~/.claude`, instead of `/tmp`, which a container restart wipes. After a crash the conversation to reopen is taken from the status file the dead process left behind, which followed any `/clear` typed at claude.ai/code.

### `list_sessions`

Lists the sessions with their URLs and mode, so you can tell which ones accept `send_prompt`: the running ones, and whether each is working, idle or waiting for input, and the conversational ones that are no longer running, with how long ago they were last active. Those stay listed, and resumable, for `SESSION_RETENTION_DAYS` (default 14) after their last activity, then their files are removed.

### `stop_session`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Yes | Full session id from `start_session` / `list_sessions` (e.g. `my-project-a1b2c3`) |
| `forget` | boolean | No | Also drop the session from `list_sessions`, so it can no longer be resumed from here |

Kills the `tmux` session. The conversation is kept, so the session can be resumed later, unless `forget` is set, which also removes its `~/.claude-rc-mcp/<id>.*` files.

## Session system prompt

Every conversational session is launched with `--append-system-prompt`, and so is every resume:

1. **A fixed note from this server.** `send_prompt` types prompts in as a bracketed paste, and Claude Code wraps pasted text in `<pasted_content>` tags while its own system prompt tells the model to follow instructions in those only when the user's own message asks for it. A prompt sent from here is nothing but pasted text, so a session can refuse it outright (seen right after a `/clear`). The note tells the model those tags carry the user's own messages in this session. Text pasted at claude.ai/code arrives as a plain message, so it is unaffected.
2. **`APPEND_SYSTEM_PROMPT`**, if set: your own rules for sessions driven remotely. The typical one is to never use interactive widgets such as `AskUserQuestion`, which cannot be answered through this MCP, and to ask questions in plain text instead.

Claude Code records a conversation's system prompt on its first request and replays that record until the conversation is compacted, so a change to `APPEND_SYSTEM_PROMPT` reaches existing conversations after their next `/compact` (or a `/clear`).

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
| `APPEND_SYSTEM_PROMPT` | No | Text appended to the system prompt of every conversational session, resumed ones included (see [Session system prompt](#session-system-prompt)) |
| `SESSION_RETENTION_DAYS` | No | How long a session that is no longer running stays listed and resumable, counted from its last activity (default: `14`) |
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
