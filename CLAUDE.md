# CLAUDE.md

## What is this?

A self-hosted MCP server that launches `claude remote-control` sessions on a remote
development server over SSH, and holds conversations with them. Eight tools:
`start_session`, `send_prompt`, `get_reply`, `interrupt_session`, `resume_session`,
`list_sessions`, `stop_session`, `list_projects`. Protected by OAuth 2.1 with
credentials derived from `MCP_SECRET`.

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
  mode. Each session runs as `claude remote-control … 2>&1 | tee <state>/<id>.log`
  inside a detached `tmux` session named `rc-<id>`.
- **State on the home volume, not /tmp** - per-session files live in
  `~/.claude-rc-mcp/<id>.{meta,url,log,prompt,sys,send,pending,tr}` on the dev
  server (`<state>` below). A container restart wipes /tmp, and the transcripts
  under `~/.claude` survive it, so the pointer to them has to survive too:
  `meta` (mode, dir, name, conversation id, bypass) is what a resume relaunches
  from. The directory is resolved to an absolute path once per process
  (`stateDir()`) so it interpolates like a literal.
- **Two launch shapes** — `claude remote-control` takes no initial prompt (its
  usage is `[options]` only). So when `start_session` is given a `prompt`, it
  launches `claude --rc <name> "<prompt>"` instead (`--rc` is the short form of
  `--remote-control [name]`): a single interactive session with Remote Control
  enabled, which does accept a positional prompt. `interactive: true` is the
  same shape with the prompt omitted. Both are "conversational" mode — the only
  mode `send_prompt` works on, because the server form spawns its sessions as
  separate child processes and its pane is not a chat. The trade-off is
  `--spawn`, which exists only on the server form, so `worktree` is ignored
  there. The session stays open after the task completes.
- **Prompt never touches a shell parser** — it is base64-encoded in Node,
  decoded into `<state>/<id>.prompt` on the server, and read back inside the
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
  Hence `pollSession({fromPane})` - pane first for prompt mode only. Both are
  fallbacks now: the status file (below) names the Remote Control session
  outright, and it is the only source trusted after a resume, whose pane and log
  redraw a history that may contain other session links. The resolved URL is
  written to `<state>/<id>.url` so `list_sessions` reports it without re-parsing.
- **Sessions auto-terminate, records do not** - because the pane runs `claude`
  directly, the `tmux` session ends when `claude` exits: no zombie tmux sessions.
  The record in `<state>` stays, and `list_sessions` shows the session as not
  running and resumable until `SESSION_RETENTION_DAYS` after its transcript was
  last written, then deletes its files. A server-mode record, or one whose
  transcript is gone, is deleted as soon as its session is not running.
- **Logfile, not `capture-pane`, for diagnostics** — `start_session` polls the
  logfile, which survives even if the session dies on a startup error;
  `capture-pane` would not. (`capture-pane` is used only to read the URL of a
  live interactive session — see below.)
- **Replies come from the transcript, not the pane** — Claude Code writes every
  conversation to `~/.claude/projects/<slug>/<uuid>.jsonl`, where each assistant
  entry carries an explicit `stop_reason`. So `send_prompt` knows a turn is over
  as a fact, instead of guessing from a pane that stopped changing, and the text
  it returns needs no ANSI stripping or unwrapping. A turn is finished when the
  last main-chain entry is an assistant message with neither a `tool_use` block
  nor `stop_reason: "tool_use"` — both checks are needed, because thinking, text
  and tool_use arrive as separate entries, so a text-only entry can still be the
  prelude to a tool call. Sidechain (sub-agent) entries are skipped: they finish
  mid-turn and would otherwise read as the answer.
- **Conversation id chosen here, transcript found by name** - `start_session`
  passes `--session-id <uuid>` and records it, so the transcript is
  `~/.claude/projects/*/<uuid>.jsonl` without reconstructing the CLI's slug
  rules. Cached in `<state>/<id>.tr`, trusted only while it names that id.
- **The CLI's status file is the live signal** - Claude Code keeps
  `~/.claude/sessions/<pid>.json` per process, and in conversational mode the
  pane pid is claude's. It gives `status` (`busy`, `idle`, `shell` = idle with a
  background shell, `waiting` + `waitingFor` for a question, approval prompt or
  dialog), the current conversation id (a `/clear` changes it, and moves to a new
  transcript file), and `bridgeSessionId` (the session URL). Pids repeat across
  container restarts and a killed process leaves its file behind, so a file whose
  `startedAt` predates the tmux session is ignored (`parseLive`). A process that
  exits cleanly deletes its file, so the conversation id is copied into `meta`
  wherever the status is read (`followConversation`); after a crash, the
  newest file naming the tmux session says which conversation it was last in
  (`lastConversation`), including a `/clear` nothing here saw.
- **Command output ends a turn too** - a slash command gets no assistant
  message: `/compact` ends on a user entry `<local-command-stdout>…`, dialog
  commands (`/model`, `/cost`) log `system`/`local_command` entries instead, and
  `/clear` writes its entries into the new transcript. Waiting for an assistant
  reply there is what made `/compact` look like it never finished. An Esc ends a
  turn on `[Request interrupted by user]`. Meta user entries (command caveats,
  the "Continue from where you left off." a resume injects) and the synthetic
  "No response requested." after it are not part of a turn; synthetic API errors
  are, since they are how a failed turn ends.
- **Idle without an ending means cut short** - the status file is read before
  the transcript on each poll, and the CLI writes a turn's last entry before it
  flips to idle. So idle, a status change after the turn started, and no ending
  in the transcript is a turn that was cut off (typically by the restart a resume
  recovers from), reported as such instead of "still working" forever.
- **`paste-buffer`, not `send-keys`, for the prompt** — `send-keys` would turn
  every newline of a multi-line prompt into a submit and replay a long prompt
  keystroke by keystroke. `paste-buffer -p` wraps it in bracketed-paste markers
  so the TUI takes it as one block; the Enter afterwards is what submits it.
- **The reply is anchored on the prompt, not the clock** — a turn that was
  already running when the prompt was pasted also finishes *after* the send
  mark, and its answer is not the one that was asked for. So the turn starts at
  the last input entry after the mark (a prompt or a slash command, not a
  `tool_result` nor a command's output); no such entry means the prompt has not
  been picked up yet, not that there is nothing to report.
- **One turn at a time: interrupt, then send** - a prompt pasted into a busy
  session never becomes a user entry: the CLI folds it into the running turn as
  a `queued_command` attachment, so the anchor never appears. A dialog would
  swallow the paste. So `send_prompt` presses Esc first when the status is
  `busy` or `waiting` (`interruptTurn`), once, and again only if it plainly did
  not take after 4s, because a second Esc on an idle prompt opens the rewind
  menu.
- **Not running is recoverable** - `send_prompt` / `get_reply` resume a stopped
  conversational session first (`openConversation`): `claude --rc <name>
  --resume <uuid>` in a tmux session of the same name, so the id and even the
  claude.ai/code URL stay the same. A resumed session that opens on a dialog is
  reported, not Esc'd.
- **System prompt on every launch** - `--append-system-prompt` carries a fixed
  note (`RC_SYSTEM_PROMPT`) plus `APPEND_SYSTEM_PROMPT`. The note exists because
  a bracketed paste reaches the model wrapped in `<pasted_content>` tags, which
  Claude Code's own system prompt says to distrust unless the user's own message
  vouches for them; a prompt from here is nothing but that, and was refused once
  right after a `/clear`. A raw paste avoids the tags only below ~800 bytes and
  brings back TUI shortcuts (`!` shell mode, tab, `@` autocomplete swallowing
  the Enter), so the paste stays bracketed. The CLI snapshots a conversation's
  system prompt until it is compacted, so resumes pass it again.
- **Section markers carry a nonce** - multi-part SSH output is split with
  `sshSections`, whose markers include a random nonce per call: a pane or
  transcript showing this very file would contain any fixed marker.
- **The send mark is stamped by the remote host** — it is compared against
  timestamps written by the session, so a container clock a few seconds ahead of
  the dev server would place it in their future and the reply would never be
  recognised. `date -u` on the server, echoed back over SSH.
- **Questions and approval prompts are reported, not waited out** - a session
  stalls mid-turn on the tool-approval box (without `bypass_permissions`) or on
  an `AskUserQuestion`, so `send_prompt`/`get_reply` report the status file's
  `waiting` (with the session URL and pane) instead of burning the timeout. When
  the status file cannot be read, a regex on the pane is the fallback: it wants
  the question *and* the numbered list that follows, including the box-drawing
  characters `capture-pane` renders around them.
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

To exercise the tools end to end, run the server against the dev server with a
pre-seeded `TOKEN_STORE_PATH` (`{"tokens":{"t":{"clientId":"x","scopes":[],"expiresAt":9999999999999}},"codes":{}}`)
and call it with the SDK's `Client` + `StreamableHTTPClientTransport`, passing
`Authorization: Bearer t`. Point `CLAUDE_BIN` at a wrapper that does
`exec claude --model haiku "$@"` to keep turns cheap, and use a throwaway
project, trusted once by hand (the trust dialog blocks a fresh directory). A
test project gets auto-memory like any other, so "remember X" style checks leak
across its sessions. Never interrupt or stop the session you are running in:
it is an `rc-*` tmux session too.

## CI/CD

Push to `main` triggers GitHub Actions: builds the Docker image and pushes it to
`ghcr.io/afonsofigs/claude-code-rc-mcp:latest` + an SHA tag.
