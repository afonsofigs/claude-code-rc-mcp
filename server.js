import { randomUUID, createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import express from "express";
import { Client as SSHClient } from "ssh2";
import { z } from "zod";

// --- Configuration ---

const MCP_SECRET = process.env.MCP_SECRET;
const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const SSH_HOST = process.env.SSH_HOST;
const SSH_PORT = parseInt(process.env.SSH_PORT || "22", 10);
const SSH_USER = process.env.SSH_USER;
const SSH_PRIVATE_KEY = process.env.SSH_PRIVATE_KEY;
const SSH_PASSPHRASE = process.env.SSH_PASSPHRASE || undefined;
const PROJECTS_BASE_DIR = process.env.PROJECTS_BASE_DIR;
const SPAWN_WORKTREE = (process.env.SPAWN_WORKTREE || "false").toLowerCase() === "true";
const CLAUDE_BIN = process.env.CLAUDE_BIN || "claude";
const TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || "/data/oauth-tokens.json";

const required = { MCP_SECRET, SERVER_URL, SSH_HOST, SSH_USER, SSH_PRIVATE_KEY, PROJECTS_BASE_DIR };
const missing = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error(`Error: missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

// SSH_PRIVATE_KEY holds the key content. As a convenience, if it looks like a
// filesystem path instead, read the file.
const sshPrivateKey = SSH_PRIVATE_KEY.includes("PRIVATE KEY")
  ? SSH_PRIVATE_KEY
  : readFileSync(SSH_PRIVATE_KEY, "utf-8");

// --- OAuth 2.1 Provider (file-persisted, survives pod restarts) ---

const FIXED_CLIENT_ID = createHash("sha256").update(`${MCP_SECRET}:client_id`).digest("hex").slice(0, 36);
const FIXED_CLIENT_SECRET = createHash("sha256").update(`${MCP_SECRET}:client_secret`).digest("hex");

class TokenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = { tokens: {}, codes: {} };
    this._load();
  }

  _load() {
    try {
      if (existsSync(this.filePath)) {
        this.data = JSON.parse(readFileSync(this.filePath, "utf-8"));
      }
    } catch (err) {
      console.warn(`[tokenstore] Failed to load ${this.filePath}: ${err.message}, starting fresh`);
      this.data = { tokens: {}, codes: {} };
    }
  }

  _save() {
    try {
      writeFileSync(this.filePath, JSON.stringify(this.data));
    } catch (err) {
      console.error(`[tokenstore] Failed to save ${this.filePath}: ${err.message}`);
    }
  }

  getToken(key) { return this.data.tokens[key]; }
  setToken(key, value) { this.data.tokens[key] = value; this._save(); }
  deleteToken(key) { delete this.data.tokens[key]; this._save(); }

  getCode(key) { return this.data.codes[key]; }
  setCode(key, value) { this.data.codes[key] = value; this._save(); }
  deleteCode(key) { delete this.data.codes[key]; this._save(); }
}

class ClientsStore {
  constructor() {
    this.client = {
      client_id: FIXED_CLIENT_ID,
      client_secret: FIXED_CLIENT_SECRET,
      redirect_uris: [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
      ],
      client_name: "Claude",
      token_endpoint_auth_method: "client_secret_post",
    };
  }
  async getClient(clientId) {
    return clientId === FIXED_CLIENT_ID ? this.client : undefined;
  }
  async registerClient(_metadata) {
    return this.client;
  }
}

class OAuthProvider {
  constructor(store) {
    this.clientsStore = new ClientsStore();
    this.store = store;
  }

  async authorize(client, params, res) {
    console.log(`[oauth] authorize: client=${client.client_id} redirect=${params.redirectUri}`);
    const code = randomUUID();
    this.store.setCode(code, { client, params, createdAt: Date.now() });

    const searchParams = new URLSearchParams({ code });
    if (params.state) searchParams.set("state", params.state);

    const targetUrl = new URL(params.redirectUri);
    targetUrl.search = searchParams.toString();
    res.redirect(targetUrl.toString());
  }

  async challengeForAuthorizationCode(_client, code) {
    const data = this.store.getCode(code);
    if (!data) throw new Error("Invalid authorization code");
    return data.params.codeChallenge;
  }

  async exchangeAuthorizationCode(client, code, _codeVerifier) {
    console.log(`[oauth] exchangeCode: client=${client.client_id} code=${code.slice(0, 8)}...`);
    const data = this.store.getCode(code);
    if (!data) throw new Error("Invalid authorization code");
    if (data.client.client_id !== client.client_id) throw new Error("Client mismatch");
    this.store.deleteCode(code);

    const accessToken = randomUUID();
    const refreshToken = randomUUID();
    const expiresIn = 86400;

    this.store.setToken(accessToken, {
      clientId: client.client_id,
      scopes: data.params.scopes || [],
      expiresAt: Date.now() + expiresIn * 1000,
      resource: data.params.resource,
    });
    this.store.setToken(refreshToken, {
      clientId: client.client_id,
      scopes: data.params.scopes || [],
      type: "refresh",
    });

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope: (data.params.scopes || []).join(" "),
    };
  }

  async exchangeRefreshToken(client, refreshToken, scopes, _resource) {
    const data = this.store.getToken(refreshToken);
    if (!data || data.type !== "refresh") throw new Error("Invalid refresh token");
    if (data.clientId !== client.client_id) throw new Error("Client mismatch");
    this.store.deleteToken(refreshToken);

    const newAccessToken = randomUUID();
    const newRefreshToken = randomUUID();
    const expiresIn = 86400;

    this.store.setToken(newAccessToken, {
      clientId: client.client_id,
      scopes: scopes || data.scopes,
      expiresAt: Date.now() + expiresIn * 1000,
    });
    this.store.setToken(newRefreshToken, {
      clientId: client.client_id,
      scopes: scopes || data.scopes,
      type: "refresh",
    });

    return {
      access_token: newAccessToken,
      token_type: "bearer",
      expires_in: expiresIn,
      refresh_token: newRefreshToken,
      scope: (scopes || data.scopes).join(" "),
    };
  }

  async verifyAccessToken(token) {
    const data = this.store.getToken(token);
    if (!data || data.type === "refresh") throw new Error("Invalid token");
    if (data.expiresAt && data.expiresAt < Date.now()) {
      this.store.deleteToken(token);
      throw new Error("Token expired");
    }
    return {
      token,
      clientId: data.clientId,
      scopes: data.scopes,
      expiresAt: data.expiresAt ? Math.floor(data.expiresAt / 1000) : undefined,
      resource: data.resource,
    };
  }

  async revokeToken(token) {
    this.store.deleteToken(token);
  }
}

// --- SSH helper ---

/**
 * Open a fresh SSH connection, run a single command, return its result.
 * A connection per call keeps the server stateless and avoids stale sockets;
 * the tool calls are infrequent enough that pooling adds no real benefit.
 */
function sshExec(command, { timeoutMs = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn, arg) => { if (!settled) { settled = true; conn.end(); fn(arg); } };

    const timer = setTimeout(() => finish(reject, new Error(`SSH command timed out after ${timeoutMs}ms`)), timeoutMs);

    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) { clearTimeout(timer); return finish(reject, err); }
        stream
          .on("close", (code) => { clearTimeout(timer); finish(resolve, { code, stdout, stderr }); })
          .on("data", (d) => { stdout += d.toString(); })
          .stderr.on("data", (d) => { stderr += d.toString(); });
      });
    });
    conn.on("error", (err) => { clearTimeout(timer); finish(reject, err); });
    conn.connect({
      host: SSH_HOST,
      port: SSH_PORT,
      username: SSH_USER,
      privateKey: sshPrivateKey,
      passphrase: SSH_PASSPHRASE,
      readyTimeout: 15000,
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Strip ANSI escape sequences (the remote-control TUI redraws are full of them). */
function stripAnsi(s) {
  return s
    .replace(/\][^]*(?:|\\)/g, "") // OSC (e.g. hyperlinks)
    .replace(/\[[0-9;?]*[ -/]*[@-~]/g, "") // CSI (cursor / colour codes)
    .replace(/\r/g, "\n"); // CR — TUI redraws overwrite lines in place
}

/**
 * The canonical claude.ai/code session link. Matching it exactly matters when
 * reading a rendered pane: the TUI also shows docs and promo links, and the URL
 * can end up flush against box-drawing characters, both of which the generic
 * "everything up to whitespace" pattern below would happily return.
 */
function extractSessionUrl(text) {
  const m = text.match(/https?:\/\/(?:claude\.ai|claude\.com)\/code\/[A-Za-z0-9_-]+/);
  return m ? m[0] : null;
}

/** As above, falling back to the first URL of any shape — for logs only. */
function extractUrl(log) {
  const session = extractSessionUrl(log);
  if (session) return session;
  const any = log.match(/https?:\/\/[^\s'"\]]+/);
  return any ? any[0] : null;
}

/** Last `n` meaningful lines of a log, with consecutive duplicates collapsed. */
function logTail(log, n = 16) {
  const lines = [];
  for (const raw of stripAnsi(log).split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (!line) continue;
    if (line !== lines[lines.length - 1]) lines.push(line);
  }
  return lines.slice(-n).join("\n");
}

// --- Input validation (these values are interpolated into shell commands) ---

const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,40}$/;
const ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,60}$/;

function validateName(name) {
  if (!NAME_RE.test(name || "")) {
    throw new Error("Invalid name: 1-41 chars, [a-zA-Z0-9_-], must start alphanumeric");
  }
  return name;
}

function validateId(id) {
  if (!ID_RE.test(id || "")) throw new Error("Invalid session id");
  return id;
}

function validateRelPath(p) {
  if (!p || typeof p !== "string") throw new Error("path is required");
  if (p.startsWith("/")) throw new Error("path must be relative to PROJECTS_BASE_DIR");
  const segs = p.split("/").filter(Boolean);
  if (!segs.length) throw new Error("path is empty");
  for (const s of segs) {
    if (s === "." || s === ".." || !/^[a-zA-Z0-9._-]+$/.test(s)) {
      throw new Error(`Invalid path segment: "${s}"`);
    }
  }
  return segs.join("/");
}

const ok = (text) => ({ content: [{ type: "text", text }] });
const fail = (text) => ({ content: [{ type: "text", text }], isError: true });

// --- Session lifecycle ---

/**
 * Poll a session until the remote-control URL appears, the tmux session dies
 * (claude exited / errored), or the timeout elapses.
 *
 * `fromPane` is for interactive sessions: their TUI draws the URL in chunks
 * separated by cursor-positioning escapes, so stripping the escapes out of the
 * raw log yields a mangled URL, while tmux — being the terminal emulator —
 * renders it correctly. It is deliberately off for the Remote Control server,
 * whose log is clean line output and whose *pane* is the unreliable one: there
 * the URL is long enough to be wrapped across two rows. The logfile is read in
 * both cases regardless — it is what the caller reports as the startup tail,
 * and all that survives a session that dies before it is ever ready.
 */
async function pollSession(id, { timeoutMs = 35000, fromPane = false } = {}) {
  const deadline = Date.now() + timeoutMs;
  let log = "";
  while (Date.now() < deadline) {
    await sleep(2000);
    const r = await sshExec(
      `tmux has-session -t rc-${id} 2>/dev/null && echo __ALIVE__ || echo __DEAD__; ` +
      `echo __PANE__; tmux capture-pane -p -S -200 -t rc-${id} 2>/dev/null || true; ` +
      `echo __LOG__; cat /tmp/rc-${id}.log 2>/dev/null || true`
    );
    const [head, ...paneAndLog] = r.stdout.split("__PANE__");
    const [pane, ...rest] = paneAndLog.join("__PANE__").split("__LOG__");
    log = stripAnsi(rest.join("__LOG__")).trim();
    const alive = head.includes("__ALIVE__");
    const url = fromPane ? extractSessionUrl(pane) : extractUrl(log);
    if (url) return { state: "ready", alive, url, log };
    if (!alive) return { state: "exited", alive: false, url: null, log };
  }
  return { state: "starting", alive: true, url: null, log };
}

// --- Talking to a live session ---

/**
 * Claude Code writes one JSONL transcript per conversation under
 * <config dir>/projects/<slugified cwd>/<session uuid>.jsonl. Reading the
 * reply from there instead of scraping the pane is what makes `send_prompt`
 * reliable: the transcript is clean UTF-8 text, unwrapped, never truncated to
 * the terminal width, and every assistant entry carries an explicit
 * `stop_reason` — so the end of a turn is a fact, not a guess about whether
 * the pane has stopped changing. The slug is not reconstructed here (the
 * escaping rules are the CLI's business); the file is found by mtime instead.
 */
const CLAUDE_PROJECTS_DIR = '"${CLAUDE_CONFIG_DIR:-$HOME/.claude}/projects"';

/**
 * Shell fragment that leaves the session's transcript path in `$TR`, resolving
 * it once and caching it in /tmp/rc-<id>.tr. A candidate qualifies if it was
 * touched after the session started — /tmp/rc-<id>.meta is written immediately
 * before `tmux new-session`, so it is the reference mtime — and records the
 * project directory as its `cwd`. Newest first, so two sessions on the same
 * project resolve to the one that has actually been written to most recently.
 */
function transcriptLookup(id, dir) {
  return (
    `TR=$(cat /tmp/rc-${id}.tr 2>/dev/null); ` +
    `if [ -z "$TR" ] || [ ! -f "$TR" ]; then ` +
    `TR=$(find ${CLAUDE_PROJECTS_DIR} -maxdepth 2 -name '*.jsonl' -newer /tmp/rc-${id}.meta -printf '%T@ %p\\n' 2>/dev/null ` +
    `| sort -rn | while read -r _ f; do head -c 4000 "$f" | grep -qE '"cwd": ?"${dir}"' && { printf %s "$f"; break; }; done); ` +
    `[ -n "$TR" ] && printf %s "$TR" > /tmp/rc-${id}.tr; fi; `
  );
}

/**
 * The tool-approval box. Deliberately strict — it wants the question *and* the
 * numbered list right after it — because a loose "1. Yes" would also match a
 * diff or a file listing that happens to be on screen. The box-drawing
 * characters are part of the line: `capture-pane` renders the frame, so the
 * options come through as "│ ❯ 1. Yes", not as "1. Yes".
 */
const PERMISSION_RE = /(?:Do you want|Would you like)[\s\S]{0,400}?(?:^|\n)[\s│┃|]*(?:[❯>]\s*)?1\.\s/;

const MAX_REPLY_CHARS = 24000;

/** How far back `get_reply` looks when it has no cursor of its own. */
const INITIAL_TAIL_LINES = 200;

/** Parse JSONL, ignoring anything that is not a complete object. */
function parseJsonl(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s.startsWith("{")) continue;
    try { entries.push(JSON.parse(s)); } catch { /* partial line */ }
  }
  return entries;
}

const isToolResult = (e) =>
  Array.isArray(e.message?.content) && e.message.content.some((c) => c.type === "tool_result");

/**
 * The assistant's closing message of the turn that started after `sinceIso`,
 * or null while that turn is still running. Sidechains (sub-agents) are
 * excluded — they finish mid-turn and would otherwise read as the answer.
 *
 * The turn is anchored on the prompt, not on the clock: a turn that was
 * already running when ours was pasted also finishes after `sinceIso`, and its
 * answer is not the one that was asked for. A prompt only becomes a user entry
 * once the session picks it up — it may sit in the queue behind whatever the
 * session was doing — so "no user entry yet" means "not started yet", not
 * "nothing to report".
 *
 * A turn is over when the last main-chain entry is an assistant message that
 * neither carries a tool_use block nor stopped *for* one. Both checks are
 * needed: thinking, text and tool_use arrive as separate entries, so a
 * text-only entry can still be the prelude to a tool call — `stop_reason` is
 * what tells them apart.
 */
function finalReply(entries, sinceIso) {
  const chain = entries.filter(
    (e) => e && !e.isSidechain && (e.type === "assistant" || e.type === "user")
  );
  let turn = chain;
  if (sinceIso) {
    const anchor = chain.findLastIndex(
      (e) => e.type === "user" && e.timestamp > sinceIso && !isToolResult(e)
    );
    // No anchor is only "not started yet" if the window reaches back before the
    // mark. When everything in view is already newer — a turn long enough to
    // have pushed the prompt out of `get_reply`'s initial window — the turn has
    // obviously started.
    if (anchor === -1 && chain[0]?.timestamp <= sinceIso) return null;
    if (anchor >= 0) turn = chain.slice(anchor);
  }
  const last = turn[turn.length - 1];
  if (!last || last.type !== "assistant") return null; // a tool_result is pending
  if (last.message?.stop_reason === "tool_use") return null;
  const content = last.message?.content;
  if (!Array.isArray(content) || content.some((c) => c.type === "tool_use")) return null;
  const text = content.filter((c) => c.type === "text").map((c) => c.text).join("\n").trim();
  if (!text) return null;
  return text.length > MAX_REPLY_CHARS
    ? `${text.slice(0, MAX_REPLY_CHARS)}\n\n… (reply truncated at ${MAX_REPLY_CHARS} characters)`
    : text;
}

/**
 * The project directory recorded at startup, re-validated. `start_session`
 * only ever writes a path it built from `PROJECTS_BASE_DIR` and a checked
 * relative path, but the value makes a round-trip through a file on the server
 * before being interpolated into a shell command — so it is checked again on
 * the way back in, like every other input that reaches a command line.
 */
function metaDir(meta) {
  const dir = meta?.dir || "";
  if (!dir.startsWith(`${PROJECTS_BASE_DIR}/`) || !/^[a-zA-Z0-9._/-]+$/.test(dir)) {
    throw new Error("session metadata is malformed — start a new session");
  }
  return dir;
}

/** Everything `send_prompt` / `get_reply` need to know about a session, in one round-trip. */
async function readState(id) {
  const r = await sshExec(
    `tmux has-session -t rc-${id} 2>/dev/null && echo __ALIVE__ || echo __DEAD__; ` +
    `echo __META__; cat /tmp/rc-${id}.meta 2>/dev/null; ` +
    `echo __PENDING__; cat /tmp/rc-${id}.pending 2>/dev/null; ` +
    `echo __URL__; cat /tmp/rc-${id}.url 2>/dev/null; ` +
    `echo __PANE__; tmux capture-pane -p -S -60 -t rc-${id} 2>/dev/null || true`
  );
  const grab = (a, b) => {
    const after = r.stdout.split(a)[1];
    return after === undefined ? "" : after.split(b)[0];
  };
  let meta = null;
  try { meta = JSON.parse(grab("__META__", "__PENDING__").trim()); } catch { /* pre-1.1 session */ }
  return {
    alive: r.stdout.split("__META__")[0].includes("__ALIVE__"),
    meta,
    pending: grab("__PENDING__", "__URL__").trim() || null,
    url: grab("__URL__", "__PANE__").trim() || null,
    pane: stripAnsi(r.stdout.split("__PANE__").slice(1).join("__PANE__")),
  };
}

/**
 * Poll a session until its current turn produces a final answer, it stops for
 * a permission prompt, it dies, or `timeoutMs` elapses. Timing out is a normal
 * outcome, not an error: the caller reports it and the user collects the
 * answer later with `get_reply`.
 *
 * Reading is incremental — each poll asks only for the transcript lines it has
 * not seen. Transcripts routinely reach hundreds of KB (a single tool result
 * can be 70 KB on one line), so re-reading the tail every three seconds would
 * push megabytes through the SSH channel for one turn. The cursor is a line
 * count, not a byte offset, so it cannot be knocked out of step by a multi-byte
 * character landing on a chunk boundary. `fromLine` lets `send_prompt` start at
 * the end of the transcript as it stood when the prompt was pasted, which makes
 * the first poll free too.
 */
async function waitForReply(id, dir, sinceIso, { timeoutMs, fromLine = null }) {
  const deadline = Date.now() + timeoutMs;
  const entries = [];
  let cursor = fromLine;
  for (;;) {
    const cursorExpr = cursor === null
      ? `LINES=$(wc -l < "$TR" 2>/dev/null || echo 0); START=$(( LINES > ${INITIAL_TAIL_LINES} ? LINES - ${INITIAL_TAIL_LINES} : 0 ))`
      : `START=${cursor}`;
    const r = await sshExec(
      `tmux has-session -t rc-${id} 2>/dev/null && echo __ALIVE__ || echo __DEAD__; ` +
      transcriptLookup(id, dir) +
      `echo __PANE__; tmux capture-pane -p -S -60 -t rc-${id} 2>/dev/null || true; ` +
      `${cursorExpr}; echo "__FROM__$START"; ` +
      `[ -n "$TR" ] && tail -n +$((START+1)) "$TR" 2>/dev/null || true`,
      { timeoutMs: 30000 }
    );
    const [head, ...afterHead] = r.stdout.split("__PANE__");
    const [paneRaw, ...afterPane] = afterHead.join("__PANE__").split("__FROM__");
    const pane = stripAnsi(paneRaw);

    // Only whole lines advance the cursor; a line still being written is left
    // for the next poll to pick up in full.
    const rest = afterPane.join("__FROM__");
    const split = rest.indexOf("\n");
    const start = parseInt(rest.slice(0, split), 10);
    const chunk = rest.slice(split + 1);
    const whole = chunk.endsWith("\n") ? chunk : chunk.slice(0, chunk.lastIndexOf("\n") + 1);
    if (Number.isInteger(start)) {
      cursor = start + (whole ? whole.slice(0, -1).split("\n").length : 0);
      entries.push(...parseJsonl(whole));
    }

    // Answer first: a session can produce its reply and exit in the same tick.
    const reply = finalReply(entries, sinceIso);
    if (reply) return { state: "done", reply, pane };
    if (!head.includes("__ALIVE__")) return { state: "exited", pane };
    if (PERMISSION_RE.test(pane)) return { state: "awaiting_permission", pane };
    if (Date.now() >= deadline) return { state: "running", pane };
    await sleep(3000);
  }
}

/** Last `n` non-empty lines of a rendered pane — the "what is it doing" hint. */
function paneTail(pane, n = 8) {
  const lines = pane.split("\n").map((l) => l.replace(/\s+$/, "")).filter(Boolean);
  return lines.slice(-n).join("\n");
}

function formatOutcome(id, result, { url, waitedSeconds }) {
  if (result.state === "done") return ok(`Reply from session "${id}":\n\n${result.reply}`);
  if (result.state === "awaiting_permission") {
    return ok(
      `Session "${id}" is waiting for a tool-approval answer, so the turn cannot finish ` +
      `until someone responds. Open it and approve (or start sessions with ` +
      `\`bypass_permissions\` if they should run unattended).` +
      (url ? `\n${url}` : "") + `\n\nPane:\n${paneTail(result.pane)}`
    );
  }
  if (result.state === "exited") {
    return fail(`Session "${id}" is no longer running and produced no final answer.\n\nPane:\n${paneTail(result.pane)}`);
  }
  return ok(
    `Session "${id}" is still working after ${waitedSeconds}s. ` +
    `Call \`get_reply\` with the same id to collect the answer when it is done.` +
    `\n\nPane:\n${paneTail(result.pane)}`
  );
}

const SERVER_INSTRUCTIONS = `
This MCP launches and manages Claude Code Remote Control sessions on a remote
development server over SSH. Use it when the user asks to "open / start / launch
a remote (control) session", "spin up Claude on the dev server", "list my remote
sessions", "stop session X", or anything equivalent — including ambiguous asks
like "open Claude on <project>" once it is clear they mean the remote server,
not their local machine.

Usage guidance:
- Before calling \`start_session\`, prefer running \`list_projects\` to discover
  valid \`path\` values rather than guessing. The \`path\` is relative to the
  server's projects base directory.
- Call \`list_sessions\` first if the user might already have a live session for
  the same project — reuse it instead of creating a duplicate.
- \`bypass_permissions\` appends \`--dangerously-skip-permissions\`. Only set it
  when the user has explicitly asked to skip permission prompts (e.g. "no
  approvals", "yolo mode", "bypass permissions"). Never enable it on your own
  initiative.
- \`prompt\` makes the session start working immediately on that instruction —
  use it whenever the user says what the session should *do* ("open a session
  on X and run the tests", "start one on Y and run /security-review"), not just
  where to open it. Slash commands are valid prompts. The session stays open
  after the task, so the user can take over from claude.ai/code.
- \`interactive: true\` opens an empty conversational session, for when the user
  wants to drive it from here with \`send_prompt\` rather than give it a task
  up front.
- \`worktree: true\` is for when the user wants isolated git worktrees per
  spawned sub-session; otherwise omit it and let the server default decide. It
  does not apply to conversational sessions (\`prompt\` / \`interactive\`).
- After \`start_session\` returns a URL, surface it to the user — that is the
  link they open to drive the session from claude.ai/code.
- \`send_prompt\` continues an existing conversation and returns the session's
  final answer; \`get_reply\` collects an answer that was not ready in time, or
  the answer to the \`prompt\` a session was started with. Prefer them over
  starting a second session on the same project — they keep the context and the
  user can still watch at claude.ai/code. Both only work on conversational
  sessions; \`list_sessions\` shows which sessions those are.
- A session without \`bypass_permissions\` stalls mid-turn on tool-approval
  prompts, and \`send_prompt\` will report that instead of an answer. Say so
  rather than retrying — someone has to approve it at claude.ai/code.
- \`stop_session\` is destructive (kills the tmux session); confirm with the
  user before calling it unless they named the id explicitly.
`.trim();

function createMcpServer() {
  const server = new McpServer(
    { name: "claude-code-rc-mcp", version: "1.0.0" },
    { instructions: SERVER_INSTRUCTIONS }
  );

  server.tool(
    "start_session",
    "Launch a new Claude Code Remote Control session on the remote dev server (over SSH, inside a detached tmux session) and return its URL. " +
      "Use when the user asks to start / open / spin up a remote Claude Code session on a given project. " +
      "Pass `prompt` when the user wants the session to start working right away — 'open a session on X and run the tests', 'start a session and run /security-review'; the session stays open afterwards so they can take over from claude.ai/code. " +
      "Prefer calling `list_projects` first to discover valid `path` values, and `list_sessions` to avoid duplicating a live session for the same project. " +
      "Set `bypass_permissions` only when the user explicitly asks to skip approval prompts.",
    {
      name: z.string().describe("Short label for the session, shown in claude.ai/code (1-41 chars, [a-zA-Z0-9_-])"),
      path: z.string().describe("Project directory, relative to PROJECTS_BASE_DIR (e.g. 'my-project'). Use list_projects to discover valid values."),
      prompt: z.string().optional().describe("Initial prompt or slash command to run as soon as the session opens (e.g. 'run the test suite' or '/security-review'). Switches the session to conversational mode (`claude --rc`), where `worktree` does not apply and `send_prompt` / `get_reply` work."),
      interactive: z.boolean().optional().describe("If true, open an empty conversational session (`claude --rc`) with no initial prompt, ready to receive `send_prompt`. Implied by `prompt`. Like `prompt`, it disables `worktree`."),
      worktree: z.boolean().optional().describe("If true, spawn on-demand sessions in isolated git worktrees (--spawn worktree). Defaults to the SPAWN_WORKTREE env var. Ignored when `prompt` or `interactive` is set."),
      bypass_permissions: z.boolean().optional().describe("If true, launch with --dangerously-skip-permissions so the session does not prompt for tool approvals. Use with care — but note that a session without it will stall mid-turn on approval prompts, which blocks `send_prompt` from ever getting an answer."),
    },
    async ({ name, path, prompt, interactive, worktree, bypass_permissions }) => {
      try {
        validateName(name);
        const rel = validateRelPath(path);
        const task = (prompt || "").trim();
        const conversational = Boolean(task) || interactive === true;
        const suffix = randomBytes(3).toString("hex");
        const id = `${name}-${suffix}`;
        const dir = `${PROJECTS_BASE_DIR}/${rel}`;
        const logfile = `/tmp/rc-${id}.log`;
        const promptfile = `/tmp/rc-${id}.prompt`;
        const metafile = `/tmp/rc-${id}.meta`;
        const spawn = (worktree ?? SPAWN_WORKTREE) ? "worktree" : "same-dir";
        const bypassFlag = bypass_permissions ? " --dangerously-skip-permissions" : "";

        // Two launch shapes. Plain: the persistent Remote Control server
        // (`claude remote-control`), which supports --spawn. Conversational
        // (`prompt` or `interactive`): a single session `claude --rc <name>`,
        // the only form that accepts an initial prompt and the only one with a
        // conversation of its own to send later prompts to — the server form
        // spawns its sessions as separate processes, so its pane is not a chat.
        //
        // The prompt is never interpolated into the command line — it is
        // base64'd here, decoded into a file on the server, and read back with
        // "$(cat …)", so no part of it is ever seen by a shell parser.
        //
        // An interactive session also needs a real TTY: piping stdout into
        // `tee` makes Claude Code fall back to --print and refuse to start, so
        // the log is captured with `tmux pipe-pane` off the pane's own TTY.
        // That pipe is detached again once the session is up (see below) —
        // it mirrors every TUI redraw, so left on it would grow without bound.
        //
        // The meta file is written *before* tmux starts, so its mtime is the
        // reference point `transcriptLookup` uses to tell this session's
        // transcript from any older one in the same project.
        const meta = { mode: conversational ? "session" : "server", dir, name };
        const metaB64 = Buffer.from(JSON.stringify(meta), "utf-8").toString("base64");
        let setup = `printf %s '${metaB64}' | base64 -d > ${metafile}; `;
        let inner;
        let capture = "";
        if (conversational) {
          let arg = "";
          if (task) {
            const b64 = Buffer.from(task, "utf-8").toString("base64");
            setup += `printf %s '${b64}' | base64 -d > ${promptfile} || { echo __NO_PROMPT_FILE__; exit 6; }; `;
            arg = ` "$(cat ${promptfile})"`;
          }
          inner = `${CLAUDE_BIN}${bypassFlag} --rc ${name}${arg}`;
          capture = ` && tmux pipe-pane -o -t rc-${id} "cat >> ${logfile}"`;
        } else {
          inner = `${CLAUDE_BIN} remote-control --name ${name} --spawn ${spawn}${bypassFlag} 2>&1 | tee ${logfile}`;
        }
        const remote =
          `[ -d "${dir}" ] || { echo __NO_DIR__; exit 9; }; ` +
          `command -v tmux >/dev/null 2>&1 || { echo __NO_TMUX__; exit 8; }; ` +
          `tmux has-session -t rc-${id} 2>/dev/null && { echo __EXISTS__; exit 7; }; ` +
          setup +
          `tmux new-session -d -s rc-${id} -c "${dir}" '${inner}'${capture} && echo __STARTED__`;

        const r = await sshExec(remote);
        if (r.stdout.includes("__NO_DIR__")) return fail(`Project directory not found: ${rel}`);
        if (r.stdout.includes("__NO_TMUX__")) return fail("tmux is not installed on the remote server.");
        if (r.stdout.includes("__NO_PROMPT_FILE__")) return fail(`Could not write the prompt file ${promptfile} on the remote server.`);
        if (!r.stdout.includes("__STARTED__")) {
          return fail(`Failed to start tmux session (exit ${r.code}).\n${r.stdout}\n${r.stderr}`.trim());
        }

        // With a prompt the session is busy working while Remote Control is
        // still connecting, so the URL takes noticeably longer to show up.
        const result = await pollSession(id, { timeoutMs: task ? 50000 : 35000, fromPane: conversational });
        const tail = logTail(result.log);

        if (result.state === "exited") {
          await sshExec(`rm -f ${logfile} ${promptfile} ${metafile}`);
          return fail(
            `Session "${id}" exited before becoming ready — likely a startup error ` +
            `(e.g. Claude Code not authenticated on the server).\n\nLog:\n${tail}`
          );
        }

        // The startup log has served its purpose. Detach the pipe so the TUI
        // stops appending to it, and record the URL in its own file — by the
        // time `list_sessions` runs, the URL has usually scrolled out of the
        // pane, and the raw log only holds the escape-split version of it.
        const post = [];
        if (conversational) post.push(`tmux pipe-pane -t rc-${id} 2>/dev/null`);
        if (result.url) {
          const urlB64 = Buffer.from(result.url, "utf-8").toString("base64");
          post.push(`printf %s '${urlB64}' | base64 -d > /tmp/rc-${id}.url`);
        }
        if (post.length) await sshExec(`${post.join("; ")}; true`);

        const header =
          `Session started: ${id}\n` +
          `Project: ${rel}  ·  ` + (conversational ? `mode: conversational` : `spawn: ${spawn}`) +
          (bypass_permissions ? `  ·  bypass: on` : "") + `\n` +
          (task ? `Running: ${task.length > 120 ? `${task.slice(0, 117)}...` : task}\n` : "") +
          (result.url ? `Session URL: ${result.url}\n` : "") +
          `\nIt should now appear in the session list at https://claude.ai/code` +
          (conversational
            ? `\nYou can also drive it from here: \`send_prompt\` with id "${id}"` +
              (task ? `, or \`get_reply\` to collect the answer to the initial prompt.` : `.`)
            : "") +
          (result.state === "starting" ? `\n(still initialising — give it a few more seconds)` : "");
        return ok(`${header}\n\nLog:\n${tail}`);
      } catch (err) {
        return fail(`start_session error: ${err.message}`);
      }
    }
  );

  server.tool(
    "send_prompt",
    "Send a follow-up prompt to a Claude Code session that is already open on the remote server and return its final answer. " +
      "Use when the user wants to keep working in a session they (or you) already started — 'ask that session to also update the README', 'tell my remote session to run the tests', 'follow up on X' — instead of spinning up a new one. " +
      "The prompt is typed into the live conversation, so the session keeps all of its context and the exchange stays visible at claude.ai/code. " +
      "Long turns do not block: if the answer is not ready within `wait_seconds`, the call returns and `get_reply` collects it afterwards. " +
      "Only works on conversational sessions — those started with a `prompt` or with `interactive: true`. Use `list_sessions` to find the id.",
    {
      id: z.string().describe("Full session id from start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
      prompt: z.string().describe("What to ask the session. Slash commands work too. Multi-line text is fine — it is pasted, not typed."),
      wait_seconds: z.number().optional().describe("How long to wait for the final answer before returning (default 90, max 240). The session keeps working either way; collect the answer later with get_reply."),
    },
    async ({ id, prompt, wait_seconds }) => {
      try {
        validateId(id);
        const text = (prompt || "").trim();
        if (!text) return fail("prompt is empty.");
        const waitSeconds = Math.min(Math.max(wait_seconds ?? 90, 0), 240);

        const state = await readState(id);
        if (!state.alive) return fail(`No active session with id "${id}". Use list_sessions to see what is running.`);
        if (!state.meta) {
          return fail(
            `Session "${id}" was started by an older version of this server and has no metadata, ` +
            `so its conversation cannot be located. Start a new session to use send_prompt.`
          );
        }
        if (state.meta.mode !== "session") {
          return fail(
            `Session "${id}" is a Remote Control *server*, not a conversation — it spawns its sessions ` +
            `as separate processes, so there is nothing to send a prompt to. Start a conversational one ` +
            `with start_session (\`prompt: "…"\` or \`interactive: true\`) and send prompts to that.`
          );
        }
        const dir = metaDir(state.meta);
        // Pasting into a permission prompt would answer the wrong question.
        if (PERMISSION_RE.test(state.pane)) {
          return fail(
            `Session "${id}" is waiting for a tool-approval answer and cannot accept a prompt until ` +
            `someone responds.${state.url ? `\n${state.url}` : ""}\n\nPane:\n${paneTail(state.pane)}`
          );
        }

        // Paste rather than type: `send-keys` would turn every newline in a
        // multi-line prompt into a submit, and a long prompt into a very slow
        // keystroke replay. `-p` wraps it in bracketed-paste markers so the
        // TUI takes the whole thing as one block of text, and the explicit
        // Enter afterwards is what submits it.
        //
        // The "sent at" mark is stamped by the remote host, not by `new Date()`
        // here: it is compared against timestamps written by the session, and
        // a container clock a few seconds ahead of the dev server would put the
        // mark in their future — so the reply would never be recognised.
        // The transcript is also measured here, before the paste, so the poll
        // can start reading exactly where the new turn begins.
        const b64 = Buffer.from(text, "utf-8").toString("base64");
        const s = await sshExec(
          `SENT=$(date -u +%Y-%m-%dT%H:%M:%S.000Z); printf %s "$SENT" > /tmp/rc-${id}.pending; ` +
          transcriptLookup(id, dir) +
          `FROM=0; [ -n "$TR" ] && FROM=$(wc -l < "$TR" 2>/dev/null || echo 0); ` +
          `printf %s '${b64}' | base64 -d > /tmp/rc-${id}.send && ` +
          `tmux load-buffer -b rcbuf-${id} /tmp/rc-${id}.send && ` +
          `tmux paste-buffer -d -p -b rcbuf-${id} -t rc-${id} && ` +
          `sleep 0.4 && tmux send-keys -t rc-${id} Enter && ` +
          `echo "__SENT__$SENT $FROM"`
        );
        const sent = s.stdout.match(/__SENT__(\S+) (\d+)/);
        if (!sent) {
          return fail(`Failed to send the prompt to session "${id}" (exit ${s.code}).\n${s.stdout}\n${s.stderr}`.trim());
        }
        const [, sentAt, fromLine] = sent;

        const result = await waitForReply(id, dir, sentAt, {
          timeoutMs: waitSeconds * 1000,
          fromLine: Number(fromLine),
        });
        return formatOutcome(id, result, { url: state.url, waitedSeconds: waitSeconds });
      } catch (err) {
        return fail(`send_prompt error: ${err.message}`);
      }
    }
  );

  server.tool(
    "get_reply",
    "Collect the final answer from a Claude Code session on the remote server — the reply to the last `send_prompt`, or to the initial `prompt` a session was started with. " +
      "Use when a previous call reported the session was still working, or when the user asks 'is it done?', 'what did it say?', 'check on that session'. " +
      "Waits up to `wait_seconds` for a turn that is still in progress, and reports if the session is instead stuck on a tool-approval prompt.",
    {
      id: z.string().describe("Full session id from start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
      wait_seconds: z.number().optional().describe("How long to wait if the session is still working (default 90, max 240). Pass 0 to check without waiting."),
    },
    async ({ id, wait_seconds }) => {
      try {
        validateId(id);
        const waitSeconds = Math.min(Math.max(wait_seconds ?? 90, 0), 240);

        const state = await readState(id);
        if (!state.alive) return fail(`No active session with id "${id}". Use list_sessions to see what is running.`);
        if (!state.meta || state.meta.mode !== "session") {
          return fail(`Session "${id}" is not a conversation, so it has no reply to collect. Only sessions started with a \`prompt\` or \`interactive: true\` do.`);
        }

        // No pending marker means nothing was sent through send_prompt, so the
        // turn of interest is whatever the session ran last — typically the
        // prompt it was started with.
        const result = await waitForReply(id, metaDir(state.meta), state.pending, { timeoutMs: waitSeconds * 1000 });
        return formatOutcome(id, result, { url: state.url, waitedSeconds: waitSeconds });
      } catch (err) {
        return fail(`get_reply error: ${err.message}`);
      }
    }
  );

  server.tool(
    "list_sessions",
    "List the currently active Claude Code sessions on the remote server, with each session's URL when available " +
      "(from the URL recorded at startup, falling back to the live pane and then the log for sessions that were still initialising) " +
      "and its mode — `conversational` sessions are the ones `send_prompt` / `get_reply` can talk to. " +
      "Use when the user asks 'what sessions are running', 'do I have a session for X', before `start_session` to avoid duplicates, " +
      "or to look up the id of the session they want to send a prompt to. " +
      "Also reaps the orphan files left by sessions that have already ended.",
    {},
    async () => {
      try {
        const remote =
          `for s in $(tmux list-sessions -F '#{session_name}' 2>/dev/null | grep '^rc-'); do ` +
          `echo "SESSION ${'$'}{s#rc-}"; done; ` +
          `for id in $(ls /tmp/rc-*.log /tmp/rc-*.meta 2>/dev/null | sed -e 's#^/tmp/rc-##' -e 's#\\.[a-z]*$##' | sort -u); do ` +
          `if tmux has-session -t "rc-$id" 2>/dev/null; then ` +
          `u=$(cat "/tmp/rc-$id.url" 2>/dev/null); ` +
          `[ -n "$u" ] || u=$(tmux capture-pane -p -S -200 -t "rc-$id" 2>/dev/null | grep -oE 'https?://(claude\\.ai|claude\\.com)/code/[A-Za-z0-9_-]+' | head -1); ` +
          `[ -n "$u" ] || u=$(grep -aoE 'https?://(claude\\.ai|claude\\.com)/code/[A-Za-z0-9_-]+' "/tmp/rc-$id.log" 2>/dev/null | head -1); ` +
          `[ -n "$u" ] || u=$(grep -aoE 'https?://[^[:space:]]+' "/tmp/rc-$id.log" 2>/dev/null | head -1); ` +
          `m=$(grep -o '"mode":"[a-z]*"' "/tmp/rc-$id.meta" 2>/dev/null | cut -d'"' -f4); ` +
          `[ -n "$m" ] || m=unknown; ` +
          `echo "INFO $id $m $u"; ` +
          `else echo "CLEANED $id"; ` +
          `rm -f "/tmp/rc-$id.log" "/tmp/rc-$id.prompt" "/tmp/rc-$id.url" "/tmp/rc-$id.meta" "/tmp/rc-$id.tr" "/tmp/rc-$id.pending" "/tmp/rc-$id.send"; ` +
          `fi; done`;
        const r = await sshExec(remote);
        const lines = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
        const ids = lines.filter((l) => l.startsWith("SESSION ")).map((l) => l.slice(8));
        const info = {};
        for (const l of lines.filter((l) => l.startsWith("INFO "))) {
          const [, id, mode, url] = l.split(" ");
          info[id] = { mode, url };
        }
        if (!ids.length) return ok("No active sessions.");
        const label = { session: "conversational", server: "remote-control server" };
        const body = ids
          .map((id) => {
            const { mode, url } = info[id] || {};
            return `• ${id}${label[mode] ? `  —  ${label[mode]}` : ""}${url ? `\n    ${url}` : ""}`;
          })
          .join("\n");
        return ok(
          `Active sessions (${ids.length}):\n${body}` +
          (ids.some((id) => info[id]?.mode === "session")
            ? `\n\nConversational sessions accept \`send_prompt\` / \`get_reply\`.`
            : "")
        );
      } catch (err) {
        return fail(`list_sessions error: ${err.message}`);
      }
    }
  );

  server.tool(
    "stop_session",
    "Stop a Claude Code session by its full id (kills the tmux session and removes its scratch files). " +
      "Destructive — any in-progress work in that session is lost. Confirm with the user before calling unless they explicitly named the id. " +
      "Use `list_sessions` to look up the id if the user only referenced the session by name.",
    {
      id: z.string().describe("Full session id as returned by start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
    },
    async ({ id }) => {
      try {
        validateId(id);
        const r = await sshExec(
          `tmux kill-session -t rc-${id} 2>/dev/null && echo __KILLED__ || echo __NOT_FOUND__; ` +
          `rm -f /tmp/rc-${id}.log /tmp/rc-${id}.prompt /tmp/rc-${id}.url ` +
          `/tmp/rc-${id}.meta /tmp/rc-${id}.tr /tmp/rc-${id}.pending /tmp/rc-${id}.send`
        );
        if (r.stdout.includes("__KILLED__")) return ok(`Session "${id}" stopped.`);
        return fail(`No active session with id "${id}".`);
      } catch (err) {
        return fail(`stop_session error: ${err.message}`);
      }
    }
  );

  server.tool(
    "list_projects",
    "List the project directories available on the remote server (only those containing a .git or .claude entry). " +
      "Call this before `start_session` whenever the user-supplied project name is ambiguous, abbreviated, or you would otherwise be guessing the `path`. " +
      "The returned names are the exact values to pass as `path`.",
    {},
    async () => {
      try {
        const remote =
          `for d in "${PROJECTS_BASE_DIR}"/*/; do [ -d "$d" ] || continue; ` +
          `if [ -e "$d/.git" ] || [ -e "$d/.claude" ]; then basename "$d"; fi; done`;
        const r = await sshExec(remote);
        const projects = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean).sort();
        if (!projects.length) return ok(`No projects found under ${PROJECTS_BASE_DIR}.`);
        return ok(`Projects (${projects.length}):\n${projects.map((p) => `• ${p}`).join("\n")}`);
      } catch (err) {
        return fail(`list_projects error: ${err.message}`);
      }
    }
  );

  return server;
}

// --- Express App ---

const tokenStore = new TokenStore(TOKEN_STORE_PATH);
const provider = new OAuthProvider(tokenStore);
const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(`[http] ${req.method} ${req.path}`);
  next();
});

app.get("/health", (_, res) => res.json({ ok: true, version: "1.0.0" }));

const issuerUrl = new URL(SERVER_URL);
app.use(mcpAuthRouter({
  provider,
  issuerUrl,
  scopesSupported: ["mcp:tools"],
}));

const transports = new Map();

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "Missing token" });
    return;
  }
  try {
    req.auth = await provider.verifyAccessToken(authHeader.slice(7));
    next();
  } catch (err) {
    res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: err.message });
  }
};

app.post("/mcp", authMiddleware, async (req, res) => {
  try {
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId && transports.has(sessionId)) {
      await transports.get(sessionId).handleRequest(req, res, req.body);
    } else {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      transport.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      const server = createMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      if (transport.sessionId) {
        transports.set(transport.sessionId, transport);
        console.log(`[mcp] new session: ${transport.sessionId}`);
      }
    }
  } catch (err) {
    console.error(`[mcp] POST error: ${err.message}\n${err.stack}`);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

app.get("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId || !transports.has(sessionId)) {
    return res.status(400).json({ error: "Missing or invalid session ID" });
  }
  await transports.get(sessionId).handleRequest(req, res);
});

app.delete("/mcp", authMiddleware, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId).handleRequest(req, res);
    transports.delete(sessionId);
  } else {
    res.status(404).json({ error: "Session not found" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`claude-code-rc-mcp listening on :${PORT}`);
  console.log(`OAuth issuer:        ${SERVER_URL}`);
  console.log(`OAuth client_id:     ${FIXED_CLIENT_ID}`);
  console.log(`OAuth client_secret: ${FIXED_CLIENT_SECRET}`);
  console.log(`MCP endpoint:        ${SERVER_URL}/mcp (Streamable HTTP)`);
  console.log(`SSH target:          ${SSH_USER}@${SSH_HOST}:${SSH_PORT}`);
  console.log(`Projects base dir:   ${PROJECTS_BASE_DIR}`);
});
