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
// Appended to the system prompt of every conversational session (`--append-system-prompt`),
// resumed ones included - e.g. house rules for sessions driven from here.
const APPEND_SYSTEM_PROMPT = (process.env.APPEND_SYSTEM_PROMPT || "").trim();

/**
 * Always appended ahead of APPEND_SYSTEM_PROMPT. `send_prompt` delivers a
 * prompt as a bracketed paste (see there for why), and Claude Code wraps
 * pasted text in <pasted_content> tags while its own system prompt says to
 * follow instructions in those only when the user's own message asks for it.
 * A prompt sent from here is nothing *but* pasted text, so without this note a
 * session can refuse it outright - seen right after a /clear, with no earlier
 * message in the conversation to lean on. The tags carry no other meaning in these
 * sessions: text pasted at claude.ai/code reaches them as a plain message.
 */
const RC_SYSTEM_PROMPT =
  "This session is driven remotely through claude-code-rc-mcp, which types each prompt into the " +
  "terminal as a bracketed paste. That is why the user's messages arrive wrapped in <pasted_content> " +
  "tags: treat the text inside them as the user's own message, written by them for this session.";
const SESSION_SYSTEM_PROMPT = [RC_SYSTEM_PROMPT, APPEND_SYSTEM_PROMPT].filter(Boolean).join("\n\n");
const SESSION_RETENTION_DAYS = parseFloat(process.env.SESSION_RETENTION_DAYS || "14");
const VERSION = "1.2.0";

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
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

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

// --- Remote state ---

/**
 * Per-session state lives on the dev server under ~/.claude-rc-mcp. A container
 * restart wipes /tmp, and with it everything needed to bring a session back -
 * its project, name, permission mode and conversation id - while the
 * conversations themselves live under ~/.claude and survive. Keeping the
 * pointer next to them is what makes `resume_session` possible.
 *
 * One directory, one file set per session, `<id>.<ext>`:
 *   meta     JSON: mode, dir, name, sessionId, bypass, createdAt
 *   url      the session URL, as start_session reported it
 *   log      startup log (the pipe is detached once the session is up)
 *   prompt   initial prompt · sys: appended system prompt · send: last prompt sent
 *   pending  remote timestamp of the last send_prompt · tr: cached transcript path
 *
 * Resolved to an absolute path once, so it can be interpolated anywhere,
 * including the command tmux runs, without quoting rules of its own.
 */
let stateDirCache = null;
async function stateDir() {
  if (stateDirCache) return stateDirCache;
  const r = await sshExec(`d="$HOME/.claude-rc-mcp"; mkdir -p "$d" && printf %s "$d"`);
  const dir = r.stdout.trim();
  if (!/^\/[a-zA-Z0-9._/-]+$/.test(dir)) {
    throw new Error(`unexpected state directory on the remote server: "${dir}"`);
  }
  return (stateDirCache = dir);
}

const CLAUDE_DIR = '"${CLAUDE_CONFIG_DIR:-$HOME/.claude}"';

/**
 * Claude Code writes one JSONL transcript per conversation under
 * <config dir>/projects/<slugified cwd>/<session uuid>.jsonl. Reading the
 * reply from there instead of scraping the pane is what makes `send_prompt`
 * reliable: the transcript is clean UTF-8 text, unwrapped, never truncated to
 * the terminal width, and every assistant entry carries an explicit
 * `stop_reason` — so the end of a turn is a fact, not a guess about whether
 * the pane has stopped changing. The slug is not reconstructed here (the
 * escaping rules are the CLI's business); the file is found by its name, the
 * conversation id, which `start_session` chooses itself with `--session-id`.
 */
const CLAUDE_PROJECTS_DIR = `${CLAUDE_DIR}/projects`;

const b64 = (text) => Buffer.from(text, "utf-8").toString("base64");
const fromB64 = (s) => (s && s !== "-" ? Buffer.from(s, "base64").toString("utf-8") : "");

/** Shell fragment that writes `text` to `path` without it ever meeting a shell parser. */
const remoteWrite = (path, text) => `printf %s '${b64(text)}' | base64 -d > ${path}`;

/**
 * Run a command made of labelled sections and split its output back up. The
 * labels carry a per-call nonce because several sections are arbitrary text:
 * a pane or a transcript that shows this very file would contain any fixed
 * marker, and cut the output in the wrong place.
 */
async function sshSections(build, opts) {
  const nonce = randomBytes(6).toString("hex");
  const r = await sshExec(build((name) => `echo '@@${name}:${nonce}@@'; `), opts);
  const out = {};
  let prev = null;
  for (const m of r.stdout.matchAll(new RegExp(`@@([A-Z]+):${nonce}@@\\n`, "g"))) {
    if (prev) out[prev.name] = r.stdout.slice(prev.end, m.index);
    prev = { name: m[1], end: m.index + m[0].length };
  }
  if (prev) out[prev.name] = r.stdout.slice(prev.end);
  return { ...r, out };
}

function parseMeta(text) {
  try {
    const meta = JSON.parse((text || "").trim());
    return meta && typeof meta === "object" ? meta : null;
  } catch {
    return null; // missing, or a session that predates the metadata file
  }
}

// --- Live status ---

/**
 * Claude Code keeps a small status file per running process,
 * <config dir>/sessions/<pid>.json: whether it is busy, idle or waiting on a
 * dialog, which conversation it is in (a /clear switches to a new one), and
 * the Remote Control session it is bridged to. In conversational mode the
 * pane's process *is* claude, so the pane pid names the file.
 */
const liveSections = (id, section) =>
  `P=$(tmux display -p -t rc-${id} '#{pane_pid} #{session_created}' 2>/dev/null); ` +
  section("PROC") + `echo "$P"; ` +
  section("LIVE") + `[ -n "$P" ] && cat ${CLAUDE_DIR}/sessions/"\${P%% *}".json 2>/dev/null; echo; `;

/**
 * `status` is "busy", "idle", "shell" (idle, with a background shell still
 * running) or "waiting" (a question, approval prompt or dialog is open, named
 * by `waitingFor`). Pids repeat across container restarts, and a process that
 * is killed outright leaves its file behind, so one that predates the tmux
 * session belongs to an earlier process that happened to get the same pid,
 * and is ignored.
 */
function parseLive(proc, json) {
  const created = Number((proc || "").trim().split(" ")[1]);
  let s;
  try { s = JSON.parse((json || "").trim()); } catch { return null; }
  if (!s || !(s.startedAt >= created * 1000 - 2000)) return null;
  return {
    status: s.status,
    waitingFor: typeof s.waitingFor === "string" ? s.waitingFor : null,
    sessionId: UUID_RE.test(s.sessionId || "") ? s.sessionId : null,
    statusUpdatedAt: Number(s.statusUpdatedAt) || 0,
    url: /^session_[A-Za-z0-9]+$/.test(s.bridgeSessionId || "")
      ? `https://claude.ai/code/${s.bridgeSessionId}`
      : null,
  };
}

const isBusy = (live) => live?.status === "busy" || live?.status === "waiting";
const isIdle = (live) => live?.status === "idle" || live?.status === "shell";

async function readLive(id) {
  const { out } = await sshSections((section) => liveSections(id, section));
  return parseLive(out.PROC, out.LIVE);
}

/**
 * The conversation a session that is no longer running was last in, by Claude
 * Code's own account: the status file of the newest process that ran in its
 * tmux session. The file survives a container restart - what a resume is
 * mostly for - and unlike <id>.meta it followed any /clear typed at
 * claude.ai/code while nothing here was watching.
 */
async function lastConversation(id) {
  const r = await sshExec(
    `grep -l '"tmux":"rc-${id}:' ${CLAUDE_DIR}/sessions/*.json 2>/dev/null | ` +
    `while read -r f; do base64 < "$f" | tr -d '\\n'; echo; done`
  );
  let newest = null;
  for (const line of r.stdout.split("\n")) {
    try {
      const s = JSON.parse(fromB64(line.trim()));
      if (UUID_RE.test(s.sessionId || "") && !(newest?.startedAt >= s.startedAt)) newest = s;
    } catch { /* not a status file */ }
  }
  return newest?.sessionId || null;
}

/**
 * Press Esc until the session stops being busy - what the stop button does.
 * One press is given time to land before another: on an idle prompt a second
 * Esc opens the rewind menu, so it only goes out if the first plainly did not
 * take (a dialog on top of a running turn closes one layer per press).
 */
async function interruptTurn(id, live) {
  const deadline = Date.now() + 15000;
  let pressedAt = 0;
  while (isBusy(live)) {
    if (Date.now() >= deadline) return { done: false, live };
    if (Date.now() - pressedAt >= 4000) {
      await sshExec(`tmux send-keys -t rc-${id} Escape`);
      pressedAt = Date.now();
    }
    await sleep(700);
    live = await readLive(id);
  }
  return { done: true, live };
}

// --- Session lifecycle ---

/**
 * Poll a session until its URL appears, the tmux session dies (claude
 * exited / errored), or the timeout elapses.
 *
 * The status file is the first source: it names the Remote Control session
 * outright. The fallbacks differ per mode. `fromPane` is for conversational
 * sessions: their TUI draws the URL in chunks separated by cursor-positioning
 * escapes, so stripping the escapes out of the raw log yields a mangled URL,
 * while tmux - being the terminal emulator - renders it correctly. It is off
 * for the Remote Control server, whose log is clean line output and whose
 * *pane* is the unreliable one: there the URL is long enough to be wrapped
 * across two rows. A `resumed` session gets no fallback at all - it redraws
 * its own history, and any session link in there would read as its URL. The
 * logfile is read regardless: it is what the caller reports as the startup
 * tail, and all that survives a session that dies before it is ever ready.
 */
async function pollSession(S, id, { timeoutMs = 35000, fromPane = false, resumed = false } = {}) {
  const deadline = Date.now() + timeoutMs;
  let log = "";
  while (Date.now() < deadline) {
    await sleep(2000);
    const { out } = await sshSections((section) =>
      section("ALIVE") + `tmux has-session -t rc-${id} 2>/dev/null && echo yes; ` +
      liveSections(id, section) +
      section("PANE") + `tmux capture-pane -p -S -200 -t rc-${id} 2>/dev/null; ` +
      section("LOG") + `cat ${S}/${id}.log 2>/dev/null; true`
    );
    const alive = (out.ALIVE || "").includes("yes");
    const live = parseLive(out.PROC, out.LIVE);
    log = stripAnsi(out.LOG || "").trim();
    const url = live?.url ||
      (resumed ? null : fromPane ? extractSessionUrl(out.PANE || "") : extractUrl(log));
    if (url) return { state: "ready", alive, url, log, live };
    if (!alive) return { state: "exited", alive: false, url: null, log };
  }
  return { state: "starting", alive: true, url: null, log };
}

/**
 * Launch `claude --rc` for a conversational session - a new conversation with
 * the id recorded in `meta`, or, with `resume`, that same conversation again -
 * and wait for it to come up.
 *
 * The prompt and the appended system prompt never touch a shell parser: they
 * are base64'd here, decoded into files on the server, and read back with
 * "$(cat …)". An interactive session also needs a real TTY - piping stdout
 * into `tee` makes Claude Code fall back to --print and refuse to start - so
 * the log is captured with `tmux pipe-pane` off the pane's own TTY. That pipe
 * is detached again once the session is up: it mirrors every TUI redraw, and
 * left on it would grow without bound.
 *
 * The system prompt goes on every launch, resumes included. Claude Code
 * records a conversation's system prompt on its first request and replays
 * that record until the conversation is compacted; from then on it renders
 * the prompt afresh from what the running process was given.
 */
async function launchConversation(S, id, meta, { task = "", resume = false } = {}) {
  const dir = metaDir(meta);
  const name = metaName(meta);
  const sid = metaSessionId(meta);
  if (!sid) return { error: "the session has no recorded conversation id" };
  const file = (ext) => `${S}/${id}.${ext}`;

  const setup = [
    remoteWrite(file("meta"), JSON.stringify(meta)),
    remoteWrite(file("sys"), SESSION_SYSTEM_PROMPT),
    `: > ${file("log")}`,
  ];
  let args = `${resume ? " --resume" : " --session-id"} ${sid} --append-system-prompt "$(cat ${file("sys")})"`;
  if (task) {
    setup.push(remoteWrite(file("prompt"), task));
    args += ` "$(cat ${file("prompt")})"`;
  }
  const bypassFlag = meta.bypass ? " --dangerously-skip-permissions" : "";
  const inner = `${CLAUDE_BIN}${bypassFlag} --rc ${name}${args}`;

  const r = await sshExec(
    `[ -d "${dir}" ] || { echo __NO_DIR__; exit 9; }; ` +
    `command -v tmux >/dev/null 2>&1 || { echo __NO_TMUX__; exit 8; }; ` +
    `tmux has-session -t rc-${id} 2>/dev/null && { echo __EXISTS__; exit 7; }; ` +
    `{ ${setup.join(" && ")}; } || { echo __NO_STATE__; exit 6; }; ` +
    `tmux new-session -d -s rc-${id} -c "${dir}" '${inner}' && ` +
    `tmux pipe-pane -o -t rc-${id} "cat >> ${file("log")}" && echo __STARTED__`
  );
  if (r.stdout.includes("__NO_DIR__")) return { error: `project directory not found: ${dir}` };
  if (r.stdout.includes("__NO_TMUX__")) return { error: "tmux is not installed on the remote server" };
  if (r.stdout.includes("__EXISTS__")) return { error: `a tmux session rc-${id} is already running` };
  if (r.stdout.includes("__NO_STATE__")) return { error: `could not write the session files under ${S}` };
  if (!r.stdout.includes("__STARTED__")) {
    return { error: `failed to start tmux session (exit ${r.code}).\n${r.stdout}\n${r.stderr}`.trim() };
  }

  // With a prompt the session is busy working while Remote Control is still
  // connecting, so the URL takes noticeably longer to show up.
  const result = await pollSession(S, id, { timeoutMs: task ? 50000 : 35000, fromPane: true, resumed: resume });
  if (result.state !== "exited") {
    // The startup log has served its purpose. Record the URL in its own file:
    // by the time `list_sessions` runs it has usually scrolled out of the pane.
    const post = [`tmux pipe-pane -t rc-${id} 2>/dev/null`];
    if (result.url) post.push(remoteWrite(file("url"), result.url));
    await sshExec(`${post.join("; ")}; true`);
  }
  return result;
}

// --- Talking to a live session ---

/**
 * Shell fragment that leaves the transcript of conversation `$SID` in `$TR`,
 * cached per session in <id>.tr. The cache is only trusted while it still
 * names that conversation: a /clear moves the session on to a new one.
 */
function transcriptLookup(S, id) {
  return (
    `TR=$(cat ${S}/${id}.tr 2>/dev/null); ` +
    `case "$TR" in */"$SID".jsonl) [ -f "$TR" ] || TR= ;; *) TR= ;; esac; ` +
    `if [ -z "$TR" ]; then ` +
    `TR=$(find ${CLAUDE_PROJECTS_DIR} -maxdepth 2 -name "$SID.jsonl" 2>/dev/null | head -n 1); ` +
    `[ -n "$TR" ] && printf %s "$TR" > ${S}/${id}.tr; fi; `
  );
}

/**
 * The tool-approval box - the fallback for when the status file cannot be
 * read, which otherwise reports it as "waiting". Deliberately strict - it
 * wants the question *and* the numbered list right after it - because a loose
 * "1. Yes" would also match a diff or a file listing that happens to be on
 * screen. The box-drawing characters are part of the line: `capture-pane`
 * renders the frame, so the options come through as "│ ❯ 1. Yes".
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

/** The plain text of an entry: its string content, or its text blocks joined. */
function textOf(e) {
  const c = e.message?.content ?? e.content;
  if (typeof c === "string") return c;
  if (!Array.isArray(c)) return "";
  return c.filter((b) => b.type === "text").map((b) => b.text).join("\n");
}

/**
 * The entries a turn is made of. Left out: sidechains (sub-agents finish
 * mid-turn and would read as the answer); meta user entries (command caveats,
 * injected skill bodies, the "Continue from where you left off." a resume
 * adds) and the compaction summary, none of which the user typed; and the
 * synthetic "No response requested." that follows a resume - while synthetic
 * API errors stay, since they are how a turn that failed ends. Local commands
 * that open a dialog (/model, /cost…) are logged as `system` entries rather
 * than `user` ones, and are kept for the same reason.
 */
function mainChain(entries) {
  return entries.filter((e) => {
    if (!e || e.isSidechain) return false;
    if (e.type === "user") return !e.isMeta && !e.isCompactSummary;
    if (e.type === "assistant") return e.message?.model !== "<synthetic>" || e.isApiErrorMessage === true;
    return e.type === "system" && e.subtype === "local_command";
  });
}

const COMMAND_OUTPUT_RE = /<(local-command|bash)-(stdout|stderr)>([\s\S]*?)<\/\1-\2>/g;
const COMMAND_OUTPUT_START_RE = /^\s*<(local-command|bash)-(stdout|stderr)>/;

/**
 * Something that starts a turn: a prompt, or a slash command. The output of a
 * command is logged as a user entry of its own, and is what ends that turn.
 */
const isInput = (e) =>
  e.type === "user"
    ? !isToolResult(e) && !COMMAND_OUTPUT_START_RE.test(textOf(e))
    : textOf(e).includes("<command-name>");

/**
 * How the turn ended, judged by its last entry - or null while it is running.
 *
 * An assistant message ends it when it neither carries a tool_use block nor
 * stopped *for* one. Both checks are needed: thinking, text and tool_use
 * arrive as separate entries, so a text-only entry can still be the prelude to
 * a tool call - `stop_reason` is what tells them apart.
 *
 * A local command (/compact, /clear, /model…) gets no assistant message at
 * all: it ends on its own output, `<local-command-stdout>`. Waiting for an
 * answer there is what made /compact look like it never finished. An Esc
 * ends it on "[Request interrupted by user]".
 */
function outcomeOf(turn) {
  const last = turn[turn.length - 1];
  if (!last) return null;
  const text = textOf(last);
  if (last.type === "assistant") {
    if (last.isApiErrorMessage) return { state: "error", text: text.trim() };
    if (last.message?.stop_reason === "tool_use") return null;
    const content = last.message?.content;
    if (!Array.isArray(content) || content.some((c) => c.type === "tool_use")) return null;
    return text.trim() ? { state: "done", reply: text.trim() } : null;
  }
  const outputs = [...text.matchAll(COMMAND_OUTPUT_RE)];
  if (outputs.length) {
    const input = textOf(turn[0]);
    const slash = input.match(/<command-name>([^<]*)<\/command-name>/);
    const bang = input.match(/<bash-input>([\s\S]*?)<\/bash-input>/);
    const command = slash ? slash[1] : bang ? `!${bang[1]}` : null;
    return { state: "command", command, output: stripAnsi(outputs.map((m) => m[3]).join("\n")).trim() };
  }
  if (last.type === "user" && /^\[Request interrupted by user/.test(text.trim())) return { state: "interrupted" };
  return null;
}

/**
 * The turn that started after `sinceIso` (or the latest one in view), and how
 * it ended - `outcome` is null while it is still running.
 *
 * The turn is anchored on the prompt, not on the clock: a turn that was
 * already running when ours was pasted also finishes after `sinceIso`, and its
 * answer is not the one that was asked for. A prompt only becomes an entry
 * once the session picks it up, so "no input after the mark" means "not
 * started yet", not "nothing to report".
 */
function turnAfter(entries, sinceIso) {
  const chain = mainChain(entries);
  let anchor;
  if (sinceIso) {
    anchor = chain.findLastIndex((e) => isInput(e) && e.timestamp > sinceIso);
    // No anchor is only "not started yet" if the window reaches back before the
    // mark. When everything in view is already newer — a turn long enough to
    // have pushed the prompt out of `get_reply`'s initial window — the turn has
    // obviously started.
    if (anchor === -1 && chain[0]?.timestamp <= sinceIso) return { outcome: null, startedAt: null };
  } else {
    anchor = chain.findLastIndex(isInput);
  }
  const turn = anchor >= 0 ? chain.slice(anchor) : chain;
  const said = turn.filter((e) => e.type === "assistant").map(textOf).filter((t) => t.trim());
  return {
    outcome: outcomeOf(turn),
    startedAt: anchor >= 0 ? turn[0].timestamp : null,
    partial: said.pop() || null,
    empty: chain.length === 0,
  };
}

/** The project directory recorded at startup, re-validated. */
function metaDir(meta) {
  // `start_session` only ever writes a path it built from PROJECTS_BASE_DIR
  // and a checked relative path, but the value makes a round-trip through a
  // file on the server before being interpolated into a shell command - so it
  // is checked again on the way back in, like every other input that reaches
  // a command line. The same goes for the name and the conversation id.
  const dir = meta?.dir || "";
  if (!dir.startsWith(`${PROJECTS_BASE_DIR}/`) || !/^[a-zA-Z0-9._/-]+$/.test(dir)) {
    throw new Error("session metadata is malformed — start a new session");
  }
  return dir;
}

function metaName(meta) {
  if (!NAME_RE.test(meta?.name || "")) throw new Error("session metadata is malformed - start a new session");
  return meta.name;
}

const metaSessionId = (meta) => (UUID_RE.test(meta?.sessionId || "") ? meta.sessionId : null);

const saveMeta = (S, id, meta) => sshExec(remoteWrite(`${S}/${id}.meta`, JSON.stringify(meta)));

/**
 * `meta` following the conversation the session is in now, if a /clear moved
 * it on; null when nothing changed. Recorded wherever the live status is read,
 * because a status file only outlives a process that was killed outright (a
 * container restart): one that exits cleanly - `stop_session`, /exit - takes
 * it along, and a /clear typed at claude.ai/code is then remembered only here.
 */
const followConversation = (meta, live) =>
  meta && live?.sessionId && live.sessionId !== meta.sessionId ? { ...meta, sessionId: live.sessionId } : null;

/** Everything `send_prompt` / `get_reply` need to know about a session, in one round-trip. */
async function readState(S, id) {
  const { out } = await sshSections((section) =>
    section("ALIVE") + `tmux has-session -t rc-${id} 2>/dev/null && echo yes; ` +
    liveSections(id, section) +
    section("META") + `cat ${S}/${id}.meta 2>/dev/null; echo; ` +
    section("PENDING") + `cat ${S}/${id}.pending 2>/dev/null; echo; ` +
    section("URL") + `cat ${S}/${id}.url 2>/dev/null; echo; ` +
    section("PANE") + `tmux capture-pane -p -S -60 -t rc-${id} 2>/dev/null; true`
  );
  const alive = (out.ALIVE || "").includes("yes");
  const live = alive ? parseLive(out.PROC, out.LIVE) : null;
  return {
    alive,
    live,
    meta: parseMeta(out.META),
    pending: (out.PENDING || "").trim() || null,
    url: live?.url || (out.URL || "").trim() || null,
    pane: stripAnsi(out.PANE || ""),
  };
}

/** Relaunch a conversational session that is not running, in the conversation it was last in. */
async function resumeConversation(S, id, meta) {
  const sid = await lastConversation(id);
  return launchConversation(S, id, sid ? { ...meta, sessionId: sid } : meta, { resume: true });
}

/**
 * A conversational session ready to talk to, resumed first if it is not
 * running. A dev server restart takes every tmux session with it but none of
 * the conversations, so "not running" is something to recover from rather
 * than report - which is what lets `send_prompt` / `get_reply` work on any
 * session `list_sessions` shows.
 */
async function openConversation(S, id) {
  let state = await readState(S, id);
  if (!state.meta) {
    return {
      error: state.alive
        ? `Session "${id}" was started by an older version of this server and has no metadata, ` +
          `so its conversation cannot be located. Start a new session to use send_prompt.`
        : `No session with id "${id}". Use list_sessions to see what exists.`,
    };
  }
  if (state.meta.mode !== "session") {
    return {
      error:
        `Session "${id}" is a Remote Control *server*, not a conversation - it spawns its sessions ` +
        `as separate processes, so there is nothing to send a prompt to or collect a reply from. Start ` +
        `a conversational one with start_session (\`prompt: "…"\` or \`interactive: true\`) and use that.`,
    };
  }

  let resumed = false;
  if (!state.alive) {
    const launched = await resumeConversation(S, id, state.meta);
    if (launched.error) return { error: `Session "${id}" was not running and could not be resumed: ${launched.error}.` };
    if (launched.state === "exited") {
      return { error: `Session "${id}" was not running, and exited again right after resuming.\n\nLog:\n${logTail(launched.log)}` };
    }
    state = await readState(S, id);
    resumed = true;
  }

  const followed = followConversation(state.meta, state.live);
  if (followed) {
    state.meta = followed;
    await saveMeta(S, id, followed);
  }
  return { state, resumed };
}

/**
 * Poll a session until its current turn ends, it stops on a question or
 * dialog, it dies, or `timeoutMs` elapses. Timing out is a normal outcome,
 * not an error: the caller reports it and the user collects the answer later
 * with `get_reply`.
 *
 * Reading is incremental — each poll asks only for the transcript lines it has
 * not seen. Transcripts routinely reach hundreds of KB (a single tool result
 * can be 70 KB on one line), so re-reading the tail every three seconds would
 * push megabytes through the SSH channel for one turn. The cursor is a line
 * count, not a byte offset, so it cannot be knocked out of step by a multi-byte
 * character landing on a chunk boundary. `fromLine` lets `send_prompt` start at
 * the end of the transcript as it stood when the prompt was pasted, which makes
 * the first poll free too.
 *
 * The status file is read before the transcript on every poll, and Claude Code
 * writes the last entry of a turn before it flips to idle. So "idle, yet the
 * turn has no ending" is a fact about the transcript, not a race with it: the
 * turn was cut short - typically by the restart that a resume recovers from.
 */
async function waitForReply(S, id, meta, sinceIso, { timeoutMs, fromLine = null, sid }) {
  const deadline = Date.now() + timeoutMs;
  let entries = [];
  let cursor = fromLine;
  for (;;) {
    const cursorExpr = cursor === null
      ? `LINES=$(wc -l < "$TR" 2>/dev/null || echo 0); START=$(( LINES > ${INITIAL_TAIL_LINES} ? LINES - ${INITIAL_TAIL_LINES} : 0 ))`
      : `START=${cursor}`;
    const { out } = await sshSections((section) =>
      section("ALIVE") + `tmux has-session -t rc-${id} 2>/dev/null && echo yes; ` +
      liveSections(id, section) +
      section("PANE") + `tmux capture-pane -p -S -60 -t rc-${id} 2>/dev/null; ` +
      `SID=${sid}; ` + transcriptLookup(S, id) +
      `${cursorExpr}; ` + section("FROM") + `echo "$START"; ` +
      section("TR") + `[ -n "$TR" ] && tail -n +$((START+1)) "$TR" 2>/dev/null; true`,
      { timeoutMs: 30000 }
    );
    const alive = (out.ALIVE || "").includes("yes");
    const live = alive ? parseLive(out.PROC, out.LIVE) : null;
    const pane = stripAnsi(out.PANE || "");

    // A /clear switched the session to a new conversation, and a new file.
    if (live?.sessionId && live.sessionId !== sid) {
      sid = live.sessionId;
      cursor = 0;
      entries = [];
      meta = { ...meta, sessionId: sid };
      await saveMeta(S, id, meta);
      continue;
    }

    // Only whole lines advance the cursor; a line still being written is left
    // for the next poll to pick up in full.
    const start = parseInt((out.FROM || "").trim(), 10);
    const chunk = out.TR || "";
    const whole = chunk.endsWith("\n") ? chunk : chunk.slice(0, chunk.lastIndexOf("\n") + 1);
    if (Number.isInteger(start)) {
      cursor = start + (whole ? whole.slice(0, -1).split("\n").length : 0);
      entries.push(...parseJsonl(whole));
    }

    // Ending first: a session can finish its turn and exit in the same tick.
    const turn = turnAfter(entries, sinceIso);
    if (turn.outcome) return { ...turn.outcome, pane };
    if (!alive) return { state: "exited", pane };
    if (live?.status === "waiting") return { state: "waiting", waitingFor: live.waitingFor, pane };
    if (isIdle(live) && turn.startedAt && live.statusUpdatedAt > Date.parse(turn.startedAt)) {
      return { state: "ended", partial: turn.partial, pane };
    }
    if (isIdle(live) && !sinceIso && turn.empty) return { state: "nothing", pane };
    if (!live && PERMISSION_RE.test(pane)) return { state: "awaiting_permission", pane };
    if (Date.now() >= deadline) return { state: "running", pane };
    await sleep(3000);
  }
}

/** Last `n` non-empty lines of a rendered pane — the "what is it doing" hint. */
function paneTail(pane, n = 8) {
  const lines = pane.split("\n").map((l) => l.replace(/\s+$/, "")).filter(Boolean);
  return lines.slice(-n).join("\n");
}

const clip = (text) =>
  text.length > MAX_REPLY_CHARS
    ? `${text.slice(0, MAX_REPLY_CHARS)}\n\n… (truncated at ${MAX_REPLY_CHARS} characters)`
    : text;

function formatOutcome(id, result, { url, waitedSeconds, notes = [] }) {
  const lead = notes.map((n) => `(${n})\n\n`).join("");
  const pane = `\n\nPane:\n${paneTail(result.pane || "")}`;
  const link = url ? `\n${url}` : "";
  switch (result.state) {
    case "done":
      return ok(`${lead}Reply from session "${id}":\n\n${clip(result.reply)}`);
    case "command":
      return ok(
        `${lead}Session "${id}" ran ${result.command || "the command"}` +
        (result.output ? `:\n\n${clip(result.output)}` : ` (no output).`)
      );
    case "interrupted":
      return ok(`${lead}The turn in session "${id}" was interrupted before it finished, so there is no answer to collect.`);
    case "error":
      return fail(`${lead}The turn in session "${id}" ended with an error: ${result.text}`);
    case "ended":
      return ok(
        `${lead}Session "${id}" is idle, but its last turn ended without a final answer - it was cut short, ` +
        `typically because the session stopped mid-turn (a server restart, say). Send a new prompt to carry on.` +
        (result.partial ? `\n\nThe last thing it said:\n${clip(result.partial)}` : "")
      );
    case "nothing":
      return ok(`${lead}Session "${id}" is idle and has no turn to report yet.`);
    case "waiting":
      return ok(
        `${lead}Session "${id}" is waiting for input (${result.waitingFor || "dialog open"}): a question, a ` +
        `tool-approval prompt or a dialog is open, and it cannot be answered from here. Answer it at ` +
        `claude.ai/code, or dismiss it with \`interrupt_session\` - a new \`send_prompt\` dismisses it too.` +
        link + pane
      );
    case "awaiting_permission":
      return ok(
        `${lead}Session "${id}" is waiting for a tool-approval answer, so the turn cannot finish ` +
        `until someone responds. Open it and approve (or start sessions with ` +
        `\`bypass_permissions\` if they should run unattended).` + link + pane
      );
    case "exited":
      return fail(`${lead}Session "${id}" is no longer running and produced no final answer.${pane}`);
    default:
      return ok(
        `${lead}Session "${id}" is still working after ${waitedSeconds}s. ` +
        `Call \`get_reply\` with the same id to collect the answer when it is done.` + pane
      );
  }
}

/** "3m", "5h", "2d" - how long ago an epoch-ms instant was. */
function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 90) return `${s}s`;
  if (s < 90 * 60) return `${Math.round(s / 60)}m`;
  if (s < 36 * 3600) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
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
- Call \`list_sessions\` first if the user might already have a session for the
  same project - reuse it instead of creating a duplicate. It also lists
  conversational sessions that are no longer running (typically because the dev
  server restarted); those can be picked up again as they are.
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
- A session that is not running is resumed automatically by \`send_prompt\` and
  \`get_reply\`, with its full conversation; \`resume_session\` does only that.
- \`send_prompt\` on a session that is still busy interrupts the running turn
  first (like pressing Esc), then sends - one turn at a time. To stop a turn
  without sending anything, use \`interrupt_session\`.
- A question, tool-approval prompt or dialog open in a session blocks its turn,
  and \`send_prompt\` / \`get_reply\` will report it instead of an answer. Say so
  rather than retrying: it is answered at claude.ai/code, or dismissed with
  \`interrupt_session\`.
- \`stop_session\` ends the session's process (the conversation can still be
  resumed); confirm with the user before calling it unless they named the id
  explicitly. \`interrupt_session\` is the one for "stop what you are doing".
`.trim();

function createMcpServer() {
  const server = new McpServer(
    { name: "claude-code-rc-mcp", version: VERSION },
    { instructions: SERVER_INSTRUCTIONS }
  );

  server.tool(
    "start_session",
    "Launch a new Claude Code Remote Control session on the remote dev server (over SSH, inside a detached tmux session) and return its URL. " +
      "Use when the user asks to start / open / spin up a remote Claude Code session on a given project. " +
      "Pass `prompt` when the user wants the session to start working right away — 'open a session on X and run the tests', 'start a session and run /security-review'; the session stays open afterwards so they can take over from claude.ai/code. " +
      "Prefer calling `list_projects` first to discover valid `path` values, and `list_sessions` to avoid duplicating a session for the same project. " +
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
        const spawn = (worktree ?? SPAWN_WORKTREE) ? "worktree" : "same-dir";
        const S = await stateDir();

        // Two launch shapes. Conversational (`prompt` or `interactive`): a
        // single session `claude --rc <name>`, the only form that accepts an
        // initial prompt and the only one with a conversation of its own to
        // send later prompts to. Its conversation id is chosen here rather than
        // discovered afterwards, so the transcript is always the one file named
        // after it, and a resume after a restart knows exactly what to reopen.
        // Plain: the persistent Remote Control server (`claude remote-control`),
        // which supports --spawn, but spawns its sessions as separate processes,
        // so its pane is not a chat.
        let result;
        if (conversational) {
          const meta = {
            mode: "session",
            dir,
            name,
            sessionId: randomUUID(),
            bypass: Boolean(bypass_permissions),
            createdAt: new Date().toISOString(),
          };
          result = await launchConversation(S, id, meta, { task });
          if (result.error) return fail(`Could not start session "${id}": ${result.error}.`);
        } else {
          const logfile = `${S}/${id}.log`;
          const bypassFlag = bypass_permissions ? " --dangerously-skip-permissions" : "";
          const meta = { mode: "server", dir, name, bypass: Boolean(bypass_permissions), createdAt: new Date().toISOString() };
          const inner = `${CLAUDE_BIN} remote-control --name ${name} --spawn ${spawn}${bypassFlag} 2>&1 | tee ${logfile}`;
          const r = await sshExec(
            `[ -d "${dir}" ] || { echo __NO_DIR__; exit 9; }; ` +
            `command -v tmux >/dev/null 2>&1 || { echo __NO_TMUX__; exit 8; }; ` +
            `tmux has-session -t rc-${id} 2>/dev/null && { echo __EXISTS__; exit 7; }; ` +
            `${remoteWrite(`${S}/${id}.meta`, JSON.stringify(meta))}; ` +
            `tmux new-session -d -s rc-${id} -c "${dir}" '${inner}' && echo __STARTED__`
          );
          if (r.stdout.includes("__NO_DIR__")) return fail(`Project directory not found: ${rel}`);
          if (r.stdout.includes("__NO_TMUX__")) return fail("tmux is not installed on the remote server.");
          if (!r.stdout.includes("__STARTED__")) {
            return fail(`Failed to start tmux session (exit ${r.code}).\n${r.stdout}\n${r.stderr}`.trim());
          }
          result = await pollSession(S, id, { timeoutMs: 35000 });
          if (result.url) await sshExec(`${remoteWrite(`${S}/${id}.url`, result.url)}; true`);
        }
        const tail = logTail(result.log);

        if (result.state === "exited") {
          await sshExec(`rm -f ${S}/${id}.*`);
          return fail(
            `Session "${id}" exited before becoming ready — likely a startup error ` +
            `(e.g. Claude Code not authenticated on the server).\n\nLog:\n${tail}`
          );
        }

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
    "Send a follow-up prompt to a Claude Code session on the remote server and return its final answer. " +
      "Use when the user wants to keep working in a session they (or you) already started — 'ask that session to also update the README', 'tell my remote session to run the tests', 'follow up on X' — instead of spinning up a new one. " +
      "The prompt is typed into the live conversation, so the session keeps all of its context and the exchange stays visible at claude.ai/code. " +
      "If the session is not running (e.g. the dev server restarted) it is resumed first; if it is still busy with a previous turn, that turn is interrupted first (like pressing Esc) - one turn at a time. " +
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
        const S = await stateDir();

        const opened = await openConversation(S, id);
        if (opened.error) return fail(opened.error);
        const { state } = opened;
        const notes = [];
        if (opened.resumed) {
          notes.push("the session was not running, so it was resumed first");
          if (!state.live) {
            return fail(`Session "${id}" was resumed but is still starting up. Send the prompt again in a few seconds.`);
          }
          // Whatever dialog a session opens on at startup is not one to wave away.
          if (state.live.status === "waiting") {
            return fail(
              `Session "${id}" was resumed, but opened on a dialog (${state.live.waitingFor}) that has to be ` +
              `answered first.${state.url ? `\n${state.url}` : ""}\n\nPane:\n${paneTail(state.pane)}`
            );
          }
        }

        // One turn at a time. A prompt pasted into a busy session is not a new
        // turn: Claude Code folds it into the running one as a queued
        // attachment, so there is never an entry to anchor the reply on and it
        // is never recognised. Nor is it what was asked for - the new prompt
        // supersedes the old one. An open question, approval prompt or dialog
        // would swallow the paste outright. So either is interrupted first,
        // exactly like pressing Esc.
        if (isBusy(state.live)) {
          const r = await interruptTurn(id, state.live);
          if (!r.done) {
            return fail(`Session "${id}" is still busy after pressing Esc, so the prompt was not sent.\n\nPane:\n${paneTail(state.pane)}`);
          }
          notes.push(`the ${state.live.status === "waiting" ? "open dialog was dismissed" : "turn that was still running was interrupted"} first`);
        } else if (!state.live && PERMISSION_RE.test(state.pane)) {
          // No status file to go by: at least do not answer an approval prompt by accident.
          return fail(
            `Session "${id}" is waiting for a tool-approval answer and cannot accept a prompt until ` +
            `someone responds.${state.url ? `\n${state.url}` : ""}\n\nPane:\n${paneTail(state.pane)}`
          );
        }

        const sid = state.live?.sessionId || metaSessionId(state.meta);
        if (!sid) {
          return fail(`Session "${id}" has no recorded conversation id, so its reply cannot be located. Start a new session to use send_prompt.`);
        }

        // Paste rather than type: `send-keys` would turn every newline in a
        // multi-line prompt into a submit, and a long prompt into a very slow
        // keystroke replay. `-p` wraps it in bracketed-paste markers so the
        // TUI takes the whole thing as one block of text, and the explicit
        // Enter afterwards is what submits it. A raw paste would dodge the
        // <pasted_content> wrapping RC_SYSTEM_PROMPT has to explain, but only
        // below ~800 bytes, and typed input brings back the TUI's shortcuts:
        // a leading "!" switches to shell mode, a tab disappears, and an Enter
        // after an "@path" picks a file from the autocomplete instead.
        //
        // The "sent at" mark is stamped by the remote host, not by `new Date()`
        // here: it is compared against timestamps written by the session, and
        // a container clock a few seconds ahead of the dev server would put the
        // mark in their future — so the reply would never be recognised.
        // The transcript is also measured here, before the paste, so the poll
        // can start reading exactly where the new turn begins.
        const s = await sshExec(
          `SENT=$(date -u +%Y-%m-%dT%H:%M:%S.000Z); printf %s "$SENT" > ${S}/${id}.pending; ` +
          `SID=${sid}; ` + transcriptLookup(S, id) +
          `FROM=0; [ -n "$TR" ] && FROM=$(wc -l < "$TR" 2>/dev/null || echo 0); ` +
          `${remoteWrite(`${S}/${id}.send`, text)} && ` +
          `tmux load-buffer -b rcbuf-${id} ${S}/${id}.send && ` +
          `tmux paste-buffer -d -p -b rcbuf-${id} -t rc-${id} && ` +
          `sleep 0.4 && tmux send-keys -t rc-${id} Enter && ` +
          `echo "__SENT__$SENT $FROM"`
        );
        const sent = s.stdout.match(/__SENT__(\S+) (\d+)/);
        if (!sent) {
          return fail(`Failed to send the prompt to session "${id}" (exit ${s.code}).\n${s.stdout}\n${s.stderr}`.trim());
        }
        const [, sentAt, fromLine] = sent;

        const result = await waitForReply(S, id, state.meta, sentAt, {
          timeoutMs: waitSeconds * 1000,
          fromLine: Number(fromLine),
          sid,
        });
        return formatOutcome(id, result, { url: state.url, waitedSeconds: waitSeconds, notes });
      } catch (err) {
        return fail(`send_prompt error: ${err.message}`);
      }
    }
  );

  server.tool(
    "get_reply",
    "Collect the final answer from a Claude Code session on the remote server — the reply to the last `send_prompt`, or to the initial `prompt` a session was started with. " +
      "Use when a previous call reported the session was still working, or when the user asks 'is it done?', 'what did it say?', 'check on that session'. " +
      "Resumes the session first if it is not running. Waits up to `wait_seconds` for a turn that is still in progress, and reports if the session is instead waiting on a question, approval prompt or dialog, or if its turn was cut short.",
    {
      id: z.string().describe("Full session id from start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
      wait_seconds: z.number().optional().describe("How long to wait if the session is still working (default 90, max 240). Pass 0 to check without waiting."),
    },
    async ({ id, wait_seconds }) => {
      try {
        validateId(id);
        const waitSeconds = Math.min(Math.max(wait_seconds ?? 90, 0), 240);
        const S = await stateDir();

        const opened = await openConversation(S, id);
        if (opened.error) return fail(opened.error);
        const { state } = opened;
        const sid = state.live?.sessionId || metaSessionId(state.meta);
        if (!sid) return fail(`Session "${id}" has no recorded conversation id, so its reply cannot be located.`);

        // No pending marker means nothing was sent through send_prompt, so the
        // turn of interest is whatever the session ran last — typically the
        // prompt it was started with.
        const result = await waitForReply(S, id, state.meta, state.pending, { timeoutMs: waitSeconds * 1000, sid });
        const notes = opened.resumed ? ["the session was not running, so it was resumed first"] : [];
        return formatOutcome(id, result, { url: state.url, waitedSeconds: waitSeconds, notes });
      } catch (err) {
        return fail(`get_reply error: ${err.message}`);
      }
    }
  );

  server.tool(
    "interrupt_session",
    "Interrupt what a Claude Code session on the remote server is doing right now - the same as pressing Esc or the stop button. " +
      "Use when the user says 'stop', 'cancel that', 'esc', 'abort what it is doing', or to dismiss a question, approval prompt or dialog that is blocking a session. " +
      "The session stays open and keeps its context, ready for the next `send_prompt`. To end the session itself, use `stop_session`.",
    {
      id: z.string().describe("Full session id from start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
    },
    async ({ id }) => {
      try {
        validateId(id);
        const S = await stateDir();
        const state = await readState(S, id);
        if (!state.alive) return fail(`Session "${id}" is not running, so there is nothing to interrupt.`);
        if (!state.live) {
          // No status file to go by: press Esc once, the one press that is always safe.
          await sshExec(`tmux send-keys -t rc-${id} Escape`);
          await sleep(1500);
          const pane = stripAnsi((await sshExec(`tmux capture-pane -p -S -60 -t rc-${id} 2>/dev/null; true`)).stdout);
          return ok(`Pressed Esc in session "${id}" (its status could not be read to confirm the effect).\n\nPane:\n${paneTail(pane)}`);
        }
        if (!isBusy(state.live)) return ok(`Session "${id}" is idle - there was nothing to interrupt.`);
        const was = state.live.status === "waiting" ? `waiting for input (${state.live.waitingFor})` : "working";
        const r = await interruptTurn(id, state.live);
        if (!r.done) return fail(`Session "${id}" is still busy after pressing Esc.\n\nPane:\n${paneTail(state.pane)}`);
        return ok(`Interrupted session "${id}", which was ${was}. It is idle now, with its context intact.`);
      } catch (err) {
        return fail(`interrupt_session error: ${err.message}`);
      }
    }
  );

  server.tool(
    "resume_session",
    "Bring back a conversational Claude Code session that is no longer running - typically because the dev server restarted, or the session was stopped - with its full conversation, under the same id and URL. " +
      "Use when the user asks to reopen / reconnect / revive / resume a session that `list_sessions` shows as not running. " +
      "`send_prompt` and `get_reply` already do this on their own, so this is for when the user only wants the session back.",
    {
      id: z.string().describe("Full session id from list_sessions (e.g. 'my-project-a1b2c3')"),
      bypass_permissions: z.boolean().optional().describe("Override the permission mode the session was started with. Omit to keep it. Only set it when the user explicitly asks."),
    },
    async ({ id, bypass_permissions }) => {
      try {
        validateId(id);
        const S = await stateDir();
        const state = await readState(S, id);
        if (!state.meta) return fail(`No session with id "${id}" to resume. Use list_sessions to see what exists.`);
        if (state.meta.mode !== "session") {
          return fail(`Session "${id}" is a Remote Control server, which has no conversation to resume. Start a new one with start_session.`);
        }
        if (state.alive) return ok(`Session "${id}" is already running.${state.url ? `\nSession URL: ${state.url}` : ""}`);

        const meta = bypass_permissions === undefined ? state.meta : { ...state.meta, bypass: bypass_permissions };
        const result = await resumeConversation(S, id, meta);
        if (result.error) return fail(`Could not resume session "${id}": ${result.error}.`);
        if (result.state === "exited") {
          return fail(`Session "${id}" exited right after resuming.\n\nLog:\n${logTail(result.log)}`);
        }
        return ok(
          `Session resumed: ${id}\n` +
          `Project: ${metaDir(meta).slice(PROJECTS_BASE_DIR.length + 1)}  ·  mode: conversational` +
          (meta.bypass ? `  ·  bypass: on` : "") + `\n` +
          (result.url ? `Session URL: ${result.url}\n` : "") +
          `\nIt carries on the same conversation; drive it with \`send_prompt\` / \`get_reply\` as before.` +
          (result.state === "starting" ? `\n(still initialising - give it a few more seconds)` : "")
        );
      } catch (err) {
        return fail(`resume_session error: ${err.message}`);
      }
    }
  );

  server.tool(
    "list_sessions",
    "List the Claude Code sessions on the remote server: the running ones, with their URL, mode and whether they are working, idle or waiting for input, " +
      "and the conversational ones that are no longer running (typically after a dev server restart), which `send_prompt` / `get_reply` / `resume_session` pick up again. " +
      "`conversational` sessions are the ones `send_prompt` / `get_reply` can talk to. " +
      "Use when the user asks 'what sessions are running', 'do I have a session for X', before `start_session` to avoid duplicates, " +
      `or to look up the id of the session they want to send a prompt to. Sessions not running for more than ${SESSION_RETENTION_DAYS} days are forgotten.`,
    {},
    async () => {
      try {
        const S = await stateDir();
        const remote =
          `for f in ${S}/*.meta; do [ -f "$f" ] || continue; id=$(basename "$f" .meta); ` +
          `m=$(base64 < "$f" | tr -d '\\n'); u=$(cat ${S}/"$id".url 2>/dev/null); ` +
          `if tmux has-session -t "rc-$id" 2>/dev/null; then ` +
          `P=$(tmux display -p -t "rc-$id" '#{pane_pid} #{session_created}' 2>/dev/null); ` +
          `L=$(cat ${CLAUDE_DIR}/sessions/"\${P%% *}".json 2>/dev/null | base64 | tr -d '\\n'); ` +
          `echo "ON $id \${P:-- -} \${L:--} $m \${u:--}"; ` +
          `else sid=$(grep -o '"sessionId":"[0-9a-f-]*"' "$f" | cut -d'"' -f4); t=; ` +
          `[ -n "$sid" ] && t=$(find ${CLAUDE_PROJECTS_DIR} -maxdepth 2 -name "$sid.jsonl" -printf '%T@\\n' 2>/dev/null | head -n 1); ` +
          `echo "OFF $id \${t:-0} $m \${u:--}"; fi; done; ` +
          `tmux list-sessions -F '#{session_name}' 2>/dev/null | sed -n 's/^rc-/TMUX /p'`;
        const r = await sshExec(remote);

        const sessions = [];
        const known = new Set();
        const stale = [];
        const followed = [];
        const retentionMs = SESSION_RETENTION_DAYS * 86400000;
        for (const line of r.stdout.split("\n")) {
          const [kind, id, ...f] = line.trim().split(" ");
          if (!ID_RE.test(id || "")) continue;
          if (kind === "ON") {
            const [pid, created, liveB64, metaB64, url] = f;
            const live = parseLive(`${pid} ${created}`, fromB64(liveB64));
            const meta = parseMeta(fromB64(metaB64));
            const moved = followConversation(meta, live);
            if (moved) followed.push(remoteWrite(`${S}/${id}.meta`, JSON.stringify(moved)));
            sessions.push({ id, running: true, meta, live, url: live?.url || (url !== "-" ? url : null) });
            known.add(id);
          } else if (kind === "OFF") {
            const [mtime, metaB64, url] = f;
            const meta = parseMeta(fromB64(metaB64));
            const lastActive = parseFloat(mtime) * 1000;
            known.add(id);
            // Only a conversation whose transcript still exists can come back.
            if (meta?.mode !== "session" || !lastActive || Date.now() - lastActive > retentionMs) {
              stale.push(id);
              continue;
            }
            sessions.push({ id, running: false, meta, lastActive, url: url !== "-" ? url : null });
          } else if (kind === "TMUX" && !known.has(id)) {
            sessions.push({ id, running: true, meta: null, live: null, url: null });
          }
        }
        const upkeep = [...followed, ...stale.map((id) => `rm -f ${S}/${id}.*`)];
        if (upkeep.length) await sshExec(`${upkeep.join("; ")}; true`);
        if (!sessions.length) return ok("No sessions.");

        const status = (live) => {
          if (!live) return "running";
          if (live.status === "busy") return "working";
          if (live.status === "waiting") return `waiting for input (${live.waitingFor || "dialog open"})`;
          if (live.status === "shell") return "idle, background shell running";
          return live.status || "running";
        };
        sessions.sort((a, b) => (b.running - a.running) || ((b.lastActive || 0) - (a.lastActive || 0)));
        const body = sessions
          .map((s) => {
            const kind = s.meta?.mode === "session" ? "conversational" : s.meta?.mode === "server" ? "remote-control server" : "no metadata";
            const state = s.running
              ? (s.meta?.mode === "session" ? status(s.live) : "running")
              : `not running (last active ${ago(s.lastActive)} ago), resumable`;
            return `• ${s.id}  -  ${kind} · ${state}${s.url ? `\n    ${s.url}` : ""}`;
          })
          .join("\n");
        const running = sessions.filter((s) => s.running).length;
        return ok(
          `Sessions (${running} running, ${sessions.length - running} not running):\n${body}` +
          (sessions.some((s) => s.meta?.mode === "session")
            ? `\n\nConversational sessions accept \`send_prompt\` / \`get_reply\`; ones that are not running are resumed automatically.`
            : "")
        );
      } catch (err) {
        return fail(`list_sessions error: ${err.message}`);
      }
    }
  );

  server.tool(
    "stop_session",
    "Stop a Claude Code session by its full id: ends its process (kills the tmux session). " +
      "Any turn in progress is lost, but the conversation is kept - the session stays in `list_sessions` and can be resumed - unless `forget` is set. " +
      "Confirm with the user before calling unless they explicitly named the id. " +
      "To only stop what the session is doing, and keep it open, use `interrupt_session` instead. " +
      "Use `list_sessions` to look up the id if the user only referenced the session by name.",
    {
      id: z.string().describe("Full session id as returned by start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
      forget: z.boolean().optional().describe("If true, also drop the session from list_sessions, so it can no longer be resumed from here. The conversation itself stays in claude.ai/code."),
    },
    async ({ id, forget }) => {
      try {
        validateId(id);
        const S = await stateDir();
        if (!forget) {
          const state = await readState(S, id);
          const followed = followConversation(state.meta, state.live);
          if (followed) await saveMeta(S, id, followed);
        }
        const r = await sshExec(
          `tmux kill-session -t rc-${id} 2>/dev/null && echo __KILLED__; ` +
          `[ -f ${S}/${id}.meta ] && echo __KNOWN__; ` +
          (forget ? `rm -f ${S}/${id}.*` : `rm -f ${S}/${id}.send ${S}/${id}.prompt`)
        );
        const killed = r.stdout.includes("__KILLED__");
        const known = r.stdout.includes("__KNOWN__");
        if (!killed && !known) return fail(`No session with id "${id}".`);
        if (forget) return ok(`Session "${id}" ${killed ? "stopped and " : ""}forgotten.`);
        if (!killed) return ok(`Session "${id}" was not running.`);
        return ok(`Session "${id}" stopped.` + (known ? ` Its conversation is kept: send_prompt, get_reply or resume_session bring it back.` : ""));
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

app.get("/health", (_, res) => res.json({ ok: true, version: VERSION }));

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
