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
    .replace(/\[[0-9;?]*[ -/]*[@-~]/g, ""); // CSI (cursor / colour codes)
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
 * Poll the per-session logfile until the remote-control URL appears, the tmux
 * session dies (claude exited / errored), or the timeout elapses.
 */
async function pollSession(id, timeoutMs = 35000) {
  const deadline = Date.now() + timeoutMs;
  let log = "";
  while (Date.now() < deadline) {
    await sleep(2000);
    const r = await sshExec(
      `tmux has-session -t rc-${id} 2>/dev/null && echo __ALIVE__ || echo __DEAD__; ` +
      `echo __LOG__; cat /tmp/rc-${id}.log 2>/dev/null || true`
    );
    const [head, ...rest] = r.stdout.split("__LOG__");
    log = stripAnsi(rest.join("__LOG__")).trim();
    const alive = head.includes("__ALIVE__");
    const url = (log.match(/https?:\/\/[^\s'"\]]+/g) || [])[0];
    if (url) return { state: "ready", alive, url, log };
    if (!alive) return { state: "exited", alive: false, url: null, log };
  }
  return { state: "starting", alive: true, url: null, log };
}

function createMcpServer() {
  const server = new McpServer({ name: "claude-code-rc-mcp", version: "1.0.0" });

  server.tool(
    "start_session",
    "Start a new Claude Code Remote Control session on the remote development server. " +
      "SSHes in, launches `claude remote-control` inside a detached tmux session in the chosen " +
      "project directory, and returns the session URL once it is available. The session then " +
      "also shows up in the session list at claude.ai/code.",
    {
      name: z.string().describe("Short label for the session, shown in claude.ai/code (1-41 chars, [a-zA-Z0-9_-])"),
      path: z.string().describe("Project directory, relative to PROJECTS_BASE_DIR (e.g. 'my-project'). Use list_projects to discover valid values."),
      worktree: z.boolean().optional().describe("If true, spawn on-demand sessions in isolated git worktrees (--spawn worktree). Defaults to the SPAWN_WORKTREE env var."),
      bypass_permissions: z.boolean().optional().describe("If true, launch with --dangerously-skip-permissions so the session does not prompt for tool approvals. Use with care."),
    },
    async ({ name, path, worktree, bypass_permissions }) => {
      try {
        validateName(name);
        const rel = validateRelPath(path);
        const suffix = randomBytes(3).toString("hex");
        const id = `${name}-${suffix}`;
        const dir = `${PROJECTS_BASE_DIR}/${rel}`;
        const logfile = `/tmp/rc-${id}.log`;
        const spawn = (worktree ?? SPAWN_WORKTREE) ? "worktree" : "same-dir";
        const bypassFlag = bypass_permissions ? " --dangerously-skip-permissions" : "";
        const inner = `${CLAUDE_BIN} remote-control --name ${name} --spawn ${spawn}${bypassFlag} 2>&1 | tee ${logfile}`;
        const remote =
          `[ -d "${dir}" ] || { echo __NO_DIR__; exit 9; }; ` +
          `command -v tmux >/dev/null 2>&1 || { echo __NO_TMUX__; exit 8; }; ` +
          `tmux has-session -t rc-${id} 2>/dev/null && { echo __EXISTS__; exit 7; }; ` +
          `tmux new-session -d -s rc-${id} -c "${dir}" "${inner}" && echo __STARTED__`;

        const r = await sshExec(remote);
        if (r.stdout.includes("__NO_DIR__")) return fail(`Project directory not found: ${rel}`);
        if (r.stdout.includes("__NO_TMUX__")) return fail("tmux is not installed on the remote server.");
        if (!r.stdout.includes("__STARTED__")) {
          return fail(`Failed to start tmux session (exit ${r.code}).\n${r.stdout}\n${r.stderr}`.trim());
        }

        const result = await pollSession(id);
        const tail = logTail(result.log);

        if (result.state === "exited") {
          await sshExec(`rm -f ${logfile}`);
          return fail(
            `Session "${id}" exited before becoming ready — likely a startup error ` +
            `(e.g. Claude Code not authenticated on the server).\n\nLog:\n${tail}`
          );
        }
        const header =
          `Session started: ${id}\n` +
          `Project: ${rel}  ·  spawn: ${spawn}` +
          (bypass_permissions ? `  ·  bypass: on` : "") + `\n` +
          (result.url ? `Session URL: ${result.url}\n` : "") +
          `\nIt should now appear in the session list at https://claude.ai/code` +
          (result.state === "starting" ? `\n(still initialising — give it a few more seconds)` : "");
        return ok(`${header}\n\nLog:\n${tail}`);
      } catch (err) {
        return fail(`start_session error: ${err.message}`);
      }
    }
  );

  server.tool(
    "list_sessions",
    "List the active Claude Code Remote Control sessions (tmux sessions named rc-*) on the remote " +
      "server, with each session's URL when available. Also cleans up orphan log files left by " +
      "sessions that have already ended.",
    {},
    async () => {
      try {
        const remote =
          `for s in $(tmux list-sessions -F '#{session_name}' 2>/dev/null | grep '^rc-'); do ` +
          `echo "SESSION ${'$'}{s#rc-}"; done; ` +
          `for f in /tmp/rc-*.log; do [ -e "$f" ] || continue; ` +
          `id=$(basename "$f" .log); id=${'$'}{id#rc-}; ` +
          `if tmux has-session -t "rc-$id" 2>/dev/null; then ` +
          `echo "URL $id $(grep -oE 'https?://[^[:space:]]+' "$f" 2>/dev/null | head -1)"; ` +
          `else echo "CLEANED $f"; rm -f "$f"; fi; done`;
        const r = await sshExec(remote);
        const lines = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
        const ids = lines.filter((l) => l.startsWith("SESSION ")).map((l) => l.slice(8));
        const urls = {};
        for (const l of lines.filter((l) => l.startsWith("URL "))) {
          const [, id, url] = l.split(" ");
          if (url) urls[id] = url;
        }
        if (!ids.length) return ok("No active Remote Control sessions.");
        const body = ids
          .map((id) => `• ${id}${urls[id] ? `\n    ${urls[id]}` : ""}`)
          .join("\n");
        return ok(`Active sessions (${ids.length}):\n${body}`);
      } catch (err) {
        return fail(`list_sessions error: ${err.message}`);
      }
    }
  );

  server.tool(
    "stop_session",
    "Stop a Claude Code Remote Control session by its id (kills the tmux session and removes its log file).",
    {
      id: z.string().describe("Full session id as returned by start_session / list_sessions (e.g. 'my-project-a1b2c3')"),
    },
    async ({ id }) => {
      try {
        validateId(id);
        const r = await sshExec(
          `tmux kill-session -t rc-${id} 2>/dev/null && echo __KILLED__ || echo __NOT_FOUND__; ` +
          `rm -f /tmp/rc-${id}.log`
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
    "List the project directories available on the remote server under PROJECTS_BASE_DIR. " +
      "Only directories that look like projects (contain a .git or .claude entry) are returned. " +
      "Use the returned names as the `path` input of start_session.",
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
