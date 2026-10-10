// End-to-end check of every tool against a running instance of this server.
//
// It drives real Claude Code sessions, so it runs on the dev server itself
// (it looks at tmux, processes and status files there) against a local
// instance whose SSH_HOST is 127.0.0.1 - see "Test locally" in CLAUDE.md.
// The sessions it opens show up at claude.ai/code and are closed (archived)
// before it ends.
//
//   E2E_URL      MCP endpoint            (default http://localhost:3901/mcp)
//   E2E_TOKEN    bearer token            (default "t")
//   E2E_BASE     PROJECTS_BASE_DIR       (default /home/vscode/localCode)
//   E2E_PROJECT  trusted test project    (default rc-mcp-test)
//   E2E_STATE    the instance's REMOTE_STATE_DIR (default ~/.claude-rc-mcp-e2e), kept apart
//                from the real one: expiry would otherwise close real sessions
//   E2E_ONLY     comma-separated scenario names, to run a subset
//
// The trust_folder scenario trusts a fresh folder under E2E_PROJECT for good:
// Claude Code keeps that entry in its config after the folder is removed.

import { execSync } from "node:child_process";
import { mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { randomBytes, randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const URL_ = process.env.E2E_URL || "http://localhost:3901/mcp";
const TOKEN = process.env.E2E_TOKEN || "t";
const BASE = process.env.E2E_BASE || "/home/vscode/localCode";
const PROJECT = process.env.E2E_PROJECT || "rc-mcp-test";
const ONLY = (process.env.E2E_ONLY || "").split(",").filter(Boolean);
// The instance under test must run with REMOTE_STATE_DIR set to this, apart from any real one.
const STATE = process.env.E2E_STATE || `${homedir()}/.claude-rc-mcp-e2e`;
const SESSIONS = `${process.env.CLAUDE_CONFIG_DIR || `${homedir()}/.claude`}/sessions`;
const PROJECTS = `${process.env.CLAUDE_CONFIG_DIR || `${homedir()}/.claude`}/projects`;

const sh = (cmd) => {
  try { return execSync(cmd, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return ""; }
};
// Claude Code moves a plain `sleep` to the background, which ends the turn; this keeps it busy.
const LONG_TURN =
  "Use the Bash tool, in the foreground (not in the background), to run exactly: " +
  "python3 -c \"import time; time.sleep(60)\" - wait for it to finish, then reply with exactly: DONE";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const client = new Client({ name: "e2e", version: "1" });
await client.connect(new StreamableHTTPClientTransport(new URL(URL_), {
  requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
}));

async function call(name, args = {}) {
  const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 600000 });
  const text = r.content.map((c) => c.text).join("\n");
  console.log(`\n→ ${name} ${JSON.stringify(args)}\n${r.isError ? "[isError] " : ""}${text}`);
  return { text, isError: Boolean(r.isError) };
}

let failures = 0;
function check(cond, what) {
  console.log(`${cond ? "  ✔" : "  ✘"} ${what}`);
  if (!cond) failures++;
}

const idOf = (text) => text.match(/^Session started: (\S+)/m)?.[1];
const urlOf = (text) => text.match(/https:\/\/claude\.ai\/code\/session_\w+/)?.[0];
const panePid = (id) => sh(`tmux display -p -t rc-${id} '#{pane_pid}' 2>/dev/null`);
const procAlive = (pid) => Boolean(pid) && sh(`ps -o stat= -p ${pid}`).replace(/Z.*/, "") !== "";
const statusFiles = (id) => sh(`grep -l '"tmux": *"rc-${id}:' ${SESSIONS}/*.json 2>/dev/null`);
const tmuxAlive = (id) => sh(`tmux has-session -t rc-${id} 2>/dev/null && echo yes`) === "yes";
const recordExists = (id) => existsSync(`${STATE}/${id}.meta`);
const filesLeft = (id) => sh(`ls ${STATE} | grep -F ${id}`);
const transcriptOf = (id) => sh(`find ${PROJECTS} -maxdepth 2 -name "${meta(id).sessionId}.jsonl" | head -n 1`);
/** Make a session look idle for longer than the retention (default 14 days). */
const age = (id) => sh(`touch -d "40 days ago" "${transcriptOf(id)}"`);
const meta = (id) => JSON.parse(readFileSync(`${STATE}/${id}.meta`, "utf-8"));

/** Nothing of the session left running: tmux, process, status file. */
function checkGone(id, pid) {
  check(!tmuxAlive(id), `tmux session rc-${id} is gone`);
  check(!procAlive(pid), `process ${pid || "?"} is gone`);
  check(statusFiles(id) === "", `no status file names rc-${id}`);
}

async function startInteractive(name, extra = {}) {
  const r = await call("start_session", { name, path: PROJECT, bypass_permissions: true, ...extra });
  const id = idOf(r.text);
  check(!r.isError && id && urlOf(r.text) && /mode: conversational/.test(r.text), `${name}: started empty, conversational, with a URL`);
  return { id, url: urlOf(r.text), pid: panePid(id) };
}

const scenarios = {
  async tools() {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    check(names.includes("disconnect_session"), "disconnect_session is offered");
    const stop = tools.find((t) => t.name === "stop_session");
    check(/Deprecated/.test(stop.inputSchema.properties.forget?.description || ""), "stop_session still accepts forget, marked deprecated");
    const start = tools.find((t) => t.name === "start_session").inputSchema.properties;
    check(/Deprecated/.test(start.interactive?.description || "") && /Deprecated/.test(start.worktree?.description || ""),
      "start_session still accepts interactive and worktree, marked deprecated");
  },

  // start → send_prompt → get_reply → interrupt → list → disconnect → resume → send_prompt → stop
  async lifecycle() {
    const s = await startInteractive("e2e-life");
    if (!s.id) return;
    let r = await call("send_prompt", { id: s.id, prompt: "Reply with exactly: PONG", wait_seconds: 120 });
    check(!r.isError && /PONG/.test(r.text), "send_prompt returns the answer");
    r = await call("get_reply", { id: s.id, wait_seconds: 10 });
    check(/PONG/.test(r.text), "get_reply returns the same answer");

    r = await call("send_prompt", { id: s.id, prompt: LONG_TURN, wait_seconds: 8 });
    check(/still working/.test(r.text), "a long turn is reported as still working");
    r = await call("interrupt_session", { id: s.id });
    check(!r.isError && /Interrupted/.test(r.text), "interrupt_session stops it");

    r = await call("list_sessions");
    check(r.text.includes(s.id), "list_sessions lists it");

    r = await call("disconnect_session", { id: s.id });
    check(!r.isError && /archive=200/.test(r.text), "disconnect_session confirms the archive");
    checkGone(s.id, s.pid);
    check(recordExists(s.id) && Boolean(meta(s.id).archivedAt), "the record is kept, marked archived");
    r = await call("list_sessions");
    check(new RegExp(`${s.id}.*disconnected \\(archived`).test(r.text), "list_sessions shows it disconnected and resumable");

    r = await call("resume_session", { id: s.id });
    check(!r.isError && urlOf(r.text) === s.url, "resume_session brings it back under the same URL");
    check(recordExists(s.id) && !meta(s.id).archivedAt, "the record no longer says archived");
    r = await call("send_prompt", { id: s.id, prompt: "Reply with exactly: AGAIN", wait_seconds: 120 });
    check(/AGAIN/.test(r.text), "it answers after the resume");

    const pid = panePid(s.id);
    r = await call("stop_session", { id: s.id });
    check(!r.isError && /archive=200/.test(r.text), "stop_session confirms the archive");
    checkGone(s.id, pid);
    check(!recordExists(s.id) && filesLeft(s.id) === "", "the record is removed, with every file of it");
    r = await call("list_sessions");
    check(!r.text.includes(s.id), "list_sessions no longer lists it");
    r = await call("get_reply", { id: s.id, wait_seconds: 0 });
    check(r.isError && /No session/.test(r.text), "get_reply cannot bring it back");
    r = await call("send_prompt", { id: s.id, prompt: "hello" });
    check(r.isError && /No session/.test(r.text), "send_prompt cannot bring it back");
  },

  // A session started with a prompt, closed in the middle of a turn.
  async busy() {
    const r0 = await call("start_session", {
      name: "e2e-busy", path: PROJECT, bypass_permissions: true,
      prompt: LONG_TURN,
    });
    const id = idOf(r0.text);
    check(Boolean(id && urlOf(r0.text)), "started with a prompt");
    if (!id) return;
    const pid = panePid(id);
    await sleep(5000);
    const r = await call("stop_session", { id, forget: false });
    check(!r.isError && /archive=200/.test(r.text), "stop_session mid-turn confirms the archive (forget is ignored)");
    checkGone(id, pid);
    check(!recordExists(id) && filesLeft(id) === "", "the record is removed, with every file of it");
  },

  // Killed outright, like a container restart does: closing it resumes it and ends it again.
  async dead() {
    const a = await startInteractive("e2e-dead-stop");
    const b = await startInteractive("e2e-dead-disc");
    for (const s of [a, b]) {
      if (s.pid) sh(`kill -9 ${s.pid}`);
    }
    await sleep(1500);
    check(!tmuxAlive(a.id) && statusFiles(a.id) !== "", "a SIGKILL leaves no tmux session but an orphan status file");

    let r = await call("stop_session", { id: a.id });
    check(!r.isError && /archive=200/.test(r.text) && /resumed and ended again/.test(r.text), "stop_session resumes a dead session to archive it");
    checkGone(a.id, a.pid);
    check(!recordExists(a.id) && filesLeft(a.id) === "", "its record is removed, with every file of it");

    r = await call("disconnect_session", { id: b.id });
    check(!r.isError && /archive=200/.test(r.text), "disconnect_session archives a dead session too");
    checkGone(b.id, b.pid);
    check(recordExists(b.id) && Boolean(meta(b.id).archivedAt), "its record is kept, marked archived");
    r = await call("stop_session", { id: b.id });
    check(!r.isError && /already archived/.test(r.text), "stopping it afterwards needs no second resume");
    check(!recordExists(b.id) && !tmuxAlive(b.id), "and removes it");
  },

  // A folder Claude Code does not trust.
  async untrusted() {
    const rel = `${PROJECT}/untrusted-${randomBytes(3).toString("hex")}`;
    const dir = `${BASE}/${rel}`;
    mkdirSync(dir, { recursive: true });
    sh(`git -C ${dir} init -q`);
    try {
      const before = sh(`ls ${STATE}`);
      let r = await call("start_session", { name: "e2e-untrusted", path: rel });
      check(r.isError && /does not trust/.test(r.text) && /trust_folder: true/.test(r.text), "start_session refuses it up front, and says why");
      check(sh(`ls ${STATE}`) === before && !sh("tmux ls 2>/dev/null").includes("e2e-untrusted"), "nothing was launched or recorded");

      // A session that got stuck on the dialog anyway (launched by hand, as an older version would have).
      const id = `e2e-blocked-${randomBytes(3).toString("hex")}`;
      writeFileSync(`${STATE}/${id}.meta`, JSON.stringify({
        mode: "session", dir, name: "e2e-blocked", sessionId: randomUUID(), bypass: true, createdAt: new Date().toISOString(),
      }));
      sh(`tmux new-session -d -s rc-${id} -c ${dir} '${process.env.CLAUDE_BIN || "claude"} --dangerously-skip-permissions --rc e2e-blocked'`);
      await sleep(6000);
      const pid = panePid(id);
      r = await call("list_sessions");
      check(new RegExp(`${id}.*folder trust dialog`).test(r.text), "list_sessions shows it stuck on the trust dialog");
      r = await call("get_reply", { id, wait_seconds: 15 });
      check(r.isError && /folder trust dialog/.test(r.text) && !/still working/.test(r.text), "get_reply reports the dialog, never 'still working'");
      r = await call("send_prompt", { id, prompt: "hello" });
      check(r.isError && /folder trust dialog/.test(r.text), "send_prompt refuses it");
      r = await call("interrupt_session", { id });
      check(r.isError && /folder trust dialog/.test(r.text), "interrupt_session refuses it");
      r = await call("resume_session", { id });
      check(r.isError && /folder trust dialog/.test(r.text), "resume_session reports it");
      check(tmuxAlive(id) && /No, exit/.test(sh(`tmux capture-pane -p -t rc-${id}`)), "the dialog is still there, unanswered");
      r = await call("stop_session", { id });
      check(!r.isError && /never connected/.test(r.text), "stop_session ends it: nothing to archive");
      checkGone(id, pid);
      check(!recordExists(id) && filesLeft(id) === "", "its record is removed, with every file of it");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },

  // trust_folder, explicitly asked for, on a folder that was never trusted.
  async trustFolder() {
    const rel = `${PROJECT}/trusted-by-e2e-${randomBytes(3).toString("hex")}`;
    const dir = `${BASE}/${rel}`;
    mkdirSync(dir, { recursive: true });
    sh(`git -C ${dir} init -q`);
    try {
      const r0 = await call("start_session", { name: "e2e-trust", path: rel, trust_folder: true });
      const id = idOf(r0.text);
      check(!r0.isError && Boolean(id && urlOf(r0.text)), "with trust_folder the session starts and connects");
      const config = JSON.parse(readFileSync(`${homedir()}/.claude.json`, "utf-8"));
      check(config.projects?.[dir]?.hasTrustDialogAccepted === true, "Claude Code recorded the trust itself");
      if (id) {
        const pid = panePid(id);
        const r = await call("stop_session", { id });
        check(!r.isError && /archive=200/.test(r.text), "and stop_session archives it");
        checkGone(id, pid);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },

  // Sessions not active for longer than the retention are closed for good - archived first.
  async expiry() {
    // A session killed outright (as a restart does): expiring it resumes and ends it, archived.
    const a = await startInteractive("e2e-expire");
    if (!a.id) return;
    sh(`kill -9 ${a.pid}`);
    await sleep(1500);
    age(a.id);
    let r = await call("list_sessions");
    check(new RegExp(`${a.id}.*being closed for good`).test(r.text), "list_sessions starts closing an expired session, and says so");
    let closedLine = "";
    for (let i = 0; i < 24 && !closedLine; i++) {
      await sleep(5000);
      r = await call("list_sessions");
      closedLine = r.text.split("\n").find((l) => l.includes(a.id) && /archive=200/.test(l)) || "";
    }
    check(/Closed for good after/.test(r.text) && Boolean(closedLine), "a later list_sessions reports it closed and archived (archive=200)");
    check(!r.text.split("Sessions (")[1]?.includes(a.id), "and no longer lists it");
    checkGone(a.id, a.pid);
    check(!recordExists(a.id) && filesLeft(a.id) === "", "its record is removed, with every file of it");

    // Disconnected (so archived already) and then expired: forgotten, with no resume.
    const b = await startInteractive("e2e-expire-disc");
    if (b.id) {
      await call("disconnect_session", { id: b.id });
      age(b.id);
      r = await call("list_sessions");
      check(!r.text.includes(b.id) && !tmuxAlive(b.id) && !recordExists(b.id), "an expired disconnected session is forgotten at once, without a resume");
    }

    // One that cannot be archived from here (its transcript is gone): it stays, flagged, with its URL.
    const c = await startInteractive("e2e-expire-gone");
    if (c.id) {
      sh(`kill -9 ${c.pid}`);
      await sleep(1500);
      const tr = transcriptOf(c.id);
      sh(`mv "${tr}" "${tr}.e2e"`);
      r = await call("list_sessions");
      check(new RegExp(`${c.id}.*NOT archived at claude.ai/code \\(its transcript is gone`).test(r.text) && r.text.includes(c.url),
        "a session that cannot be archived stays listed as NOT archived, with the reason and its URL");
      check(recordExists(c.id), "its record is kept");
      sh(`mv "${tr}.e2e" "${tr}"`);
      r = await call("stop_session", { id: c.id });
      check(!r.isError && /archive=200/.test(r.text), "once it can be resumed, stop_session archives it and removes it");
      check(!recordExists(c.id) && !tmuxAlive(c.id), "and it is gone");
    }

    // A legacy Remote Control server that is not running: flagged too, never silently dropped.
    const id = `e2e-srv-off-${randomBytes(3).toString("hex")}`;
    writeFileSync(`${STATE}/${id}.meta`, JSON.stringify({ mode: "server", dir: `${BASE}/${PROJECT}`, name: "e2e-srv-off", bypass: false }));
    writeFileSync(`${STATE}/${id}.url`, "https://claude.ai/code?environment=env_e2eOff");
    r = await call("list_sessions");
    check(new RegExp(`${id}.*NOT archived.*legacy Remote Control server`).test(r.text), "a legacy server that is not running stays listed as NOT archived");
    r = await call("stop_session", { id });
    check(!r.isError && !recordExists(id) && filesLeft(id) === "", "stop_session removes it");
  },

  // The old parameters, and what they no longer do: no Remote Control server is launched.
  async legacyParams() {
    const r0 = await call("start_session", { name: "e2e-legacy", path: PROJECT, interactive: false, worktree: true });
    const id = idOf(r0.text);
    check(!r0.isError && Boolean(id && urlOf(r0.text)) && /mode: conversational/.test(r0.text),
      "interactive: false and worktree: true are ignored: an empty conversational session opens");
    if (!id) return;
    check(meta(id).mode === "session" && !/remote-control/.test(sh(`tmux display -p -t rc-${id} '#{pane_start_command}'`)),
      "it is not a Remote Control server");
    const pid = panePid(id);
    const r = await call("stop_session", { id });
    check(!r.isError && /archive=200/.test(r.text), "and stop_session archives it");
    checkGone(id, pid);
  },

  // A Remote Control server recorded by an older version, which this one still has to close.
  // It is a stand-in: a real `claude remote-control` leaves an unarchived session at
  // claude.ai/code on every run (it keeps its environment on shutdown, by design). The
  // stand-in runs the same way - under a shell, piped into tee - and logs what the CLI
  // logs on SIGTERM, which was checked by hand against the real one.
  async legacyServer() {
    const id = `e2e-srv-${randomBytes(3).toString("hex")}`;
    const fake = `${STATE}/${id}.fake.sh`;
    writeFileSync(fake, [
      "#!/bin/sh",
      'debug="$1"',
      'echo "[bridge:work] Starting poll loop spawnMode=same-dir" >> "$debug"',
      'trap \'echo "[bridge:shutdown] SIGTERM received, shutting down" >> "$debug"; ' +
        'echo "[bridge:shutdown] Skipping archive+deregister to allow resume (env env_e2eFake, spawnMode same-dir)" >> "$debug"; exit 0\' TERM',
      'echo "Continue coding at https://claude.ai/code?environment=env_e2eFake"',
      "while :; do sleep 1; done",
    ].join("\n"), { mode: 0o755 });
    writeFileSync(`${STATE}/${id}.meta`, JSON.stringify({
      mode: "server", dir: `${BASE}/${PROJECT}`, name: "e2e-srv", bypass: false, createdAt: new Date().toISOString(),
    }));
    writeFileSync(`${STATE}/${id}.url`, "https://claude.ai/code?environment=env_e2eFake");
    sh(`tmux new-session -d -s rc-${id} -c ${BASE}/${PROJECT} '${fake} ${STATE}/${id}.debug 2>&1 | tee ${STATE}/${id}.log'`);
    await sleep(1500);
    const pid = panePid(id);
    const children = sh(`pgrep -P ${pid}`).split("\n").filter(Boolean);
    let r = await call("list_sessions");
    check(new RegExp(`${id}.*legacy remote-control server`).test(r.text), "list_sessions lists it as a legacy server");
    r = await call("send_prompt", { id, prompt: "hello" });
    check(r.isError && /legacy Remote Control/.test(r.text), "send_prompt refuses it");
    r = await call("disconnect_session", { id });
    check(r.isError && /cannot be resumed/.test(r.text) && tmuxAlive(id), "disconnect_session refuses it, and leaves it running");
    r = await call("stop_session", { id });
    check(r.isError && /NOT confirmed archived/.test(r.text) && /keeps its environment/.test(r.text) && /environment=env_e2eFake/.test(r.text),
      "stop_session ends it and says plainly it is not archived, with the URL");
    checkGone(id, pid);
    check(children.length === 2 && children.every((c) => !procAlive(c)), "the server and its tee are gone");
    check(!recordExists(id) && filesLeft(id) === "", "its record is removed, with every file of it");
  },
};

for (const [name, run] of Object.entries(scenarios)) {
  if (ONLY.length && !ONLY.includes(name)) continue;
  console.log(`\n=== ${name} ===`);
  try { await run(); } catch (err) { check(false, `${name} threw: ${err.stack || err}`); }
}
await client.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
