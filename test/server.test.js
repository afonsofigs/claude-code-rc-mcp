import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  parseLive, parseJsonl, turnAfter, startupDialog, TRUST_YES_SELECTED_RE, trustedBy,
  archiveOutcome, serverArchiveOutcome, bridgeConnected, archiveLine, formatOutcome,
  expiryAction, flagReason, ago, liveStatusText,
} from "../server.js";

const fixture = (name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf-8");
const textOf = (result) => result.content.map((c) => c.text).join("\n");

// --- Startup dialogs ---

test("the folder trust dialog is recognised from a real pane", () => {
  assert.equal(startupDialog(fixture("trust-dialog.txt")), "trust");
  assert.equal(startupDialog(fixture("trust-dialog-yes.txt")), "trust");
});

test("the trust dialog opens on 'No, exit', and the yes is only seen as selected once it is", () => {
  assert.equal(TRUST_YES_SELECTED_RE.test(fixture("trust-dialog.txt")), false);
  assert.equal(TRUST_YES_SELECTED_RE.test(fixture("trust-dialog-yes.txt")), true);
});

test("a prompt that only quotes the dialog is not taken for it", () => {
  const pane = [
    "❯ Explain the trust dialog: it says Yes, I trust this folder and Enter to confirm · Esc to cancel",
    "",
    "● Sure.",
    "────────────",
    "❯ ",
    "────────────",
    "  ⏵⏵ bypass permissions on (shift+tab to cycle)",
  ].join("\n");
  assert.equal(startupDialog(pane), null);
});

test("any other selector with the confirm/cancel hints counts as a startup dialog", () => {
  const pane = [
    " New MCP server found in .mcp.json: github",
    "",
    " ❯ Use this and all future MCP servers in this project",
    "   Use this MCP server",
    "   Continue without using this MCP server",
    "",
    " Enter to confirm · Esc to cancel",
  ].join("\n");
  assert.equal(startupDialog(pane), "other");
});

test("an ordinary pane is no dialog", () => {
  assert.equal(startupDialog("❯ \n  ⏵⏵ bypass permissions on\n"), null);
  assert.equal(startupDialog(""), null);
});

// --- Folder trust, by Claude Code's rule ---

test("outside git, a trusted parent folder vouches for the folders under it", () => {
  const projects = { "/home/u/code": { hasTrustDialogAccepted: true } };
  assert.equal(trustedBy(projects, "/home/u/code/scratch", ""), "/home/u/code");
});

test("inside a git repository, a trusted parent folder does not count", () => {
  const projects = { "/home/u/code": { hasTrustDialogAccepted: true } };
  assert.equal(trustedBy(projects, "/home/u/code/repo", "/home/u/code/repo"), null);
});

test("a trusted repository root vouches for its subfolders", () => {
  const projects = { "/home/u/code/repo": { hasTrustDialogAccepted: true } };
  assert.equal(trustedBy(projects, "/home/u/code/repo/pkg/a", "/home/u/code/repo"), "/home/u/code/repo");
  assert.equal(trustedBy(projects, "/home/u/code/repo", "/home/u/code/repo"), "/home/u/code/repo");
});

test("an explicit false, or no entry at all, is untrusted", () => {
  const projects = { "/x/repo": { hasTrustDialogAccepted: false } };
  assert.equal(trustedBy(projects, "/x/repo", "/x/repo"), null);
  assert.equal(trustedBy(undefined, "/x/other", ""), null);
});

// --- The archive at claude.ai/code ---

const TORN_DOWN = [
  "2026-10-10T18:34:47.646Z [DEBUG] [remote-bridge] Created session cse_01Uor6WKgyWzg4JManD1mF9a",
  "2026-10-10T18:34:56.198Z [DEBUG] [code-session] Archive cse_01Uor6WKgyWzg4JManD1mF9a status=200",
  "2026-10-10T18:34:56.383Z [DEBUG] [remote-bridge] Torn down (archive=200)",
].join("\n");

test("archive=200 in the debug log is a confirmed archive", () => {
  assert.deepEqual(archiveOutcome(TORN_DOWN), { archived: true, status: "200" });
});

test("a timeout, an error status or a skipped archive is not", () => {
  assert.deepEqual(archiveOutcome("[remote-bridge] Torn down (archive=timeout)"), { archived: false, status: "timeout" });
  assert.deepEqual(archiveOutcome("[remote-bridge] Torn down (archive=500)"), { archived: false, status: "500" });
  assert.deepEqual(
    archiveOutcome("[remote-bridge] Teardown complete (skipArchive): session=cse_x"),
    { archived: false, status: "skipped" }
  );
});

test("no teardown line means no outcome; the last teardown is the one that counts", () => {
  assert.equal(archiveOutcome("[remote-bridge] Created session cse_x"), null);
  assert.equal(archiveOutcome(""), null);
  assert.deepEqual(
    archiveOutcome("[remote-bridge] Torn down (archive=timeout)\n[remote-bridge] Torn down (archive=200)"),
    { archived: true, status: "200" }
  );
});

test("the Remote Control server's shutdown is read from its own lines", () => {
  const ok = "[bridge:shutdown] Archiving 1 session(s)\n[code-session] Archive cse_a status=200\n[bridge:shutdown] Environment deregistered, bridge offline";
  assert.deepEqual(serverArchiveOutcome(ok), { archived: true, status: "200" });
  assert.deepEqual(
    serverArchiveOutcome("[bridge:shutdown] Environment deregistered, bridge offline"),
    { archived: true, status: "no sessions" }
  );
  assert.equal(serverArchiveOutcome(ok.replace("status=200", "status=503")).archived, false);
  assert.equal(serverArchiveOutcome("[bridge:shutdown] Skipping archive+deregister to allow resume").archived, false);
  assert.equal(serverArchiveOutcome("[bridge:shutdown] Archiving 1 session(s)"), null);
});

test("a session whose log shows no bridge never reached claude.ai/code", () => {
  assert.equal(bridgeConnected(TORN_DOWN), true);
  assert.equal(bridgeConnected("[DEBUG] Keeping /home/u/.claude/plugins/cache"), false);
});

test("an unconfirmed archive is reported as such, with the URL to archive by hand", () => {
  const url = "https://claude.ai/code/session_01Abc";
  const line = archiveLine({ archive: { archived: false, status: "timeout" }, url, notes: [] });
  assert.match(line, /NOT confirmed archived/);
  assert.match(line, /archive=timeout/);
  assert.ok(line.includes(url));
  assert.match(archiveLine({ archive: null, url, notes: [] }), /no record of the archive/);
  assert.match(archiveLine({ archive: { archived: true, status: "200" }, url, notes: [] }), /^Archived .*archive=200/);
  assert.match(archiveLine({ neverConnected: true, archive: null, notes: [] }), /nothing to archive/);
});

// --- Reporting a turn ---

test("a session stuck on a startup dialog is never reported as still working", () => {
  const pane = fixture("trust-dialog.txt");
  for (const dialog of ["trust", "other"]) {
    const result = formatOutcome("s-1", { state: "dialog", dialog, pane }, { waitedSeconds: 90 });
    assert.equal(result.isError, true);
    assert.doesNotMatch(textOf(result), /still working/);
  }
  const trust = textOf(formatOutcome("s-1", { state: "dialog", dialog: "trust", pane }, { waitedSeconds: 90 }));
  assert.match(trust, /folder trust dialog/);
  assert.match(trust, /trust_folder: true/);
});

test("a turn that is genuinely running still says so", () => {
  const text = textOf(formatOutcome("s-1", { state: "running", pane: "" }, { waitedSeconds: 30 }));
  assert.match(text, /still working after 30s/);
});

// --- Status file and transcript (regression) ---

test("parseLive ignores a status file older than the tmux session", () => {
  const file = JSON.stringify({ status: "idle", startedAt: 1000_000, sessionId: "2f8bd080-2260-4185-95b2-c821808e7915", bridgeSessionId: "session_01Abc" });
  assert.equal(parseLive("42 2000", file), null);
  const live = parseLive("42 999", file);
  assert.equal(live.status, "idle");
  assert.equal(live.url, "https://claude.ai/code/session_01Abc");
  assert.equal(parseLive("42 999", ""), null);
});

const entry = (type, content, extra = {}) => ({
  type, timestamp: extra.timestamp || "2026-10-10T10:00:01.000Z",
  message: { role: type, content, ...(extra.message || {}) }, ...extra.top,
});

test("a turn ends on an assistant message that neither carries nor stops for a tool call", () => {
  const prompt = entry("user", "hi", { timestamp: "2026-10-10T10:00:01.000Z" });
  const toolCall = entry("assistant", [{ type: "tool_use", id: "t" }], { message: { stop_reason: "tool_use" } });
  const prelude = entry("assistant", [{ type: "text", text: "Let me check." }], { message: { stop_reason: "tool_use" } });
  const answer = entry("assistant", [{ type: "text", text: "OK" }], { message: { stop_reason: "end_turn" } });
  assert.equal(turnAfter([prompt, prelude], "2026-10-10T10:00:00.000Z").outcome, null);
  assert.equal(turnAfter([prompt, toolCall], "2026-10-10T10:00:00.000Z").outcome, null);
  assert.deepEqual(turnAfter([prompt, answer], "2026-10-10T10:00:00.000Z").outcome, { state: "done", reply: "OK" });
});

test("no prompt after the send mark is a turn not started yet", () => {
  const old = entry("user", "earlier", { timestamp: "2026-10-10T09:00:00.000Z" });
  const answer = entry("assistant", [{ type: "text", text: "old answer" }], { timestamp: "2026-10-10T09:00:01.000Z", message: { stop_reason: "end_turn" } });
  assert.equal(turnAfter([old, answer], "2026-10-10T10:00:00.000Z").outcome, null);
});

test("an interrupted turn and a slash command's output both end a turn", () => {
  const prompt = entry("user", "go");
  const interrupted = entry("user", [{ type: "text", text: "[Request interrupted by user]" }]);
  assert.deepEqual(turnAfter([prompt, interrupted], "2026-10-10T10:00:00.000Z").outcome, { state: "interrupted" });
  const cmd = entry("user", "<command-name>/compact</command-name>");
  const out = entry("user", "<local-command-stdout>Compacted</local-command-stdout>");
  assert.deepEqual(turnAfter([cmd, out], "2026-10-10T10:00:00.000Z").outcome, { state: "command", command: "/compact", output: "Compacted" });
});

test("parseJsonl skips partial lines", () => {
  assert.equal(parseJsonl('{"a":1}\n{"b":\nnot json\n{"c":3}\n').length, 2);
});

// --- Expiry ---

const DAY = 86400000;
const NOW = Date.parse("2026-10-20T12:00:00Z");
const conv = (extra = {}) => ({ mode: "session", sessionId: "2f8bd080-2260-4185-95b2-c821808e7915", ...extra });
const expiry = (over) => expiryAction({ meta: conv(), searched: true, lastActive: NOW - 20 * DAY, url: "https://claude.ai/code/session_01A", now: NOW, retentionMs: 14 * DAY, ...over });

test("an expired session is closed (archived) before it is forgotten", () => {
  assert.equal(expiry({}), "close");
  assert.equal(expiry({ lastActive: NOW - 3 * DAY }), "keep");
});

test("an expired session that was archived when it was disconnected is simply forgotten", () => {
  assert.equal(expiry({ meta: conv({ archivedAt: "2026-10-01T00:00:00Z" }) }), "forget");
});

test("a record that cannot be archived from here stays listed, flagged", () => {
  assert.equal(expiry({ meta: conv({ archiveFailed: { reason: "archive=500" } }) }), "flag");
  assert.equal(expiry({ lastActive: 0 }), "flag");
  assert.equal(expiry({ meta: { mode: "server" } }), "flag");
  assert.equal(expiry({ meta: null }), "flag");
});

test("with no URL there is nothing at claude.ai/code to archive", () => {
  assert.equal(expiry({ lastActive: 0, url: null }), "forget");
  assert.equal(expiry({ meta: { mode: "server" }, url: null }), "forget");
});

test("a record the shell could not read is kept, and one being closed stays being closed", () => {
  assert.equal(expiry({ searched: false }), "keep");
  assert.equal(expiry({ meta: conv({ expiringSince: "2026-10-20T11:59:00Z" }), lastActive: NOW - 60000 }), "close");
});

test("a flagged record says why it is not archived", () => {
  assert.match(flagReason({ mode: "server" }), /archives none of its sessions/);
  assert.match(flagReason(conv({ archiveFailed: { reason: "the bridge reported archive=500" } })), /archive=500/);
  assert.match(flagReason(conv()), /transcript is gone/);
  assert.match(flagReason(null), /no metadata/);
});

// --- How long a session has been sitting there ---

test("ago counts whole units, rounded down, so a threshold is never reached early", () => {
  const t = Date.parse("2026-10-10T12:00:00Z");
  assert.equal(ago(t - 89 * 1000, t), "89s");
  assert.equal(ago(t - 90 * 1000, t), "1m");
  assert.equal(ago(t - (5 * 3600 + 59 * 60) * 1000, t), "5h");
  assert.equal(ago(t - 6 * 3600 * 1000, t), "6h");
  assert.equal(ago(t - 35 * 3600 * 1000, t), "35h");
  assert.equal(ago(t - 36 * 3600 * 1000, t), "1d");
});

test("a running session that is idle or waiting says since when; a working one does not", () => {
  const t = Date.parse("2026-10-10T12:00:00Z");
  const since = t - 7 * 3600 * 1000;
  assert.equal(liveStatusText({ status: "idle", statusUpdatedAt: since }, null, t), "idle (last active 7h ago)");
  assert.equal(liveStatusText({ status: "shell", statusUpdatedAt: since }, null, t), "idle, background shell running (last active 7h ago)");
  assert.equal(
    liveStatusText({ status: "waiting", waitingFor: "AskUserQuestion", statusUpdatedAt: since }, null, t),
    "waiting for input (AskUserQuestion) (last active 7h ago)"
  );
  assert.equal(liveStatusText({ status: "busy", statusUpdatedAt: since }, null, t), "working");
  assert.equal(liveStatusText(null, null, t), "running");
  assert.equal(liveStatusText({ status: "idle", statusUpdatedAt: 0 }, null, t), "idle");
  assert.match(liveStatusText(null, "trust", t), /^stuck on the folder trust dialog/);
});

test("the running and the stopped forms share one pattern", () => {
  const re = /\(last active (\d+)([smhd]) ago\)/;
  const t = Date.parse("2026-10-10T12:00:00Z");
  assert.deepEqual(liveStatusText({ status: "idle", statusUpdatedAt: t - 8 * 3600 * 1000 }, null, t).match(re).slice(1), ["8", "h"]);
});
