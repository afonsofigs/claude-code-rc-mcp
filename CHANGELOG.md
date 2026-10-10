# Changelog

## 1.3.0 - 2026-10-10

### Changed

- `stop_session` closes a session for good: it ends the process and the tmux session, archives the session at claude.ai/code and removes it from `list_sessions`, so it can no longer be resumed (or unarchived) from here. The archive is reported as Claude Code logged it (`archive=200`); when it cannot be confirmed, the reply says so and gives the URL to archive it by hand.
- Closing a session that is no longer running (a container restart kills it outright, which archives nothing) resumes it briefly and ends it again, so it is archived too.
- `start_session` without a `prompt` opens an empty conversational session ("open me an RC session on X"), to use at claude.ai/code or drive with `send_prompt`.
- Every launch passes `--debug-file <state>/<id>.debug`: the only record of whether claude.ai/code archived the session.

### Added

- `disconnect_session`: ends the process and archives the session at claude.ai/code like `stop_session`, but keeps it in `list_sessions`, resumable - a resume unarchives it under the same URL. `list_sessions` shows it as disconnected.
- Folder trust: `start_session` (and any resume) checks Claude Code's own trust rule first and launches nothing in an untrusted folder, saying what trusting it implies. `trust_folder: true`, only on the user's explicit request, answers the trust dialog in the terminal.
- Startup dialogs (the folder trust dialog, or any other before the session starts) are reported as such by every tool, never as "still working"; `send_prompt` and `interrupt_session` refuse to press keys there.
- Quality gates: `npm run verify` (`node --check`, ESLint, `node:test` unit tests), also run in CI before the image is built. `npm run e2e` checks every tool against a local instance.

### Removed

- The Remote Control server form (`claude remote-control`, launched by `start_session` without `prompt` / `interactive`): Claude Code keeps a server's environment on shutdown and never archives its sessions, so it could not be closed cleanly. Server sessions recorded by an older version are still listed and closed by `stop_session`, which ends them with a SIGTERM and reports them as not archived, with the URL.
- `SPAWN_WORKTREE` is no longer read.

### Deprecated

- `stop_session`'s `forget`, and `start_session`'s `interactive` and `worktree`: accepted and ignored. They will be removed in the next version.

### Fixed

- A session stuck on the folder trust dialog was reported by `get_reply` as "still working", and a `send_prompt` would have answered the dialog with its default, "No, exit".
- Stopping a Remote Control server killed the `tee` it writes to, so it died halfway through its shutdown without marking its environment offline.
