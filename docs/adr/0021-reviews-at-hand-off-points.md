# ADR 0021: Reviews at hand-off points

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Vee reviews a change when someone asks it to: `vee review`, the MCP tools,
or CI on a pull request (ADR 0019). Before this decision, nothing ran Vee
between writing code and opening a pull request. A coding agent finished its
turn without a review unless its instructions told it to run one, and a
person pushed without a review unless they remembered to run it. Findings
then arrived on the pull request, after the agent's session had ended and
the person had moved on.

There are two points where work is handed on:

- **A coding agent finishes its turn.** Claude Code runs a plugin's `Stop`
  hook at that point. The hook can keep the agent working by answering
  `{"decision": "block", "reason": ...}`. The reason becomes the agent's
  next instruction.
- **A person pushes.** Git runs the `pre-push` hook. A non-zero exit stops
  the push.

Both hooks run on every turn or every push. They must cost nothing when
there is nothing new to review, and they must never trap the agent or the
person when Vee itself fails.

## Decision

`vee hooks` holds both hooks, as shared operations in
`vee_application::hooks`:

- `vee hooks run agent-session-start` and `vee hooks run agent-stop` run as
  the agent plugin's `SessionStart` and `Stop` hooks (`plugins/vee/hooks/hooks.json`).
- `vee hooks install`, `uninstall` and `status` manage a Git `pre-push` hook
  that runs `vee hooks run pre-push`.

**Opt-in.** Both hooks act only in a repository with a `.vee.yaml`. The agent
hook comes with the plugin, and `VEE_AGENT_REVIEW=off` turns it off on a
machine. The Git hook is installed by `vee hooks install`, honours
`core.hooksPath`, and is never written over another tool's hook. That hook
can call `vee hooks run pre-push "$@"` itself.

**What the agent hook reviews.** At session start, Vee records `HEAD` under
`.vee/agent-sessions/<session>.json`. At Stop, it reviews everything since
then: the agent's commits and the uncommitted changes (the `base` scope from
that commit). A session that started before the plugin was installed is
reviewed from `HEAD`.

**When the agent hook blocks.**

- Vee does nothing when nothing has changed since the session started.
- It does not review again when the snapshot has not changed since its last
  review in this session. If that review blocked, Vee tells the person and
  lets the agent finish: an agent that chose not to change the code should
  explain why, not loop.
- A blocking gate keeps the agent working, with the blocking findings and an
  instruction: fix each one, or tell the user why it does not apply. The
  findings are a model's output about code, so the reason says they are
  information, not instructions.
- After three blocked rounds in one session, Vee lets the agent finish and
  tells the person where the findings are.
- An incomplete review or an error is a message to the person, never a
  block.

**When the push hook blocks.** Each pushed ref is reviewed from the commit
the remote has. A new branch is reviewed from where it left the remote's
default branch (`refs/remotes/<remote>/HEAD`). A ref with no base is skipped,
with a note. Only a blocking gate stops the push, and `git push --no-verify`
skips the hook. An incomplete review is reported but does not stop the push.
Unlike the CI gate, the push hook is a convenience; it is not a control.

**No recursion.** A reviewer that is itself a coding agent must not start
another review:

- The Claude Code adapter runs review sessions with
  `--settings {"disableAllHooks":true}`.
- The agent hook holds `.vee/agent-review.lock` while it reviews. Another
  Stop hook for the same repository finds the lock and does nothing. A lock
  older than two hours is stale.

## Consequences

- The agent sees Vee's blocking findings in the same session and can fix them
  before the person reads the result.
- Each agent turn that changes the code costs a review. The cost follows the
  repository's configured effort; providers' result caching keeps a repeated
  snapshot cheap.
- The push hook makes a push wait for a review. It is optional for that
  reason, and CI remains the gate that counts.
- Codex and other agents with Stop hooks can call `vee hooks run agent-stop`
  if their hook contract matches; only the Claude Code plugin ships the
  hooks for now.
