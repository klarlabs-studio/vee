# Using Vee day to day

Vee reviews a change at the points where work is handed on. Each point uses
the same configuration (`.vee.yaml`), the same reviewers and the same gate,
so a change that passes in one place passes in the next.

| When | How | What happens on a block |
|---|---|---|
| A coding agent finishes its turn | The plugin's Stop hook, in Claude Code or Codex | The agent gets the blocking findings and keeps working |
| You push | `vee hooks install` (optional) | The push stops; `git push --no-verify` skips the review |
| A pull request opens or changes | `vee init --ci github` or `--ci gitlab` | The check fails and findings appear as threads |
| You act on a finding in the pull request | `@vee explain`, `fix`, `dismiss`, `waive`, `review` | Vee replies in the thread; a reviewed fix is pushed as one commit; a waiver can pass the gate |

The pull request check is the gate that counts. The two local points find
problems earlier, while the agent or the author still has the context.

## While an agent codes

Install the plugin (see the README), and make sure `vee` is on `PATH`. The
hooks work in Claude Code and in Codex. Codex runs a new or changed hook
only after you trust it, so open `/hooks` once after installing or updating
the plugin. In a repository with a `.vee.yaml`, Vee records where each agent
session starts.
When the agent finishes a turn that changed code, Vee reviews everything
since then: commits and uncommitted changes.

- **Pass:** the agent finishes, and you see `Vee review … passed.`
- **Block:** the agent receives the blocking findings and is told to fix
  each one, or to explain to you why one does not apply. When it finishes
  again, Vee reviews again.
- **Unchanged:** if the agent finishes without changing anything after a
  block, Vee lets it finish and tells you the findings still stand.
- **Three rounds:** after three blocked rounds in one session, Vee lets the
  agent finish and points you to `vee findings list --review <id>`.
- **Incomplete or failing:** if a reviewer cannot run, you get a message.
  The agent is never kept working because Vee failed.

Set `VEE_AGENT_REVIEW=off` to turn the hook off on a machine. You can still
ask the agent to review: the plugin's `/vee:vee-local-review` skill and the
MCP tools work as before.

The hook reviews at the repository's configured effort. A turn that changes
code costs one review, so a lower effort for local work (`vee init --effort
low`, which sets this machine only) keeps turns fast.

## Before you push

```sh
vee hooks install
```

This writes a `pre-push` hook (honouring `core.hooksPath`) that reviews the
commits the push sends. A new branch is reviewed from where it left the
remote's default branch. If Git does not know that branch, run
`git remote set-head origin --auto`. Only a blocking gate stops the push.

`vee hooks status` shows the hook's state, and `vee hooks uninstall` removes
it. Vee never writes over another tool's `pre-push` hook. To keep that hook,
add this line to it; the line reads the same input:

```sh
vee hooks run pre-push "$@" || exit 1
```

## The steward

When the gate blocks, let the steward take the routine fixes:

```sh
vee steward --base main
```

It works through the problems that keep the branch from passing, in order:

1. a merge conflict with `main`;
2. each required verification that fails and names a changed file;
3. each blocking finding.

For each one, the configured reviewer's model proposes a fix and Vee
commits it. Then Vee reviews the branch again and keeps the commit only
when:

- the review is complete;
- nothing new blocks;
- every verification that passed still passes;
- the problem is solved.

Otherwise it resets the branch to before the fix and reports why. Read
the report, then `git log` the kept commits. Each one says how to undo it,
for example `git revert <commit>`. Nothing is pushed.

- A merge conflict is resolved only when a required verification
  (`policy.required_verifications`) passes on the result. Without one, it
  stays yours.
- Start from a clean branch: the steward refuses uncommitted changes to
  tracked files, because it undoes a fix by resetting the branch.
- `steward.max_fixes` (default 5, at most 10) or `--max-fixes` bounds the
  model calls of a run.
- A coding agent can run the steward through the MCP tool `run_steward`
  once `.vee.yaml` allows it:

  ```yaml
  steward:
    agents: true
  ```

## On the pull request

See [the pull request guide](pull-requests.md).
