# Using Vee day to day

Vee reviews a change at the points where work is handed on. Each point uses
the same configuration (`.vee.yaml`), the same reviewers and the same gate,
so a change that passes in one place passes in the next.

| When | How | What happens on a block |
|---|---|---|
| A coding agent finishes its turn | The Claude Code plugin's Stop hook | The agent gets the blocking findings and keeps working |
| You push | `vee hooks install` (optional) | The push stops; `git push --no-verify` skips the review |
| A pull request opens or changes | `vee init --ci github` or `--ci gitlab` | The check fails and findings appear as threads |
| You act on a finding in the pull request | `@vee explain`, `dismiss`, `waive`, `review` | Vee replies in the thread; a waiver can pass the gate |

The pull request check is the gate that counts. The two local points find
problems earlier, while the agent or the author still has the context.

## While an agent codes

Install the plugin (see the README), and make sure `vee` is on `PATH`. In a
repository with a `.vee.yaml`, Vee records where each agent session starts.
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

## On the pull request

See [the pull request guide](pull-requests.md).
