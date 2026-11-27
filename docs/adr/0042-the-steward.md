# ADR 0042: The steward

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

A change often stops at its gate for reasons a person fixes by rote:

- a merge conflict with the base;
- a required verification, such as the tests, that fails;
- a blocking finding with an obvious fix.

`@vee fix` ([ADR 0023](0023-fixes-from-pull-request-comments.md),
[ADR 0027](0027-fixing-every-open-finding.md)) fixes Vee's own findings on
a pull request, one at a time, reviewing each fix before it pushes it.
Nothing fixes failing verifications or merge conflicts, and nothing runs
the same loop on a developer's or an agent's branch.

## Decision

**One engine, several entry points.** The steward takes the problems from
the review of the change's head, in this order:

1. a merge conflict with the base;
2. each required verification profile that fails, when its diagnostics
   name a changed file;
3. each blocking finding that names a file.

Problems the steward cannot take on stay in its report for a person: a
verification whose output names no changed file, or a finding without a
file. Each run attempts at most `steward.max_fixes` fixes (default 5, at
most 10).

**The configured model proposes; Vee decides.** The reviewer the
repository already uses for fixes, an agent CLI or a local model,
proposes each fix with the same constrained edits as `@vee fix`. Fixes
never touch `.vee.yaml`, `.vee/` or CI definitions. Problem text, CI
output and file contents go to the model as untrusted data.

**A fix is kept only when the gate holds again.** Vee commits each fix
and reviews the new head, running the policy's required verifications
first. It keeps the commit only when:

- the review is complete;
- no blocking finding appears that the review before the fix did not have;
- every verification that passed before the fix still passes;
- the problem is solved: the finding is gone, or the verification passes.

Otherwise Vee resets the branch to the commit before the fix, and the
report says why. A pull request with several blocking findings still
blocks after one is fixed. The rule is therefore that each kept fix leaves
the gate no worse and solves its problem, not that the gate passes after
every fix.

**Conflicts are resolved only when the result can be verified.** The
steward merges the base, then asks the model to resolve each conflicted
file, at most five, and returns the whole file. It keeps the merge only
when no conflict marker remains and at least one required verification
runs on the merged result and passes. Without such a verification, the
conflict goes back to a person, because a review alone cannot show that
both sides still work together. The merge commit's undo is
`git revert -m 1`.

**Whoever starts the steward approves its commits.** Applying a change
stays approved by a person or permitted by policy:

- `vee steward --base <ref>` is run by a person. It commits to the
  checked-out branch, never pushes, and refuses to start with uncommitted
  changes to tracked files, since it undoes a fix by resetting the branch.
- The MCP tool `run_steward` is how a coding agent runs it. The
  repository must allow that with `steward.agents: true`, which is off by
  default.

Every commit names who asked for it and how to undo it, and the report
(`steward-run-v1`) lists each step's commit and undo command.

## Consequences

- Developers and agents can hand the routine fixes to the steward and get
  back commits they can read, keep or revert one at a time.
- Every attempt costs model calls and a review. `steward.max_fixes` bounds
  the cost of a run.
- A change to a person's review comment can be checked only for not making
  the gate worse; whether it does what the person asked stays theirs to
  judge.
- On a pull request, `@vee steward` from a person with write access runs
  the same engine on the head. It adds the review comments on lines that
  people with write access started and the steward has not answered yet.
  The comment text goes to the model as untrusted data, so this is the one
  place a person's comment reaches a model, and only when another person
  with write access asks for it. Commands, bots and Vee's own threads are
  left out. It pushes the kept fixes in one push and publishes the review
  of the new head. It answers in each addressed comment's thread with the
  commit and how to undo it, marked so a later run skips that thread.
  Forks are refused, as for `@vee fix`.
