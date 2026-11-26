# ADR 0023: Fixes from pull request comments

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

People can explain, dismiss and waive Vee's findings from a pull request
(ADR 0020). Fixing one still means checking out the branch, editing, and
pushing. Many findings are small and local: a missed null check, an
off-by-one, a result that is dropped. The reviewer that raised one can
usually propose the fix.

A fix written by a model and pushed to someone's branch is a change to their
code. It needs:

- a person who asked for it;
- a check that it fixes what it claims to fix, and breaks nothing the review
  can see;
- an obvious way to undo it.

## Decision

`@vee fix [finding]` is a comment command, with the same authorization as the
others: write access, no forks, an open pull request, and comment text that
never reaches a model. Written in a finding's thread, it names that finding.

1. Vee checks out the pull request's head and asks the model of the reviewer
   that answers `explain` for edits to the finding's file. The model sees
   the finding as Vee published it, and the file.
2. An edit replaces an exact passage that occurs exactly once in the file, so
   a fix cannot land in the wrong place. Vee applies the edits itself.
3. A fix changes only the finding's file. It never changes `.vee.yaml`,
   `.vee/`, `.github/`, `.gitlab/` or `.gitlab-ci.yml`. The file must be
   UTF-8 and at most 64 KiB, and a fix has at most 10 edits.
4. Vee commits the fix on top of the head and reviews the new head,
   incrementally (ADR 0022).
5. Vee pushes only when that review:
   - is complete;
   - no longer reports the finding;
   - has no blocking finding that the last review's record did not have.
   Without a record, the gate must pass. The push is a fast-forward to the
   pull request's branch, never forced.
6. A push with the workflow's token starts no workflow, so Vee publishes the
   review it made, once the host shows the new head.
7. Vee replies in the finding's thread. The reply says:
   - who proposed the fix, and with which model;
   - what changed;
   - the gate on the new head;
   - `git revert <commit>` to undo it.
   The commit message names the person who asked and carries a
   `Vee-Finding:` trailer.

When any step fails, nothing is pushed, the checkout is reset to the head,
and the reply says why. Failures include a model that proposes no change,
an edit that does not apply, a review that rejects the fix, and a push that
is refused (a protected branch, a moved head, or a token without
`contents: write`).

**Permissions.** The workflow that `vee init --ci github` writes gives the
comment job `contents: write`. A team that does not want fixes can remove it;
`@vee fix` then reports that the push was refused.

## Consequences

- A small finding can be fixed from the pull request, and the fix is
  reviewed before anyone sees it on the branch.
- A fix that changes the finding's line moves the finding's anchor. If the
  same problem remains, the review reports it as a new finding, and the fix
  is refused.
- Fixes that need several files, or code the model cannot see, are refused.
  The reply says so.
- Each `@vee fix` costs a model call for the fix and a review of the fixed
  file.
- A pushed fix is a commit by the workflow's account. Branch protection that
  requires signed commits refuses it.
