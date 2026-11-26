# ADR 0030: GitLab parity for the summary record, approvals and commands

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

On GitLab, `vee ci run` published a commit status and discussions, and
nothing else. The summary note with its review record (ADR 0022), labels
and approvals (ADR 0024), and comment commands (ADR 0020) existed only on
GitHub, because only the GitHub adapter implemented Vee's conversation
interface. GitLab also does not start pipelines for comments.

## Decision

- **The conversation interface on GitLab.**
  - **Comments** are merge request notes, read from discussions. Their ID is
    `<discussion ID>:<note ID>`, so replies, edits and resolutions always
    reach the right discussion. Notes in diff discussions are thread
    comments; system notes are skipped.
  - **Permissions** come from project membership: Owner as admin,
    Maintainer as maintain, Developer as write, Reporter as triage, and
    Planner or Guest as read. A team is a group path.
  - **Labels** are changed with `add_labels` and `remove_labels`, only
    under Vee's prefixes.
  - **Approvals.**
    - Vee approves with the head's `sha`, so GitLab refuses a stale
      approval, and withdraws with `unapprove`. Its reasons are posted as
      notes.
    - GitLab keeps no review objects. Approvals, withdrawals and requests
      for changes are read from system notes. Each is tied to the head of
      the newest merge request version created before it.
- **Vee's account is the token's user.** GitLab CI does not name the
  account Vee posts as, so Vee asks the API (`/user`). Only notes by that
  user are trusted as Vee's summary and acknowledgements.
- **Commands through a triggered pipeline.**
  - A Comments webhook pointed at the pipeline trigger URL starts the
    template's `vee-command` job, with the payload in `TRIGGER_PAYLOAD`.
  - Anyone with the trigger token can start such a pipeline with any
    payload. Vee therefore takes only the merge request and comment IDs
    from it, and reads the comment, its author and its text from the API.
    A comment GitLab does not report is ignored.
  - The project is the pipeline's own, not the payload's.
  - Commands check out `refs/merge-requests/<iid>/head`.
  - `@vee fix` commits as the token's user and pushes with `GL_TOKEN`.

## Consequences

- GitLab teams get incremental review, labels, approvals in observe or
  enforce mode, the approval report, and every `@vee` command.
- `GL_TOKEN` needs the `api` and `write_repository` scopes.
- Approval history ties each event to a merge request version by time; an
  approval given within the same second as a push may be attributed to the
  version before it.
- GitLab approval rules and code owner approvals still apply; Vee's
  approval counts as one approval among them.
