# ADR 0020: Commands in pull request comments

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

With `vee ci run` (ADR 0019), Vee reviews every pull request and posts a
check and threads. People then want to act on those threads where they read
them: ask for another review, ask why a finding was raised, dismiss a false
positive, or waive a finding for a while. Vee hosts nothing, so a comment can
only reach it through the team's CI, and comment events raise risks that
`pull_request` events do not:

- Comment workflows run with the repository's secrets, even for comments on
  pull requests from forks. A job that checks out a fork's head and loads its
  `.vee.yaml` would run programs that the fork chose (providers and
  verification profiles name programs).
- Anyone who can comment can type a command, so every command needs an
  authorization check.
- In GitHub Actions, Vee posts as `github-actions[bot]`, which every workflow
  in the repository can post as. A reply from that account proves nothing.

## Decision

`vee ci command` handles the comment that started the CI job. It is a shared
operation (`vee_application::pr_commands`); the GitHub Action runs it for
`issue_comment` and `pull_request_review_comment` events.

**Commands.** A command is the first line of the comment that starts with
`@vee`:

| Command | Effect |
|---|---|
| `@vee review` | Review the pull request's head again and publish, as `vee ci run`. |
| `@vee status` | Reply with Vee's findings on the pull request and the waivers and dismissals in effect. |
| `@vee explain [finding]` | Reply with a model's explanation of the finding, from the finding and the code around it. |
| `@vee dismiss [finding] <reason>` | Record the finding as a false positive and resolve its thread when it does not block. |
| `@vee waive [finding] <days>d <reason>` | Waive the finding on the current head for at most 90 days, then review again. |
| `@vee help` | Reply with the commands. |

In a finding's thread the finding is implied; elsewhere it is named by its
ID (`find_…`).

**Authorization.**

- The commenter must have write access to the repository, as the host
  reports it. Bots, including Vee's own account, are ignored.
- A waiver also needs code ownership. When `CODEOWNERS` assigns the finding's
  path, the commenter must be one of its owners, directly or through a team
  the host confirms. Vee fails closed when it cannot check a team. A path
  with no owner needs write access only.

**Forks.** Commands that load the repository's configuration (`review`,
`explain`, `waive`) are refused on pull requests from forks. Vee itself
fetches and checks out the head, after the checks above, so a fork's code
never reaches the runner. `status`, `dismiss` and `help` read only the pull
request.

**Comment text is data.** A command maps to one of the operations above and
nothing else. No part of the comment reaches a model. `explain` sends the
finding as Vee published it and the source around its line.

**The pull request is the record, and the person's comment is the
authority.** `vee ci run` keeps no state, so every run reads the pull
request's comments again and applies each dismissal and waiver whose
command:

- was written by a person who passes the authorization check now;
- still reads as the command that Vee acknowledged, so an edited command
  stops counting;
- has an acknowledgement from Vee, which records the head it was given on
  and the expiry.

The acknowledgement is not trusted on its own, so a workflow posting as the
bot cannot grant a waiver.

**Gate effect follows the existing rules.** A waiver applies to one
finding's fingerprint on one snapshot until it expires. On a pull request
that snapshot is the head on which the waiver was given, so a new push needs
a new waiver. A dismissal is feedback and never changes the gate.

## Consequences

- People act on findings in the pull request, and every decision there names
  who made it and why.
- Each `@vee review`, `explain` or `waive` costs a model run; `waive` runs a
  review so that the check shows the new verdict.
- GitLab does not start pipelines for comments. `vee ci command` covers
  GitHub first; GitLab needs a webhook that starts a pipeline, which is
  follow-up work.
- A pull request with many commands needs one permission lookup per distinct
  commenter on every run.
