# ADR 0034: Owner approval before Vee approves

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`approval.never_owners` (ADR 0026) keeps changes to some owners' code away
from Vee. Many teams want a middle ground. Vee may provide the second
approval a branch rule asks for, but only next to a code owner of what the
change touches. Some hosts enforce code-owner review only on paid tiers,
and others not at all.

## Decision

`approval.require_owner_approval: true` adds an `owner_approvals` stage to
approval eligibility.

- **Owners.** `CODEOWNERS` is read from the change's base, never from the
  change, as for `never_owners`. Files without an owner need nobody.
- **Approvers.** A person counts when their latest approving or blocking
  review approves the current head. A later request for changes or a
  dismissal withdraws it, and a push makes it stale. Bots and Vee's own
  account never count.
- **Matching.**
  - `@user` matches a login, ignoring case.
  - `@org/team` matches an approver the host reports as a team member. An
    error counts as not a member.
  - An email owner cannot be matched to a login, so its files always wait
    for a person.
- **Where it is checked.** Only `vee ci run --approve` can read the pull
  request. Local `vee gate approval` reports the stage as not passed and
  says why, so approval is never granted without the check.
- **Re-checking.** On GitHub, `vee ci run` also accepts `pull_request_review`
  events, so an owner's approval triggers another run. Unchanged files are
  carried (ADR 0022), so that run costs no model calls. GitLab has no
  pipeline event for approvals; `@vee review` or a re-run picks it up.

## Consequences

- Vee's approval becomes additive: it never stands in for an owner.
- Owner matching follows `CODEOWNERS` syntax as Vee parses it (the last
  matching rule wins). Host-specific features, such as GitLab's optional
  sections and approval counts, are not modelled.
- In enforce mode, Vee withdraws its approval when an owner's approval is
  withdrawn, on the next run.
