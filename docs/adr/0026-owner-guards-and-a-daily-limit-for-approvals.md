# ADR 0026: Owner guards and a daily limit for approvals

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Approval without a person (ADR 0015) has guards on paths, commit authors,
risk and the gate. Two things teams ask for before they turn on enforcement
(ADR 0025) are missing:

- some owners' code always needs one of those owners;
- a mistake in eligibility must not approve many pull requests at once.

## Decision

**`approval.never_owners`** lists owners, such as `@acme/security`, `@user`
or an email, whose code always needs a person. A new `owners` stage runs
after `authors`:

- It reads `CODEOWNERS` from the change's base, at `.github/CODEOWNERS`,
  `CODEOWNERS` or `docs/CODEOWNERS`. The base's copy is used, not the
  change's, so a change cannot edit its own guard away.
- It fails when any changed file's owners include a guarded owner. Owners
  are compared without regard to case.
- It fails when `CODEOWNERS` cannot be read in full, because a skipped rule
  could be the one that matches.
- It passes when the base has no `CODEOWNERS`.

**`approval.max_per_day`**, 1 to 1000, caps Vee's approvals in enforce mode.
Before approving, Vee counts the approvals it gave in the last 24 hours:

- on the 100 most recently updated pull requests;
- including approvals it withdrew since, because they were given.

At the limit, Vee approves nothing. The verdict is still eligible and is
recorded as `rate_limited`, and the summary says the head is left to a
person. Observe mode never approves, so the limit does not apply there.

## Consequences

- Teams can keep their security or payments owners in every decision on
  their code, without listing paths twice.
- A wrong eligibility rule approves at most `max_per_day` pull requests
  before people notice in the report (`vee ci approvals`).
- The count costs one API call per recently updated pull request. In a
  repository with more than 100 pull requests updated in a day, the count
  can be low.
