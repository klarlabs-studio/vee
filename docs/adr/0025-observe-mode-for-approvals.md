# ADR 0025: Observe mode for approvals

- **Status:** Accepted; amends ADR 0024
- **Date:** 2026-11-26

## Context

`vee ci run --approve` lets Vee approve pull requests it finds eligible for
approval without a person (ADR 0024). Teams will not turn that on without
first seeing what Vee would have approved, and how often people agreed.
CI keeps no state, so the evidence has to live where the pull requests are.

## Decision

**`approval.mode` in `.vee.yaml`: `observe` (default) or `enforce`.**

- In `observe` mode, `--approve` evaluates eligibility on every review and
  approves nothing. It also withdraws any approval Vee gave before, for
  example while the mode was `enforce`.
- In `enforce` mode, `--approve` approves and withdraws as ADR 0024
  describes.

`--approve` therefore approves only when the repository's configuration says
`enforce`. The flag turns the verdicts on; the mode decides whether they act.
Changing the mode changes the effective configuration, so the next review is
a full one.

**Verdicts are recorded on the pull request.** Each verdict goes into the
record in Vee's summary comment (ADR 0022). A verdict holds:

- the head;
- the review;
- whether the head was eligible;
- whether Vee approved it;
- which approval stages failed.

A verdict on a head replaces an earlier one on the same head, and the record
keeps the latest 50. The summary says what Vee did, or would have done.

**`vee ci approvals --repository OWNER/REPO`** reads the latest closed pull
requests, 100 by default, from GitHub. For each one, it takes the verdicts
from Vee's summary and the reviews people gave. A pull request with a head
Vee called eligible ends in one of these outcomes:

| Outcome | Meaning |
|---|---|
| `merged_as_eligible` | Merged at a head Vee called eligible: people agreed. |
| `changed_after_eligible` | Merged at a later head. |
| `changes_requested_on_eligible` | A person requested changes on a head Vee called eligible. |
| `closed_after_eligible` | Closed without merging. |

`never_eligible` counts the rest. The agreement rate is the share merged as
eligible, and the override rate is the remainder. Both state their
denominator: pull requests with an eligible head. The report lists its
limitations:

- reverts are not detected;
- a later change counts as an override even when it answered something
  unrelated;
- only pull requests reviewed with `--approve` count.

## Consequences

- A team can run `--approve` in observe mode for weeks, read
  `vee ci approvals`, and switch to `enforce` with evidence.
- Nothing about the verdicts is stored outside the pull requests. The report
  costs about three API calls per closed pull request.
- Not yet covered: rate limits on automatic approvals, detecting reverts,
  code ownership as an approval stage, and other hosts.
