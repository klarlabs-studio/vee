# ADR 0024: Approval and risk on the pull request

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Vee computes two things beyond the gate: a change's risk tier, and whether
the change is eligible for approval without a person (ADR 0015). On a pull
request, `--approval` shows eligibility as a second check, and the risk tier
appears only in that check's text. Teams cannot do the following with
either:

- filter or route pull requests by them, as they do by labels;
- let branch protection count Vee's verdict as an approval.

## Decision

Two opt-in flags for `vee ci run` and `vee ci command`, with matching inputs
in the Action. Both work on GitHub only for now; elsewhere they print a
warning.

**`--labels`** keeps two labels on the pull request:

- `vee:gate:pass`, `vee:gate:block` or `vee:gate:incomplete`;
- `vee:risk:low`, `vee:risk:elevated` or `vee:risk:high`.

On each run, Vee removes its labels with the same prefix that no longer
apply, and leaves every other label alone. When the risk tier is
unavailable, the risk label is removed.

**`--approve`** makes Vee's approving review follow eligibility:

- When the reviewed head is eligible, Vee approves it, once. The review's
  text lists every approval stage.
- Vee withdraws (dismisses) its approvals of earlier heads. It also
  withdraws its approval of this head when the head is no longer eligible,
  for example after a waiver expires. The dismissal message says which.
- Only reviews by Vee's own account are touched.

GitHub only lets workflows approve pull requests when the repository allows
GitHub Actions to create and approve them. Branch protection decides whether
Vee's approval counts. Vee never asks for either setting itself. When
approving fails, the run prints a warning and the check still reports the
gate.

Neither flag changes the gate.

## Consequences

- Teams can filter by `vee:risk:high`, or require a person for it, with the
  host's own tools.
- An eligible change can be merged under branch protection without a person,
  when the team chooses that by allowing Actions approvals and counting
  them.
- A push always withdraws Vee's earlier approval before the new review can
  give a new one, so an approval never outlives the head it was given on.
- Observe mode, where Vee records what it would have approved without
  approving, is the next step (roadmap item 4).
