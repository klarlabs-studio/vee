# ADR 0015: Layered approval eligibility

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Teams want low-risk changes, such as those from coding agents and bots, to
pass without waiting for a person. A passing gate alone is the wrong signal
for that, for two reasons:

- the gate judges findings, not where the change lands or who made it;
- "approved without discussion" predicts post-release defects (McIntosh et
  al. 2016).

The literature on automated approval
([review](../research/review-literature.md), section 5) gives three
lessons:

- **Layering.** Meta's RADAR orders its stages cheapest first:
  eligibility rules, static heuristics, a risk percentile, an LLM review
  that rejects on any risk signal, and deterministic checks. Any failing or
  missing stage keeps a human in the loop.
- **Carrying approval forward.** Uber carries an approval forward only
  across changes that analysis proves don't alter behaviour.
- **Late commits.** Commits made after approval are a known review smell
  (Gön et al. 2024).

## Decision

`vee gate approval --review <id>` (MCP: `check_approval_eligibility`,
schema `approval-eligibility-v1`) evaluates five stages in order and reports
every one with its reason. A change is eligible only when all pass.

| Stage | Passes when |
|---|---|
| `snapshot` | The checkout still matches the reviewed snapshot. Otherwise approval is withdrawn until the change is reviewed again. |
| `paths` | No changed path matches `approval.never_paths`. |
| `authors` | No commit in the change has an author whose name or email matches `approval.never_authors`. |
| `risk` | The change-risk tier ([ADR 0014](0014-change-risk-as-explained-tiers.md)) is within `approval.max_risk` (`low` by default, or `elevated`). Missing risk fails. |
| `gate` | The gate passes when evaluated now, against the current snapshot, configuration and verification runs. The decision is not recorded, so approval stays read-only, and a verification run since the last `gate check` counts. |

**Output:**
- The command exits 0 when the change is eligible and 1 otherwise, like
  `gate check`.
- The author stage reports only the pattern that matched, never an
  author's name or email.
- `approval` is left out of the effective configuration digest, so adding
  or changing guards never makes existing reviews stale.

## Consequences

**Benefits:**
- The decision is deterministic and replayable from the saved review, its
  snapshot and the configuration.
- Every reason is visible, so nobody has to guess why a change needs a
  human.

**Publishing to hosts.** `vee hosting publish --approval` publishes the
verdict as a separate `Vee approval` check, so branch protection or
auto-merge can require it independently of the gate's `Vee` check:
- An eligible change is a success. Anything else is neutral, never a
  failure, because a change that needs a person is not a broken change.
  Bitbucket has no neutral state, so it shows as stopped and never as
  successful.
- The check lists every stage with its detail.
- Eligibility is evaluated before anything is written.
- Gerrit publishes one tagged review message rather than separate checks.
  It was refused at first, and has voted `Code-Review` instead since
  [ADR 0041](0041-approval-on-bitbucket-azure-devops-and-gerrit.md).

Vee publishes a check rather than a native approval or a label. A check
carries the reasons and stays read-only toward the review itself; whether a
passing check approves or merges is the repository's own policy.

**Follow-up (updated 2026-11-27):**
- **Anti-rubber-stamp signals: done.**
  - `approval.max_per_day` caps automatic approvals
    ([ADR 0026](0026-owner-guards-and-a-daily-limit-for-approvals.md)).
  - `vee ci approvals` tracks agreement and override rates against what
    happened to each pull request, reverts included
    ([ADR 0025](0025-observe-mode-for-approvals.md),
    [ADR 0037](0037-detecting-reverted-merges.md)).
  - Dismissal rates retire noisy rules
    ([ADR 0031](0031-learning-from-pull-request-feedback.md)), and
    `vee analytics aggregate` reports these rates across repositories
    ([ADR 0044](0044-team-analytics-without-a-server.md)).
- **Carrying approval across trivial deltas: not planned.** Every new head
  is reviewed and its eligibility evaluated again. Incremental review
  ([ADR 0022](0022-incremental-review-after-a-push.md),
  [ADR 0036](0036-carry-findings-on-unchanged-hunks.md)) already makes an
  unchanged file free. A whitespace or comment change alters a file's
  content, and Vee cannot prove in general that it leaves behaviour alone:
  a comment can be a directive, and whitespace is syntax in some
  languages. Keeping an approval across such a delta without a review
  would break the rule above that a missing stage keeps a person in the
  loop.
