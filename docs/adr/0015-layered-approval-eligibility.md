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
| `gate` | The latest gate decision passed. |

**Output:**
- The command exits 0 when the change is eligible and 1 otherwise, like
  `gate check`.
- The author stage reports only the pattern that matched, never an
  author's name or email.
- `approval` is omitted from the effective configuration when unset, so
  existing configuration digests do not change.

## Consequences

**Benefits:**
- The decision is deterministic and replayable from the saved review, its
  snapshot and the configuration.
- Every reason is visible, so nobody has to guess why a change needs a
  human.

**Not yet done:**
- **Publishing to hosts.** Publishing the verdict to a Git host as an
  approval or a label needs each hosting adapter to support it. Until then,
  CI can act on the exit status.
- **Anti-rubber-stamp signals.** Rate limits on automated approvals, and
  tracking of override and dismissal rates, are not built.
- **Carrying approval across trivial deltas.** Carrying an approval across
  a verified-trivial delta (whitespace, comments) is not supported. Any
  move withdraws it.
