# ADR 0016: Review sessions keep per-change gates

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Coding agents produce several related changes in one session: commits on a
branch, or a stack of branches. Reviewing them one at a time loses the
overview. Merging them into one review would let a passing change mask a
failing one.

Research on agent-authored pull requests
([review](../research/review-literature.md), section 6) finds:
- acceptance well below that of human changes;
- failures concentrated in large changes, CI failures and work that
  doesn't match the task.

The research also recommends reviewing related changes with shared context
while **gating each change**, and invalidating a verdict when its change
moves. That last recommendation is our inference; no peer-reviewed study of
stacked review was found.

## Decision

`vee reviews session --review <id>...` (MCP: `review_session`, schema
`review-session-v1`) reads 1–20 saved reviews of one repository together.

**Per change:**
- its own latest gate;
- whether the snapshot is still current;
- its risk tier ([ADR 0014](0014-change-risk-as-explained-tiers.md));
- its open findings by severity;
- its approval eligibility ([ADR 0015](0015-layered-approval-eligibility.md));
- the reasons it does not pass.

**Session verdict:**
- `block` if any change blocked;
- `pass` only if every change passed on a current snapshot;
- `incomplete` otherwise.

The command exits 0 only on `pass`. The MCP text and the CLI view are the
same Markdown and terminal rendering, so a session can be exported as text.

## Consequences

**Benefits:**
- A session never hides a failing or moved change behind passing ones.
- It reuses the per-change review, risk and approval documents, so it
  cannot disagree with them.

**Not yet done:**
- **Cross-repository sessions.** These need consumer checkouts confined
  beneath the MCP server root, as cross-repository impact already does.
- **Checking a change against its task.** The research's strongest
  agent-specific signal is whether the diff does what the task asked. That
  check is not built.
- **Using one change's context in another's review.** Parent changes'
  diffs and decisions are not yet passed into the review of the next
  change.
