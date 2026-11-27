# ADR 0045: Measured agreement quorums

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

A sampled reviewer ([ADR 0008](0008-reviewer-sampling.md)) blocks on a
finding only when `sample_quorum` of its runs reported it. The default is
a strict majority. That default is a guess. Reviewers differ: a noisy
reviewer gains from a higher quorum, and a precise one loses real defects
to it. Picking a quorum by hand gives no evidence either way.

Vee already stores the two things needed to measure it, with no model
calls:
- each finding's `sample_agreement`, which records how many runs reported it;
- people's labels on findings from `vee findings feedback`: `confirmed`
  and `actionable`, or `false_positive` and `not_actionable`.

## Decision

`vee analytics quorum` (schema `quorum-calibration-v1`) reports, for each
enabled reviewer that samples more than once:

- **What each quorum would have done.** For every quorum from 1 to the
  sample count, how many labelled findings it would let block and how many
  it would only show, confirmed and rejected counted separately.
- **A recommendation.** The quorum that keeps the most confirmed findings
  net of rejected ones. Ties keep the configured quorum, and otherwise go to
  the higher quorum, which blocks on fewer findings.

**What counts:**
- Only each finding's latest label counts.
- Only findings from runs with the reviewer's current sample count count,
  since agreement out of three runs says nothing about five.
- Under 10 labelled findings there is no recommendation, only the counts.

**What it changes:** nothing. The command prints the `sample_quorum` line
to set and leaves the configuration alone. The quorum is part of the
effective configuration, so changing it is a deliberate, reviewed edit,
and earlier reviews become stale as they should.

## Consequences

**Benefits:**
- Each reviewer's quorum rests on the team's own labels, and the evidence
  behind the recommendation is visible.
- It is deterministic and costs no model calls.

**Costs and limits:**
- **It needs labels.** A repository whose people never label findings gets
  no recommendation.
- **Labels are biased toward blocking findings.** People mostly label what
  blocked. A finding below the quorum is shown as advisory, so fewer of
  those get labelled, and the counts lean towards the current quorum.
- **Equal weighting.** A confirmed finding and a rejected one count the
  same. A team that values recall over precision, or the reverse, should
  read the counts rather than only the recommendation.
- **Local store only.** It reads this machine's findings and labels.
  Labels given on pull requests reach it only where they are recorded
  locally.
