# ADR 0014: Change risk as explained tiers, not probabilities

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Reviewers need to know where to spend attention before they read findings.
The literature ([review](../research/review-literature.md), section 2) gives
four points:

- **What predicts risk.** Diffusion predicts defect-inducing changes best:
  subsystems, directories, files and entropy. Size and history follow.
  These come from Mockus & Weiss (2000) and Kamei et al. (2013).
- **Explained tiers, not probabilities.** Mockus & Weiss's deployed tool
  reported high, medium and normal tiers, with a named flag for each
  contributing factor.
- **Uncalibrated scores are misleading.** Trained models lose calibration
  within a year (McIntosh & Kamei 2018). Vee has no labelled defect
  history per repository, so any probability it showed would be invented.
- **Risk works by routing attention.** A risk view improved review
  effectiveness (Yu et al. 2024). Routing risky changes to extra review
  helped at almost no time cost (Paraspatki et al. 2026).
- **Review size limits.** Review usefulness drops past about 20 files
  (Czerwonka et al. 2015). A 200–400 line limit comes from a vendor case
  study, not peer review.

## Decision

`vee risk` (MCP: `assess_change_risk`, schema `change-risk-v1`) reports a
`low`, `elevated` or `high` tier over five measured factors. Each factor
carries its value, its threshold, what was counted, and its research basis.

| Factor | Flag at | Basis |
|---|---|---|
| Code subsystems touched (top-level directory, or two levels under `crates/`, `packages/` and similar; documentation excluded) | ≥ 3 | Mockus & Weiss 2000; Kamei 2013 |
| Files changed | ≥ 20 | Kamei 2013; Czerwonka 2015 |
| Lines added and deleted | ≥ 400 | Kamei 2013; Cisco case study (weak evidence) |
| Production files referencing changed code | ≥ 10 | Hattori 2008; impact analysis |
| Changed source files with no test changed or referencing them | ≥ 1 | McIntosh & Kamei 2018; agent-change studies |
| Earlier changes to the touched code (NUC) | above this repository's 90th percentile | Kamei 2013 (history) |
| People who changed the touched code (NDEV) | above this repository's 90th percentile | Kamei 2013 (history) |

**History factors calibrate themselves.** No labelled defects are needed.
Every commit in the last 1,000 first-parent commits before the base is
measured the same way at the time it was made; bulk commits (more than 30
files) and documentation are skipped. A change is flagged above the 90th
percentile of those values. With fewer than 20 usable commits the factors
are left out, and a limitation says so. Only counts are reported, never who
the authors are.

**Tiers.** No flagged factor gives low, one or two give elevated, and three
or more give high.

**Counting rules:**
- Lines are a multiset difference, a lower bound on what a diff reports.
- Paths outside the repository review filter are not counted.

**What risk affects.** Risk is informational. It never changes the gate. It
appears in three places:
- the CLI and MCP;
- the review detail, while the checkout matches the snapshot;
- a summary card on the dashboard, with each factor's basis on hover.

## Consequences

**Benefits:**
- A reader can see why a change is elevated and check every number.
- Thresholds are constants with sources, so they can be tuned or made
  configurable without changing the document.

**Not yet included:**
- Author experience and file age.
- Change purpose (fix vs feature).
- Size-normalised ordering of findings, which effort-aware evaluation
  recommends.
- Using risk to route work: for example, raising reviewer samples, or
  requiring acknowledgement for high risk. That is the next step, together
  with approval guards.
