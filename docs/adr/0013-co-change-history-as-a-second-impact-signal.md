# ADR 0013: Co-change history as a second impact signal

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

[ADR 0012](0012-scoped-name-resolution-for-impact.md) made code-reference
impact precise. Code references still miss coupling that has no reference:

- a schema that must change with its serializer;
- the stylesheet that goes with a component;
- a test file that tracks a module by convention.

The literature ([review](../research/review-literature.md), section 1)
measures this gap:

- **Call/use links explain only part of change propagation.** They
  account for about 42% of propagations. Historical co-change reaches 87%
  recall at low precision. Pruning by support and confidence lifts the
  combination to about 50% precision and 50% recall (Hassan & Holt 2004).
- **Union beats intersection.** Combining a coupling signal with history by
  union beats either alone. Intersection is worse than either alone
  (Kagdi et al. 2010).
- **Bulk commits pollute history.** Tangled and bulk commits put noise into
  history mining (Herzig et al. 2016).
- **Support 3 for precision.** Zimmermann et al. (2005) use a support of 3
  when precision matters.

## Decision

Impact mines first-parent history before the change's base, so the result
is fixed for a snapshot and replays exactly. It adds `co_change` edges with
`historical` certainty and the counts behind them
(`co_change: {together, source_commits}`). The edges are added to code
references, a union with labelled provenance.

| Rule | Value | Why |
|---|---|---|
| History window | 1,000 commits | bounded cost |
| Skip commits touching more than | 30 files | bulk and tangled changes |
| Minimum shared commits (support) | 3 | precision-oriented setting |
| Minimum confidence | 30% of the changed file's commits | directional rule |
| Minimum lift | 2× the other file's base rate | drops hub files such as changelogs and registries |
| Edges kept per changed file | 5, strongest first | depth-1 and ranking evidence |
| Documentation (Markdown, text, `docs/`) | never a source or target | it changes alongside features, which is not coupling |

**Where co-change edges appear:**
- impact report schema v4 adds `co_change`, `historical`, the analyzer ID
  `git-co-change`, and `evidence_line: 0` meaning "no line";
- the CLI, MCP and dashboard show "changed together in N of M commits";
- finding tasks keep only code references for now, because their schemas
  require a source line.

## Consequences

**Effect on this repository:**
- With 19 usable commits, the rules keep 4 edges across 4 recent commits.
  Examples: `App.vue` with `style.css`, and `tests/review.rs` with
  `review.rs`.
- Hub files that changed with most commits, such as `README.md` and
  `vee-core/src/lib.rs`, are dropped.

**Limits:**
- A young repository gets few or no edges. That is the correct answer when
  there is too little history to tell coupling from chance.
- Renames are not followed, so history before a rename is lost.
