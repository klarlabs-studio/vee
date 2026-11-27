# ADR 0046: Grouping sampled findings by meaning

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

A sampled reviewer's runs are merged into findings that record how many
runs reported them ([ADR 0008](0008-reviewer-sampling.md)). Reports are
matched by location only: the same file and lines at most 3 apart. That
fails in both directions:
- **Split agreement.** Runs that describe the same defect but anchor it to
  different lines, such as the declaration and the use, count as separate
  findings. Each then falls short of the quorum.
- **False agreement.** Two different defects on adjacent lines merge, and
  one borrows the other's agreement.

The quorum is only as good as the grouping beneath it.

## Decision

A reviewer may set `sample_grouping: meaning`; the default stays
`location`. With `meaning`, two reports in the same file are the same
defect when either of these holds:
- **Nearby and related.** They are at most 3 lines apart, and either their
  categories match or their rationales overlap by at least 15%.
- **Far apart but alike.** They are at most 30 lines apart, their
  categories match, and their rationales overlap by at least 50%. A report
  without a line joins on category and wording alone.

**How wording is compared:**
- The overlap is the Jaccard similarity of the rationales' words.
- Words are lowercased, and split on anything but letters, digits and `_`,
  so identifiers survive.
- Words under 3 characters and a short list of words common to every
  rationale are left out.

The grouping is deterministic, costs no model call, and keeps the
closest-pair matching of ADR 0008.

**Why opt-in:** grouping changes which findings block. The benchmark
results in the best-results guide were measured with location grouping,
so `meaning` stays opt-in until a rerun shows it does better. When unset,
the field is left out of the configuration, so existing configurations
keep their digest.

## Consequences

**Benefits:**
- Agreement counts the defect a run described, not only the line it named.
- `vee analytics quorum` ([ADR 0045](0045-measured-agreement-quorums.md))
  can be compared across the two groupings on the same labels.

**Costs and limits:**
- **Wording is lexical, not semantic.** Two runs that describe the same
  defect in entirely different words still stay apart.
- **The thresholds are judgement, not measurement.** A rerun of the
  benchmark should set them.
