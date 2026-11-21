# ADR 0008: Reviewer sampling with agreement-scored findings

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

On the 16-case historical corpus
([benchmark](../local-historical-review-benchmark.md)), three identical
Claude runs scored 9 / 17, 11 / 17 and 10 / 15. Six cases flipped between
found and missed. A single review run is a sample from a wide distribution.

The union of three runs found 13–14 of 17 labels, against about 60% for one
run, with about 50% more distinct findings rather than three times as many.
Findings that recur across runs are therefore a smaller set than the raw
count suggests, and findings seen once are where most of the extra recall
and most of the extra noise come from.

The existing finding fingerprint (category, path and source anchor) does not
recognize the same defect across runs well: it matched 11 of 37 findings to
another run, while "same path, line within three" matched 23. Models change
the category and the anchor line between runs.

## Decision

1. A reviewer may set `samples: N` (1–5, default 1). Vee sends the same
   review request N times. Each sample is a separate provider call with its
   own provider-cache key. An unsampled Ollama review decodes greedily
   (temperature 0), which would make every sample identical, so sampled
   Ollama runs use temperature 0.8 (Ollama's default) with seeds
   `7 + index`: different from each other, repeatable run to run.
2. Vee merges the samples of one reviewer into one finding list:
   - Findings with a line are grouped when they have the same path and lines
     at most three apart. Findings without a line are grouped by fingerprint.
     A group takes at most one report per sample, and a sample's reports are
     matched to groups closest pair first, so a distant report cannot take
     the group of a nearer report from the same sample.
   - Each group becomes one finding. Its representative is the report with a
     line, then the highest severity, then the highest confidence, then the
     lowest fingerprint, so a located report is preferred over a line-less one.
   - The finding records `sample_agreement`: how many samples reported it,
     how many ran, and the quorum.
3. A reviewer may set `sample_quorum` (1–N, default a strict majority). A
   sampled finding blocks the gate only when at least `sample_quorum` samples
   reported it. Findings below the quorum are kept and shown, but are
   advisory.
4. `effort: low | medium | high` is the user-facing preset for 1, 3 or 5
   samples; `samples` remains an exact override and cannot be combined with
   `effort`. `vee review --effort` (and the MCP and local HTTP review
   inputs) applies one effort to every reviewer for that review, replacing
   configured `effort`, `samples` and `sample_quorum`. The override is part
   of the effective configuration, so the review's config digest records
   the effort used.
5. With `samples: 1` nothing changes: no `sample_agreement` is recorded, and
   saved reviews, digests and gate decisions are unaffected.
6. If any sample fails, the reviewer's outcome is the failure and the review
   is incomplete, as for a single failed run.

## Consequences

- Recall can rise with N while the gate stays about as strict as one run,
  because minority findings do not block.
- Cost and provider time grow N-fold. Samples run concurrently within
  `review.max_concurrency`, so wall-clock time grows less on hosted providers.
  On a local model they compete for the same machine.
- The quorum is part of each finding, so a saved gate decision replays
  without consulting current configuration.
- Grouping by location can merge two distinct defects three lines apart, and
  can split one defect reported at distant lines. Both are measured on the
  benchmark, not assumed away.

## Alternatives considered

- **Plain union.** Highest recall, but every finding seen once can block the
  gate. Rejected for more false blocks.
- **Scaling model confidence by agreement.** It would reuse
  `minimum_confidence`, but mixes a self-reported score with an observed
  frequency, and changes what confidence means for unsampled reviews.
- **Gate-level quorum in policy.** Policy is global, while N is per reviewer;
  storing the quorum on the finding keeps replay independent of
  configuration.
- **Merging by fingerprint.** Matched too few repeats across runs (above).
