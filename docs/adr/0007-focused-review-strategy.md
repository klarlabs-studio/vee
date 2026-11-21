# ADR 0007: Focused review strategy for small local models

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Vee sends a reviewer the whole change as one JSON request: changed files with
full baseline and current content, impact references, and the findings schema
as the required output format. On a 16-case local corpus of historical
defects ([benchmark](../local-historical-review-benchmark.md)), a strong hosted
reviewer handled this well. Local `gemma3:12b` through `ollama_native` mostly
did not: on a lost-increment race it returned an empty findings list after 13
output tokens.

Experiments on that case located two causes:

1. The schema-constrained format forces JSON from the first token, leaving the
   model no room to reason before it commits to an answer.
2. A whole change in one request, with source embedded as JSON strings, is too
   much for a small model to work through. It also cannot count lines inside a
   JSON string, so the line numbers it reports are unreliable.

Reviewing one file at a time, asking for free-text reasoning first and
structured findings second, found the race.

## Decision

1. Add a reviewer `strategy` setting: `whole_change` (default, unchanged) or
   `focused`. `focused` is valid only with an `ollama_native` provider; config
   validation rejects it elsewhere.
2. A focused review makes two requests per changed file:
   - **Reasoning:** no output format. The file's source is line-numbered, with
     changed lines marked `+`. Other changed non-test files are included as
     related context while they fit the context window; impact references are
     not sent.
   - **Structuring:** the findings schema plus a required `quote` field. Vee
     resolves the quote to exactly one changed line and sets the line itself. A
     quote it cannot match leaves the line empty. The finding's path is always
     the file under review.
3. `max_input_tokens` is checked against the largest single focused request,
   not against the whole change.
4. The structuring schema allows only rule attributions for approved guidance
   whose scope covers the file, and omits the field when none applies, so a
   constrained model cannot invent an attribution Vee would reject.
5. All Ollama requests use temperature 0 and a fixed seed, so a review of the
   same request repeats.

## Consequences

- Small local models produce findings where they produced none, and some are
  real defects. On the 14 completed corpus cases, strict recall was 1 / 14,
  against 7 / 14 for a strong hosted reviewer on the same cases. Output is
  noisier (123 findings against 30) and localization is weaker.
- Focused reviews are slow: two requests per changed file, 3.8–82 minutes
  per case on a 24 GB laptop, against 12–31 seconds per case for the hosted
  reviewer.
- A single changed file larger than `max_input_tokens` cannot be reviewed in
  focused mode; the reviewer reports `context_budget_exceeded`. Splitting a
  file is not implemented.
- `whole_change` stays the default. Documentation must not present a small
  local model as equivalent to a strong reviewer. Local inference is a privacy
  and offline option with lower review quality.
- Line localization by quote applies only to `focused`. The hosted reviewer
  reported usable lines in whole-change mode, so this is not extended to other
  providers now. Revisit if line-less findings become a measurable share of
  misses.

## Alternatives considered

- **Prompt-only changes to whole-change mode** (checklists, stricter
  instructions). Earlier local experiments, recorded in the benchmark document,
  did not recover the missed defect.
- **One request per file without a reasoning step.** The schema-first failure
  remains, file by file.
- **Larger local models.** Not runnable on the 24 GB development machine
  alongside the toolchain; worth re-measuring on larger hardware.
