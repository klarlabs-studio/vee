# ADR 0010: Changed files no reviewer received leave the gate incomplete

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Reviewers can be limited to paths with `include` and `exclude`. Dogfooding
Vee on its own repository showed what happens when those rules leave a gap:
the change to `crates/vee-application/src/local_analytics.rs` and
`operations.rs`, which held most of the new logic, matched no reviewer's
rules. Every reviewer completed, the review reported "analysis complete", and
the gate would have passed. Nothing in the output said that the core of the
change had not been read.

The repository-wide `review.include` and `review.exclude` rules are a
deliberate statement of scope. A per-reviewer gap is usually an accident: a
new directory, a file added after the reviewers were split.

## Decision

1. Every review lists `unreviewed_paths`: changed files that pass the
   repository review filter but that no reviewer received as full source or
   as a diff. Files the repository filter excludes are out of scope and are
   not listed. Text output, Markdown reports and the UI show the list.
2. `policy.on_unreviewed` decides what the list means for the gate:
   - `block` (default): a non-empty list leaves the analysis incomplete, so
     the gate is `incomplete` and `on_incomplete` applies.
   - `allow`: the list is reported only.
3. Policy packs and the protected policy can only tighten it: `block` wins
   when either side sets it, as for `on_incomplete`.
4. The review queue's next action for such a review is `cover_unreviewed`.

## Consequences

- A gate can no longer pass on a changed source file that no reviewer saw,
  unless the repository opts out.
- Repositories that split reviewers by path must cover every in-scope path,
  or narrow `review.include` to what they mean to review.
- A file whose context was dropped by the context budget counts as
  unreviewed, which is accurate: no reviewer read it.
- Saved gate decisions replay unchanged: completeness is recorded on the
  review, and earlier reviews have no `unreviewed_paths`.

## Alternatives considered

- **Warn only by default.** It keeps today's behavior, but a warning next to
  a passing gate is easy to miss, and a gate that passes on unread code
  contradicts what Vee promises. Vee is unreleased, so no setup relies on
  the old behavior.
- **A separate gate status for unreviewed changes.** It would add a fourth
  status to every consumer of gate decisions for something `incomplete`
  already means.
- **Checking coverage in `vee doctor` only.** Doctor sees configuration,
  not the files a particular change touches.
