# ADR 0036: Carry findings on unchanged hunks

- **Status:** Accepted
- **Date:** 2026-11-26
- **Amends:** [ADR 0022](0022-incremental-review-after-a-push.md)

## Context

ADR 0022 carries findings only on files whose change is the same as at the
last review. A push that touches one line of a large changed file sends the
whole file again. The findings on the rest of that file can then change
because model output varies, so threads open and close without a code
change.

## Decision

**Hunks in the record.** For each changed file that exists on both sides,
Vee's record on the pull request keeps the change's hunks:

- the hunks come from a unified diff with three lines of context;
- each hunk has a digest of its rows without line numbers (16 hex
  digits), its first head line, and how many head lines it spans.

When the hunks make the record too large for a comment, they are left out,
and the next review carries whole files only.

**What is carried.** A file whose base content is the same as in the record
but whose head changed may keep some hunks:

- A hunk whose digest appears exactly once in the record and exactly once
  now is the same hunk. Earlier findings inside its head lines are carried,
  moved by the hunk's shift. So is a suggestion's end line, when it is
  inside the hunk; otherwise the suggestion is dropped.
- New findings inside a carried hunk are dropped. The earlier ones stand, as
  for carried files.
- The file is still sent to reviewers. `changed_line_ranges` lists only the
  ranges outside carried hunks. `carried_line_ranges` and a note tell
  reviewers that the earlier review covered those lines.
- An edit within three lines of a hunk changes that hunk, so it is reviewed
  again.

**What is not carried.**
- **A changed base:** when a rebase changed the file's base, its change
  differs, and the file is reviewed in full as in ADR 0022.
- **Findings outside every hunk:** an earlier finding on a line the change
  does not touch has no hunk to move with, so it is not carried. The new
  review finds it again or not.
- **Repeated hunks:** hunks whose digest repeats within a file are not
  matched.

All conditions of ADR 0022 that make a review a full one still apply.

## Consequences

- A small push to a large file no longer makes the rest of that file's
  findings change.
- Reviewers still get the whole file. The saving is in attention and
  stability, not in context size.
- As with carried files, a finding in a carried hunk that a change elsewhere
  caused or fixed is not revisited until that hunk changes, or until a full
  review.
