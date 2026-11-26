# ADR 0031: Learning from pull request feedback

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Vee's rule candidates came only from explicit feedback recorded with
`vee findings feedback` in a local store. In CI, no store survives the job,
but the pull request still shows what people did with each finding:
- they dismissed it with a reason;
- they fixed it before merging;
- they reacted to it.

Approved rules also stayed in effect however often their findings were
rejected, and they lived only in Vee, out of reach of other agents and
editors.

## Decision

- **Weak labels from pull requests.** `vee rules candidates --pull-requests`
  reads the most recently closed pull requests through the host's
  conversation interface (ADRs 0020 and 0030). For each Vee finding thread:
  - **Dismissed**: an `@vee dismiss` that Vee acknowledged, by someone who
    still has write access. It suggests `false_positive` and keeps the
    reason.
  - **Fixed**: on a merged pull request, a finding the summary's record no
    longer reports at merge. It suggests `confirmed`.
  - **Thumbs-up or thumbs-down** by a person. Bots and Vee's own account are
    ignored, and each person counts once. These suggest `actionable` and
    `false_positive`.
- **Kept apart.**
  - Weak candidates appear in `weak_candidates`, never mixed with
    candidates from explicit feedback.
  - Each needs five distinct findings rather than three. A finding with
    both kinds of signal is disputed and left out.
  - Their examples name the pull request, the thread, the author and the
    reason.
  - A person approves them with the same command and the same
    `--pull-requests` options. The candidate is mined again at approval, so
    stale evidence is refused.
  - Weak labels never reach the gate.
- **Noisy rules are suspended.**
  - When explicit feedback marks at least five findings that cite an active
    rule as `false_positive` or `not_actionable`, and they are at least half
    of the rule's findings, recording that feedback adds a `suspended` event
    by `vee`, with the counts as its reason.
  - A suspended rule is not sent to reviewers.
  - `vee rules restore` adds a `restored` event. Only feedback after it
    counts toward suspending the rule again.
  - The events are append-only, like revocation, and the storage schema
    moves to version 14 to allow them.
- **Export.** `vee rules export` renders the active rules as a Markdown
  section between `<!-- vee:rules:start -->` and `<!-- vee:rules:end -->`.
  `--write` replaces that section in a repository Markdown file, or adds it,
  leaving the rest of the file alone.

## Consequences

- Teams learn from their pull requests without keeping a store in CI.
- The fix signal is a proxy: a finding can also disappear because the code
  around it was rewritten. That is one reason weak candidates need more
  findings.
- A thread a person resolved by hand is not read yet. GitHub exposes thread
  resolution only through GraphQL.
- The export writes the file; committing it and opening a pull request stays
  with the person, which keeps a person in the loop for every change to
  shared guidance.
- Since #64 reviewers read `REVIEW.md`, so an exported rule reaches Vee's
  reviewers twice: as active guidance and as repository standards. The two
  say the same thing.
