# ADR 0037: Detecting reverted merges

- **Status:** Accepted
- **Date:** 2026-11-26
- **Amends:** [ADR 0025](0025-observe-mode-for-approvals.md)

## Context

`vee ci approvals` counts a pull request merged at a head Vee called
eligible as agreement. When that merge is reverted later, people disagreed
with the change after all, and the report overstates agreement. Teams read
this report before turning on automatic approval, so the error points the
wrong way.

## Decision

**Outcome `reverted_after_eligible`:** a pull request that was merged at a
head Vee called eligible and reverted later. It counts as an override, not
as agreement. A reverted pull request merged at another head stays
`changed_after_eligible`, already an override.

**Where reverts are found.** Vee reads the words that revert tools write:

- **Revert pull requests.** Among the pull requests the report reads, a
  merged one whose title or description says one of these:
  - `Reverts owner/repo#N` or `Reverts #N`: GitHub's Revert button.
  - `This reverts merge request !N`: GitLab's.
  - `This reverts commit <sha>`: `git revert`. It names the pull request
    whose merge commit is that SHA (merge, squash, or the head of a
    fast-forward merge on GitLab).

  A revert pull request that was closed without merging reverted nothing.
  A reference to another repository's pull request does not count.
- **The checked-out branch.** When the report runs in a clone, it also
  reads the last 1,000 commits on `HEAD` whose message says
  `This reverts`, with the same three forms. A revert pushed without a pull
  request is found this way.

**A revert that was itself reverted** does not count: the change is back.
Only one level is undone this way.

**Cases name the revert:** `reverted_by_pull_request` or
`reverted_by_commit`.

## Consequences

- The agreement rate no longer counts merges that people later undid.
- **Not found:**
  - reverts written by hand without these words;
  - partial reverts;
  - revert pull requests older than those the report reads;
  - commits outside a shallow clone.

  The report's limitations say so.
- **No extra API calls:** the closed pull request listing already carries
  titles, descriptions and merge commits.
