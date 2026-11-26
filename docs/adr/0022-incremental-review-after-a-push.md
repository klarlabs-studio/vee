# ADR 0022: Incremental review after a push

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`vee ci run` reviews the whole change on every push. On a long-lived pull
request, a one-line fix sends every changed file to the reviewers again:

- It costs as much as the first review.
- Findings on files nobody touched can change between runs, because model
  output varies. People see threads open and close without a code change.

CI keeps no state (ADR 0019). Whatever the next run builds on has to come
from the pull request.

## Decision

**A record on the pull request.** After each review, `vee ci run` posts one
summary comment in the conversation and edits it on later runs. The comment
holds a hidden record (`<!-- vee:record:… -->`, base64 JSON):

- the head that was reviewed and the review ID;
- the effective configuration digest;
- the content digest of every changed file at the base and at the head;
- each reviewer's findings.

**What the next review carries.** A changed file whose base and head digests
both match the record has the same change as before. Its change is not sent
to reviewers again, and the recorded findings on it are carried over as they
were. The other changed files are reviewed as usual.

- Comparing content rather than commits also covers rebases and force-pushes.
  A file whose base moved has a different change and is reviewed again.
- Reviewers that read the snapshot through Vee's tools (ADR 0017) can still
  read carried files.
- A reviewer whose files are all carried is not run. Its outcome is
  `carried`.
- New findings on carried files are dropped: the recorded findings stand.

**The gate is evaluated over the whole change.** Carried findings get their
source evidence from the current snapshot, as new findings do. Waivers,
dismissals and thread resolution then work as before. A carried file counts
as reviewed for `on_unreviewed`.

**When nothing is carried.** In these cases the review is a full one:

- the record was made under another effective configuration, including
  changes to `.vee.yaml`, reviewer instructions, approved rules and provider
  versions;
- the record has a finding without a location, which could concern any file;
- no changed file matches the record;
- the record is not in a comment by Vee's own account, or names another
  repository or pull request;
- `--full` is given, or `full-review: true` is set in the Action;
- the review was started by an `@vee review` comment.

A record too large for a comment is left out, and the next review is then a
full one. Only GitHub reads and writes the record so far. GitLab always
reviews the whole change.

**Trust.** Only a comment by the account Vee publishes as is read. In GitHub
Actions, any workflow in the repository can post as that account, so the
record is as trustworthy as the repository's workflows. People who can change
workflows can already change `.vee.yaml` on their branch, so the record
grants them nothing new. Forks' `pull_request` workflows get a read-only
token and cannot post. A signed record is the later "review once, reuse in
CI" item on the roadmap.

## Consequences

- A push that touches a few files costs a review of those files.
- Findings on untouched files stay as they were, threads included.
- A finding in a carried file that a change elsewhere caused or fixed is not
  revisited until that file changes, or until a full review. `@vee review`
  and `--full` give one on demand.
- One summary comment on every pull request.
