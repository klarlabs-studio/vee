# ADR 0027: Fixing every open finding

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`@vee fix` fixes one finding per comment (ADR 0023). A pull request with
several small findings then takes several comments, several pushes and
several reviews. A person wants to say "fix what you can" once, and see what
was fixed and what was not.

## Decision

`@vee fix all` takes on up to five of Vee's open findings on the pull
request:

- **Which findings.** Those with a thread whose fingerprint is in the last
  review's record. Findings a person dismissed are skipped. They are taken
  in file and line order.
- **One fix at a time.** Each fix goes through the steps of `@vee fix`:
  1. the model proposes edits;
  2. Vee commits them on top of the fixes kept so far;
  3. Vee reviews the new head;
  4. Vee keeps the fix only when the review no longer reports that finding
     and finds nothing new that blocks.

  A fix that is not kept is undone, and the next fix starts from the last
  kept one.
- **One push.** The kept fixes are pushed together, one commit per finding,
  as a fast-forward of the pull request's branch. Vee publishes the review
  of the last kept fix, which covers them all.
- **One answer.** It is posted where the command was written, and says:
  - for each pushed commit, the finding it fixes, who proposed it, and
    `git revert <commit>`;
  - for each finding not fixed, why;
  - the gate on the new head.

`@vee fix all` has the same authorization as other commands: write access,
no forks, and an open pull request.

## Consequences

- One comment fixes several findings, and each fix is still reviewed on its
  own before it is kept.
- A fix that only works together with another one is reviewed alone and may
  be refused.
- At most five model calls for fixes and five incremental reviews per
  comment.
- Fixing failing CI and resolving merge conflicts are not covered (roadmap
  item 5).
