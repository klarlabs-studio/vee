# ADR 0041: Approval on Bitbucket, Azure DevOps and Gerrit

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

On GitHub and GitLab, `vee ci run --approve` gives and withdraws Vee's
approval ([ADR 0024](0024-approval-and-risk-on-the-pull-request.md),
[ADR 0030](0030-gitlab-parity.md)). It relies on the conversation adapter
those two hosts have: reviews tied to commits, team membership, and the
pull requests Vee approved recently. Bitbucket, Azure DevOps and Gerrit
have no CI entry point or conversation adapter. Their only way to publish
is `vee hosting publish`, whose `--approval` published a separate check
and was refused on Gerrit.

Each of these hosts approves through a single standing mark per account:

- Bitbucket Cloud: an approval, with no text and no commit;
- Azure DevOps: a reviewer vote, where 10 means "approved";
- Gerrit: a label vote on a patch set, normally `Code-Review`.

## Decision

**A narrow port.** `PullRequestApprovalProvider` reads whether the
authenticated account's approval stands, approves at a given head, and
withdraws. GitHub and GitLab keep their richer path.

**Publication syncs the approval.** `vee hosting publish --approval`
publishes the gate and the "Vee approval" check as before, except on
Gerrit, which has no check. On these three hosts it then makes Vee's
approval stand exactly when `approval.mode` is `enforce` and the reviewed
head is eligible:

- **Eligible in enforce mode:** Vee approves, or keeps an approval that
  already stands.
- **Otherwise:** Vee withdraws any approval it gave.

The receipt reports `given`, `kept`, `withdrawn` or `not_given`.

**Approve only the reviewed head.** Publication already refuses a pull
request whose head differs from the reviewed commit. Each adapter checks
again just before it approves, and refuses when the head has moved or the
pull request is closed. Bitbucket reports abbreviated hashes, so its
adapter now resolves them to full hashes. That also fixes publishing, which
compared them with the full reviewed hash and could never match.

**Gerrit votes the highest value permitted.** Vee votes `Code-Review` at
the highest value Gerrit's `permitted_labels` allows its account on the
change. The project's access rules therefore decide whether Vee can
approve outright (+2) or only recommend (+1), and no Vee setting can grant
more than the administrators did. The vote is cast on the reviewed patch
set, and its message lists the approval stages.

**Guards that can't be evaluated fail closed.** These hosts cannot yet
answer `approval.require_owner_approval`, which needs owners' approvals of
the current head and team membership, or `approval.max_per_day`, which
needs Vee's approvals across pull requests. When either is set, Vee
approves nothing on these hosts and withdraws an approval it gave.

## Consequences

- Teams on these hosts can run approval in enforce mode, from a CI job or a
  webhook-driven publication that runs `vee hosting publish --approval`.
- Approvals on Bitbucket and Azure DevOps carry no commit. Between a push
  and the next publication, an approval stands unless the host resets
  approvals on a push. The guide asks teams to turn that reset on, and on
  Gerrit not to copy `Code-Review` votes to new patch sets.
- Owner approvals, the daily limit, and a `vee ci run` entry point for these
  hosts remain future work.
