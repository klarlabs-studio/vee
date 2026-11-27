# ADR 0043: Review once, reuse in CI

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

A developer or a coding agent often reviews a change with Vee before
pushing it, through `vee review`, the pre-push hook or the agent's Stop
hook. CI then reviews the same commits again and pays for the same model
calls. Since the review on a pull request is incremental
([ADR 0022](0022-incremental-review-after-a-push.md),
[ADR 0036](0036-carry-findings-on-unchanged-hunks.md)), CI already knows
how to build on an earlier review. What it lacks is a reason to trust a
review it did not run.

## Decision

**A signed review, stored with the commit.** `vee reviews share <review>
--private-key <key> --key-id <id>` signs a saved review with an Ed25519
key from `vee reviews keygen`. It signs only a complete review whose
snapshot is exactly the committed range from its base to its head. The
signature is a DSSE envelope around an in-toto statement with predicate
`https://vee.klarlabs.de/attestations/shared-review/v1`. Its subject is
the head commit, and its predicate holds:

- the base;
- the effective configuration and standards digests;
- each changed file's content digests and hunks;
- the findings.

The envelope is stored as a Git note on the head under
`refs/notes/vee-reviews`. The developer pushes it with
`git push origin refs/notes/vee-reviews`.

**Trust comes from the base branch.** `review_signers` in `.vee.yaml`
lists the public keys whose reviews CI may reuse. CI reads the list from
the pull request's base commit, never from its head, so a change cannot
add the key that signs its own review. Lists are short (at most 50 keys),
and adding or removing a key is a reviewed change to the base branch.

**Reuse goes through carrying, not around it.** When the pull request's
head has a note, `vee ci run` fetches the notes and checks the signature
with the base's signers. It also checks that the note was signed for this
head and from the pull request's base, or that base's merge base with the
head. It then hands the signed review to the incremental review as the
earlier review. Carrying applies its own rules:

- nothing carries under a different effective configuration or different
  standards;
- only files whose base and head content are identical keep their
  findings without a model call;
- any other file is reviewed again.

CI still runs the policy's required verifications and evaluates the gate
itself. A note is not tried when Vee's summary comment already records a
review of the same head, or with `--full`. The run's `reused_review` names
the review, its signer and how many files were reused. A note that fails
verification, or that verifies but carries nothing, leaves a warning and
a full review.

## Consequences

- A change reviewed locally and pushed unchanged costs no model calls in
  CI, while CI's own verifications and gate still decide.
- Reuse needs the same effective configuration on both sides: the same
  reviewers, providers, models and provider versions. A developer whose
  agent CLI is a different version from CI's gets a full review in CI.
  That is deliberate: a different reviewer is a different review.
- A signer is trusted with the reviewers' findings for the changes it
  signs. A compromised key can hide findings until it is removed from
  `review_signers`. A key holder could also skip local review and sign a
  forged result. The list should name the people and machines the team
  would trust to run CI's review themselves.
- Nothing about the signer's machine is recorded beyond the key.
  Verification runs from the signer's machine are not trusted, since CI
  runs its own.
