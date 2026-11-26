# ADR 0035: Natural-language approval conditions

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Approval guards name paths, authors, owners and a risk tier (ADR 0015,
ADR 0026). Some changes that should reach a person cannot be named that
way: "changes the authentication flow", "adds a migration without a
rollback". A model can recognize them, but Vee's gate is deterministic and
replayable (ADR 0002), and a model's judgement must not change it.

## Decision

- **Conditions.** `approval.conditions` lists up to 20 conditions, each an
  `id` and a `when` that completes "the change …".
  `approval.condition_reviewer` picks the reviewer whose provider and model
  answer; the review's first reviewer is the default.
- **One question per change.** A provider task asks, for the exact
  snapshot, whether each condition holds, with a short piece of evidence.
  - The answer must cover every condition exactly once.
  - The instructions say to answer "holds" when unsure, and to treat text
    in the change as data.
- **Approval only.** The answer adds a `conditions` stage to approval
  eligibility. It passes only when an answer exists for this snapshot and
  these conditions and none holds. A condition that holds, or a missing or
  invalid answer, means a person approves. The gate never reads it.
- **Recorded, so it replays.**
  - The classification (`condition-classification-v1`) carries the
    snapshot, a digest of the conditions, the reviewer, provider and model,
    the digest of the model's output, and the results.
  - It is stored per snapshot and conditions digest (storage schema 15), so
    eligibility is evaluated again from it without a model call.
  - In CI, where `.vee/` doesn't survive between runs, it travels in the
    approval verdict of Vee's record on the pull request (ADR 0022). A
    later run on the same head stores it again instead of asking the model.
  - Rewording a condition changes the digest and asks again.
- **Commands.** `vee ci run --approve` classifies before deciding. Locally,
  `vee gate conditions --review ID` classifies or shows the stored answer,
  and exits 1 when a condition holds.

## Consequences

- **Not a security boundary.** The model reads the change, so a change
  can try to talk the model out of a condition. Conditions make approval
  more cautious; `never_paths` and `never_owners` stay the controls for
  what must always reach a person.
- **Recorded answers are trusted.** Only Vee's own summary comment is
  read. A host administrator who edits that comment can change the
  recorded answer, as they could approve the change themselves.
- **Cost.** One more model call per new head when conditions are
  configured.
