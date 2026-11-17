# ADR 0004: Gate decisions as in-toto attestations

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

Vero's evidence bundles prove that a gate decision is internally consistent and
replayable, and `sign-bundle` adds an Ed25519 signature. Supply-chain tooling does
not read Vero bundles, though. Policy engines, admission controllers, and
artifact registries consume in-toto attestations in DSSE envelopes (Sigstore,
SLSA, Witness, GUAC). For "this change passed review" to count in those systems,
Vero has to speak their format.

## Decision

1. `vero reviews attest <review-id>` emits an **in-toto Statement v1** with the
   predicate type `https://vero.dev/attestations/review-gate/v1`. By default it is
   signed into a **DSSE envelope** (`application/vnd.in-toto+json`) with the same
   Ed25519 keys as evidence bundles. `--format statement` prints the unsigned
   statement for external signers.
2. **Subjects** are Vero's snapshot digest (`sha256`) and, only when the reviewed
   snapshot is exactly a commit's change, that commit (`gitCommit`). That covers
   `--commit` and commit-range reviews, and base reviews whose worktree matches the
   committed diff. An uncommitted working-tree or staged review is never attributed
   to a commit, because a verifier binding the attestation to a revision must get
   what was actually reviewed.
3. The **predicate** records the decision (ID, status, blocking findings, reasons,
   evidence digest), the policy and effective-config digests, reviewer outcomes
   (provider kind, model, version), the gate's verification runs (command and
   output digests), analyzer summaries, and the evidence bundle's manifest digest.
   The full evidence stays in the bundle, linked by that digest.
4. `vero reviews verify-attestation` checks the DSSE signature over the
   pre-authentication encoding and the statement and predicate types. Trust in the
   signer comes from the supplied public key.
5. We use a Vero predicate rather than the SLSA Verification Summary Attestation:
   VSA describes SLSA levels of artifacts, while a review gate describes a policy
   decision over a source change. The predicate can be mapped to VSA later if
   consumers need it.

## Consequences

- CI can attest each merged commit and store the envelope with the release.
  Admission and release policies can then require "a Vero gate passed for this
  commit, under policy digest X, signed by key Y".
- No Sigstore/Fulcio keyless signing yet: keys are local Ed25519 files. Keyless
  signing can be layered on with `--format statement` and an external signer.
- Attestation is a human or CI step (it needs a private key), so it is not exposed
  over MCP.
