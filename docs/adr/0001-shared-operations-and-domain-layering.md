# ADR 0001: One operations layer for all transports, and a path to domain layering

- **Status:** Accepted (step 1 and step 2.1 implemented); steps 2.2 and 2.3 in progress
- **Date:** 2026-11-17

## Context

Vero exposes the same capabilities through the CLI, an MCP server, and the local
HTTP dashboard. Until now each transport implemented its own handler around the
application services, and they drifted:

- `gate check` resolved the work-item token from `.vero.yaml` on the CLI, but not over MCP.
- The same operation returned different documents: `findings list` was unpaged on
  the CLI and paged over MCP; `findings show` omitted evidence on the CLI; MCP
  wrapped tasks, gate, impact, verification, review, and search results in ad hoc
  envelopes. The MCP search envelope violated the published
  `imported-review-search-v3` schema.
- Input rules (reason and name lengths, the waiver guard) existed in one transport only.
- Rule approval logic was duplicated, with checks in a different order.
- MCP parsed stored reviews with its own struct instead of the application deserializer.

Separately, the layering only partly follows domain-driven design:

- The domain language is consistent (snapshot, finding, gate decision, waiver,
  evidence, verification run). Ports exist for reviewer providers
  (`ReviewProvider`), Git hosting (`GitHostingProvider`), and Git capture (`vero-git`).
- `vero-core` mixes the domain model with infrastructure: the SQLite `ReviewStore`
  (`rusqlite`) and reviewer subprocess execution (`libc`, `tempfile`).
- Application services depend on the concrete SQLite store; there is no repository port.
- Invariants live in transports instead of the model (the waiver guard, input
  bounds). Some lifecycle state is stringly typed (`RuleApproval.status`).
- Use cases live in the CLI crate (`finding_task`, `rule_candidates`, `acceptance`,
  `analytics`, `standards`, `repository_map`), so the HTTP transport cannot reuse
  them. `vero-application` is a single 13k-line module without bounded contexts.

## Decision

### Step 1 (implemented)

1. `crates/vero-cli/src/operations.rs` is the single implementation of every
   operation shared by the CLI and MCP. Each operation validates input once, calls
   the application services, and returns the published result document. Errors use
   the existing usage/configuration markers, so the CLI keeps its exit codes and MCP
   returns the same message.
2. The schema files in `schemas/` are the contract for both transports.
   `contracts.rs` embeds them and bundles external `$ref`s into `$defs` (the JSON
   Schema 2020-12 compound-document form). MCP tools declare the bundled schema as
   their `outputSchema`, so the server validates each structured result against the
   contract the CLI emits.
3. `tests/transport_parity.rs` runs each shared operation through both transports
   and requires identical, schema-valid documents.
4. Every `--output` flag defaults to `text`; `--output json` prints one compact
   document. A unit test enforces the default.

### Step 2 (proposed, separate change)

Restructure toward domain layering, in this order:

1. **Repository port.** Define review, finding, verification, and rule-approval
   repository traits in the domain; move `ReviewStore` into a `vero-store-sqlite`
   adapter crate. Keep subprocess provider execution in an adapter crate.

   *Implemented (2026-11-18):* `vero_core::ports` defines one trait per bounded
   context (`ReviewRepository`, `FindingRepository`, `GateRepository`,
   `VerificationRepository`, `RuleApprovalRepository`, `ProviderResponseCache`,
   `HostedDeliveryRepository`) and `Repositories` for all of them.
   `vero-store-sqlite` implements them; `vero-core` no longer depends on
   `rusqlite`, and `vero-application` uses the store only in tests. Active rule
   approvals, which the effective config digest binds, are now read through
   `RuleApprovalRepository` and passed in explicitly instead of the digest
   function opening `.vero/vero.sqlite` itself. Reviewer provider and
   verification subprocess execution moved to the `vero-process` adapter, so
   `vero-core` no longer depends on `libc`, `tempfile`, or `tokio-util`.
2. **Invariants in the model.** Finding status transitions (no waiving through a
   status change), typed approval status, and bounded value types for reasons and
   actor names.
3. **Use cases in `vero-application`, by bounded context:** Review (capture,
   reviewers, findings), Gate & Policy (decisions, waivers, evidence), Verification,
   Learning (feedback, rule candidates and approvals), and Context & Impact.
   Move `operations.rs` and the use-case modules out of `vero-cli`, so `vero-http`
   uses the same operations as the CLI and MCP.

## Consequences

- One code path per operation; transport drift is caught by the parity test and by
  MCP output validation.
- Breaking contract changes, acceptable before 0.1.0:
  - `findings-list-v2` (adds `limit`, `offset`, `total`; CLI gains `--limit` and
    `--offset`) and `finding-detail-v2` (adds `evidence`).
  - MCP results lose their wrapper objects and match the CLI documents.
  - MCP `review_changes` and `start_review` return the full review document.
  - Nine commands now default to text instead of JSON.
- `acceptance_traceability` over MCP no longer rejects a review whose working tree
  changed. Impact reads are digest-verified against the saved snapshot, so the
  result remains bound to that snapshot, matching the CLI.
- `operations.rs` is in the CLI crate until step 2. The HTTP transport still has
  its own handlers.
