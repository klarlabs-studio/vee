# ADR 0002: Trusted SARIF analyzers can block the gate on changed lines

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

Model reviewers produce hypotheses. Vee gates them behind confidence, severity,
and observed-source-evidence rules, but they remain probabilistic. Repositories
already run deterministic tools (linters, type checkers, security scanners such as
Semgrep, CodeQL, Clippy via `clippy-sarif`, Trivy) that report in SARIF 2.1.0.
Competing AI review products present those tools' output, if at all, as more AI
comments. We want deterministic analyzer results to be first-class gate evidence
without weakening Vee's guarantees: snapshot binding, no execution of
model-suggested commands, and decisions that replay from stored inputs.

## Decision

1. An analyzer is a **verification profile with a `sarif` section**. It runs
   through the existing verification path: repository-configured argv, no shell,
   cleared environment, bounded time and output, snapshot recaptured before and
   after, stdout stored as a content-addressed artifact.
2. An analyzer **blocks only when trusted**: it must be listed in
   `policy.required_verifications`, and only results whose SARIF level appears in
   its `sarif.block_levels` block. An empty list makes it advisory.
3. **Only results on changed lines count.** Vee maps each result's first physical
   location to a repository path inside the root and keeps it only when the line was
   added or modified in the snapshot. Pre-existing results never block, so adopting
   an analyzer does not require fixing its backlog first.
4. A required analyzer whose run did not finish or produced no valid SARIF makes
   the gate **incomplete**, never passing. A non-zero exit with valid SARIF is
   complete, because analyzers exit non-zero when they report results.
5. Analyzer findings get a stable identity, `analyzer:<profile>:<digest prefix>`,
   from a fingerprint of profile, rule, path, and the trimmed source line (stable
   across line shifts). They appear in `blocking_findings` and can be waived per
   snapshot like reviewer findings.
6. The derived `analyzer-report-v1` documents are **recorded in the gate's replay
   inputs** and the evidence digest. Replay never re-runs or re-parses the analyzer.
   Decisions without analyzers keep their previous identities and documents.

## Consequences

- Vee can act as a deterministic merge gate that combines model review with
  established tools under one snapshot-bound, replayable decision.
- Analyzer configuration is trusted repository configuration, like any
  verification profile. A malicious `.vee.yaml` can already run arbitrary
  commands at `vee verify`; this adds no new execution path.
- Only the first location of a result is evaluated; results without a physical
  location never block. Files too large or binary for the bounded diff are listed
  as limitations, and their results cannot block.
- Analyzer reports are not yet merged into the reviewer findings list or the
  finding lifecycle (status, feedback, tasks). That can follow if users want it.
