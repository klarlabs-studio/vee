# ADR 0009: Advisory reviewers, and scanners for pattern vulnerabilities

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

On the historical corpus ([benchmark](../local-historical-review-benchmark.md)),
the findings of Vee's AI correctness reviewer are logic and behavior defects:
about 70% correctness, 15% concurrency and 10–15% security. The security
findings are logic flaws too (a race that skips account lockout, a key grant
made before a safety check). The reviewer instructions asked for defects, so
the corpus says nothing about design or maintainability review.

The nox security scanner, run on the same 17 defect commits with its taint,
reachability and attack-surface plugins, reported nothing inside any labeled
range, including the two command-injection defects. The corpus has no
dependency, secret or known-pattern defects, which is where a scanner is
strongest, so this measures overlap, not the scanner's value.

Teams also want design feedback (layering, coupling, duplication), but a
global policy that blocks every `high` finding would let a design reviewer
block merges on judgment calls.

## Decision

1. A reviewer may set `advisory: true`. Its findings are shown, tagged
   `advisory`, and never block the gate. The flag is recorded on each finding
   at review time, so a saved gate decision replays without configuration.
   When an advisory and a blocking reviewer report the same finding, the
   blocking reviewer's report still blocks; the merged finding is advisory
   only when every reporting reviewer is advisory. Policy packs may carry the
   flag.
2. `vee init` writes an `architecture` reviewer for design and
   maintainability problems introduced by the change. It is advisory and
   disabled by default: its instructions are not benchmarked, and enabling it
   doubles provider calls.
3. Scanner-class vulnerabilities (vulnerable dependencies, secrets, injection
   patterns) are left to established scanners run as trusted SARIF analyzers
   (ADR 0002), for example nox. Vee does not grow its own scanner rules.

## Consequences

- Three lanes with different gate roles: scanners block on error-level
  results in changed lines; the correctness reviewer blocks on findings at
  the policy threshold; the architecture reviewer informs.
- Advisory findings still count in analytics and exports, so their usefulness
  can be measured from feedback before anyone makes them blocking.
- Architecture review quality is unmeasured until the corpus has labeled
  design cases.

## Alternatives considered

- **Per-reviewer severity caps** (for example, never above `medium`). Severity
  would stop meaning the cost of the problem.
- **Reviewer policy with no blocking severities.** Reviewer policies only add
  blocking rules to the global policy, so this cannot make a reviewer
  advisory.
- **Security rules in the AI reviewer instead of a scanner.** Deterministic
  scanners are cheaper, reproducible and maintained by specialists.
