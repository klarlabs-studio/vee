# ADR 0018: A fixed finding rubric, with severity floors in policy

- **Status:** Proposed
- **Date:** 2026-11-24

## Context

Teams want to tune review to their codebase. Most of that is already
configurable:

| What | Where |
|---|---|
| What each reviewer looks for | `.vee/reviewers/*.md`, context files, include/exclude |
| What blocks the gate | `policy.block_severities`, `minimum_confidence`, required reviewers, policy profiles |
| Shared team guidance | Approved rules |
| Organization baselines | Policy packs, pinned and tighten-only ([ADR 0003](0003-policy-packs-pinned-and-tighten-only.md)) |

Two things are fixed in code: how a reviewer writes a finding, and what each
severity means. Both are now spelled out in every review prompt and in the
provider findings schema. A finding reports one defect, led by what goes
wrong. Severity follows the defect's consequence, and a defect that causes
wrong behavior is at least `medium`.

Two requests recur:
1. **Redefine the rubric.** For example, "for us, every unhandled error is
   high".
2. **Raise the bar in sensitive code.** For example, "any defect in the
   payment code blocks".

## Decision

### The rubric stays fixed

The finding format and the meaning of each severity are part of Vee's
contract, not configuration.

- **Policy depends on the meaning of severity.** `block_severities: [high]`,
  a pack's baseline and a gate attestation all assume that `high` means the
  same thing in every repository. A repository that redefines `high` would
  silently change what those mean.
- **The format is load-bearing.** Single-claim findings are what make
  deduplication, line anchoring, agreement between sampled runs and
  publication work.
- **Defaults should improve with Vee.** The rubric is versioned with Vee and
  is not copied into repositories, so a repository picks up a better rubric
  on upgrade.

Domain-specific examples ("in this codebase, a missing tenant filter is a
data leak") belong in reviewer instructions, which already exist.

### Severity floors raise the bar where it matters

Policy gains `severity_floors`. Each floor selects findings by path globs,
categories, or both, and sets a minimum severity:

```yaml
policy:
  block_severities: [critical, high]
  severity_floors:
    - paths: ["payments/**", "billing/**"]
      minimum: high
    - categories: [security]
      minimum: high
```

- **Selection.** A floor applies to a finding that matches any of its path
  globs (when `paths` is set) and any of its categories (when `categories` is
  set). A floor must set at least one of them. A path floor never applies to
  a finding without a path.
- **Effect.** When the gate evaluates a finding, it uses the higher of the
  reported severity and every matching floor's minimum. This holds for the
  repository policy and for reviewer policies.
- **Reported severity is kept.** The review record keeps what the reviewer
  reported. When a raised severity makes a finding block, the gate decision
  says so, naming the finding, both severities and the floor.
- **Tighten-only.** Floors from a protected local policy and from packs are
  added to the repository's floors. A floor can only raise severity, so
  adding floors never relaxes a policy.
- **Replay.** An empty floor list is not serialized, so existing policy
  digests and recorded decisions are unchanged.

## Consequences

**Benefits:**
- Teams set a higher bar exactly where they need it, and that bar does not
  depend on the reviewer model following an instruction.
- Severity means the same thing in every repository, so packs and
  attestations stay comparable.
- Improvements to the rubric reach every repository on upgrade.

**Costs and risks:**
- Teams cannot lower the rubric's severities. A team that disagrees with a
  rating can stop blocking on that severity, waive the finding, or narrow
  the reviewer's scope.
- A broad floor can make the gate block often. The gate decision names the
  floor that raised each blocking finding, so the cause is visible.
