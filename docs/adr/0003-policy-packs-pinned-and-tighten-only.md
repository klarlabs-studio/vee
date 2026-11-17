# ADR 0003: Policy packs are digest-pinned directories that can only be tightened

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

Teams want one review policy across many repositories: the same reviewers and
instructions, the same gate thresholds and required checks, and the reviewer
guidance they approved from feedback. Until now each repository kept its own
`.vero.yaml`, reviewer files, and a local-only SQLite record of approved rules,
so nothing was shareable and an approved rule never left the machine that
approved it.

## Decision

1. A **pack** is a directory containing `pack.yaml` (`policy-pack-v1`) and the
   reviewer instruction and context files it names. It may define a baseline
   policy, policy profiles, reviewers, verification profiles, and approved rules
   (with their original approval provenance).
2. Repositories commit packs (`vero packs add` installs them under
   `.vero/packs/<name>/`) and **pin each by content digest** in `.vero.yaml`.
   Loading recomputes the digest; any difference fails configuration loading
   (exit 3) until a human re-pins. The pin is part of the effective configuration
   digest, so changing a pack makes earlier reviews stale.
3. Pack reviewers have no provider; the pin names one (default `default`, which
   `vero init` configures per machine), so packs are portable across machines.
4. Reviewers, verification profiles, and policy profiles from packs are added;
   **repository definitions win on ID collisions**, and two packs defining the same
   ID is an error.
5. **Policy merges by strictness**: required reviewers, required verifications,
   acceptance profiles, and blocking severities are unioned; the lowest confidence
   threshold applies; `on_incomplete: block` wins. A repository can tighten a
   pack's baseline but never loosen it.
6. Pack rules join local approvals as reviewer guidance; a local approval wins when
   both share an approval ID.

## Consequences

- An organization can distribute a baseline that repositories cannot weaken
  without visibly editing or unpinning the pack in a reviewed change.
- Packs are plain files: they travel through Git, review, and any package or
  artifact channel; no registry or network access is needed.
- Verification profiles in packs name commands, which are repository-specific, so
  export includes them only when selected.
- Pack rule expiry (`expires_at_unix`) is carried but not yet enforced at load;
  revoking a pack rule means publishing a new pack version.
