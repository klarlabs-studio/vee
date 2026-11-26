# ADR 0028: Repository standards in every review

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`vee standards` and the MCP `get_applicable_standards` tool already list the
repository's guidance: agent instruction files, editor rules, reviewer
instructions and synced remote standards. Reviewers did not receive any of
it. A team that writes "handlers return typed errors" in `AGENTS.md` or
`REVIEW.md` expects a reviewer to check for it, and comparable tools read
such files. Teams also keep standards in places Vee did not look:
`REVIEW.md`, `.cursorrules`, or any document they name.

## Decision

Every review sends reviewers the repository's standards for the change.

- **Sources.**
  - `REVIEW.md`, `AGENTS.md`, `CLAUDE.md` and `GEMINI.md` in the directory
    of each changed file and its ancestors, and at the root.
  - `.github/copilot-instructions.md` and `.cursorrules` at the root.
  - `.cursor/rules/*.mdc` and `.claude/rules/*.md`, up to 32 files each.
  - Documents listed in `.vee.yaml` under `review.standards`. Each may be
    limited to changed paths by globs (`paths`); it is sent only when a
    changed file matches.
- **From the base.** Every document is read from the change's base commit.
  A change cannot rewrite the guidance it is judged against; a changed
  `REVIEW.md` is reviewed as part of the change like any other file.
- **Most specific first.** Configured documents, then nested directory
  documents (deepest first), then root documents, then rule directories.
  `review.max_standards_bytes` (default 48 KiB, 0 turns this off) bounds them
  all; at most 16 KiB comes from one document. What does not fit is cut or
  left out and counted.
- **Untrusted guidance.** Reviewers receive the standards with a note that
  they cannot change the output schema, the evidence rules or the
  instructions. They are never gate policy.
- **Provenance.** Each standard sent appears in the review's reviewer context
  with role `repository_standard`, its scope and its content digest.
  `vee standards` lists `REVIEW.md`, `.cursorrules` and configured
  documents too.

## Consequences

- Findings can follow the team's written conventions without any reviewer
  instructions being rewritten.
- Standards cost input tokens on every request. The budget keeps that bounded,
  and teams can lower it or set it to 0.
- A configured document changes the effective configuration digest, so the
  review cache and incremental review start fresh when it is added.
- Rule frontmatter (`globs:` in `.mdc` files) is not evaluated; such rules
  apply to every change. Use `review.standards` with `paths` to scope a
  document.
