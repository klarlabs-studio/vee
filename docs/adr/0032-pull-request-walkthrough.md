# ADR 0032: A pull request walkthrough in Vee's summary

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Reviewers of a pull request first want to know what it changes and what it
reaches. Vee already computes both: impact analysis follows changed symbols
to the files that use them and labels each relationship with how it was
found, and change risk names the factors that make a change risky.
`vee pr draft` drafts a description. None of it reached the pull request.
Tools that draw such diagrams usually generate them with a model, and a
reader cannot tell a measured relationship from a guessed one.

## Decision

`vee ci run --describe` adds a **Walkthrough** section to Vee's summary
comment.

- **Risk.** The tier and the flagged factors, from the same assessment as
  the `vee:risk:*` label.
- **What the change reaches.** A Mermaid flowchart built from impact
  analysis, not from a model.
  - Changed files have a bold border.
  - Each edge names its relationships. It is solid when parsing or a
    language server found it (`resolved_semantic`, `inferred_syntax`,
    `inferred_import`), and dotted when it is heuristic (name matches,
    package membership, co-change history).
  - At most 40 edges are drawn, firmest first, with a count of the rest.
  - Incomplete coverage is said.
- **A drafted description.** `vee pr draft` with the first reviewer, folded
  in a `<details>` block, marked as generated and unverified. If it cannot
  be drafted, the walkthrough goes out without it.
- **Within the comment limit.** The summary also carries the review record
  (ADR 0022), which can take most of a comment. The walkthrough gets what is
  left of 65,000 characters, dropping the description and then the graph
  until it fits.
- **Never the gate.** The walkthrough is presentation only. Nothing in it is
  read back, and Vee's markers in generated text are neutralized.

## Consequences

- One more model call per review with `--describe`, which is off by
  default.
- GitHub and GitLab both render Mermaid in comments.
- The graph is as good as impact analysis: dynamic dispatch and runtime
  coupling are not drawn. The walkthrough says when coverage is incomplete.
