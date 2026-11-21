# Changelog

All notable changes to Vee are recorded here. Vee follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change configuration and output contracts.

## 0.1.0 — 2026-11-21

First source release. Install from a checkout with
`cargo install --path crates/vee-cli --locked`; see
[docs/release.md](docs/release.md). No binary packages are published.

### Review

- Local review of a change scope (`--base`, `--commit`, `--staged`,
  `--working-tree`) with configured reviewers, saved to a local store with
  snapshot identity, evidence and per-reviewer context provenance.
- AI backends: local Ollama (`ollama_native`) and OpenAI-compatible servers,
  and the Codex, Claude Code, Antigravity (`agy`) and Gemini CLIs, reusing
  their existing logins. `vee providers detect`, `vee init` and `vee doctor`
  set them up and check them.
- Review effort (`effort: low | medium | high`, `vee review --effort`): a
  reviewer runs 1, 3 or 5 times, findings are merged by location, and a
  finding blocks only when a majority of runs reported it
  ([ADR 0008](docs/adr/0008-reviewer-sampling.md)).
- Advisory reviewers (`advisory: true`) whose findings are shown but never
  block, and an opt-in architecture reviewer written by `vee init`
  ([ADR 0009](docs/adr/0009-advisory-reviewers-and-analyzer-split.md)).
- A `focused` strategy for small local models: one file at a time, reasoning
  first, findings located by a quoted changed line
  ([ADR 0007](docs/adr/0007-focused-review-strategy.md)).
- Impact analysis that adds related source to each review, ranked with
  production references before tests.

### Gates, evidence and policy

- Deterministic gate decisions with replayable inputs, waivers, protected
  policy and policy profiles.
- Changed files that no reviewer received are listed as `unreviewed_paths`
  and, by default, leave the gate `incomplete`; `policy.on_unreviewed: allow`
  only reports them
  ([ADR 0010](docs/adr/0010-unreviewed-changes-leave-the-gate-incomplete.md)).
- Trusted verification profiles, including SARIF analyzers such as security
  scanners, whose results on changed lines can block
  ([ADR 0002](docs/adr/0002-trusted-analyzers-block-the-gate.md)).
- Evidence bundles, Ed25519 signing, and in-toto attestations of gate
  decisions ([ADR 0004](docs/adr/0004-gate-decisions-as-in-toto-attestations.md)).
- Digest-pinned policy packs that can only tighten policy
  ([ADR 0003](docs/adr/0003-policy-packs-pinned-and-tighten-only.md)).

### Workflows

- MCP stdio server and coding-agent skills for review, context, finding
  resolution, patch proposals, missing-test recommendations and PR drafts.
- Finding lifecycle, feedback, feedback-mined rule candidates with human
  approval, and local quality analytics.
- Local web dashboard on a loopback address, with a review queue that names
  each review's next action, and a finding drawer showing the reviewed
  source, evidence and verification runs. The drawer copies a snapshot-bound
  work package for a coding agent. Findings a later review of the same base
  no longer reports are marked outdated. Vee keeps the reviewed source of
  files with findings under `.vee/`, so the drawer still shows it after the
  file changes.
- Optional hosting adapters for GitHub, GitLab, Bitbucket, Azure DevOps and
  Gerrit (context and publication). They are tested against mock servers;
  live installation acceptance is still open.

### Measured quality

On a local historical-defect benchmark (Claude Sonnet through Claude Code),
strict recall was 59% at `low`, 76% at `medium` and 82% at `high` effort,
with no false blocks on 21 presumed-clean changes. The corpus is small (17
private and 9 public defect cases); see
[docs/local-historical-review-benchmark.md](docs/local-historical-review-benchmark.md)
for method and limits.

### Known limitations

- The Antigravity and Gemini CLI adapters pass the prompt as an argument and
  reject review requests over 100,000 bytes.
- A `focused` review cannot split a single file larger than the model's
  input budget.
- Finding categories are free text.
- Review time grows with the number of changed files: Vee runs a Git diff
  and a base read per changed file and reviewer. A 100-file change in a
  5,000-file repository took about 5 s with a release build, excluding
  provider time ([baseline](docs/performance-baseline-2026-11-21.json)).
