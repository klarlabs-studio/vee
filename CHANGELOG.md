# Changelog

All notable changes to Vee are recorded here. Vee follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change configuration and output contracts.

## 0.1.0 — unreleased

First release. Install a release binary with the shell or PowerShell
installer attached to the release, use the `ghcr.io/klarlabs-studio/vee`
container image in CI, or build from a checkout with
`cargo install --path crates/vee-cli --locked`; see
[docs/release.md](docs/release.md). Release archives come with checksums and
build provenance.

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
  production references before tests. Names are resolved within their scope
  ([ADR 0012](docs/adr/0012-scoped-name-resolution-for-impact.md)), and files
  that changed together in history are a second signal
  ([ADR 0013](docs/adr/0013-co-change-history-as-a-second-impact-signal.md)).
- Snapshot exploration: reviewers on Claude Code can list, read and search
  the unchanged code of the reviewed snapshot through budgeted, read-only
  tools, limited to each reviewer's own paths and a deny list of secrets
  ([ADR 0017](docs/adr/0017-reviewers-explore-the-review-snapshot.md)).
- A fixed finding rubric: one defect per finding, and severity set by
  consequence ([ADR 0018](docs/adr/0018-fixed-finding-rubric-and-severity-floors.md)).
- A guided `vee init` that detects the AI backends on this machine and, in a
  terminal, asks which one, which model and which effort to use, with
  guidance from the measured results
  ([best results](docs/guides/best-results.md)). The provider and effort are
  recorded for this machine, outside the repository.
- An opt-in, advisory task-alignment reviewer that checks a change against
  its linked work item.
- Live progress: the terminal, MCP progress notifications and the dashboard
  show which reviewer runs have finished.
- Usage limits: when a provider reports a usage, quota or rate limit, its
  remaining runs are skipped and recorded as `rate_limited`, and the review
  is incomplete.
- Context for larger changes: every changed file first gets its bounded diff,
  and leftover budget upgrades diffs to full contents, so a few large files
  no longer crowd later files out of the reviewer's context.

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
- Severity floors: paths or categories whose findings are evaluated at no
  less than a minimum severity, from the repository, packs or the protected
  policy ([ADR 0018](docs/adr/0018-fixed-finding-rubric-and-severity-floors.md)).
- Change risk as explained tiers (`low`, `elevated`, `high`) with the
  factors behind them
  ([ADR 0014](docs/adr/0014-change-risk-as-explained-tiers.md)).
- Approval eligibility (`vee gate approval`): staged checks of whether a
  passing change may be approved without a person, and an approval check
  published with `vee hosting publish --approval`
  ([ADR 0015](docs/adr/0015-layered-approval-eligibility.md)).
- Review sessions (`vee reviews session`): several saved reviews, such as
  one coding-agent session's commits, even across repositories
  (`REPO:REVIEW_ID`), with a gate per change and one verdict
  ([ADR 0016](docs/adr/0016-review-sessions-keep-per-change-gates.md)).

### Workflows

- MCP stdio server and coding-agent skills for review, context, finding
  resolution, patch proposals, missing-test recommendations and PR drafts.
  A plugin (`plugins/vee`) installs the skills and the MCP server in Claude
  Code and in Codex.
  Every MCP tool declares an output schema, and saved reviews, verification
  runs and finding feedback can be listed over MCP as on the CLI.
- Finding lifecycle, feedback, feedback-mined rule candidates with human
  approval, and local quality analytics. Finding tasks and work packages
  carry the changed hunk around the flagged line.
- Patch proposals: an agent's fix is validated in a sandbox and saved under a
  digest. Applying it needs a person to confirm at a terminal; a patch may
  not change Vee configuration, CI definitions or Git hooks, make a file
  executable, or link outside the repository.
- Local web dashboard on a loopback address, opened with a per-run access
  token that every API request must carry, with a review queue that names
  each review's next action, and a finding drawer showing the reviewed
  source, evidence and verification runs. The drawer copies a snapshot-bound
  work package for a coding agent. Findings a later review of the same base
  no longer reports are marked outdated. Vee keeps the reviewed source of
  files with findings under `.vee/`, so the drawer still shows it after the
  file changes.
- Optional hosting adapters for GitHub, GitLab, Bitbucket, Azure DevOps and
  Gerrit (context and publication). They are tested against mock servers;
  live installation acceptance is still open. A hosting credential goes only to
  the provider's public service or to a host named with `--host`,
  `--api-base` or `VEE_HOSTING_HOSTS`, never to one set only in `.vee.yaml`.
  When a finding moves to another line, its old thread is resolved and a new
  one opens; threads of fixed findings are resolved.

### Pull requests in CI

- `vee ci run` reviews the pull request a GitHub Actions or GitLab CI job
  runs for, publishes the check and finding threads, and exits with the gate
  ([ADR 0019](docs/adr/0019-reviews-on-pull-requests-run-in-the-teams-ci.md)).
- A GitHub Action (`klarlabs-studio/vee`) and a GitLab CI template that
  install a pinned release and run `vee ci run`.
- `vee init --ci github|gitlab` writes a pipeline that uses them, pinned to
  this release, with an API-key provider ([guide](docs/guides/pull-requests.md)).
- Commands in pull request comments on GitHub (`vee ci command`):
  `@vee review`, `status`, `explain`, `dismiss`, `waive` and `help`. Only
  people with write access can run them, waivers also need code ownership
  from the base branch's `CODEOWNERS`, and commands that load the
  repository's configuration are refused on forks
  ([ADR 0020](docs/adr/0020-commands-in-pull-request-comments.md)).
- A reviewer may return a fix with a finding. It is posted as a suggestion
  that can be committed from the pull request on GitHub and GitLab, and as a
  diff on other hosts, after Vee checks that it replaces lines of the diff
  ([guide](docs/guides/pull-requests.md#suggested-fixes)).

### CLI and MCP output

- The CLI and the MCP server run the same operations and show the same view
  of each result ([ADR 0011](docs/adr/0011-shared-presentation-for-cli-and-mcp.md)).
  The terminal gets aligned, colored text; MCP gets that view as Markdown,
  with the full JSON document as structured content.
- `--color auto|always|never` on every command. `auto` colors only a
  terminal and honors `NO_COLOR`, `CLICOLOR` and `CLICOLOR_FORCE`. Status
  symbols (`✔ ✖ ▲ ● ·`) keep the meaning visible without color.
- `--output json` follows the published schemas in [schemas/](schemas/).
  Text output is for people and is not a stable interface.

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
- Configuration is parsed with `serde_yaml` 0.9, which is no longer
  maintained; a replacement is planned.
- Finding categories are free text, so a category severity floor applies only
  when the reviewer uses the floor's exact category name.
- Review time grows with the number of changed files: Vee runs a Git diff
  and a base read per changed file and reviewer. A 100-file change in a
  5,000-file repository took about 5 s with a release build, excluding
  provider time ([baseline](docs/performance-baseline-2026-11-21.json)).
