# Changelog

All notable changes to Vee are recorded here. Vee follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change configuration and output contracts.

## Unreleased

### Reasoning effort for providers

- `providers.<id>.reasoning_effort: low|medium|high` sets a reasoning
  model's effort: Codex CLI's `model_reasoning_effort`, the OpenAI-compatible
  `reasoning_effort` field, or Ollama's `think` level. It is refused for
  provider kinds without such a setting, and it keys the review cache.

### Team analytics without a server

- `vee analytics aggregate <paths>` combines the JSON of `vee analytics`,
  `vee ci approvals` and `vee rules effectiveness` from several repositories
  into one report.
  - It covers gate outcomes, finding accuracy and actionability, approval
    agreement and override, cost, and rule effectiveness.
  - Rates are recomputed from summed counts and shown with their
    denominators.
  - Per-pull-request cases are left out, so no person is named.
- `--html <file>` writes the report as one self-contained page, with no
  script or external resources. JSON follows `team-analytics-v1`
  (ADR 0044).

### Review once, reuse in CI

- `vee reviews share <review> --private-key <key> --key-id <id>` signs a
  complete local review of committed changes and stores it as a Git note
  on its head (`refs/notes/vee-reviews`).
- `vee ci run` reuses it when the base branch's new `review_signers` lists
  the key. Files whose content is unchanged keep their findings with no
  model call. CI still runs its required verifications and decides the
  gate. The run's `reused_review` names the review and its signer
  (ADR 0043).

### The steward

- `vee steward --base <ref>` fixes what keeps the current branch from
  passing its gate: a merge conflict with the base, required verifications
  that fail, and blocking findings. The configured reviewer's model
  proposes each fix. Vee commits it and keeps it only when a new review is
  complete, adds no blocking finding, breaks no verification that passed,
  and shows the problem solved; otherwise it resets the branch to before
  the fix.
- A merge resolution is kept only when a required verification passes on
  the merged result. Kept fixes stay on the branch, unpushed, each with
  how to undo it.
- `steward.max_fixes` (default 5) bounds a run. The MCP tool `run_steward`
  needs `steward.agents: true`. JSON output follows `steward-run-v1`
  (ADR 0042).
- `@vee steward` on GitHub and GitLab runs the steward on the pull
  request's head. It also addresses review comments on lines from people
  with write access, pushes the fixes the reviews accept, and answers in
  each addressed thread with how to undo the commit.

### Approval on Bitbucket, Azure DevOps and Gerrit

- `vee hosting publish --approval` with `approval.mode: enforce` gives
  Vee's own approval on Bitbucket Cloud (an approval), Azure DevOps (a
  reviewer vote of 10) and Gerrit (a `Code-Review` vote at the highest
  value its account may give). It withdraws that approval from a change
  that no longer qualifies, and in observe mode. `--approval` is no longer
  refused on Gerrit. The receipt's `approval` field reports `given`,
  `kept`, `withdrawn` or `not_given`. `approval.require_owner_approval`
  and `approval.max_per_day` can't be evaluated on these hosts, so either
  one stops Vee from approving there (ADR 0041).

### Fixes

- Bitbucket pull requests report abbreviated commit hashes; Vee now
  resolves them, so publishing to Bitbucket no longer fails because the
  reviewed head never matches.

### Signed and notarized macOS binaries

- Release builds sign the macOS binaries with a Developer ID and the
  hardened runtime, and notarize them with Apple, so Gatekeeper accepts a
  binary downloaded in a browser. `scripts/notarize-macos.py` checks every
  macOS archive's binary and fails the release when it is unsigned or Apple
  rejects it (ADR 0040).

### Releases signed with a maintainer key

- `scripts/release-signature.py sign` signs a published release's
  `sha256.sum` with a maintainer's SSH key, on the maintainer's machine,
  after checking every archive's digest and build provenance, and uploads
  `sha256.sum.sig`. `verify` checks the signature against
  `.github/release-signers` and then the archives' digests (ADR 0039).

### HTTPS for the webhook server

- `vee hosting webhook-serve --tls-cert --tls-key` serves HTTPS, and with
  `--allow-network` it may bind beyond loopback, including a wildcard
  address. Plaintext beyond loopback stays refused. A private key that
  other users can read is refused. The webhook server's `/api/health` now
  answers `{"status":"ok"}` on any host name and no longer names the
  repository path (ADR 0038).

### Reverted merges in the approval report

- `vee ci approvals` counts a pull request merged at a head Vee called
  eligible and reverted later as `reverted_after_eligible`, an override
  rather than agreement. Reverts are found in merged revert pull requests
  (`Reverts owner/repo#N`, `This reverts merge request !N`) and, in a clone,
  in `This reverts commit` messages on the checked-out branch. Cases name
  the reverting pull request or commit (ADR 0037).

### Findings carried on unchanged hunks

- In a file a push changed, hunks whose content is the same as at the last
  review keep their findings, moved with the hunk, and new findings there are
  dropped. Reviewers still get the whole file, with `carried_line_ranges`
  marking what was covered, and `changed_line_ranges` lists only the rest.
  Vee's record on the pull request keeps each file's hunks, and the review
  output's `carried.partial_paths` names such files (ADR 0036).

### Natural-language approval conditions

- `approval.conditions` names conditions, such as "changes the
  authentication flow", that a reviewer's model checks for each change.
  One that holds, or a missing answer, sends the change to a person; the
  gate is unaffected. The answer is stored with its model and digest
  (`condition-classification-v1`, storage schema 15) and carried in Vee's
  record on the pull request, so approval replays. `vee gate conditions`
  classifies locally (ADR 0035).
- The approval eligibility schema lists the `owner_approvals` and
  `conditions` stages.

### Owner approval before Vee approves

- `approval.require_owner_approval: true` makes Vee approve only once, for
  every changed file `CODEOWNERS` on the base assigns, one of its owners
  has approved the current head; team owners are checked for membership.
  `vee ci run` also runs on `pull_request_review`, so an owner's approval
  is picked up (ADR 0034).

### Jira and Linear work items

- `work_items` in `.vee.yaml` names Jira (Cloud or Data Center) or Linear,
  and `vee review --work-item PROJ-123` reads the issue from it. Issues are
  digest-bound and revalidated by `vee gate check`; a Jira acceptance field
  feeds acceptance traceability. A Jira site receives a token only once it
  is listed in `VEE_HOSTING_HOSTS` (ADR 0033).

### Pull request walkthrough

- `vee ci run --describe` (Action input `describe`, GitLab `VEE_DESCRIBE`)
  adds a walkthrough to Vee's summary: the risk tier, a Mermaid graph of
  what the change reaches with each edge labelled measured or heuristic, and
  a drafted description marked as unverified. It never affects the gate
  (ADR 0032).

### Learning from pull request feedback

- `vee rules candidates --pull-requests OWNER/REPO` reads closed pull
  requests on GitHub or GitLab. Dismissals, findings no longer reported at
  merge, and thumbs-up or thumbs-down on Vee's threads become weak labels.
  Rule candidates from them (`weak_candidates`) carry each signal's
  provenance, need five distinct findings, need a person's approval, and
  never affect the gate.
- A rule whose findings people keep rejecting is suspended automatically,
  with an audit event; `vee rules restore` puts it back. The rule approval
  schemas gain the `suspended` status and the `suspended` and `restored`
  events (storage schema 14).
- `vee rules export [--write REVIEW.md]` renders the active rules as a
  Markdown section that agents and editors read too (ADR 0031).

### GitLab parity

- On GitLab merge requests, `vee ci run` now keeps Vee's summary note with
  its review record, so later pushes are reviewed incrementally, and
  supports `--labels` and `--approve` (approve and unapprove, with the
  approval's history read from system notes).
- `@vee` commands work on GitLab through a Comments webhook that triggers a
  pipeline. Vee reads the comment back from the API instead of trusting the
  payload, and `@vee fix` pushes with `GL_TOKEN`.
- Vee posts as the token's user; `VEE_ACTOR_LOGIN` is no longer needed.
- `vee ci approvals --provider gitlab` reports on GitLab projects (ADR 0030).

### Security scanner presets

- `vee init` finds nox, gitleaks, semgrep and trivy on the machine and writes
  SARIF verification profiles for them, with `security` and `regulated`
  policy profiles that require them. In an existing repository it prints the
  configuration to add. osv-scanner is detected but not used: its SARIF has
  no result lines.
- `policy.automatic_approval: false` makes every change under that policy
  need a person; approval eligibility gains a `policy` stage. Packs can turn
  it off but never back on. The `regulated` profile sets it.
- `vee ci run` runs the verification profiles the policy requires before it
  reviews (ADR 0029).

### Repository standards in every review

- Reviewers now receive the repository's standards with every review:
  `REVIEW.md`, `AGENTS.md`, `CLAUDE.md` and `GEMINI.md` from each changed
  file's directories and the root, `.cursorrules`, Copilot instructions,
  `.cursor/rules/` and `.claude/rules/`, and documents listed under
  `review.standards` (optionally limited to changed paths). They are read
  from the change's base, most specific first, within
  `review.max_standards_bytes` (48 KiB by default; 0 turns this off).
- Each standard sent is recorded in the reviewer context with role
  `repository_standard`; `review-output-v2` gains `standards_digest` and the
  `truncated_source` context status. Incremental review carries nothing
  across a change of standards.
- `vee standards` also lists `REVIEW.md`, `.cursorrules` and configured
  documents (ADR 0028).

### Reviews while you work

- The Claude Code plugin reviews an agent's changes when it finishes a turn:
  its commits since the session started and its uncommitted changes. A
  blocking gate keeps the agent working with the findings, for at most three
  rounds per session; an incomplete review is only reported.
  `VEE_AGENT_REVIEW=off` turns it off
  ([ADR 0021](docs/adr/0021-reviews-at-hand-off-points.md)).
- `vee hooks install`, `uninstall` and `status` manage an optional Git
  `pre-push` hook that reviews the commits a push sends and stops the push
  when the gate blocks. It honours `core.hooksPath` and never replaces
  another tool's hook.
- Claude Code review sessions run with hooks turned off, so a reviewer never
  starts another review.

### Pull requests

- Incremental review after a push on GitHub: Vee's summary comment records
  what each review covered, and the next review sends reviewers only the
  changed files whose change differs. The earlier findings on the others are
  carried over, and the gate still covers the whole change. `vee ci run
  --full`, the Action's `full-review` input and `@vee review` review
  everything ([ADR 0022](docs/adr/0022-incremental-review-after-a-push.md)).
- `vee ci run` posts one summary comment per pull request and edits it after
  each review.
- `@vee fix` in a finding's thread asks the reviewer's model for a fix to the
  finding's file. Vee reviews the fixed head and pushes the fix as one commit
  only when the finding is gone and nothing new blocks, then replies with how
  to revert it ([ADR 0023](docs/adr/0023-fixes-from-pull-request-comments.md)).
  The workflow `vee init --ci github` writes gives the comment job
  `contents: write`.
- `vee ci run --labels` keeps `vee:gate:*` and `vee:risk:*` labels on GitHub
  pull requests. `--approve` approves an eligible head and withdraws Vee's
  approvals that a push or a later review made stale
  ([ADR 0024](docs/adr/0024-approval-and-risk-on-the-pull-request.md)).
- `approval.mode: observe | enforce`. In observe mode, the default, `--approve`
  records Vee's verdict in its summary comment and approves nothing.
  `vee ci approvals --repository OWNER/REPO` compares the verdicts on closed
  GitHub pull requests with what people did, with agreement and override
  rates ([ADR 0025](docs/adr/0025-observe-mode-for-approvals.md)).
- `@vee fix all` fixes up to five open findings in turn. Vee keeps each fix
  the review accepts and pushes the kept fixes together, one commit per
  finding ([ADR 0027](docs/adr/0027-fixing-every-open-finding.md)).
- Approval guards `approval.never_owners`, a new `owners` stage that reads
  `CODEOWNERS` from the base, and `approval.max_per_day`, a limit on Vee's
  approvals in enforce mode
  ([ADR 0026](docs/adr/0026-owner-guards-and-a-daily-limit-for-approvals.md)).

### Fixes

- A failed reviewer's outcome now says why (`detail`, shortened). For the
  Claude Code CLI, that is the reason from its error result, not only its
  exit status.
- The historical benchmark reports a case where no reviewer completed as
  `no_reviewer_completed`, with each reviewer's failure, rather than as a
  context-coverage gap.
- Go and TypeScript language-server queries wait up to 15 seconds each,
  within the 45-second total, so a cold or busy machine does not lose
  semantic references.
- Tests no longer read the developer's own Vee configuration.

## 0.1.0 — 2026-11-25

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
