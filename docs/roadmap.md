# Roadmap: open feature gaps

These are the capabilities that teams compare AI code reviewers on and that
Vee does not yet offer, ranked by their impact on Vee's position. That
position is an open-source, local-first review gate for teams and coding
agents. It runs on the team's own machines and CI runners with the team's
own model keys, so code goes only to the model the team chose; this suits
regulated and zero-data-retention teams in particular.

Effort is rough: **S** is under a week, **M** is one to three weeks, **L**
is longer. Every item fits the shared-operations architecture
([ADR 0001](adr/0001-shared-operations-and-domain-layering.md)): new or
extended operations, adapters or presentation, with no logic specific to
one transport. Check an item off when it ships, and link its ADR or pull
request.

## Ranked gaps

### 1. Turnkey deployment in CI (M)

Teams cannot adopt a gate they cannot install in minutes. Releases now ship
binaries, installers and a container image, but running Vee on pull
requests still takes hand-written CI, and the hosted lifecycle has not been
run on a real host. For regulated teams, "runs in your own CI runner and
sends nothing anywhere" has to be one block of YAML.

- [x] Release binaries with checksums and build provenance, and shell and PowerShell installers ([release](release.md))
- [x] A multi-stage, non-root container image, built from the release binaries
- [x] Signing and verifying releases with a maintainer's SSH key, beyond build provenance (`scripts/release-signature.py`, [ADR 0039](adr/0039-releases-signed-with-a-maintainer-key.md))
- [ ] The first release signed with a key listed in `.github/release-signers`
- [x] macOS binaries signed with a Developer ID and notarized ([ADR 0040](adr/0040-signed-and-notarized-macos-binaries.md))
- [x] A GitHub Action and a GitLab CI template that run `vee ci run` ([guide](guides/pull-requests.md))
- [x] `vee ci run`, which reads the CI environment, and `vee init --ci github|gitlab`, which writes the pipeline ([ADR 0019](adr/0019-reviews-on-pull-requests-run-in-the-teams-ci.md))
- [ ] A first run of [the GitHub hosted acceptance runbook](acceptance/github-hosted.md)

### 1a. Reviews while the work happens (S)

Findings on the pull request arrive after the agent's session has ended.
Reviews at the hand-off points find them while the agent or the author
still has the context.

- [x] An agent Stop hook in the Claude Code plugin that keeps the agent working on blocking findings ([ADR 0021](adr/0021-reviews-at-hand-off-points.md))
- [x] An optional `pre-push` hook (`vee hooks install`)
- [ ] The same Stop hook for Codex, once its hook contract is confirmed
- [x] Review once, reuse in CI: a signed local review of the exact head that CI verifies instead of reviewing again (`vee reviews share`, [ADR 0043](adr/0043-review-once-reuse-in-ci.md))

### 2. Approval and risk visible on the pull request (S)

The gate decision is published as a check, but the approval verdict and the
risk tier are only visible locally or in that check's text.

- [x] Publish an eligible approval as an approving review on GitHub ([ADR 0024](adr/0024-approval-and-risk-on-the-pull-request.md))
- [x] The same on GitLab: labels, and an approval given and withdrawn ([ADR 0030](adr/0030-gitlab-parity.md))
- [x] The same on Bitbucket (an approval), Azure DevOps (a vote) and Gerrit (a label vote), through `vee hosting publish --approval` ([ADR 0041](adr/0041-approval-on-bitbucket-azure-devops-and-gerrit.md))
- [x] Risk-tier and gate labels on GitHub pull requests, so teams can filter and route by them
- [x] Withdraw both when a new push makes the review stale

### 3. Incremental review after a push (M)

Each push is reviewed as a whole change again. Reviewers want only what
changed since the last review, with earlier findings carried over.

- [x] Review only the files whose change differs from the last review, with the whole snapshot readable through Vee's tools ([ADR 0022](adr/0022-incremental-review-after-a-push.md))
- [x] Carry forward findings on unchanged files without asking the model again
- [x] Resolve threads whose finding the new code fixed, and keep the gate over the whole change
- [x] Carry findings on unchanged lines within a file that changed ([ADR 0036](adr/0036-carry-findings-on-unchanged-hunks.md))
- [x] The review record on GitLab merge requests

### 4. Observe mode for approvals (S–M)

Teams will not turn on automatic approval without first seeing what it
would have approved.

- [x] `approval.mode: observe | enforce` ([ADR 0025](adr/0025-observe-mode-for-approvals.md))
- [x] Record each would-have-approved verdict next to the outcome: merged unchanged, changes requested, or closed (`vee ci approvals`)
- [x] Detect merges that were reverted ([ADR 0037](adr/0037-detecting-reverted-merges.md))
- [x] Agreement and override rates, with their denominator (`vee ci approvals`)
- [x] Rate limits on automatic approvals: `approval.max_per_day` ([ADR 0026](adr/0026-owner-guards-and-a-daily-limit-for-approvals.md))
- [ ] Close the remaining items of [ADR 0015](adr/0015-layered-approval-eligibility.md)
- [x] Code ownership in approval: `approval.never_owners` keeps changes to some owners' paths for a person
- [x] Require approval from the owners of touched paths: `approval.require_owner_approval` ([ADR 0034](adr/0034-owner-approval-before-vee-approves.md))

### 5. A PR steward on the user's own agent (M–L)

Fix failing CI, review feedback and simple merge conflicts, with an undo
trail. Most of the parts exist:
- `verification diagnose` for CI output;
- pull request issue intake;
- work packages;
- `propose-patch` and digest-approved `apply-patch`, followed by a new review.

What is missing is the loop.

- [x] A `vee steward` operation, available in the CLI and MCP, that drives the configured agent CLI or local model ([ADR 0042](adr/0042-the-steward.md))
- [x] The gate must pass again after every fix: a fix is kept only when the review is complete, nothing new blocks, no passing verification breaks, and its problem is solved
- [x] `@vee steward` on pull requests: review comments from people with write access, and pushing the kept fixes
- [x] After every push, a comment naming the commit and how to revert it (`@vee fix`, `@vee fix all`: [ADR 0023](adr/0023-fixes-from-pull-request-comments.md), [ADR 0027](adr/0027-fixing-every-open-finding.md))
- [x] Merge conflicts resolved only when the result can be verified; otherwise the change goes back to a person
- [x] Applying a patch stays approved by a person or permitted by policy (`steward.agents`)

### 6. Commands in PR comments (M)

- [x] `@vee explain`, `dismiss <reason>`, `waive <days>d <reason>`, `review` and `status` on GitHub ([ADR 0020](adr/0020-commands-in-pull-request-comments.md))
- [x] Waivers only for actors that code ownership permits, read from the base branch
- [x] Comment text stays untrusted and maps only to these operations
- [x] `@vee fix`: a reviewed fix pushed as one commit, with how to revert it ([ADR 0023](adr/0023-fixes-from-pull-request-comments.md))
- [x] Dismissals become finding feedback in `vee rules candidates`
- [x] Commands on GitLab, through a webhook that starts a pipeline

### 7. Learn from PR feedback automatically (S–M)

- [x] Reactions, resolved threads, and fix commits that touch a flagged line become weak labels, kept apart from explicit labels
- [x] Weak labels shown with their provenance in `vee rules candidates`
- [x] Rules still need a person's approval, and weak labels never affect the gate
- [x] Export learned guidance as a pull request to `REVIEW.md` or `AGENTS.md`
- [x] Retire noisy rules automatically: a rule whose findings are dismissed above a threshold is suspended, with an audit entry and a way to restore it

Weak labels come from dismissals, thumbs-up and thumbs-down, and findings no
longer reported at merge. A thread a person resolved is not yet read, and the
export writes the file for a person to commit rather than opening a pull
request itself ([ADR 0031](adr/0031-learning-from-pull-request-feedback.md)).

### 8. Committable suggestions (S)

- [x] Publish a reviewer's fix, checked against one hunk of the pull request's diff, as a host suggestion (GitHub, GitLab)
- [x] Other hosts get a fenced diff

### 9. Security presets and a regulated policy pack (S)

- [x] `vee init` detects gitleaks, semgrep, osv-scanner and trivy, and scaffolds trusted verification profiles and a `security` policy profile
- [x] A "regulated" policy pack: required analyzers, severity floors for protected paths, and automatic approval off
- [x] Analyzers stay external; Vee does not ship a scanner

`vee init` sets up nox, gitleaks, semgrep and trivy; osv-scanner is detected but
not used, since its SARIF gives no line for a result. The regulated setup is
a `regulated` policy profile, which `vee packs export` shares across
repositories. `vee ci run` runs the scanners a policy requires
([ADR 0029](adr/0029-security-scanner-presets.md)).

### 10. Configurable standards sources (S)

Reviewers read a fixed set of agent instruction files, such as `AGENTS.md`
and `CLAUDE.md`. Teams keep standards elsewhere too.

- [x] Read `REVIEW.md`, `.cursorrules` and `.cursor/rules/`, and paths listed in `.vee.yaml`
- [x] Scope a source to paths, as the existing sources are scoped by directory
- [x] Keep provenance for each standard, as today
- [x] Send the standards to reviewers in every review, from the change's base ([ADR 0028](adr/0028-repository-standards-in-every-review.md))

### 11. Jira and Linear work items (S–M each)

- [x] Jira Cloud and Data Center adapters for `--work-item`, acceptance traceability and repository context ([ADR 0033](adr/0033-jira-and-linear-work-items.md))
- [x] A Linear adapter
- [x] Acceptance criteria are mapped, and work items are digest-bound, as the existing connectors do

### 12. A PR walkthrough with measured diagrams (S–M)

- [x] `vee ci run --describe` (Action input `describe`, GitLab `VEE_DESCRIBE`) adds the PR draft and the risk tier to Vee's summary ([ADR 0032](adr/0032-pull-request-walkthrough.md))
- [x] A Mermaid graph of the changed files and their impacted consumers and tests, with each edge labelled measured or heuristic
- [x] Generated text never affects the gate

### 13. Team analytics without a server (M)

- [x] `vee analytics aggregate` over analytics exports collected across repositories: `vee analytics`, `vee ci approvals` and `vee rules effectiveness` JSON ([ADR 0044](adr/0044-team-analytics-without-a-server.md))
- [x] One static report (`--html`):
  - gate outcomes;
  - approval override rate;
  - cost;
  - rule effectiveness, with denominators stated.
- [x] No server, no identity, and no per-person scores

### 14. Natural-language policy conditions (M)

- [x] A classifier reviewer whose output is a labelled condition, such as "changes the authentication flow" or "adds a migration without a rollback": `approval.conditions` ([ADR 0035](adr/0035-natural-language-approval-conditions.md))
- [x] Conditions only route a change to a person through approval eligibility; they never pass or block the gate
- [x] The classifier's response, model and digest are recorded, so the decision replays

### 15. A network webhook server, and acceptance on more hosts (M)

- [x] TLS for `vee webhook-serve` beyond loopback ([ADR 0038](adr/0038-tls-for-the-webhook-server.md))
- [ ] Real-host acceptance runs for GitLab, Azure DevOps, Bitbucket and Gerrit

### 16. Bitbucket Data Center (M)

- [ ] A Bitbucket Data Center and Server adapter for context, publication and webhooks; the current adapter covers Bitbucket Cloud only

## Review quality

Vee's review quality is measured on a public offline benchmark
([best results](guides/best-results.md)). Open work:

- [ ] Per-reviewer agreement thresholds, so that each reviewer keeps findings at its own measured quorum
- [ ] Security and line-by-line consistency reviewers as shipped defaults, once a fixed configuration is confirmed by a rerun
- [x] A reasoning-effort setting for providers that support one (`providers.<id>.reasoning_effort` for `codex_cli`, `openai_compatible` and `ollama_native`); whether a higher setting improves the benchmark still needs a rerun
- [ ] Group findings from sampled runs by meaning, rather than by nearby lines

## Not planned

- **An IDE extension.** MCP and the agent plugins already reach editors and coding agents.
- **A hosted, cross-repository semantic index.** It conflicts with local-first.
- **SSO and role-based access.** Vee has no server to sign in to.
- **Merge queues and stacked pull requests.** They belong to the host.
