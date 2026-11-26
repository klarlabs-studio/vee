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
- [ ] Release binaries signed with a maintainer key, beyond build provenance
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
- [ ] Review once, reuse in CI: a signed local review of the exact head that CI verifies instead of reviewing again

### 2. Approval and risk visible on the pull request (S)

The gate decision is published as a check, but the approval verdict and the
risk tier are only visible locally or in that check's text.

- [ ] Publish an eligible approval as the host's own approval: an approving review on GitHub, an approval on GitLab and Bitbucket, a vote on Azure DevOps, a label vote on Gerrit
- [ ] Risk-tier and gate labels on the pull request, so teams can filter and route by them
- [ ] Withdraw both when a new push makes the review stale

### 3. Incremental review after a push (M)

Each push is reviewed as a whole change again. Reviewers want only what
changed since the last review, with earlier findings carried over.

- [x] Review only the files whose change differs from the last review, with the whole snapshot readable through Vee's tools ([ADR 0022](adr/0022-incremental-review-after-a-push.md))
- [x] Carry forward findings on unchanged files without asking the model again
- [x] Resolve threads whose finding the new code fixed, and keep the gate over the whole change
- [ ] Carry findings on unchanged lines within a file that changed
- [ ] The review record on GitLab merge requests

### 4. Observe mode for approvals (S–M)

Teams will not turn on automatic approval without first seeing what it
would have approved.

- [ ] `approval.mode: observe | enforce`
- [ ] Record each would-have-approved verdict next to the outcome: merged unchanged, changes requested, or reverted
- [ ] Agreement and override rates in `vee analytics`
- [ ] Rate limits on automatic approvals
- [ ] Close the remaining items of [ADR 0015](adr/0015-layered-approval-eligibility.md)
- [ ] Code ownership in approval: require the owners of touched paths, or keep changes to some owners' paths for a person

### 5. A PR steward on the user's own agent (M–L)

Fix failing CI, review feedback and simple merge conflicts, with an undo
trail. Most of the parts exist:
- `verification diagnose` for CI output;
- pull request issue intake;
- work packages;
- `propose-patch` and digest-approved `apply-patch`, followed by a new review.

What is missing is the loop.

- [ ] A `vee steward` operation, available in the CLI and MCP, that drives the configured agent CLI or local model
- [ ] The gate must pass again after every fix
- [ ] After every push, a comment naming the commit and how to revert it
- [ ] Merge conflicts resolved only when the result can be verified; otherwise the change goes back to a person
- [ ] Applying a patch stays approved by a person or permitted by policy

### 6. Commands in PR comments (M)

- [x] `@vee explain`, `dismiss <reason>`, `waive <days>d <reason>`, `review` and `status` on GitHub ([ADR 0020](adr/0020-commands-in-pull-request-comments.md))
- [x] Waivers only for actors that code ownership permits, read from the base branch
- [x] Comment text stays untrusted and maps only to these operations
- [ ] Dismissals become finding feedback in `vee rules candidates`
- [ ] Commands on GitLab, through a webhook that starts a pipeline

### 7. Learn from PR feedback automatically (S–M)

- [ ] Reactions, resolved threads, and fix commits that touch a flagged line become weak labels, kept apart from explicit labels
- [ ] Weak labels shown with their provenance in `vee rules candidates`
- [ ] Rules still need a person's approval, and weak labels never affect the gate
- [ ] Export learned guidance as a pull request to `REVIEW.md` or `AGENTS.md`
- [ ] Retire noisy rules automatically: a rule whose findings are dismissed above a threshold is suspended, with an audit entry and a way to restore it

### 8. Committable suggestions (S)

- [x] Publish a reviewer's fix, checked against one hunk of the pull request's diff, as a host suggestion (GitHub, GitLab)
- [x] Other hosts get a fenced diff

### 9. Security presets and a regulated policy pack (S)

- [ ] `vee init` detects gitleaks, semgrep, osv-scanner and trivy, and scaffolds trusted verification profiles and a `security` policy profile
- [ ] A "regulated" policy pack: required analyzers, severity floors for protected paths, and automatic approval off
- [ ] Analyzers stay external; Vee does not ship a scanner

### 10. Configurable standards sources (S)

Reviewers read a fixed set of agent instruction files, such as `AGENTS.md`
and `CLAUDE.md`. Teams keep standards elsewhere too.

- [ ] Read `REVIEW.md`, `.cursorrules` and `.cursor/rules/`, and paths listed in `.vee.yaml`
- [ ] Scope a source to paths, as the existing sources are scoped by directory
- [ ] Keep provenance for each standard, as today

### 11. Jira and Linear work items (S–M each)

- [ ] Jira Cloud and Data Center adapters for `--work-item`, acceptance traceability and repository context
- [ ] A Linear adapter
- [ ] Acceptance criteria are mapped, and work items are digest-bound, as the existing connectors do

### 12. A PR walkthrough with measured diagrams (S–M)

- [ ] `vee hosting publish --describe` posts the PR draft and the risk tier
- [ ] A Mermaid graph of the changed files and their impacted consumers and tests, with each edge labelled measured or heuristic
- [ ] Generated text never affects the gate

### 13. Team analytics without a server (M)

- [ ] `vee analytics aggregate` over evidence bundles or analytics exports collected from CI across repositories
- [ ] One static report:
  - gate outcomes;
  - approval override rate;
  - cost;
  - rule effectiveness, with denominators stated.
- [ ] No server, no identity, and no per-person scores

### 14. Natural-language policy conditions (M)

- [ ] A classifier reviewer whose output is a labelled condition, such as "changes the authentication flow" or "adds a migration without a rollback"
- [ ] Conditions only route a change to a person through approval eligibility; they never pass or block the gate
- [ ] The classifier's response, model and digest are recorded, so the decision replays

### 15. A network webhook server, and acceptance on more hosts (M)

- [ ] TLS for `vee webhook-serve` beyond loopback
- [ ] Real-host acceptance runs for GitLab, Azure DevOps, Bitbucket and Gerrit

### 16. Bitbucket Data Center (M)

- [ ] A Bitbucket Data Center and Server adapter for context, publication and webhooks; the current adapter covers Bitbucket Cloud only

## Review quality

Vee's review quality is measured on a public offline benchmark
([best results](guides/best-results.md)). Open work:

- [ ] Per-reviewer agreement thresholds, so that each reviewer keeps findings at its own measured quorum
- [ ] Security and line-by-line consistency reviewers as shipped defaults, once a fixed configuration is confirmed by a rerun
- [ ] A reasoning-effort setting for providers that support one
- [ ] Group findings from sampled runs by meaning, rather than by nearby lines

## Not planned

- **An IDE extension.** MCP and the agent plugins already reach editors and coding agents.
- **A hosted, cross-repository semantic index.** It conflicts with local-first.
- **SSO and role-based access.** Vee has no server to sign in to.
- **Merge queues and stacked pull requests.** They belong to the host.
