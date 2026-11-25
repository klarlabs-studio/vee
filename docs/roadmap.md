# Roadmap: open feature gaps

These are the capabilities that teams compare AI code reviewers on and that
Vee does not yet offer, ranked by their impact on Vee's position. That
position is an open-source, local-first review gate for teams and coding
agents, including regulated and zero-data-retention teams that hosted
reviewers cannot serve.

Effort is rough: **S** is under a week, **M** is one to three weeks, **L**
is longer. Every item fits the shared-operations architecture
([ADR 0001](adr/0001-shared-operations-and-domain-layering.md)): new or
extended operations, adapters or presentation, with no logic specific to
one transport. Check an item off when it ships, and link its ADR or pull
request.

## Ranked gaps

### 1. Turnkey deployment in CI (M)

Teams cannot adopt a gate they cannot install in minutes. Vee installs from
source only, and the hosted lifecycle has not been run on a real host. For
regulated teams, "runs in your own CI runner and sends nothing anywhere"
has to be one block of YAML.

- [ ] Signed release binaries, with Vee's own attestation of the build
- [ ] A multi-stage, non-root container image
- [ ] A GitHub Action and a GitLab CI template that run `vee review --gate`, then `vee hosting publish --approval`
- [ ] A non-interactive CI preset in `vee init` that reads the CI environment
- [ ] A first run of [the GitHub hosted acceptance runbook](acceptance/github-hosted.md)

### 2. Observe mode for approvals (S–M)

Teams will not turn on automatic approval without first seeing what it
would have approved.

- [ ] `approval.mode: observe | enforce`
- [ ] Record each would-have-approved verdict next to the outcome: merged unchanged, changes requested, or reverted
- [ ] Agreement and override rates in `vee analytics`
- [ ] Rate limits on automatic approvals
- [ ] Close the remaining items of [ADR 0015](adr/0015-layered-approval-eligibility.md)

### 3. A PR steward on the user's own agent (M–L)

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

### 4. Commands in PR comments (M)

- [ ] `@vee explain`, `dismiss <reason>`, `waive <expiry>`, `rereview` and `status`
- [ ] Dismissals become finding feedback
- [ ] Waivers only for actors that code ownership permits
- [ ] Comment text stays untrusted and maps only to these operations

### 5. Learn from PR feedback automatically (S–M)

- [ ] Reactions, resolved threads, and fix commits that touch a flagged line become weak labels, kept apart from explicit labels
- [ ] Weak labels shown with their provenance in `vee rules candidates`
- [ ] Rules still need a person's approval, and weak labels never affect the gate
- [ ] Export learned guidance as a pull request to `REVIEW.md` or `AGENTS.md`

### 6. Committable suggestions (S)

- [ ] Publish a validated, single-hunk patch bound to the reviewed snapshot as a host suggestion (GitHub, GitLab)
- [ ] Other hosts get a fenced diff

### 7. Security presets and a regulated policy pack (S)

- [ ] `vee init` detects gitleaks, semgrep, osv-scanner and trivy, and scaffolds trusted verification profiles and a `security` policy profile
- [ ] A "regulated" policy pack: required analyzers, severity floors for protected paths, and automatic approval off
- [ ] Analyzers stay external; Vee does not ship a scanner

### 8. Jira and Linear work items (S–M each)

- [ ] Jira Cloud and Data Center adapters for `--work-item`, acceptance traceability and repository context
- [ ] A Linear adapter
- [ ] Acceptance criteria are mapped, and work items are digest-bound, as the existing connectors do

### 9. A PR walkthrough with measured diagrams (S–M)

- [ ] `vee hosting publish --describe` posts the PR draft and the risk tier
- [ ] A Mermaid graph of the changed files and their impacted consumers and tests, with each edge labelled measured or heuristic
- [ ] Generated text never affects the gate

### 10. Team analytics without a server (M)

- [ ] `vee analytics aggregate` over evidence bundles or analytics exports collected from CI across repositories
- [ ] One static report:
  - gate outcomes;
  - approval override rate;
  - cost;
  - rule effectiveness, with denominators stated.
- [ ] No server, no identity, and no per-person scores

### 11. Natural-language policy conditions (M)

- [ ] A classifier reviewer whose output is a labelled condition, such as "changes the authentication flow" or "adds a migration without a rollback"
- [ ] Conditions only route a change to a person through approval eligibility; they never pass or block the gate
- [ ] The classifier's response, model and digest are recorded, so the decision replays

### 12. A network webhook server, and acceptance on more hosts (M)

- [ ] TLS for `vee webhook-serve` beyond loopback
- [ ] Real-host acceptance runs for GitLab, Azure DevOps and Bitbucket

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
