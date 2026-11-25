# ADR 0019: Reviews on pull requests run in the team's CI

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Teams expect a reviewer to comment on every pull request without anyone
running it by hand. Hosted reviewers do this with a service that holds the
code and the model key. Vee is local-first: it hosts nothing and keeps code
with the team. It already publishes a saved review to a pull request
(`vee hosting publish`), but running review and publication in CI took
hand-written scripting.

## Decision

`vee ci run` is one shared operation (`vee_application::ci`) that a CI job
runs on the team's own runner with the team's own model key:

1. **Detect** the pull request from the CI environment: GitHub Actions
   (`GITHUB_EVENT_PATH` and related variables, `pull_request` events only)
   or GitLab CI (merge request pipelines only).
2. **Check out the head.** The checkout must be the pull request's head
   commit, not the merge commit CI creates by default, so that the review and
   the published threads describe the commits the pull request shows.
3. **Review** from the pull request's base, with the repository's
   configuration and policy, as `vee review --base` does.
4. **Publish** the check and finding threads with the existing adapters, and
   exit with the gate: 0 pass, 1 block, 2 incomplete.

Rules that follow from running in CI:

- **The pull request is the record.** CI keeps no Vee state between runs.
  What a later run needs, such as which threads Vee owns, is read back from
  the pull request through their fingerprint markers.
- **The CI environment is trusted, the branch is not.** The host and API
  base come from the CI runner's variables, so the hosting token goes to
  them. The repository's `.vee.yaml` cannot redirect it (see the hosting
  credential rule).
- **Runtime files stay out of the diff.** Vee's store under `.vee/` is
  excluded through the checkout's local `.git/info/exclude`, which hides only
  untracked files; committed reviewer instructions and policy still count.
- **A moved base branch is not a stale review.** GitHub reports the base
  branch's tip; a review whose base is the merge base of that tip and the
  head still matches.
- **Agent CLIs are not used in CI.** They need an interactive login. The
  pipeline `vee init --ci` writes configures an API-key provider with
  `vee init --provider <vendor>-api --model <model>` on the runner.

`vee init --ci github|gitlab` writes the pipeline: a GitHub workflow, or a
GitLab file to include. It pins the Vee release that wrote it, and it never
overwrites an existing file.

## Consequences

- One block of CI configuration and one secret give a team reviews on every
  pull request, with code going only to the model the team chose.
- Pull requests from forks get no secrets on GitHub, so the workflow skips
  them.
- An incomplete review, for example after a provider's usage limit, is not
  published (publication requires a complete review); the job fails with
  exit code 2 and the CI log says why.
- GitLab needs a project access token (`GL_TOKEN`) and its bot username,
  because a CI job token cannot post discussions.
- Comment commands and the fix loop (later phases) build on the same
  operation and the same rule that the pull request is the record.
