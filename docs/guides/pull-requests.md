# Reviews on every pull request

Vee can review each pull request in your CI, on your runner, with your model
key, and publish a check and one thread per finding. Nothing is hosted by
Vee, and your code goes only to the model you choose
([ADR 0019](../adr/0019-reviews-on-pull-requests-run-in-the-teams-ci.md)).

## GitHub

1. In a repository with `.vee.yaml` (run `vee init` first), write the
   workflow:

   ```sh
   vee init --ci github --provider anthropic-api --model <model> --effort medium
   ```

   `--provider` is `anthropic-api`, `openai-api` or `gemini-api`; agent CLIs
   need an interactive login, which CI does not have. See
   [best results](best-results.md) for choosing a model and effort.
2. Add the model key as a repository secret, for example
   `ANTHROPIC_API_KEY`.
3. Commit `.github/workflows/vee.yml`. The next pull request gets a "Vee"
   check, and a thread on each finding on a changed line.

The workflow checks out the pull request's head with full history and uses
the Vee action at the release that wrote it. The action installs that
release, checking its checksum, sets up the provider and runs `vee ci run`
with the workflow's own `GITHUB_TOKEN`. Pull requests from forks are skipped,
because GitHub gives them no secrets.

To add Vee to an existing workflow instead, check out the head with full
history and add the action:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
    fetch-depth: 0
- uses: klarlabs-studio/vee@v0.1.0
  with:
    provider: anthropic-api        # or openai-api, gemini-api
    model: <model>
    effort: medium                 # low, medium or high
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    # approval: true               # also publish the approval verdict
```

The job needs `checks: write` and `pull-requests: write` permissions. The
action's outputs are `gate` (`pass`, `block` or `incomplete`) and
`review-id`; it runs on Linux and macOS runners.

## GitLab

1. Write the pipeline file:

   ```sh
   vee init --ci gitlab --provider anthropic-api --model <model>
   ```

2. Include it from `.gitlab-ci.yml`:

   ```yaml
   include:
     - local: .gitlab/vee.gitlab-ci.yml
   ```

3. Add masked CI/CD variables:
   - the model key, for example `ANTHROPIC_API_KEY`;
   - `GL_TOKEN`, a project access token with the `api` scope;
   - `VEE_ACTOR_LOGIN`, the username of that token's bot.

The written file includes Vee's template,
`integrations/gitlab/vee.gitlab-ci.yml`, at the release that wrote it, and
sets its variables (`VEE_VERSION`, `VEE_PROVIDER`, `VEE_MODEL`, `VEE_EFFORT`,
and `VEE_APPROVAL` to also publish the approval verdict). The job runs in
merge request pipelines, in the Vee container image of that release, with
full history, and publishes a commit status and discussions.

## What `vee ci run` does

1. Reads the pull request from the CI environment.
2. Refuses to run unless the checkout is the pull request's head.
3. Reviews from the pull request's base with your `.vee.yaml` and policy.
4. Publishes the check and threads. A finding that moves to another line
   gets a new thread; a fixed finding's thread is resolved.
5. Exits 0 when the gate passes, 1 when it blocks and 2 when the review is
   incomplete, so the job's status is the gate.

Add `--approval` to also publish whether the change may be approved without
a person ([ADR 0015](../adr/0015-layered-approval-eligibility.md)).

## Suggested fixes

When a reviewer is sure of a small fix to the lines a finding points at, it
returns the replacement text with the finding, and the thread shows it as a
suggestion:

- On GitHub and GitLab it is a suggestion block that a person with write
  access can commit from the pull request page. Vee never commits it.
- On Azure DevOps, Bitbucket and Gerrit it is a diff in the comment, to copy
  by hand.

Vee checks a suggestion before posting it, and posts the finding without it
when the check fails. The replaced lines must all be on the new side of one
hunk of the pull request's diff, so they are lines the reviewer saw. The
replacement must change them and stay within 30 lines and 4 KiB. A
suggestion is not part of a finding's identity: a later run that suggests
something else, or nothing, updates the same thread.
