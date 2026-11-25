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

The workflow checks out the pull request's head with full history, installs
the Vee release that wrote it, and runs `vee ci run` with the workflow's own
`GITHUB_TOKEN`. Pull requests from forks are skipped, because GitHub gives
them no secrets.

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

The job runs in merge request pipelines, in the Vee container image, with
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
