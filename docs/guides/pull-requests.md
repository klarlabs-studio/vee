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

The workflow `vee init --ci github` writes also answers commands in pull
request comments; see [Commands in comments](#commands-in-comments).

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
   - `GL_TOKEN`, a project access token with the `api` and
     `write_repository` scopes. Vee posts as that token's user.

The written file includes Vee's template,
`integrations/gitlab/vee.gitlab-ci.yml`, at the release that wrote it, and
sets its variables:
- `VEE_VERSION`, `VEE_PROVIDER`, `VEE_MODEL` and `VEE_EFFORT`;
- `VEE_APPROVAL`, to also publish the approval verdict;
- `VEE_LABELS` and `VEE_APPROVE`, as on GitHub;
- `VEE_POLICY_PROFILE`.

The job runs in merge request pipelines, in the Vee container image of that
release, with full history. It publishes a commit status, discussions and a
summary note that carries the review record, so later pushes are reviewed
incrementally ([ADR 0030](../adr/0030-gitlab-parity.md)).

### Commands on GitLab

GitLab does not start pipelines for comments, but a webhook can:

1. Create a pipeline trigger token (Settings → CI/CD → Pipeline trigger
   tokens).
2. Add a project webhook for **Comments** events with the URL
   `https://<gitlab>/api/v4/projects/<project id>/ref/<default branch>/trigger/pipeline?token=<trigger token>`.

GitLab then starts the template's `vee-command` job with the comment in
`TRIGGER_PAYLOAD`. Anyone with the trigger token can start such a pipeline,
so Vee takes only the comment's IDs from the payload and reads the comment,
its author and its text back from the API before acting. `@vee fix` pushes
to the merge request's branch with `GL_TOKEN`.

## What `vee ci run` does

1. Reads the pull request from the CI environment.
2. Refuses to run unless the checkout is the pull request's head.
3. Runs the verification profiles the policy requires, such as security
   scanners, on the change. Install those tools on the runner first; a
   profile that cannot run leaves the review incomplete.
4. Reviews from the pull request's base with your `.vee.yaml` and policy.
5. Publishes the check and threads. A finding that moves to another line
   gets a new thread; a fixed finding's thread is resolved.
6. Posts a summary comment, or edits the one it posted before.
7. Exits 0 when the gate passes, 1 when it blocks and 2 when the review is
   incomplete, so the job's status is the gate.

On GitHub and GitLab, a later push is reviewed incrementally
([ADR 0022](../adr/0022-incremental-review-after-a-push.md)). The summary
comment records what the last review covered. A changed file whose change is
the same as then is not sent to reviewers again, and its findings are
carried over. In a file the push changed, each hunk that is the same as
before keeps its findings, moved to where the hunk is now, and reviewers are
pointed at the other changed lines
([ADR 0036](../adr/0036-carry-findings-on-unchanged-hunks.md)). The gate
still covers the whole change. A changed `.vee.yaml`,
reviewer instructions or provider version makes the next review a full one,
as does `--full`, `full-review: true` in the Action, or an `@vee review`
comment.

Add `--approval` to also publish whether the change may be approved without
a person ([ADR 0015](../adr/0015-layered-approval-eligibility.md)).

Add `--describe` (Action input `describe`, GitLab `VEE_DESCRIBE`) to add a
walkthrough to Vee's summary comment
([ADR 0032](../adr/0032-pull-request-walkthrough.md)):
- the change's risk tier and the factors that raised it;
- a Mermaid graph from impact analysis of what the changed files reach.
  Solid edges were measured by parsing or a language server; dotted edges
  are heuristic, from name matches, packages or history;
- a description drafted by the first reviewer's model, folded away and
  marked as unverified. This is one more model call per review.

The walkthrough never affects the gate. When the summary would exceed the
host's comment limit, the description is dropped first, then the graph.

Add `--policy-profile NAME` (Action input `policy-profile`) to gate with a
policy profile, such as the `security` and `regulated` profiles `vee init`
writes when it finds security scanners
([ADR 0029](../adr/0029-security-scanner-presets.md)). Under a policy with
`automatic_approval: false`, every change needs a person's approval.

On GitHub and GitLab, two more flags put Vee's verdict where the host's own tools use
it ([ADR 0024](../adr/0024-approval-and-risk-on-the-pull-request.md)). Both
have matching Action inputs, `labels` and `approve`.

- `--labels` keeps a `vee:gate:pass|block|incomplete` label and a
  `vee:risk:low|elevated|high` label on the pull request.
- `--approve` decides on every review whether the head is eligible for
  approval without a person, and records the verdict in Vee's summary
  comment.
  - With `approval.mode: observe`, the default, Vee approves nothing.
  - With `approval.mode: enforce`, Vee approves an eligible head. It
    withdraws its approval when a push or a later review makes it stale.
    For this to work, allow GitHub Actions to approve pull requests in the
    repository's Actions settings; branch protection decides whether the
    approval counts.

Two more guards apply ([ADR 0026](../adr/0026-owner-guards-and-a-daily-limit-for-approvals.md)):

- `approval.never_owners: ["@acme/security"]` keeps every change to code
  those owners own, per `CODEOWNERS` on the base, for a person.
- `approval.max_per_day: 10` caps Vee's approvals in any 24 hours in enforce
  mode. Past the limit, an eligible head is left to a person.

With `approval.require_owner_approval: true`, Vee approves only once a code
owner has approved each changed file that has one
([ADR 0034](../adr/0034-owner-approval-before-vee-approves.md)). Vee's
approval then adds to the owners' approval and never replaces it.

- Owners come from `CODEOWNERS` on the base, so a change cannot edit its
  own owners.
- An `@user` owner counts when that person's latest review approves the
  current head.
- An `@org/team` owner counts when such an approver is a member of the
  team.
- Email owners cannot be matched to an approval, so their files always wait
  for a person.
- Bots and Vee's own approvals don't count. A push makes every earlier
  approval stale.

On GitHub, add `pull_request_review` to the workflow's triggers, so Vee
looks again when an owner approves. A re-run whose files haven't changed
carries the earlier findings and makes no model calls:

```yaml
on:
  pull_request:
  pull_request_review:
    types: [submitted, dismissed]
```

GitLab doesn't start a pipeline when someone approves; write `@vee review`
or re-run the pipeline.

`approval.conditions` sends a change to a person when a reviewer's model says
it does something you name
([ADR 0035](../adr/0035-natural-language-approval-conditions.md)):

```yaml
approval:
  conditions:
    - { id: auth_flow, when: changes the authentication flow }
    - { id: migration_without_rollback, when: adds a database migration without a rollback }
  condition_reviewer: correctness   # optional; the review's first reviewer by default
```

- **How it's checked.** `vee ci run --approve` asks the model once per
  change, stores the answer with the model and a digest of its output, and
  adds a `conditions` stage to the approval verdict. A condition that holds,
  or a missing answer, means a person approves.
- **Replay.** The answer is kept in Vee's record on the pull request, so a
  later run on the same head reads it instead of asking again. Rewording a
  condition asks again.
- **Locally.** `vee gate conditions --review ID` classifies a saved review,
  or shows the stored answer, and exits 1 when a condition holds.
- **Never the gate.** Conditions never pass or block the gate.
- **Not a security boundary.** The model reads the change, and a change can
  try to talk it out of a condition. Use `never_paths` and `never_owners`
  for what must always reach a person; conditions catch what paths can't
  name. `vee gate approval` outside CI cannot see the pull
request, so it reports owner approval as not yet checked.

Before switching to `enforce`, see how Vee's verdicts compared with what
people did ([ADR 0025](../adr/0025-observe-mode-for-approvals.md)):

```sh
GH_TOKEN=... vee ci approvals --repository OWNER/REPO
```

It reads the latest 100 closed pull requests and counts those with a head
Vee called eligible:

- merged at that head (agreement);
- merged at that head and reverted later;
- changed afterwards;
- sent back by a person;
- closed without merging.

Reverts are found in merged revert pull requests, the kind the hosts'
Revert buttons open, and in `git revert` commits on the checked-out branch
when you run it in a clone. Use a full clone (`fetch-depth: 0`) in CI so
the history is there
([ADR 0037](../adr/0037-detecting-reverted-merges.md)).

## Commands in comments

On GitHub, people with write access can talk to Vee in a pull request's
comments ([ADR 0020](../adr/0020-commands-in-pull-request-comments.md)).
Write the command on its own line:

| Command | What Vee does |
|---|---|
| `@vee review` | Reviews the pull request's head again and publishes the result. |
| `@vee status` | Replies with its findings on the pull request and the waivers and dismissals in effect. |
| `@vee explain` | Replies in the finding's thread with an explanation from the configured model. |
| `@vee fix all` | Fixes up to five open findings in turn, keeps each fix the review accepts, and pushes the kept fixes together ([ADR 0027](../adr/0027-fixing-every-open-finding.md)). |
| `@vee fix` | Asks the configured model for a fix to the finding's file, reviews the result, and pushes it as one commit only if the finding is gone and nothing new blocks ([ADR 0023](../adr/0023-fixes-from-pull-request-comments.md)). |
| `@vee dismiss <reason>` | Records the finding as a false positive and resolves its thread. A finding that blocks keeps blocking. |
| `@vee waive <days>d <reason>` | Waives the finding on the current head, for 1 to 90 days, and reviews again so the check shows the new verdict. |
| `@vee help` | Lists the commands. |

Write `explain`, `fix`, `dismiss` and `waive` as a reply in the finding's thread, or
name the finding anywhere: `@vee waive find_0123456789ab 7d accepted for the
hotfix`.

What Vee checks:

- **Write access.** Vee asks GitHub for the commenter's access to the
  repository each time. Comments from bots are ignored.
- **Code ownership for waivers.** When `CODEOWNERS` on the base branch
  assigns the finding's file, only those owners can waive it. To accept team
  owners, give the action a `github-token` that can read the organization's
  teams; the workflow's own token cannot, so Vee treats team owners as
  unconfirmed and refuses.
- **No forks for `review`, `explain`, `fix` and `waive`.** These load the
  repository's configuration, which names programs Vee runs, so Vee refuses
  them on pull requests from forks. It fetches the head itself, after these
  checks.
- **The comment is data.** It selects one of these commands, and no part of
  it reaches the model.

A waiver applies to the head it was given on, like `vee waivers create`: a
new push needs a new waiver. Every later run reads the pull request again
and applies a dismissal or waiver only if its command is unedited and its
author still has the access it needs, so Vee's own replies grant nothing by
themselves.

On GitLab, commands run in a pipeline a Comments webhook triggers; see
[Commands on GitLab](#commands-on-gitlab).

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
