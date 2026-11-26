# ADR 0033: Jira and Linear work items

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`vee review --work-item` reads an issue from the code host (GitHub, GitLab
or Azure Boards), binds its digest into the review, and `vee gate check`
reads it again. Many teams keep their work in Jira or Linear instead, so the
task-alignment reviewer and acceptance traceability had nothing to read.

## Decision

- **A tracker separate from the code host.** `work_items` in `.vee.yaml`
  names `jira` or `linear`. When it is set, `--work-item` takes an issue
  key such as `PROJ-123`, and `hosting` keeps serving pull requests.
- **The same snapshot.** A tracker issue is a `WorkItemSnapshot`: the key's
  project is the repository, its number the number, and the tracker's host
  the host. Title, description, state, labels and update time are bounded
  and covered by the content digest, so the gate's revalidation, acceptance
  traceability and the task-alignment reviewer work unchanged.
- **Jira.**
  - REST API v2 (`/rest/api/2/issue/KEY`), which answers with plain text
    fields on both Cloud and Data Center.
  - Cloud uses basic auth with `JIRA_EMAIL` and `JIRA_API_TOKEN`; without
    an email, the token is sent as a Data Center personal access token.
  - `acceptance_field` names the custom field that holds acceptance
    criteria. It is kept apart from the description, as Azure Boards'
    field is.
  - An answer for another key, such as a moved issue, is refused.
- **Linear.** GraphQL `issue(id: "KEY")` with `LINEAR_API_KEY`. The answer
  must carry the requested identifier and a `linear.app` URL.
- **Credentials.**
  - Tokens come only from environment variables, and `.vee.yaml` may only
    name allowlisted ones (`JIRA_API_TOKEN`, `JIRA_EMAIL`,
    `LINEAR_API_KEY` or a `VEE_` variable), as for `hosting`.
  - Linear's public API may receive its key.
  - A Jira site is named by the shared repository configuration, and anyone
    can create an Atlassian site, so Vee sends it a token only once the
    person running Vee lists it in `VEE_HOSTING_HOSTS`.
- **Revalidation.** `vee gate check` reads the issue again from the
  recorded endpoint with the tracker's credentials, so a changed or
  unreadable issue stops an earlier decision from passing.

## Consequences

- One tracker per repository; issues from the code host and a tracker
  cannot be mixed in one configuration.
- Jira's description is wiki markup, and its numbered lists (`# item`) look
  like headings to the acceptance parser; bulleted lists and structured
  criteria work.
- Rich-text custom fields that Jira returns as document objects are left
  out; plain-text fields are read.
