# ADR 0047: Bitbucket Data Center

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

The Bitbucket adapter speaks the Bitbucket Cloud API (`/2.0/`). Bitbucket
Data Center, and the Server edition before it, is self-hosted and has its
own REST API (`/rest/api/1.0/`): projects instead of workspaces, numeric
comment versions, build statuses instead of commit statuses, and reviewer
status on a participant instead of an approve endpoint. Teams on Data
Center could not use Vee's hosting commands at all.

## Decision

**A separate provider, `bitbucket-data-center`.** It shares nothing with
Cloud's URLs or payloads, so it is its own adapter behind the same ports:
context, publication, review issues, approval and webhooks. A repository
is `PROJECT/repo-slug`.

**An explicit server.** There is no public service to default to. The
provider needs `--host`; the base URL defaults to `https://<host>/` and
can carry a context path (`--api-base https://example.com/bitbucket/`).
HTTPS is required, plain HTTP only on loopback. As for every self-hosted
server, the token goes only to a host named on the command line or in
`VEE_HOSTING_HOSTS`, never to one named only in `.vee.yaml`. The token is
an HTTP access token or personal access token, sent as a bearer token and
read from `BITBUCKET_DC_TOKEN` by default. Requests follow no redirects,
time out after 30 seconds, and each response is capped at 5 MiB, as for
Bitbucket Cloud.

**Endpoints.**

- Context: the pull request, its `changes` (paged, bounded to 3,000
  files) and its raw `.diff` for line-level patches. The revision is the
  base and head commits and the pull request `version`.
- Build status: `POST /rest/api/1.0/projects/{key}/repos/{slug}/commits/{hash}/builds`,
  available since 7.14 on every supported Data Center version. The older
  `/rest/build-status/1.0/commits/{hash}` is deprecated, is not tied to a
  repository and has fewer states, so Vee does not use it. A neutral check
  publishes `UNKNOWN`, never `SUCCESSFUL`.
- Comments: created with an `anchor` (`path`, `line`, `lineType`,
  `fileType`, `diffType: EFFECTIVE`), updated with their `version`, and
  resolved with `threadResolved` (Data Center 8.9 and later). Vee's
  comments are found again through the pull request's `activities`.
- Approval: `PUT …/pull-requests/{id}/participants/{userSlug}` with
  `APPROVED` or `UNAPPROVED`. The approval carries the pull request
  `version` Vee checked the head at, so the server refuses it if the pull
  request changed in between.
- Current user: Data Center has no "current user" resource. Every
  authenticated response names the user in `X-AUSERNAME`; Vee reads it
  from `application-properties` and looks the user's slug up, since a
  slug can differ from the name.
- Webhooks: `X-Event-Key` and `X-Hub-Signature: sha256=…` over the raw
  body, at `/api/webhooks/bitbucket-data-center`. `pr:opened` and
  `pr:from_ref_updated` are reviewed, as is `pr:modified` when the target
  branch changed; other events are acknowledged.

**Idempotent publication.** One build status per check name (`vee`,
`vee-approval`), so a later review replaces the status on the same
commit. One summary comment per check name, marked
`<!-- vee:summary:<key> -->`, and one inline comment per finding, marked
`<!-- vee:fingerprint:<fingerprint> -->`. On republish Vee edits its own
marked comments in place, by the token's user only, and leaves unchanged
comments alone. A resolved finding resolves its thread; a finding that
returns reopens it. Vee never creates a comment only to resolve it.

## Consequences

- Data Center teams get the same flow as Bitbucket Cloud, plus a summary
  comment, since a build status holds only 255 characters.
- Approvals carry no commit between a push and the next publication, as on
  Cloud; the guide asks teams to reset approvals when the source branch
  changes. The approval guards ADR 0041 cannot evaluate still fail closed.
- A finding that moves to another line keeps its comment where it was:
  Data Center cannot move a comment's anchor.
- The markers are HTML comments, as on every other host. Whether Data
  Center hides them or shows them as text has not been checked on a real
  server; that belongs to the real-host acceptance runs.
- Personal repositories (`~USER/repo`) are not supported: `~` is not a
  valid character in Vee's repository identity.
- Bitbucket Server before 7.14 and Data Center before 8.9 are not
  supported: they lack the repository build status or thread resolution.
