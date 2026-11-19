# GitHub hosted acceptance

This runbook verifies Vee's GitHub publication behavior against a real GitHub repository. It is intentionally separate from local fixture tests: a green fixture suite does not prove GitHub App permissions, Checks behavior, review-thread behavior, or provider consistency.

## Safety and prerequisites

- Use a disposable private repository with no production code, secrets, or required branch protections. Do not use the Vee source repository or a customer repository.
- Create a short-lived GitHub App for the test. Install it only on the disposable repository. Grant **Checks: read and write** and **Pull requests: read and write**. Configure a webhook only if the webhook case is being tested.
- Use an installation token in `GH_TOKEN`; do not paste it into commands, shell history, reports, or screenshots. Set `actor_login` to the App bot login in `.vee.yaml`.
- Install the same Vee build being qualified. Keep `.vee/` and the disposable repository's Git history intact until all evidence is recorded.
- The PR must point at a committed local branch whose base and head match GitHub. `vee hosting publish` intentionally rejects dirty or staged-only snapshots.
- Configure a deterministic test reviewer/provider that can produce one finding on a known added line and then report it resolved after the test patch is fixed. Use a synthetic, non-security-sensitive defect. Record the exact review and finding IDs.

Example local configuration (provide the token through the environment, never this file):

```yaml
hosting:
  provider: github
  host: github.com
  token_env: GH_TOKEN
  actor_login: vee-test[bot]
```

## Test sequence

Run from the disposable checkout. Replace the example values with the actual owner, repository, PR number, and saved review ID.

1. **Publish a blocked review.** Create a committed PR change with the synthetic finding on an added line. Run `vee review --base <base-branch> --gate --output json`, capture its `review_id` and `snapshot_id`, then publish it:

   ```sh
   vee hosting publish --provider github --review <review-id> \
     --repository <owner>/<repo> --number <pr-number> \
     --actor-login <app-bot-login> --output json
   ```

   Confirm the PR shows a failed Vee check at the exact head SHA and one Vee-owned inline thread at the added line. Save the returned `provider_check_id`, `thread_ids`, revision, and a redacted screenshot/API record.

2. **Repeat the same publication.** Run the identical command again. It must succeed with the same check ID and fingerprint-to-thread ID mapping. GitHub must still show one Vee check for the Vee idempotency key and one comment for the finding fingerprint; the existing objects should be updated in place, not duplicated.

3. **Resolve the finding.** Fix the synthetic defect in a new commit, rerun the review, and publish the new review. The prior Vee-owned thread must be resolved or updated according to the provider lifecycle contract. Reviewer-authored comments must remain unchanged. Confirm the new check is bound to the new head and the local saved review remains available.

4. **Reject a stale review.** Save a review for one head, then advance the PR head on GitHub before publishing that saved review. Publication must fail with a stale-revision error; it must not create an inline comment on the new head or return a successful receipt. If an already-started request races with a head update, any partial provider writes must be documented and a fresh review must be required.

5. **Check permission diagnostics.** Temporarily remove Checks write permission from the App installation (or use a deliberately under-scoped test App), mint a new installation token, and publish to a separate test PR. The command must fail with a bounded permission diagnostic that identifies the missing permission when GitHub supplies it. The token must not appear in stderr, JSON, logs, or artifacts. Restore permissions and confirm publication works again.

6. **Check local-data independence.** Uninstall the test App or remove its credentials. Confirm `vee reviews list` and `vee reviews show <review-id>` still return the saved local records. No local finding or gate history should be deleted by provider removal.

## Evidence to retain

Record the Vee version and binary digest, GitHub App permission manifest, repository/PR identity, base/head OIDs for each step, review and snapshot IDs, returned check/thread IDs, exact commands with secrets removed, observed provider state, and pass/fail for each sequence item. Keep only synthetic source and redact user identities where practical. Do not record the token or webhook secret.

Acceptance passes only when all six steps pass and the evidence identifies the exact revisions tested. A mocked HTTP fixture, a successful CLI exit alone, or a screenshot without revision and object identity is insufficient. Re-run the matrix after changes to publication, authentication, idempotency, or thread reconciliation.

## Local preflight evidence

Local adapter fixtures cover bounded permission diagnostics, stale-head checks before and after publication, idempotent check/thread updates, recovery after a lost comment response, owned-thread resolution/reopening, and redirect rejection. The redirect regression verifies that a GitHub API `302` is returned as an error rather than followed with the bearer token. These checks guard the local adapter contract; they do not count toward any of the six live-host steps above.
