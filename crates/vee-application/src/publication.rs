//! What Vee writes to a pull request: one check per review, one thread per
//! finding on an added diff line, and resolutions for threads whose findings
//! were resolved since. Shared by `vee hosting publish` and webhook reviews.
//!
//! A ledger of the finding fingerprints Vee has published per pull request
//! makes resolution possible across runs. Publication records a superset first,
//! because a provider can accept a write whose response is lost.

use std::collections::BTreeSet;
use vee_core::ports::{FindingRepository, HostedDeliveryRepository};
use vee_core::{Finding, FindingRecord, FindingStatus, GateDecision, GateStatus, Severity};
use vee_hosting::{
    CheckConclusion, CheckRun, CheckStatus, DiffSide, PullRequestFile, PullRequestRef,
    ReviewThread, ThreadResolution,
};

/// Whether `wanted` is an added line on the new side of a unified diff.
pub fn diff_contains_added_line(patch: Option<&str>, wanted: u32) -> bool {
    let Some(patch) = patch else {
        return false;
    };
    let mut new_line = 0u32;
    let mut in_hunk = false;
    for row in patch.lines() {
        if row.starts_with("@@") {
            let Some(range) = row.split_whitespace().find(|part| part.starts_with('+')) else {
                in_hunk = false;
                continue;
            };
            new_line = range
                .trim_start_matches('+')
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            in_hunk = new_line > 0;
            continue;
        }
        if !in_hunk {
            continue;
        }
        if row.starts_with('+') {
            if new_line == wanted {
                return true;
            }
            new_line = new_line.saturating_add(1);
        } else if row.starts_with(' ') {
            new_line = new_line.saturating_add(1);
        }
    }
    false
}

/// The finding's path and line when it can be a pull request thread at all:
/// informational findings and findings without a location are never posted.
pub fn thread_location(finding: &Finding) -> Option<(&str, u32)> {
    if matches!(finding.severity, Severity::Info) {
        return None;
    }
    Some((finding.path.as_deref()?, finding.line?))
}

/// An open thread for `finding`. `key_prefix` scopes the idempotency key: the
/// review ID for a publish, the delivery digest for a webhook review.
pub fn finding_thread(
    finding: &Finding,
    path: &str,
    line: u32,
    pull_request: &PullRequestRef,
    snapshot_id: &str,
    key_prefix: &str,
) -> ReviewThread {
    ReviewThread {
        pull_request: pull_request.clone(),
        fingerprint: finding.fingerprint.clone(),
        path: path.to_owned(),
        line: u64::from(line),
        side: DiffSide::New,
        body: format!(
            "**{:?} · {}** (confidence: {}%)\n\n{}\n\nVee finding `{}` · snapshot `{}`",
            finding.severity,
            finding.category,
            finding.confidence.unwrap_or(0),
            finding.rationale,
            finding.id,
            snapshot_id
        ),
        resolution: ThreadResolution::Open,
        snapshot_id: snapshot_id.to_owned(),
        idempotency_key: format!("{key_prefix}:{}", finding.fingerprint),
    }
}

/// Threads for the findings on added lines of the provider's changed files.
pub fn build_hosting_threads(
    findings: &[Finding],
    pull_request: &PullRequestRef,
    changed_files: &[PullRequestFile],
    snapshot_id: &str,
    key_prefix: &str,
) -> Vec<ReviewThread> {
    findings
        .iter()
        .filter_map(|finding| {
            let (path, line) = thread_location(finding)?;
            changed_files
                .iter()
                .any(|file| {
                    file.path == path && diff_contains_added_line(file.patch.as_deref(), line)
                })
                .then(|| finding_thread(finding, path, line, pull_request, snapshot_id, key_prefix))
        })
        .collect()
}

/// Resolutions for previously published threads whose findings are now
/// resolved locally and absent from the current review.
pub fn build_resolved_hosting_threads(
    records: &[FindingRecord],
    active_fingerprints: &BTreeSet<String>,
    previously_published_fingerprints: &BTreeSet<String>,
    pull_request: &PullRequestRef,
    review_id: &str,
    snapshot_id: &str,
) -> Vec<ReviewThread> {
    records
        .iter()
        .filter_map(|record| {
            let finding = &record.finding;
            if record.status != FindingStatus::Resolved
                || active_fingerprints.contains(&finding.fingerprint)
                || !previously_published_fingerprints.contains(&finding.fingerprint)
            {
                return None;
            }
            let (path, line) = thread_location(finding)?;
            Some(ReviewThread {
                pull_request: pull_request.clone(),
                fingerprint: finding.fingerprint.clone(),
                path: path.to_owned(),
                line: u64::from(line),
                side: DiffSide::New,
                body: format!(
                    "**Resolved finding**\n\n{}\n\nVee finding `{}` · previously reviewed snapshot `{}`",
                    record.status_reason.as_deref().unwrap_or("Marked resolved locally"),
                    finding.id,
                    snapshot_id
                ),
                resolution: ThreadResolution::Resolved,
                snapshot_id: snapshot_id.to_owned(),
                idempotency_key: format!("{review_id}:{}:resolved", finding.fingerprint),
            })
        })
        .collect()
}

/// The ledger key for one provider's pull request.
pub fn hosting_thread_target_key(
    provider_id: &str,
    pull_request: &PullRequestRef,
) -> Result<String, String> {
    let identity = serde_json::to_string(pull_request).map_err(|error| error.to_string())?;
    Ok(format!("{provider_id}:{identity}"))
}

/// The ledger after a successful publication: open threads are added and
/// resolved ones removed; threads this publication did not mention remain.
pub fn updated_hosted_finding_fingerprints(
    previously_published: &BTreeSet<String>,
    desired_threads: &[ReviewThread],
) -> BTreeSet<String> {
    let mut retained = previously_published.clone();
    for thread in desired_threads {
        match thread.resolution {
            ThreadResolution::Open => {
                retained.insert(thread.fingerprint.clone());
            }
            ThreadResolution::Resolved => {
                retained.remove(&thread.fingerprint);
            }
        }
    }
    retained
}

/// Persist a recoverable superset before publishing. A provider may accept a
/// thread update while its response is lost, so the next run must still know
/// every fingerprint that could exist remotely until publication completes.
pub fn hosting_thread_intent_fingerprints(
    previously_published: &BTreeSet<String>,
    desired_threads: &[ReviewThread],
) -> BTreeSet<String> {
    previously_published
        .iter()
        .cloned()
        .chain(
            desired_threads
                .iter()
                .map(|thread| thread.fingerprint.clone()),
        )
        .collect()
}

/// The completed check that reports `gate` on the pull request. `key` is both
/// the check's external ID and its idempotency key.
pub fn gate_check_run(
    gate: &GateDecision,
    pull_request: &PullRequestRef,
    key: String,
    snapshot_id: &str,
) -> CheckRun {
    let (conclusion, title) = match gate.status {
        GateStatus::Pass => (CheckConclusion::Success, "Vee passed"),
        GateStatus::Block => (CheckConclusion::Failure, "Vee blocked"),
        GateStatus::Incomplete => (CheckConclusion::ActionRequired, "Vee incomplete"),
    };
    let summary = if gate.reasons.is_empty() {
        format!("Gate status: {:?}", gate.status)
    } else {
        gate.reasons
            .iter()
            .map(|reason| format!("- {reason}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    CheckRun {
        pull_request: pull_request.clone(),
        external_id: key.clone(),
        name: "Vee".into(),
        status: CheckStatus::Completed,
        conclusion: Some(conclusion),
        title: title.into(),
        summary,
        snapshot_id: snapshot_id.to_owned(),
        idempotency_key: key,
    }
}

/// The check name of the approval verdict, distinct from the gate's "Vee"
/// check so branch protection can require one without the other.
pub const APPROVAL_CHECK_NAME: &str = "Vee approval";

/// The completed check that reports whether a change may be approved without
/// a human ([ADR 0015](../../../docs/adr/0015-layered-approval-eligibility.md)).
/// Eligible is a success; anything else is neutral, never a failure: a change
/// that needs a person is not a broken change. Every stage is listed, so the
/// reason is visible on the pull request.
pub fn approval_check_run(
    eligibility: &crate::ApprovalEligibility,
    pull_request: &PullRequestRef,
    snapshot_id: &str,
) -> CheckRun {
    let (conclusion, title) = if eligibility.eligible {
        (
            CheckConclusion::Success,
            "Eligible for approval without a human",
        )
    } else {
        (CheckConclusion::Neutral, "Needs a human reviewer")
    };
    let summary = eligibility
        .stages
        .iter()
        .map(|stage| {
            let mark = if stage.passed { "passed" } else { "failed" };
            format!("- {} {mark}: {}", stage.id, stage.detail)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let key = format!("{}:approval", eligibility.review_id);
    CheckRun {
        pull_request: pull_request.clone(),
        external_id: key.clone(),
        name: APPROVAL_CHECK_NAME.into(),
        status: CheckStatus::Completed,
        conclusion: Some(conclusion),
        title: title.into(),
        summary,
        snapshot_id: snapshot_id.to_owned(),
        idempotency_key: key,
    }
}

/// The review a publication reports.
pub struct PublishedReview<'a> {
    pub review_id: &'a str,
    pub snapshot_id: &'a str,
    pub findings: &'a [Finding],
}

/// Publish `threads`, plus resolutions for previously published findings that
/// are now resolved, through `publish`, keeping the ledger recoverable: the
/// intent superset is stored first and the final set only after `publish`
/// succeeds.
pub fn publish_with_thread_ledger<S, T>(
    store: &mut S,
    provider_id: &str,
    pull_request: &PullRequestRef,
    review: &PublishedReview<'_>,
    mut threads: Vec<ReviewThread>,
    publish: impl FnOnce(Vec<ReviewThread>) -> Result<T, String>,
) -> Result<T, String>
where
    S: FindingRepository + HostedDeliveryRepository + ?Sized,
{
    let active_fingerprints = review
        .findings
        .iter()
        .map(|finding| finding.fingerprint.clone())
        .collect();
    let resolved_findings = store.list_findings(None, Some(FindingStatus::Resolved), None)?;
    let target = hosting_thread_target_key(provider_id, pull_request)?;
    let previously_published = store.hosted_finding_threads(&target)?;
    threads.extend(build_resolved_hosting_threads(
        &resolved_findings,
        &active_fingerprints,
        &previously_published,
        pull_request,
        review.review_id,
        review.snapshot_id,
    ));
    let published = updated_hosted_finding_fingerprints(&previously_published, &threads);
    let intent = hosting_thread_intent_fingerprints(&previously_published, &threads);
    store.replace_hosted_finding_threads(&target, &intent)?;
    let receipt = publish(threads)?;
    store.replace_hosted_finding_threads(&target, &published)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vee_hosting::{FileChange, RepositoryRef};

    fn pull_request() -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                full_name: "example/repo".into(),
            },
            number: 12,
        }
    }

    fn finding(id: &str, line: u32, severity: Severity) -> Finding {
        Finding {
            id: id.into(),
            fingerprint: format!("sha256:{id}"),
            category: "correctness".into(),
            severity,
            confidence: Some(90),
            rationale: "A concrete issue".into(),
            path: Some("src/lib.rs".into()),
            line: Some(line),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        }
    }

    fn record(id: &str, status: FindingStatus) -> FindingRecord {
        FindingRecord {
            assessments: Vec::new(),
            finding: finding(id, 10, Severity::High),
            status,
            status_reason: Some("fixed and verified".into()),
            occurrence_count: 1,
            first_seen: "2026-11-14T00:00:00Z".into(),
            last_seen: "2026-11-14T00:00:00Z".into(),
            occurrences: Vec::new(),
        }
    }

    fn thread(fingerprint: &str, resolution: ThreadResolution) -> ReviewThread {
        ReviewThread {
            pull_request: pull_request(),
            fingerprint: fingerprint.into(),
            path: "src/lib.rs".into(),
            line: 10,
            side: DiffSide::New,
            body: "finding".into(),
            resolution,
            snapshot_id: "sha256:snapshot".into(),
            idempotency_key: format!("key:{fingerprint}"),
        }
    }

    #[test]
    fn review_location_must_be_on_an_added_line() {
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -2,2 +2,3 @@\n context\n+added line\n more context\n";
        assert!(diff_contains_added_line(Some(patch), 3));
        let plus_prefixed_addition = "@@ -1,0 +1,1 @@\n+++ valid added source\n";
        assert!(diff_contains_added_line(Some(plus_prefixed_addition), 1));
        assert!(!diff_contains_added_line(Some(patch), 4));
        assert!(!diff_contains_added_line(Some(patch), 2));
        assert!(!diff_contains_added_line(None, 3));
    }

    #[test]
    fn hosting_threads_only_target_findings_on_added_diff_lines() {
        let findings = vec![
            finding("added", 3, Severity::High),
            finding("context", 4, Severity::High),
            finding("informational", 3, Severity::Info),
        ];
        let changed_files = vec![PullRequestFile {
            path: "src/lib.rs".into(),
            change: FileChange::Modified,
            previous_path: None,
            patch: Some("@@ -2,2 +2,3 @@\n context\n+added\n more context\n".into()),
            additions: 1,
            deletions: 0,
        }];

        let threads = build_hosting_threads(
            &findings,
            &pull_request(),
            &changed_files,
            "sha256:snapshot",
            "sha256:delivery",
        );

        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].fingerprint, "sha256:added");
        assert_eq!(threads[0].line, 3);
        assert_eq!(threads[0].side, DiffSide::New);
        assert_eq!(threads[0].snapshot_id, "sha256:snapshot");
        assert_eq!(threads[0].idempotency_key, "sha256:delivery:sha256:added");
        assert!(threads[0]
            .body
            .starts_with("**High · correctness** (confidence: 90%)"));
    }

    #[test]
    fn hosted_finding_ledger_retains_unmentioned_threads_until_resolved() {
        let previous = BTreeSet::from(["sha256:stale".into(), "sha256:resolved".into()]);
        let desired = [
            thread("sha256:new", ThreadResolution::Open),
            thread("sha256:resolved", ThreadResolution::Resolved),
        ];
        assert_eq!(
            updated_hosted_finding_fingerprints(&previous, &desired),
            BTreeSet::from(["sha256:new".into(), "sha256:stale".into()])
        );
        let intent = hosting_thread_intent_fingerprints(&previous, &desired);
        assert_eq!(
            intent,
            BTreeSet::from([
                "sha256:new".into(),
                "sha256:resolved".into(),
                "sha256:stale".into(),
            ]),
            "pending publication must retain prior and all possibly written fingerprints"
        );

        // Model a provider accepting the write while Vee exits before it can
        // store the final publication receipt. The prewritten intent survives
        // restart and still allows the next review to resolve that thread.
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("hosted-threads.sqlite");
        let target = "github:example/repo#12";
        let mut store = vee_store_sqlite::ReviewStore::open(&database).unwrap();
        store
            .replace_hosted_finding_threads(target, &intent)
            .unwrap();
        drop(store);

        let reopened = vee_store_sqlite::ReviewStore::open(&database).unwrap();
        let recovered = reopened.hosted_finding_threads(target).unwrap();
        assert_eq!(recovered, intent);

        let mut recovered_record = record("recovered", FindingStatus::Resolved);
        recovered_record.finding.fingerprint = "sha256:new".into();
        let resolved = build_resolved_hosting_threads(
            &[recovered_record],
            &BTreeSet::new(),
            &recovered,
            &pull_request(),
            "review-after-restart",
            "sha256:next-snapshot",
        );
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].fingerprint, "sha256:new");
        assert_eq!(resolved[0].resolution, ThreadResolution::Resolved);
    }

    #[test]
    fn resolved_hosting_threads_exclude_active_and_non_resolved_findings() {
        let records = vec![
            record("resolved", FindingStatus::Resolved),
            record("active", FindingStatus::Resolved),
            record("refuted", FindingStatus::Refuted),
        ];
        let threads = build_resolved_hosting_threads(
            &records,
            &BTreeSet::from(["sha256:active".to_owned()]),
            &BTreeSet::from(["sha256:resolved".to_owned()]),
            &pull_request(),
            "review-2",
            "sha256:snapshot",
        );
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].fingerprint, "sha256:resolved");
        assert_eq!(threads[0].resolution, ThreadResolution::Resolved);
        assert_eq!(
            threads[0].idempotency_key,
            "review-2:sha256:resolved:resolved"
        );
    }

    #[test]
    fn publication_records_intent_first_and_the_final_ledger_only_on_success() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            vee_store_sqlite::ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        let pull_request = pull_request();
        let target = hosting_thread_target_key("github", &pull_request).unwrap();
        let previous = BTreeSet::from(["sha256:stale".to_owned()]);
        store
            .replace_hosted_finding_threads(&target, &previous)
            .unwrap();
        let findings = [finding("new", 3, Severity::High)];
        let review = PublishedReview {
            review_id: "review-3",
            snapshot_id: "sha256:snapshot",
            findings: &findings,
        };

        let failed: Result<(), String> = publish_with_thread_ledger(
            &mut store,
            "github",
            &pull_request,
            &review,
            vec![thread("sha256:new", ThreadResolution::Open)],
            |_| Err("provider unavailable".into()),
        );
        assert_eq!(failed.unwrap_err(), "provider unavailable");
        assert_eq!(
            store.hosted_finding_threads(&target).unwrap(),
            BTreeSet::from(["sha256:new".to_owned(), "sha256:stale".to_owned()]),
            "a failed publication keeps the intent superset"
        );

        let published = publish_with_thread_ledger(
            &mut store,
            "github",
            &pull_request,
            &review,
            vec![thread("sha256:new", ThreadResolution::Open)],
            |threads| Ok(threads.len()),
        )
        .unwrap();
        assert_eq!(published, 1);
        assert_eq!(
            store.hosted_finding_threads(&target).unwrap(),
            BTreeSet::from(["sha256:new".to_owned(), "sha256:stale".to_owned()])
        );
    }

    #[test]
    fn gate_check_reports_status_and_reasons() {
        let policy = vee_core::Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: Vec::new(),
        };
        let mut gate = vee_core::evaluate_gate(
            "sha256:snapshot",
            "config",
            "policy",
            &[],
            &policy,
            true,
            vee_core::GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        gate.status = GateStatus::Block;
        gate.reasons = vec!["finding f1 blocks".into()];
        let check = gate_check_run(&gate, &pull_request(), "review-4".into(), "sha256:snapshot");
        assert_eq!(check.conclusion, Some(CheckConclusion::Failure));
        assert_eq!(check.title, "Vee blocked");
        assert_eq!(check.summary, "- finding f1 blocks");
        assert_eq!(check.external_id, "review-4");
        assert_eq!(check.idempotency_key, "review-4");

        gate.status = GateStatus::Pass;
        gate.reasons.clear();
        let check = gate_check_run(&gate, &pull_request(), "review-4".into(), "sha256:snapshot");
        assert_eq!(check.title, "Vee passed");
        assert_eq!(check.summary, "Gate status: Pass");
    }

    #[test]
    fn approval_check_is_separate_and_never_fails_a_change_that_needs_a_person() {
        let stage = |id: &str, passed: bool| crate::ApprovalStage {
            id: id.into(),
            passed,
            detail: format!("{id} detail"),
        };
        let mut eligibility = crate::ApprovalEligibility {
            schema_version: 1,
            review_id: "review-4".into(),
            snapshot_id: "sha256:snapshot".into(),
            eligible: true,
            stages: vec![stage("snapshot", true), stage("risk", true)],
        };
        let check = approval_check_run(&eligibility, &pull_request(), "sha256:snapshot");
        assert_eq!(check.name, APPROVAL_CHECK_NAME);
        assert_eq!(check.conclusion, Some(CheckConclusion::Success));
        assert_eq!(check.idempotency_key, "review-4:approval");
        // The gate check's key is the bare review ID.
        assert_ne!(check.idempotency_key, "review-4");

        eligibility.eligible = false;
        eligibility.stages[1].passed = false;
        let check = approval_check_run(&eligibility, &pull_request(), "sha256:snapshot");
        assert_eq!(check.conclusion, Some(CheckConclusion::Neutral));
        assert_eq!(check.title, "Needs a human reviewer");
        assert_eq!(
            check.summary,
            "- snapshot passed: snapshot detail\n- risk failed: risk detail"
        );
    }
}
