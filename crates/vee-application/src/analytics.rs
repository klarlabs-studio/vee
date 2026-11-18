use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use vee_core::ports::*;
use vee_core::{FindingFeedbackLabel, FindingStatus, GateStatus, Severity, VerificationStatus};

const MAX_DIAGNOSTIC_RUNS: usize = 500;
const MAX_DIAGNOSTIC_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROVIDER_LATENCY_REVIEWS: usize = 500;

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct QualityAnalytics {
    pub schema_version: u32,
    pub review_count: usize,
    /// Latest saved gate decision per review, so re-evaluations do not inflate counts.
    pub latest_gate_decisions: BTreeMap<String, usize>,
    pub reviews_without_gate_decision: usize,
    /// Current unique finding records by lifecycle state.
    pub findings_by_status: BTreeMap<String, usize>,
    pub findings_by_severity: BTreeMap<String, usize>,
    /// Persisted verification runs grouped by profile and terminal result.
    pub verification_runs_by_profile: BTreeMap<String, BTreeMap<String, usize>>,
    /// Deterministically recognized test events in integrity-checked saved logs.
    /// These are observed event counts, not complete CI test-run denominators.
    pub test_diagnostics_by_profile: BTreeMap<String, BTreeMap<String, usize>>,
    pub test_diagnostics_limitations: Vec<String>,
    /// Explicit human feedback labels; these are counts, not quality-rate estimates.
    pub reviewed_feedback_by_label: BTreeMap<String, usize>,
    /// Rates over uniquely reviewed finding/snapshot pairs only. Conflicting
    /// labels are excluded from the denominator and reported as disputed.
    pub reviewed_feedback_metrics: ReviewedFeedbackMetrics,
    /// Adapter wall-clock timing from the latest bounded review history.
    pub provider_latency: BTreeMap<String, ProviderLatency>,
    pub provider_latency_history_complete: bool,
    pub provider_latency_note: String,
    /// Token counts explicitly reported by providers in the same bounded history.
    pub provider_usage: BTreeMap<String, ProviderUsageAnalytics>,
    pub provider_usage_note: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema, Default)]
pub struct ProviderUsageAnalytics {
    pub reported_runs: usize,
    pub unreported_runs: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    /// Sum of estimated input and output costs for runs with explicit usage,
    /// a known model, and a configured rate. Never used by gate policy.
    pub estimated_cost_usd: Option<f64>,
    pub priced_runs: usize,
    pub unpriced_runs: usize,
}

#[derive(Debug, Serialize, schemars::JsonSchema, Default)]
pub struct ProviderLatency {
    pub measured_runs: usize,
    pub unmeasured_runs: usize,
    pub failed_runs: usize,
    pub median_duration_ms: Option<u64>,
    pub p95_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize, schemars::JsonSchema, Default)]
pub struct ReviewedFeedbackMetrics {
    pub finding_accuracy: FeedbackRate,
    pub actionability: FeedbackRate,
}

#[derive(Debug, Serialize, schemars::JsonSchema, Default)]
pub struct FeedbackRate {
    pub positive_occurrences: usize,
    pub negative_occurrences: usize,
    pub disputed_occurrences: usize,
    pub denominator: usize,
    /// Observed fraction among non-disputed labeled occurrences; not a
    /// population estimate and absent when there are no eligible labels.
    pub observed_rate: Option<f64>,
}

pub fn summarize(
    root: &std::path::Path,
    store: &dyn Repositories,
) -> Result<QualityAnalytics, String> {
    let config = crate::load_repository_config(root)?;
    let reviews = store.list_reviews()?;
    let mut latest_gate_decisions = BTreeMap::new();
    let mut reviews_without_gate_decision = 0;
    for review in &reviews {
        if let Some(decision) = store.gate_decisions_for_review(&review.review_id)?.last() {
            *latest_gate_decisions
                .entry(gate_status_name(decision.status).to_owned())
                .or_insert(0) += 1;
        } else {
            reviews_without_gate_decision += 1;
        }
    }

    let findings = store.list_findings(None, None, None)?;
    let mut findings_by_status = BTreeMap::new();
    let mut findings_by_severity = BTreeMap::new();
    for finding in findings {
        *findings_by_status
            .entry(finding_status_name(finding.status).to_owned())
            .or_insert(0) += 1;
        *findings_by_severity
            .entry(severity_name(finding.finding.severity).to_owned())
            .or_insert(0) += 1;
    }

    // Reviews can share a snapshot. Query each snapshot once so persisted
    // verification runs are not counted multiple times.
    let snapshot_ids: BTreeSet<_> = reviews
        .iter()
        .map(|review| review.snapshot_id.as_str())
        .collect();
    let mut verification_runs_by_profile = BTreeMap::new();
    let mut test_diagnostics_by_profile = BTreeMap::new();
    let mut test_diagnostics_limitations = BTreeSet::new();
    let mut diagnostic_run_count = 0usize;
    let mut diagnostic_artifact_bytes = 0u64;
    let mut diagnostics_were_bounded = false;
    for snapshot_id in snapshot_ids {
        for run in store.verifications_for_snapshot(snapshot_id)? {
            let outcomes = verification_runs_by_profile
                .entry(run.profile_id.clone())
                .or_insert_with(|| {
                    BTreeMap::from([
                        ("passed".to_owned(), 0),
                        ("failed".to_owned(), 0),
                        ("timed_out".to_owned(), 0),
                        ("incomplete".to_owned(), 0),
                    ])
                });
            let key = match run.status {
                VerificationStatus::Passed => "passed",
                VerificationStatus::Failed => "failed",
                VerificationStatus::TimedOut => "timed_out",
                VerificationStatus::Incomplete => "incomplete",
            };
            *outcomes.entry(key.to_owned()).or_insert(0) += 1;

            let artifact_bytes = run
                .stdout_artifact
                .iter()
                .chain(run.stderr_artifact.iter())
                .map(|artifact| artifact.size_bytes)
                .sum::<u64>();
            if diagnostic_run_count >= MAX_DIAGNOSTIC_RUNS
                || diagnostic_artifact_bytes.saturating_add(artifact_bytes)
                    > MAX_DIAGNOSTIC_ARTIFACT_BYTES
            {
                diagnostics_were_bounded = true;
                continue;
            }
            diagnostic_run_count += 1;
            diagnostic_artifact_bytes = diagnostic_artifact_bytes.saturating_add(artifact_bytes);
            let diagnosis = crate::verification_diagnosis::diagnose(root, store, &run)?;
            let test_counts = test_diagnostics_by_profile
                .entry(run.profile_id)
                .or_insert_with(|| {
                    BTreeMap::from([
                        ("test_failure".to_owned(), 0),
                        ("test_flaky".to_owned(), 0),
                        ("test_retry_failure".to_owned(), 0),
                    ])
                });
            for diagnostic in diagnosis.diagnostics {
                if matches!(
                    diagnostic.kind.as_str(),
                    "test_failure" | "test_flaky" | "test_retry_failure"
                ) {
                    *test_counts.entry(diagnostic.kind).or_insert(0) += 1;
                }
            }
            for limitation in diagnosis.limitations {
                test_diagnostics_limitations.insert(limitation);
            }
        }
    }
    let mut reviewed_feedback_by_label = BTreeMap::new();
    let mut labels_by_occurrence: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for feedback in store.list_finding_feedback()? {
        let label = feedback_label_name(feedback.label).to_owned();
        *reviewed_feedback_by_label.entry(label.clone()).or_insert(0) += 1;
        labels_by_occurrence
            .entry((feedback.finding_id, feedback.snapshot_id))
            .or_default()
            .insert(label);
    }
    let reviewed_feedback_metrics = feedback_metrics(&labels_by_occurrence);

    let mut provider_latency_history_complete = reviews.len() <= MAX_PROVIDER_LATENCY_REVIEWS;
    let mut provider_samples: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut provider_unmeasured: BTreeMap<String, usize> = BTreeMap::new();
    let mut provider_failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut provider_usage: BTreeMap<String, ProviderUsageAnalytics> = BTreeMap::new();
    for summary in reviews.iter().take(MAX_PROVIDER_LATENCY_REVIEWS) {
        let Some(payload) = store.get(&summary.review_id)? else {
            provider_latency_history_complete = false;
            continue;
        };
        let Ok(review) = crate::deserialize_review_result(&payload) else {
            provider_latency_history_complete = false;
            continue;
        };
        for outcome in review.reviewer_outcomes {
            if outcome.provider_id.is_empty() || outcome.provider_id == "vee" {
                continue;
            }
            if outcome.status == "failed" {
                *provider_failures
                    .entry(outcome.provider_id.clone())
                    .or_default() += 1;
            }
            if let Some(duration_ms) = outcome.duration_ms {
                provider_samples
                    .entry(outcome.provider_id.clone())
                    .or_default()
                    .push(duration_ms);
            } else {
                *provider_unmeasured
                    .entry(outcome.provider_id.clone())
                    .or_default() += 1;
            }
            let metric = provider_usage
                .entry(outcome.provider_id.clone())
                .or_default();
            if let Some(usage) = outcome.usage {
                metric.reported_runs += 1;
                metric.input_tokens = metric
                    .input_tokens
                    .saturating_add(usage.input_tokens.unwrap_or(0));
                metric.output_tokens = metric
                    .output_tokens
                    .saturating_add(usage.output_tokens.unwrap_or(0));
                metric.total_tokens = metric
                    .total_tokens
                    .saturating_add(usage.total_tokens.unwrap_or(0));
                let pricing = config.providers.get(&outcome.provider_id);
                let model = outcome
                    .model
                    .as_deref()
                    .or_else(|| pricing.and_then(|provider| provider.model.as_deref()));
                let rate = pricing
                    .and_then(|provider| model.and_then(|model| provider.pricing.get(model)));
                if let (Some(rate), Some(input), Some(output)) =
                    (rate, usage.input_tokens, usage.output_tokens)
                {
                    let estimate = (input as f64 * rate.input_usd_per_million
                        + output as f64 * rate.output_usd_per_million)
                        / 1_000_000.0;
                    *metric.estimated_cost_usd.get_or_insert(0.0) += estimate;
                    metric.priced_runs += 1;
                } else {
                    metric.unpriced_runs += 1;
                }
            } else {
                metric.unreported_runs += 1;
                metric.unpriced_runs += 1;
            }
        }
    }
    let provider_ids: BTreeSet<_> = provider_samples
        .keys()
        .chain(provider_unmeasured.keys())
        .chain(provider_failures.keys())
        .cloned()
        .collect();
    let provider_latency = provider_ids
        .into_iter()
        .map(|provider_id| {
            let mut samples = provider_samples.remove(&provider_id).unwrap_or_default();
            samples.sort_unstable();
            let percentile = |numerator: usize, denominator: usize| {
                (!samples.is_empty()).then(|| {
                    let rank = samples
                        .len()
                        .saturating_mul(numerator)
                        .div_ceil(denominator)
                        .max(1);
                    samples[rank.saturating_sub(1).min(samples.len() - 1)]
                })
            };
            (
                provider_id.clone(),
                ProviderLatency {
                    measured_runs: samples.len(),
                    unmeasured_runs: provider_unmeasured.remove(&provider_id).unwrap_or(0),
                    failed_runs: provider_failures.remove(&provider_id).unwrap_or(0),
                    median_duration_ms: percentile(50, 100),
                    p95_duration_ms: percentile(95, 100),
                },
            )
        })
        .collect();

    Ok(QualityAnalytics {
        schema_version: 9,
        review_count: reviews.len(),
        latest_gate_decisions,
        reviews_without_gate_decision,
        findings_by_status,
        findings_by_severity,
        verification_runs_by_profile,
        test_diagnostics_by_profile,
        test_diagnostics_limitations: {
            let mut limitations = vec![
                "Test diagnostic totals count recognized events in saved logs for reviewed snapshots; they are not complete CI run denominators or a flaky-test rate.".to_owned(),
                "Repeated verification of the same test or snapshot contributes repeated observed events.".to_owned(),
            ];
            limitations.extend(test_diagnostics_limitations);
            if diagnostics_were_bounded {
                limitations.push(format!(
                    "Test log event aggregation was bounded to {MAX_DIAGNOSTIC_RUNS} runs and {MAX_DIAGNOSTIC_ARTIFACT_BYTES} artifact bytes; some saved runs were not inspected."
                ));
            }
            limitations.sort();
            limitations.dedup();
            limitations
        },
        reviewed_feedback_by_label,
        reviewed_feedback_metrics,
        provider_latency,
        provider_latency_history_complete,
        provider_latency_note: "Wall-clock time spent inside provider adapters, grouped by provider ID over the latest 500 saved reviews. Cached outcomes and outcomes without adapter execution have no measured duration. This is not model compute time, and it excludes review preparation and policy evaluation.".into(),
        provider_usage,
        provider_usage_note: "Token totals include only explicit usage metadata returned by provider adapters in the latest 500 saved reviews. Estimated USD cost is reported only for runs with explicit input/output token counts, a known model, and user-configured non-negative per-million rates in .vee.yaml. Estimates exclude cache-tier pricing, provider discounts, taxes, and other billing adjustments; unreported or unpriced runs are counted separately. Estimates do not affect review gates.".into(),
    })
}

fn feedback_metrics(
    labels_by_occurrence: &BTreeMap<(String, String), BTreeSet<String>>,
) -> ReviewedFeedbackMetrics {
    let mut metrics = ReviewedFeedbackMetrics::default();
    for labels in labels_by_occurrence.values() {
        update_rate(
            &mut metrics.finding_accuracy,
            labels.contains("confirmed"),
            labels.contains("false_positive"),
        );
        update_rate(
            &mut metrics.actionability,
            labels.contains("actionable"),
            labels.contains("not_actionable"),
        );
    }
    for metric in [&mut metrics.finding_accuracy, &mut metrics.actionability] {
        metric.denominator = metric.positive_occurrences + metric.negative_occurrences;
        metric.observed_rate = (metric.denominator > 0)
            .then(|| metric.positive_occurrences as f64 / metric.denominator as f64);
    }
    metrics
}

fn update_rate(metric: &mut FeedbackRate, positive: bool, negative: bool) {
    match (positive, negative) {
        (true, false) => metric.positive_occurrences += 1,
        (false, true) => metric.negative_occurrences += 1,
        (true, true) => metric.disputed_occurrences += 1,
        (false, false) => {}
    }
}

fn feedback_label_name(label: FindingFeedbackLabel) -> &'static str {
    match label {
        FindingFeedbackLabel::Confirmed => "confirmed",
        FindingFeedbackLabel::FalsePositive => "false_positive",
        FindingFeedbackLabel::Actionable => "actionable",
        FindingFeedbackLabel::NotActionable => "not_actionable",
    }
}

fn gate_status_name(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    }
}

fn finding_status_name(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "open",
        FindingStatus::Verified => "verified",
        FindingStatus::Refuted => "refuted",
        FindingStatus::Resolved => "resolved",
        FindingStatus::Waived => "waived",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vee_core::{ActorName, Reason};
    use vee_store_sqlite::ReviewStore;

    #[test]
    fn empty_repository_has_stable_zero_counts() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
        let store = ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        let analytics = summarize(directory.path(), &store).unwrap();
        assert_eq!(analytics.schema_version, 9);
        assert_eq!(analytics.review_count, 0);
        assert!(analytics.latest_gate_decisions.is_empty());
        assert!(analytics.findings_by_status.is_empty());
        assert!(analytics.verification_runs_by_profile.is_empty());
        assert!(analytics.reviewed_feedback_by_label.is_empty());
        assert!(analytics.provider_latency.is_empty());
        assert!(analytics.provider_usage.is_empty());
        assert!(analytics.provider_latency_history_complete);
        assert_eq!(
            analytics
                .reviewed_feedback_metrics
                .finding_accuracy
                .denominator,
            0
        );
        assert_eq!(
            analytics
                .reviewed_feedback_metrics
                .finding_accuracy
                .observed_rate,
            None
        );
    }

    #[test]
    fn only_the_latest_gate_decision_per_review_is_counted() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
        let mut store = ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        store
            .save("review-1", "snapshot-1", "config", "complete", "{}")
            .unwrap();
        for (decision_id, status) in [
            ("decision-1", GateStatus::Pass),
            ("decision-2", GateStatus::Block),
        ] {
            store
                .save_gate_decision(
                    "review-1",
                    &vee_core::GateDecision {
                        schema_version: 1,
                        decision_id: decision_id.into(),
                        snapshot_id: "snapshot-1".into(),
                        effective_config_digest: "config".into(),
                        policy_digest: "policy".into(),
                        status,
                        blocking_findings: Vec::new(),
                        verification_run_ids: Vec::new(),
                        evidence_digest: "evidence".into(),
                        reasons: Vec::new(),
                        replay_inputs: None,
                    },
                )
                .unwrap();
        }
        let analytics = summarize(directory.path(), &store).unwrap();
        assert_eq!(analytics.review_count, 1);
        assert_eq!(analytics.latest_gate_decisions.get("block"), Some(&1));
        assert!(!analytics.latest_gate_decisions.contains_key("pass"));
        assert_eq!(analytics.reviews_without_gate_decision, 0);
    }

    #[test]
    fn provider_latency_uses_persisted_samples_and_excludes_unmeasured_runs() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".vee.yaml"),
            "version: 1\noffline: true\nproviders:\n  local-test-provider:\n    kind: openai_compatible\n    egress: local\n    endpoint: http://127.0.0.1:11434/v1/chat/completions\n    model: pricing-model\n    pricing:\n      pricing-model:\n        input_usd_per_million: 2\n        output_usd_per_million: 10\n",
        )
        .unwrap();
        let mut store = ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        for (id, duration, status) in [
            ("rev-a", Some(100), "completed"),
            ("rev-b", Some(300), "failed"),
            ("rev-c", None, "cached"),
        ] {
            let review = serde_json::json!({
                "schema_version": 2,
                "review_id": id,
                "snapshot_id": format!("snapshot-{id}"),
                "status": "incomplete",
                "findings": [],
                "evidence": [],
                "verification_runs": [],
                "reviewer_outcomes": [{
                    "reviewer_id": "correctness",
                    "provider_id": "local-test-provider",
                    "provider_kind": "cli",
                    "model": "pricing-model",
                    "provider_version": null,
                    "status": status,
                    "duration_ms": duration,
                    "usage": if id == "rev-a" { serde_json::json!({"input_tokens":120,"output_tokens":30,"total_tokens":150}) } else { serde_json::Value::Null }
                }],
                "analysis_complete": false,
                "reasons": [],
                "gate": {
                    "schema_version": 1,
                    "decision_id": format!("decision-{id}"),
                    "snapshot_id": format!("snapshot-{id}"),
                    "effective_config_digest": "config",
                    "policy_digest": "policy",
                    "status": "incomplete",
                    "blocking_findings": [],
                    "verification_run_ids": [],
                    "evidence_digest": "evidence",
                    "reasons": [],
                    "replay_inputs": null
                },
                "change_set": {
                    "schema_version": 1,
                    "base_oid": null,
                    "head_oid": null,
                    "scope": "working_tree",
                    "files": [],
                    "warnings": [],
                    "digest": format!("snapshot-{id}")
                },
                "effective_config_digest": "config",
                "selected_reviewers": ["correctness"],
                "policy_profile": null
            });
            store
                .save_review(
                    id,
                    &format!("snapshot-{id}"),
                    "config",
                    "incomplete",
                    &review.to_string(),
                    &[],
                )
                .unwrap();
        }
        let analytics = summarize(directory.path(), &store).unwrap();
        let metric = &analytics.provider_latency["local-test-provider"];
        assert_eq!(metric.measured_runs, 2);
        assert_eq!(metric.unmeasured_runs, 1);
        assert_eq!(metric.failed_runs, 1);
        assert_eq!(metric.median_duration_ms, Some(100));
        assert_eq!(metric.p95_duration_ms, Some(300));
        let usage = &analytics.provider_usage["local-test-provider"];
        assert_eq!(usage.reported_runs, 1);
        assert_eq!(usage.unreported_runs, 2);
        assert_eq!(usage.input_tokens, 120);
        assert_eq!(usage.output_tokens, 30);
        assert_eq!(usage.total_tokens, 150);
        assert!((usage.estimated_cost_usd.unwrap() - 0.00054).abs() < 1e-12);
        assert_eq!(usage.priced_runs, 1);
        assert_eq!(usage.unpriced_runs, 2);
        assert!(analytics.provider_latency_history_complete);
    }

    #[test]
    fn verification_outcomes_are_grouped_by_profile_and_snapshot_once() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
        let mut store = ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        store
            .save("review-1", "snapshot-1", "config", "complete", "{}")
            .unwrap();
        store
            .save("review-2", "snapshot-1", "config", "complete", "{}")
            .unwrap();
        store
            .save("review-3", "snapshot-2", "config", "complete", "{}")
            .unwrap();
        for (run_id, snapshot_id, profile_id, status) in [
            ("verify-1", "snapshot-1", "unit", VerificationStatus::Passed),
            ("verify-2", "snapshot-1", "unit", VerificationStatus::Failed),
            (
                "verify-3",
                "snapshot-2",
                "integration",
                VerificationStatus::TimedOut,
            ),
            (
                "verify-4",
                "snapshot-2",
                "offline",
                VerificationStatus::Incomplete,
            ),
        ] {
            let stdout_artifact = if run_id == "verify-2" {
                let bytes = b"test parser::rejects_bad_input ... FAILED\n";
                let digest = vee_core::digest(bytes);
                let artifact_path = directory
                    .path()
                    .join(".vee/artifacts/sha256")
                    .join(digest.trim_start_matches("sha256:"));
                std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
                std::fs::write(&artifact_path, bytes).unwrap();
                Some(vee_core::ArtifactReference {
                    digest,
                    path: format!(
                        ".vee/artifacts/sha256/{}",
                        artifact_path.file_name().unwrap().to_string_lossy()
                    ),
                    size_bytes: bytes.len() as u64,
                })
            } else {
                None
            };
            let stdout_digest = stdout_artifact
                .as_ref()
                .map(|artifact| artifact.digest.clone())
                .unwrap_or_else(|| "stdout".to_owned());
            store
                .save_verification(&vee_core::VerificationRun {
                    schema_version: 1,
                    run_id: run_id.into(),
                    snapshot_id: snapshot_id.into(),
                    profile_id: profile_id.into(),
                    finding_id: None,
                    targets: Vec::new(),
                    command_digest: "command".into(),
                    status,
                    exit_code: None,
                    stdout_digest,
                    stderr_digest: "stderr".into(),
                    stdout_artifact,
                    stderr_artifact: None,
                })
                .unwrap();
        }
        let analytics = summarize(directory.path(), &store).unwrap();
        assert_eq!(analytics.schema_version, 9);
        assert_eq!(analytics.verification_runs_by_profile["unit"]["passed"], 1);
        assert_eq!(analytics.verification_runs_by_profile["unit"]["failed"], 1);
        assert_eq!(
            analytics.verification_runs_by_profile["integration"]["timed_out"],
            1
        );
        assert_eq!(
            analytics.verification_runs_by_profile["offline"]["incomplete"],
            1
        );
        assert_eq!(
            analytics.test_diagnostics_by_profile["unit"]["test_failure"],
            1
        );
        assert_eq!(
            analytics.test_diagnostics_by_profile["unit"]["test_flaky"],
            0
        );
        assert!(analytics
            .test_diagnostics_limitations
            .iter()
            .any(|limitation| { limitation.contains("not complete CI run denominators") }));
    }

    #[test]
    fn feedback_rates_use_unique_occurrences_and_exclude_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
        let mut store = ReviewStore::open(&directory.path().join("vee.sqlite")).unwrap();
        for (review_id, snapshot_id, finding_id) in
            [("r1", "s1", "f1"), ("r2", "s1", "f2"), ("r3", "s2", "f3")]
        {
            let finding = vee_core::Finding {
                id: finding_id.into(),
                fingerprint: format!("fingerprint-{finding_id}"),
                category: "correctness".into(),
                severity: Severity::High,
                confidence: Some(90),
                rationale: "fixture".into(),
                path: Some("src/lib.rs".into()),
                line: Some(1),
                provenance: "model_inference".into(),
                reviewer_ids: Vec::new(),
                evidence_ids: Vec::new(),
                rule_attributions: Vec::new(),
            };
            store
                .save_review(
                    review_id,
                    snapshot_id,
                    "config",
                    "complete",
                    "{}",
                    &[finding],
                )
                .unwrap();
        }
        for (finding_id, snapshot_id, label) in [
            ("f1", "s1", FindingFeedbackLabel::Confirmed),
            ("f1", "s1", FindingFeedbackLabel::Actionable),
            ("f2", "s1", FindingFeedbackLabel::FalsePositive),
            ("f2", "s1", FindingFeedbackLabel::NotActionable),
            ("f3", "s2", FindingFeedbackLabel::Confirmed),
            ("f3", "s2", FindingFeedbackLabel::FalsePositive),
            ("f3", "s2", FindingFeedbackLabel::Actionable),
            ("f3", "s2", FindingFeedbackLabel::NotActionable),
        ] {
            store
                .add_finding_feedback(
                    finding_id,
                    snapshot_id,
                    label,
                    &Reason::new("reviewed fixture").unwrap(),
                    &ActorName::new("reviewer", "reviewer").unwrap(),
                )
                .unwrap();
        }
        let analytics = summarize(directory.path(), &store).unwrap();
        let accuracy = &analytics.reviewed_feedback_metrics.finding_accuracy;
        assert_eq!(accuracy.positive_occurrences, 1);
        assert_eq!(accuracy.negative_occurrences, 1);
        assert_eq!(accuracy.disputed_occurrences, 1);
        assert_eq!(accuracy.denominator, 2);
        assert_eq!(accuracy.observed_rate, Some(0.5));
        let actionability = &analytics.reviewed_feedback_metrics.actionability;
        assert_eq!(actionability.positive_occurrences, 1);
        assert_eq!(actionability.negative_occurrences, 1);
        assert_eq!(actionability.disputed_occurrences, 1);
        assert_eq!(actionability.denominator, 2);
        assert_eq!(actionability.observed_rate, Some(0.5));
    }
}
