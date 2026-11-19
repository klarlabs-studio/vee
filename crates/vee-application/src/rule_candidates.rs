use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use vee_core::{FindingFeedback, FindingFeedbackLabel, FindingRecord};

const MIN_DISTINCT_FINDINGS: usize = 3;
const MAX_EXAMPLES_PER_CANDIDATE: usize = 5;
const MAX_REASON_CHARS: usize = 500;

#[derive(Clone, Debug, Serialize)]
pub struct CandidateReport {
    pub schema_version: u32,
    pub candidates: Vec<RuleCandidate>,
    pub disputed_findings_excluded: usize,
    pub disputed_external_comments_excluded: usize,
    pub feedback_without_saved_finding: usize,
    pub truncated: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleCandidate {
    pub candidate_id: String,
    pub source_kind: String,
    pub category: String,
    pub feedback_label: FindingFeedbackLabel,
    /// Number of distinct finding fingerprints supporting this suggestion.
    pub feedback_count: usize,
    pub feedback_event_count: usize,
    pub evidence_digest: String,
    #[serde(skip_serializing)]
    pub feedback_ids: Vec<String>,
    pub suggestion: String,
    pub feedback: Vec<FeedbackExample>,
    pub approval_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct FeedbackExample {
    pub source_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_comment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<vee_hosting::PullRequestRef>,
    pub snapshot_id: String,
    pub reviewer: String,
    pub reason: String,
}

pub fn mine(
    records: &[FindingRecord],
    feedback: &[FindingFeedback],
    truncated: bool,
) -> CandidateReport {
    let finding_by_id = records
        .iter()
        .map(|record| (record.finding.id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut feedback_by_fingerprint = BTreeMap::<String, Vec<&FindingFeedback>>::new();
    let mut feedback_without_saved_finding = 0;
    for item in feedback {
        let Some(record) = finding_by_id.get(item.finding_id.as_str()) else {
            if !truncated {
                feedback_without_saved_finding += 1;
            }
            continue;
        };
        feedback_by_fingerprint
            .entry(record.finding.fingerprint.clone())
            .or_default()
            .push(item);
    }

    let mut disputed = BTreeSet::new();
    for (fingerprint, items) in &feedback_by_fingerprint {
        let labels = items.iter().map(|item| item.label).collect::<BTreeSet<_>>();
        if labels.contains(&FindingFeedbackLabel::Confirmed)
            && labels.contains(&FindingFeedbackLabel::FalsePositive)
            || labels.contains(&FindingFeedbackLabel::Actionable)
                && labels.contains(&FindingFeedbackLabel::NotActionable)
        {
            disputed.insert(fingerprint.clone());
        }
    }

    let mut groups =
        BTreeMap::<(String, FindingFeedbackLabel), Vec<(&FindingRecord, &FindingFeedback)>>::new();
    for (fingerprint, items) in &feedback_by_fingerprint {
        if disputed.contains(fingerprint) {
            continue;
        }
        let Some(record) = items
            .first()
            .and_then(|item| finding_by_id.get(item.finding_id.as_str()).copied())
        else {
            continue;
        };
        let category_key = normalize_category(&record.finding.category);
        if category_key.is_empty() {
            continue;
        }
        for item in items {
            if matches!(
                item.label,
                FindingFeedbackLabel::FalsePositive | FindingFeedbackLabel::NotActionable
            ) && !item.reason.trim().is_empty()
            {
                groups
                    .entry((category_key.clone(), item.label))
                    .or_default()
                    .push((record, item));
            }
        }
    }

    let candidates = groups
        .into_iter()
        .filter_map(|((category_key, label), mut evidence)| {
            evidence.sort_by(|(left_record, left_feedback), (right_record, right_feedback)| {
                left_record
                    .finding
                    .fingerprint
                    .cmp(&right_record.finding.fingerprint)
                    .then_with(|| left_feedback.feedback_id.cmp(&right_feedback.feedback_id))
            });
            let distinct = evidence
                .iter()
                .map(|(record, _)| record.finding.fingerprint.as_str())
                .collect::<BTreeSet<_>>();
            if distinct.len() < MIN_DISTINCT_FINDINGS {
                return None;
            }
            let category = evidence[0].0.finding.category.trim().to_owned();
            let mut identity = category_key.as_bytes().to_vec();
            identity.extend_from_slice(feedback_label_key(label).as_bytes());
            identity.push(0);
            for fingerprint in &distinct {
                identity.extend_from_slice(fingerprint.as_bytes());
                identity.push(0);
            }
            let digest = Sha256::digest(identity);
            let candidate_id = format!("rule-candidate:{}", hex_prefix(&digest, 16));
            let mut evidence_identity = Vec::new();
            for (_, item) in &evidence {
                evidence_identity.extend_from_slice(item.feedback_id.as_bytes());
                evidence_identity.push(0);
            }
            let evidence_digest = vee_core::digest(&evidence_identity);
            let feedback_ids = evidence.iter().map(|(_, item)| item.feedback_id.clone()).collect::<Vec<_>>();
            let examples = evidence
                .iter()
                .take(MAX_EXAMPLES_PER_CANDIDATE)
                .map(|(record, item)| FeedbackExample {
                    source_kind: "finding_feedback".into(),
                    finding_id: Some(record.finding.id.clone()),
                    external_comment_id: None,
                    archive_digest: None,
                    provider: None,
                    pull_request: None,
                    snapshot_id: item.snapshot_id.clone(),
                    reviewer: item.reviewer.clone(),
                    reason: truncate(&item.reason, MAX_REASON_CHARS),
                })
                .collect();
            let suggestion = match label {
                FindingFeedbackLabel::FalsePositive => format!(
                    "Review the repeated false-positive feedback in category '{}'. If the evidence supports it, propose a narrowly scoped rule that prevents this specific pattern from recurring; do not suppress the whole category.",
                    category
                ),
                FindingFeedbackLabel::NotActionable => format!(
                    "Review why findings in category '{}' were marked not actionable. Consider improving reviewer instructions, evidence requirements, or message quality; do not suppress findings solely on this basis.",
                    category
                ),
                FindingFeedbackLabel::Confirmed | FindingFeedbackLabel::Actionable => return None,
            };
            Some(RuleCandidate {
                candidate_id,
                source_kind: "finding_feedback".into(),
                category,
                feedback_label: label,
                feedback_count: distinct.len(),
                feedback_event_count: evidence.len(),
                evidence_digest,
                feedback_ids,
                suggestion,
                feedback: examples,
                approval_status: "requires_human_review",
            })
        })
        .collect();

    CandidateReport {
        schema_version: 3,
        candidates,
        disputed_findings_excluded: disputed.len(),
        disputed_external_comments_excluded: 0,
        feedback_without_saved_finding,
        truncated,
        limitations: vec![
            "Candidates use explicit human feedback labels tied to a finding and snapshot; feedback is attributed but reviewer identity is not authenticated.".into(),
            "Contradictory labels for the same finding fingerprint are excluded and counted as disputed.".into(),
            "Only false_positive and not_actionable labels are considered; waived lifecycle state is not treated as a false-positive label.".into(),
            "At least three distinct finding fingerprints must support a candidate. Suggestions never modify reviewer instructions or policy and require human approval.".into(),
            "Candidate mining reads at most 10,000 saved findings per invocation; truncated runs do not label unmatched feedback as orphaned.".into(),
        ],
    }
}

pub fn mine_with_external(
    records: &[FindingRecord],
    feedback: &[FindingFeedback],
    external_feedback: &[super::imported_history::ExternalReviewFeedback],
    truncated: bool,
) -> CandidateReport {
    let mut report = mine(records, feedback, truncated);
    let mut by_comment =
        BTreeMap::<String, Vec<&super::imported_history::ExternalReviewFeedback>>::new();
    for item in external_feedback {
        let identity = external_comment_identity(item);
        by_comment.entry(identity).or_default().push(item);
    }
    let mut disputed = BTreeSet::new();
    for (identity, items) in &by_comment {
        let labels = items.iter().map(|item| item.label).collect::<BTreeSet<_>>();
        if labels.contains(&FindingFeedbackLabel::Confirmed)
            && labels.contains(&FindingFeedbackLabel::FalsePositive)
            || labels.contains(&FindingFeedbackLabel::Actionable)
                && labels.contains(&FindingFeedbackLabel::NotActionable)
        {
            disputed.insert(identity.clone());
        }
    }
    let mut groups = BTreeMap::<
        (String, FindingFeedbackLabel),
        Vec<&super::imported_history::ExternalReviewFeedback>,
    >::new();
    for (identity, items) in &by_comment {
        if disputed.contains(identity) {
            continue;
        }
        for item in items {
            if matches!(
                item.label,
                FindingFeedbackLabel::FalsePositive | FindingFeedbackLabel::NotActionable
            ) && !item.reason.trim().is_empty()
            {
                groups
                    .entry((normalize_category(&item.category), item.label))
                    .or_default()
                    .push(item);
            }
        }
    }
    for ((category_key, label), mut evidence) in groups {
        evidence.sort_by(|left, right| left.feedback_id.cmp(&right.feedback_id));
        let distinct = evidence
            .iter()
            .map(|item| external_comment_identity(item))
            .collect::<BTreeSet<_>>();
        if category_key.is_empty() || distinct.len() < MIN_DISTINCT_FINDINGS {
            continue;
        }
        let category = evidence[0].category.trim().to_owned();
        let mut identity = b"provider_discussion\0".to_vec();
        identity.extend_from_slice(category_key.as_bytes());
        identity.extend_from_slice(feedback_label_key(label).as_bytes());
        for id in &distinct {
            identity.extend_from_slice(id.as_bytes());
            identity.push(0);
        }
        let digest = Sha256::digest(identity);
        let candidate_id = format!("rule-candidate:{}", hex_prefix(&digest, 16));
        let mut evidence_identity = Vec::new();
        for item in &evidence {
            evidence_identity.extend_from_slice(item.feedback_id.as_bytes());
            evidence_identity.push(0);
        }
        let evidence_digest = vee_core::digest(&evidence_identity);
        let feedback_ids = evidence
            .iter()
            .map(|item| item.feedback_id.clone())
            .collect::<Vec<_>>();
        let examples = evidence
            .iter()
            .take(MAX_EXAMPLES_PER_CANDIDATE)
            .map(|item| FeedbackExample {
                source_kind: "provider_comment_feedback".into(),
                finding_id: None,
                external_comment_id: Some(item.external_id.clone()),
                archive_digest: Some(item.archive_digest.clone()),
                provider: Some(item.provider.clone()),
                pull_request: Some(item.pull_request.clone()),
                snapshot_id: item.revision.clone(),
                reviewer: item.reviewer.clone(),
                reason: truncate(&item.reason, MAX_REASON_CHARS),
            })
            .collect();
        let suggestion = match label {
            FindingFeedbackLabel::FalsePositive => format!("Review the repeated false-positive feedback in category '{}'. If the evidence supports it, propose a narrowly scoped rule that prevents this specific pattern from recurring; do not suppress the whole category.", category),
            FindingFeedbackLabel::NotActionable => format!("Review why provider findings in category '{}' were marked not actionable. Consider improving reviewer instructions, evidence requirements, or message quality; do not suppress findings solely on this basis.", category),
            _ => continue,
        };
        report.candidates.push(RuleCandidate {
            candidate_id,
            source_kind: "provider_discussions".into(),
            category,
            feedback_label: label,
            feedback_count: distinct.len(),
            feedback_event_count: evidence.len(),
            evidence_digest,
            feedback_ids,
            suggestion,
            feedback: examples,
            approval_status: "requires_human_review",
        });
    }
    report.disputed_external_comments_excluded = disputed.len();
    report
        .candidates
        .sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    report.limitations.push("Provider discussion candidates require a human-assigned category and explicit labels; distinctness is based on provider, repository, pull request, and external comment ID. Contradictory labels for one comment are excluded.".into());
    report
}

fn external_comment_identity(item: &super::imported_history::ExternalReviewFeedback) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        item.provider,
        item.pull_request.repository.full_name,
        item.pull_request.number,
        item.external_id
    )
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct RuleEffectivenessReport {
    pub schema_version: u32,
    pub approvals: Vec<RuleEffectiveness>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct RuleEffectiveness {
    pub approval_id: String,
    pub version: u32,
    pub status: String,
    pub source_feedback_ids: Vec<String>,
    pub evidence_digest: String,
    pub baseline: EffectivenessWindow,
    pub after_activation: EffectivenessWindow,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema, Default)]
pub struct EffectivenessWindow {
    pub accuracy_denominator: usize,
    pub false_positive_count: usize,
    pub false_positive_rate: Option<f64>,
    pub actionability_denominator: usize,
    pub not_actionable_count: usize,
    pub not_actionable_rate: Option<f64>,
    pub disputed_occurrences: usize,
}

pub fn effectiveness(
    store: &dyn vee_core::ports::Repositories,
    requested_id: Option<&str>,
    external_feedback: &[super::imported_history::ExternalReviewFeedback],
) -> Result<RuleEffectivenessReport, String> {
    let approvals = store.list_rule_approvals()?;
    let records = store.list_findings(None, None, None)?;
    let findings = records
        .iter()
        .map(|record| (record.finding.id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let feedback = store.list_finding_feedback()?;
    let mut results = Vec::new();
    for approval in approvals
        .iter()
        .filter(|approval| requested_id.is_none_or(|id| id == approval.approval_id))
    {
        let source = approval
            .source_feedback_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let activation = approval
            .events
            .iter()
            .find(|event| event.event == "activated")
            .map(|event| event.created_at.as_str())
            .ok_or_else(|| {
                format!(
                    "approval {} is missing activation event",
                    approval.approval_id
                )
            })?;
        let activation_unix = approval.activated_at_unix.unwrap_or(0);
        let mut before = BTreeMap::<(String, String), BTreeSet<FindingFeedbackLabel>>::new();
        let mut after = BTreeMap::<(String, String), BTreeSet<FindingFeedbackLabel>>::new();
        for item in &feedback {
            let Some(record) = findings.get(item.finding_id.as_str()) else {
                continue;
            };
            if normalize_category(&record.finding.category)
                != normalize_category(&approval.category)
            {
                continue;
            }
            let key = (record.finding.id.clone(), item.snapshot_id.clone());
            if source.contains(&item.feedback_id) || item.created_at.as_str() <= activation {
                before.entry(key).or_default().insert(item.label);
            } else {
                after.entry(key).or_default().insert(item.label);
            }
        }
        for item in external_feedback {
            if normalize_category(&item.category) != normalize_category(&approval.category) {
                continue;
            }
            let key = (external_comment_identity(item), item.revision.clone());
            let target =
                if source.contains(&item.feedback_id) || item.recorded_at_unix <= activation_unix {
                    &mut before
                } else {
                    &mut after
                };
            target.entry(key).or_default().insert(item.label);
        }
        let mut baseline = EffectivenessWindow::default();
        let mut after_activation = EffectivenessWindow::default();
        summarize_window(&mut baseline, &before);
        summarize_window(&mut after_activation, &after);
        results.push(RuleEffectiveness {
            approval_id: approval.approval_id.clone(),
            version: approval.version,
            status: approval.status.as_str().to_owned(),
            source_feedback_ids: approval.source_feedback_ids.clone(),
            evidence_digest: approval.evidence_digest.clone(),
            baseline,
            after_activation,
        });
    }
    if requested_id.is_some() && results.is_empty() {
        return Err("rule approval was not found".into());
    }
    Ok(RuleEffectivenessReport {
        schema_version: 1,
        approvals: results,
        limitations: vec![
            "Outcomes are descriptive associations, not causal estimates of guidance effectiveness.".into(),
            "Only explicit human feedback tied to saved finding occurrences is counted; unreviewed findings are excluded.".into(),
            "Events are split at approval activation time; source feedback events are retained in the baseline.".into(),
            "Reviewer attribution is caller-supplied and not authenticated.".into(),
        ],
    })
}

fn summarize_window(
    window: &mut EffectivenessWindow,
    items: &BTreeMap<(String, String), BTreeSet<FindingFeedbackLabel>>,
) {
    for labels in items.values() {
        let false_positive = labels.contains(&FindingFeedbackLabel::FalsePositive);
        let confirmed = labels.contains(&FindingFeedbackLabel::Confirmed);
        if false_positive && confirmed {
            window.disputed_occurrences += 1;
        } else if false_positive {
            window.false_positive_count += 1;
            window.accuracy_denominator += 1;
        } else if confirmed {
            window.accuracy_denominator += 1;
        }
        let not_actionable = labels.contains(&FindingFeedbackLabel::NotActionable);
        let actionable = labels.contains(&FindingFeedbackLabel::Actionable);
        if not_actionable && actionable {
            window.disputed_occurrences += 1;
        } else if not_actionable {
            window.not_actionable_count += 1;
            window.actionability_denominator += 1;
        } else if actionable {
            window.actionability_denominator += 1;
        }
    }
    window.false_positive_rate = (window.accuracy_denominator > 0)
        .then(|| window.false_positive_count as f64 / window.accuracy_denominator as f64);
    window.not_actionable_rate = (window.actionability_denominator > 0)
        .then(|| window.not_actionable_count as f64 / window.actionability_denominator as f64);
}

fn normalize_category(category: &str) -> String {
    category
        .trim()
        .chars()
        .flat_map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_lowercase().collect::<Vec<_>>()
            } else {
                vec![' ']
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn feedback_label_key(label: FindingFeedbackLabel) -> &'static str {
    match label {
        FindingFeedbackLabel::Confirmed => "confirmed",
        FindingFeedbackLabel::FalsePositive => "false_positive",
        FindingFeedbackLabel::Actionable => "actionable",
        FindingFeedbackLabel::NotActionable => "not_actionable",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{result}…")
    } else {
        result
    }
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vee_core::{Finding, FindingOccurrence, Severity};

    fn record(id: &str, category: &str) -> FindingRecord {
        FindingRecord {
            assessments: Vec::new(),
            finding: Finding {
                id: id.into(),
                fingerprint: format!("fingerprint-{id}"),
                category: category.into(),
                severity: Severity::Medium,
                confidence: Some(70),
                rationale: "model rationale".into(),
                path: Some("src/lib.rs".into()),
                line: Some(10),
                provenance: "model_inference".into(),
                reviewer_ids: Vec::new(),
                evidence_ids: vec![],
                rule_attributions: Vec::new(),
            },
            status: vee_core::FindingStatus::Waived,
            status_reason: Some("waiver reason does not imply false positive".into()),
            occurrence_count: 1,
            first_seen: "2026-11-14T00:00:00Z".into(),
            last_seen: "2026-11-14T00:00:00Z".into(),
            occurrences: vec![FindingOccurrence {
                review_id: "review-1".into(),
                snapshot_id: "snapshot-1".into(),
                observed_at: "2026-11-14T00:00:00Z".into(),
            }],
        }
    }

    fn feedback(finding_id: &str, label: FindingFeedbackLabel, reviewer: &str) -> FindingFeedback {
        FindingFeedback {
            schema_version: 1,
            feedback_id: format!("feedback-{finding_id}-{reviewer}"),
            finding_id: finding_id.into(),
            snapshot_id: format!("snapshot-{finding_id}"),
            label,
            reason: "reviewed example reason".into(),
            reviewer: reviewer.into(),
            created_at: "2026-11-14T00:00:00Z".into(),
        }
    }

    #[test]
    fn provider_comment_candidates_require_distinct_unconflicted_human_labels() {
        let mut external = (0..4)
            .map(
                |index| super::super::imported_history::ExternalReviewFeedback {
                    schema_version: 1,
                    feedback_id: format!("sha256:{index:064x}"),
                    archive_digest: format!("sha256:{:064x}", index + 10),
                    provider: "github".into(),
                    pull_request: vee_hosting::PullRequestRef {
                        repository: vee_hosting::RepositoryRef {
                            host: "github.com".into(),
                            full_name: "acme/service".into(),
                        },
                        number: 100 + index,
                    },
                    revision: format!("revision-{index}"),
                    external_id: format!("comment-{index}"),
                    category: "correctness".into(),
                    label: FindingFeedbackLabel::FalsePositive,
                    reason: "This is already guarded by the parser contract".into(),
                    reviewer: "maintainer".into(),
                    recorded_at_unix: 100 + index as i64,
                },
            )
            .collect::<Vec<_>>();
        let report = mine_with_external(&[], &[], &external, false);
        assert_eq!(report.schema_version, 3);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].source_kind, "provider_discussions");
        assert_eq!(report.candidates[0].feedback_count, 4);
        assert!(report.candidates[0].feedback[0].archive_digest.is_some());
        assert!(report.candidates[0].feedback[0]
            .external_comment_id
            .is_some());
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/rule-candidates-v3.schema.json"
        ))
        .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&report).unwrap()));

        let mut conflict = external[0].clone();
        conflict.feedback_id = format!("sha256:{:064x}", 99);
        conflict.label = FindingFeedbackLabel::Confirmed;
        external.push(conflict);
        let report = mine_with_external(&[], &[], &external, false);
        assert_eq!(report.disputed_external_comments_excluded, 1);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].feedback_count, 3);
        assert!(!report.candidates[0].evidence_digest.is_empty());
    }

    #[test]
    fn only_explicit_false_positive_labels_create_narrow_candidates() {
        let records = vec![
            record("one", "Race Condition"),
            record("two", "race-condition"),
            record("three", "RACE CONDITION"),
        ];
        let feedback = vec![
            feedback("one", FindingFeedbackLabel::FalsePositive, "alice"),
            feedback("two", FindingFeedbackLabel::FalsePositive, "bob"),
            feedback("three", FindingFeedbackLabel::FalsePositive, "carol"),
        ];
        let report = mine(&records, &feedback, false);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].feedback_count, 3);
        assert_eq!(
            report.candidates[0].feedback_label,
            FindingFeedbackLabel::FalsePositive
        );
        assert!(report.candidates[0].suggestion.contains("narrowly scoped"));
        assert_eq!(
            report.candidates[0].approval_status,
            "requires_human_review"
        );
    }

    #[test]
    fn waived_status_alone_never_becomes_false_positive_evidence() {
        let records = vec![record("one", "Correctness"), record("two", "Correctness")];
        assert!(mine(&records, &[], false).candidates.is_empty());
    }

    #[test]
    fn contradictory_feedback_excludes_the_finding_from_candidates() {
        let records = vec![
            record("one", "Correctness"),
            record("two", "Correctness"),
            record("three", "Correctness"),
            record("four", "Correctness"),
        ];
        let feedback = vec![
            feedback("one", FindingFeedbackLabel::FalsePositive, "alice"),
            feedback("one", FindingFeedbackLabel::Confirmed, "bob"),
            feedback("two", FindingFeedbackLabel::FalsePositive, "alice"),
            feedback("three", FindingFeedbackLabel::FalsePositive, "alice"),
            feedback("four", FindingFeedbackLabel::FalsePositive, "alice"),
        ];
        let report = mine(&records, &feedback, false);
        assert_eq!(report.disputed_findings_excluded, 1);
        assert_eq!(report.candidates[0].feedback_count, 3);
    }

    #[test]
    fn non_actionable_feedback_suggests_quality_improvement_not_suppression() {
        let records = vec![
            record("one", "Security"),
            record("two", "Security"),
            record("three", "Security"),
        ];
        let feedback = ["one", "two", "three"]
            .into_iter()
            .map(|id| feedback(id, FindingFeedbackLabel::NotActionable, "reviewer"))
            .collect::<Vec<_>>();
        let report = mine(&records, &feedback, false);
        assert_eq!(
            report.candidates[0].feedback_label,
            FindingFeedbackLabel::NotActionable
        );
        assert!(report.candidates[0]
            .suggestion
            .contains("improving reviewer instructions"));
        assert!(!report.candidates[0]
            .suggestion
            .contains("narrowly scoped rule"));
    }
}
