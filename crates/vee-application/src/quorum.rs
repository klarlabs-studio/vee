//! Measured agreement thresholds: which quorum each sampled reviewer should
//! use, judged by the findings people have labelled (ADR 0045).

use serde::Serialize;
use std::collections::BTreeMap;
use vee_core::{FindingFeedback, FindingFeedbackLabel, FindingRecord, RepositoryConfig};

/// Fewer labelled findings than this give no recommendation.
pub const MIN_LABELED_FINDINGS: usize = 10;

/// How one quorum would have treated the labelled findings.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuorumOutcome {
    pub quorum: u32,
    /// Confirmed or actionable findings that would block.
    pub kept_confirmed: usize,
    /// Rejected findings that would still block.
    pub kept_rejected: usize,
    /// Confirmed findings that would only be shown.
    pub dropped_confirmed: usize,
    /// Rejected findings that would only be shown.
    pub dropped_rejected: usize,
}

impl QuorumOutcome {
    /// Confirmed findings kept minus rejected findings kept.
    pub fn net(&self) -> i64 {
        self.kept_confirmed as i64 - self.kept_rejected as i64
    }
}

/// One sampled reviewer's calibration.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ReviewerQuorum {
    pub reviewer_id: String,
    pub samples: u32,
    pub configured_quorum: u32,
    /// Labelled findings from runs with the current sample count.
    pub labeled: usize,
    pub outcomes: Vec<QuorumOutcome>,
    /// The quorum with the best net, or none when there is too little evidence.
    pub recommended_quorum: Option<u32>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct QuorumCalibration {
    pub schema_version: u32,
    pub min_labeled: usize,
    pub reviewers: Vec<ReviewerQuorum>,
}

fn label_value(label: FindingFeedbackLabel) -> bool {
    matches!(
        label,
        FindingFeedbackLabel::Confirmed | FindingFeedbackLabel::Actionable
    )
}

/// Each finding's latest label: true when confirmed or actionable.
fn latest_labels(feedback: &[FindingFeedback]) -> BTreeMap<&str, bool> {
    let mut latest: BTreeMap<&str, &FindingFeedback> = BTreeMap::new();
    for item in feedback {
        let entry = latest.entry(item.finding_id.as_str()).or_insert(item);
        if item.created_at >= entry.created_at {
            *entry = item;
        }
    }
    latest
        .into_iter()
        .map(|(id, item)| (id, label_value(item.label)))
        .collect()
}

/// How many of `reviewer_id`'s `samples` runs reported each labelled finding.
fn labelled_agreement(
    reviewer_id: &str,
    samples: u32,
    records: &[FindingRecord],
    labels: &BTreeMap<&str, bool>,
) -> Vec<(u32, bool)> {
    records
        .iter()
        .filter_map(|record| {
            let label = *labels.get(record.finding.id.as_str())?;
            let reports = if record.assessments.is_empty() {
                std::slice::from_ref(&record.finding)
            } else {
                record.assessments.as_slice()
            };
            reports
                .iter()
                .filter(|report| report.reviewer_ids.iter().any(|id| id == reviewer_id))
                .filter_map(|report| report.sample_agreement)
                .filter(|agreement| agreement.samples == samples)
                .map(|agreement| agreement.reported)
                .max()
                .map(|reported| (reported, label))
        })
        .collect()
}

fn outcome(quorum: u32, labelled: &[(u32, bool)]) -> QuorumOutcome {
    let mut outcome = QuorumOutcome {
        quorum,
        kept_confirmed: 0,
        kept_rejected: 0,
        dropped_confirmed: 0,
        dropped_rejected: 0,
    };
    for &(reported, confirmed) in labelled {
        match (reported >= quorum, confirmed) {
            (true, true) => outcome.kept_confirmed += 1,
            (true, false) => outcome.kept_rejected += 1,
            (false, true) => outcome.dropped_confirmed += 1,
            (false, false) => outcome.dropped_rejected += 1,
        }
    }
    outcome
}

/// The quorum with the best net. Ties keep the configured quorum, and
/// otherwise go to the higher one, which blocks on fewer findings.
fn best(outcomes: &[QuorumOutcome], configured: u32) -> u32 {
    let top = outcomes.iter().map(QuorumOutcome::net).max().unwrap_or(0);
    let tied: Vec<u32> = outcomes
        .iter()
        .filter(|outcome| outcome.net() == top)
        .map(|outcome| outcome.quorum)
        .collect();
    if tied.contains(&configured) {
        configured
    } else {
        tied.into_iter().max().unwrap_or(configured)
    }
}

fn calibrate_reviewer(
    reviewer_id: &str,
    samples: u32,
    configured_quorum: u32,
    records: &[FindingRecord],
    labels: &BTreeMap<&str, bool>,
) -> ReviewerQuorum {
    let labelled = labelled_agreement(reviewer_id, samples, records, labels);
    let outcomes: Vec<QuorumOutcome> = (1..=samples)
        .map(|quorum| outcome(quorum, &labelled))
        .collect();
    let (recommended_quorum, reason) = if labelled.len() < MIN_LABELED_FINDINGS {
        (
            None,
            format!(
                "{} labelled finding(s) from {samples}-sample runs; at least {MIN_LABELED_FINDINGS} are needed",
                labelled.len()
            ),
        )
    } else {
        let quorum = best(&outcomes, configured_quorum);
        let chosen = &outcomes[(quorum - 1) as usize];
        let reason = if quorum == configured_quorum {
            format!(
                "the configured quorum already keeps the most confirmed findings net of rejected ones ({})",
                chosen.net()
            )
        } else {
            let current = &outcomes[(configured_quorum - 1) as usize];
            format!(
                "quorum {quorum} keeps {} confirmed and {} rejected finding(s), against {} and {} at {configured_quorum}",
                chosen.kept_confirmed, chosen.kept_rejected, current.kept_confirmed, current.kept_rejected
            )
        };
        (Some(quorum), reason)
    };
    ReviewerQuorum {
        reviewer_id: reviewer_id.to_owned(),
        samples,
        configured_quorum,
        labeled: labelled.len(),
        outcomes,
        recommended_quorum,
        reason,
    }
}

/// Calibrate every enabled reviewer that samples more than once.
pub fn calibrate(
    config: &RepositoryConfig,
    records: &[FindingRecord],
    feedback: &[FindingFeedback],
) -> QuorumCalibration {
    let labels = latest_labels(feedback);
    let reviewers = config
        .reviewers
        .iter()
        .filter(|(_, reviewer)| reviewer.enabled && reviewer.sample_count() > 1)
        .map(|(id, reviewer)| {
            calibrate_reviewer(
                id,
                reviewer.sample_count(),
                reviewer
                    .effective_sample_quorum()
                    .clamp(1, reviewer.sample_count()),
                records,
                &labels,
            )
        })
        .collect();
    QuorumCalibration {
        schema_version: 1,
        min_labeled: MIN_LABELED_FINDINGS,
        reviewers,
    }
}

#[cfg(test)]
#[path = "tests/quorum.rs"]
mod tests;
