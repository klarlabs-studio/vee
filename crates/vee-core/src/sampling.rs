//! Reviewer sampling: merge repeated runs of one reviewer into agreement-scored findings.

use serde::{Deserialize, Serialize};

use crate::{Finding, Severity};

/// Lines at most this far apart in the same file are treated as one reported defect.
pub const SAMPLE_LINE_WINDOW: u32 = 3;

/// How a sampled reviewer's runs are matched into one reported defect.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SampleGrouping {
    /// Same file and lines at most [`SAMPLE_LINE_WINDOW`] apart.
    #[default]
    Location,
    /// Location, refined by what each report says: reports with the same
    /// category and closely matching rationale join across a wider window,
    /// and nearby reports that share neither stay apart.
    Meaning,
}

/// The widest line distance at which two reports can still be the same defect
/// by meaning.
pub const MEANING_LINE_WINDOW: u32 = 30;
/// Rationale word overlap (Jaccard) from which two reports say the same thing.
const SAME_MEANING: f64 = 0.5;
/// Rationale word overlap below which two reports say different things.
const DIFFERENT_MEANING: f64 = 0.15;

/// The largest number of samples a reviewer may request.
pub const MAX_REVIEWER_SAMPLES: u32 = 5;

/// How many of a reviewer's samples reported a finding, and how many must agree for it to block.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SampleAgreement {
    pub reported: u32,
    pub samples: u32,
    pub quorum: u32,
}

impl SampleAgreement {
    pub fn meets_quorum(&self) -> bool {
        self.reported >= self.quorum
    }
}

/// The default quorum: a strict majority of the samples.
pub fn default_sample_quorum(samples: u32) -> u32 {
    samples / 2 + 1
}

/// Merge the findings of each sample of one reviewer into one agreement-scored list.
///
/// Located findings group by path and nearby line; line-less findings group by fingerprint.
/// A group takes at most one report from each sample. `sample_count` is how many samples
/// the reviewer ran, including any that failed. An unsampled reviewer (`sample_count` 1)
/// gets its findings back unchanged, with no agreement record.
pub fn merge_sampled_findings(
    samples: Vec<Vec<Finding>>,
    sample_count: u32,
    quorum: u32,
) -> Vec<Finding> {
    merge_sampled_findings_by(samples, sample_count, quorum, SampleGrouping::Location)
}

/// [`merge_sampled_findings`] with a chosen grouping.
pub fn merge_sampled_findings_by(
    samples: Vec<Vec<Finding>>,
    sample_count: u32,
    quorum: u32,
    grouping: SampleGrouping,
) -> Vec<Finding> {
    if sample_count <= 1 {
        return samples.into_iter().flatten().collect();
    }
    let mut groups: Vec<Group> = Vec::new();
    for (sample_index, findings) in samples.into_iter().enumerate() {
        let mut ordered = findings;
        ordered.sort_by(representative_order);
        // Match this sample's reports to existing groups closest pair first, so
        // one report cannot take a group that a nearer report of the same sample
        // belongs to. Ties go to the earlier group and the earlier report.
        let mut pairs = Vec::new();
        for (group_index, group) in groups.iter().enumerate() {
            for (finding_index, finding) in ordered.iter().enumerate() {
                if let Some(distance) = group.distance(finding, grouping) {
                    pairs.push((distance, group_index, finding_index));
                }
            }
        }
        pairs.sort_unstable();
        let mut assigned_group = vec![false; groups.len()];
        let mut target = vec![None; ordered.len()];
        for (_, group_index, finding_index) in pairs {
            if !assigned_group[group_index] && target[finding_index].is_none() {
                assigned_group[group_index] = true;
                target[finding_index] = Some(group_index);
            }
        }
        for (finding, target) in ordered.into_iter().zip(target) {
            match target {
                Some(group_index) => groups[group_index].add(sample_index, finding),
                None => groups.push(Group::new(sample_index, finding)),
            }
        }
    }
    let mut merged: Vec<Finding> = groups
        .into_iter()
        .map(|group| group.into_finding(sample_count, quorum))
        .collect();
    merged.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    merged
}

struct Group {
    samples: Vec<usize>,
    reports: Vec<Finding>,
}

impl Group {
    fn new(sample_index: usize, finding: Finding) -> Self {
        Self {
            samples: vec![sample_index],
            reports: vec![finding],
        }
    }

    /// The closest line distance to a report in this group that describes the same
    /// defect, or `None` when no report does. Fingerprint matches count as distance 0.
    fn distance(&self, finding: &Finding, grouping: SampleGrouping) -> Option<u32> {
        self.reports
            .iter()
            .filter_map(|report| match grouping {
                SampleGrouping::Location => reported_defect_distance(report, finding),
                SampleGrouping::Meaning => same_meaning_distance(report, finding),
            })
            .min()
    }

    fn add(&mut self, sample_index: usize, finding: Finding) {
        self.samples.push(sample_index);
        self.reports.push(finding);
    }

    fn into_finding(mut self, samples: u32, quorum: u32) -> Finding {
        self.reports.sort_by(representative_order);
        let reported = self.samples.len() as u32;
        let mut representative = self.reports.swap_remove(0);
        for report in &self.reports {
            for evidence_id in &report.evidence_ids {
                if !representative.evidence_ids.contains(evidence_id) {
                    representative.evidence_ids.push(evidence_id.clone());
                }
            }
        }
        representative.sample_agreement = Some(SampleAgreement {
            reported,
            samples,
            quorum,
        });
        representative
    }
}

fn reported_defect_distance(left: &Finding, right: &Finding) -> Option<u32> {
    match (left.line, right.line) {
        (Some(left_line), Some(right_line)) => {
            let distance = left_line.abs_diff(right_line);
            (left.path.is_some() && left.path == right.path && distance <= SAMPLE_LINE_WINDOW)
                .then_some(distance)
        }
        _ => (left.fingerprint == right.fingerprint).then_some(0),
    }
}

/// Distance by meaning: nearby reports join unless they differ in category
/// and wording; reports up to [`MEANING_LINE_WINDOW`] lines apart, or without
/// a line, join when category and rationale match.
fn same_meaning_distance(left: &Finding, right: &Finding) -> Option<u32> {
    if left.fingerprint == right.fingerprint {
        return Some(0);
    }
    if left.path != right.path {
        return None;
    }
    let similarity = rationale_similarity(&left.rationale, &right.rationale);
    let same_category = left.category.eq_ignore_ascii_case(&right.category);
    match (left.line, right.line) {
        (Some(left_line), Some(right_line)) if left.path.is_some() => {
            let distance = left_line.abs_diff(right_line);
            let nearby = distance <= SAMPLE_LINE_WINDOW
                && (same_category || similarity >= DIFFERENT_MEANING);
            let alike =
                distance <= MEANING_LINE_WINDOW && same_category && similarity >= SAME_MEANING;
            (nearby || alike).then_some(distance)
        }
        _ => (same_category && similarity >= SAME_MEANING).then_some(MEANING_LINE_WINDOW),
    }
}

/// Words too common in review rationales to say what a defect is.
const COMMON_WORDS: &[&str] = &[
    "the", "and", "for", "this", "that", "with", "when", "which", "from", "into", "are", "was",
    "can", "may", "could", "would", "should", "will", "not", "but", "its", "has", "have", "been",
    "than", "then", "there", "here", "also", "any", "all", "only", "line", "code", "function",
];

fn rationale_words(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .map(str::to_lowercase)
        .filter(|word| word.chars().count() >= 3 && !COMMON_WORDS.contains(&word.as_str()))
        .collect()
}

/// Word overlap of two rationales (Jaccard), from 0 to 1.
fn rationale_similarity(left: &str, right: &str) -> f64 {
    let left = rationale_words(left);
    let right = rationale_words(right);
    let union = left.union(&right).count();
    if union == 0 {
        return 0.0;
    }
    left.intersection(&right).count() as f64 / union as f64
}

/// Prefer a located report, then higher severity, then higher confidence, then fingerprint.
fn representative_order(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    right
        .line
        .is_some()
        .cmp(&left.line.is_some())
        .then_with(|| severity_rank(right.severity).cmp(&severity_rank(left.severity)))
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fingerprint: &str, path: &str, line: Option<u32>, severity: Severity) -> Finding {
        Finding {
            suggestion: None,
            id: format!("find_{fingerprint}"),
            fingerprint: fingerprint.into(),
            category: "concurrency".into(),
            severity,
            confidence: Some(80),
            rationale: format!("rationale {fingerprint}"),
            path: Some(path.into()),
            line,
            provenance: "model_inference".into(),
            reviewer_ids: vec!["correctness".into()],
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        }
    }

    fn said(fingerprint: &str, line: u32, category: &str, rationale: &str) -> Finding {
        Finding {
            category: category.into(),
            rationale: rationale.into(),
            ..finding(fingerprint, "src/lib.rs", Some(line), Severity::High)
        }
    }

    #[test]
    fn meaning_joins_one_defect_reported_on_distant_lines() {
        let samples = || {
            vec![
                vec![said(
                    "a",
                    10,
                    "concurrency",
                    "The cache map is read without holding the lock, a data race",
                )],
                vec![said(
                    "b",
                    24,
                    "concurrency",
                    "Data race: the cache map is read without the lock held",
                )],
            ]
        };
        assert_eq!(
            merge_sampled_findings(samples(), 2, 2).len(),
            2,
            "location keeps them apart"
        );
        let merged = merge_sampled_findings_by(samples(), 2, 2, SampleGrouping::Meaning);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sample_agreement.unwrap().reported, 2);
    }

    #[test]
    fn meaning_keeps_two_different_defects_on_adjacent_lines_apart() {
        let samples = || {
            vec![
                vec![said(
                    "a",
                    10,
                    "security",
                    "User input reaches the SQL query unescaped",
                )],
                vec![said(
                    "b",
                    11,
                    "performance",
                    "Allocates a vector on every iteration of the loop",
                )],
            ]
        };
        assert_eq!(
            merge_sampled_findings(samples(), 2, 2).len(),
            1,
            "location merges them"
        );
        assert_eq!(
            merge_sampled_findings_by(samples(), 2, 2, SampleGrouping::Meaning).len(),
            2
        );
    }

    #[test]
    fn meaning_does_not_join_alike_reports_beyond_its_window_or_in_other_files() {
        let far = vec![
            vec![said(
                "a",
                10,
                "concurrency",
                "The cache map is read without holding the lock",
            )],
            vec![said(
                "b",
                10 + MEANING_LINE_WINDOW + 1,
                "concurrency",
                "The cache map is read without holding the lock",
            )],
        ];
        assert_eq!(
            merge_sampled_findings_by(far, 2, 2, SampleGrouping::Meaning).len(),
            2
        );
        let mut other = said(
            "b",
            10,
            "concurrency",
            "The cache map is read without holding the lock",
        );
        other.path = Some("src/other.rs".into());
        let files = vec![
            vec![said(
                "a",
                10,
                "concurrency",
                "The cache map is read without holding the lock",
            )],
            vec![other],
        ];
        assert_eq!(
            merge_sampled_findings_by(files, 2, 2, SampleGrouping::Meaning).len(),
            2
        );
    }

    #[test]
    fn rationale_similarity_ignores_case_punctuation_and_common_words() {
        assert!(rationale_similarity("The Lock is NOT held.", "lock held") > 0.99);
        assert_eq!(rationale_similarity("", "lock"), 0.0);
    }

    #[test]
    fn a_single_sample_is_returned_unchanged_without_agreement() {
        let only = vec![finding("a", "src/lib.rs", Some(10), Severity::High)];
        let merged = merge_sampled_findings(vec![only.clone()], 1, 1);
        assert_eq!(merged, only);
    }

    #[test]
    fn nearby_lines_in_the_same_file_merge_across_samples() {
        let merged = merge_sampled_findings(
            vec![
                vec![finding("a", "src/lib.rs", Some(10), Severity::Medium)],
                vec![finding("b", "src/lib.rs", Some(13), Severity::High)],
                vec![finding("c", "src/lib.rs", Some(40), Severity::High)],
            ],
            3,
            2,
        );
        assert_eq!(merged.len(), 2);
        let repeated = merged.iter().find(|f| f.fingerprint == "b").unwrap();
        assert_eq!(
            repeated.sample_agreement,
            Some(SampleAgreement {
                reported: 2,
                samples: 3,
                quorum: 2
            })
        );
        assert!(repeated.sample_agreement.unwrap().meets_quorum());
        let single = merged.iter().find(|f| f.fingerprint == "c").unwrap();
        assert_eq!(single.sample_agreement.unwrap().reported, 1);
        assert!(!single.sample_agreement.unwrap().meets_quorum());
    }

    #[test]
    fn a_report_between_two_defects_joins_the_nearer_one() {
        let merged = merge_sampled_findings(
            vec![
                vec![
                    finding("z", "src/lib.rs", Some(1), Severity::High),
                    finding("a", "src/lib.rs", Some(5), Severity::High),
                ],
                vec![finding("m", "src/lib.rs", Some(2), Severity::High)],
            ],
            2,
            2,
        );
        let reported = |line| {
            merged
                .iter()
                .find(|f| f.line == Some(line))
                .map(|f| f.sample_agreement.unwrap().reported)
        };
        assert_eq!(merged.len(), 2);
        assert_eq!(reported(5), Some(1), "line 5 stays a single report");
        assert_eq!(
            reported(1).or(reported(2)),
            Some(2),
            "lines 1 and 2 merged into one finding"
        );
    }

    #[test]
    fn a_far_report_processed_first_does_not_take_a_nearer_reports_group() {
        let merged = merge_sampled_findings(
            vec![
                vec![finding("m", "src/lib.rs", Some(2), Severity::High)],
                vec![
                    finding("a", "src/lib.rs", Some(5), Severity::High),
                    finding("z", "src/lib.rs", Some(1), Severity::High),
                ],
            ],
            2,
            2,
        );
        let line5 = merged.iter().find(|f| f.line == Some(5)).unwrap();
        assert_eq!(line5.sample_agreement.unwrap().reported, 1);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn different_files_do_not_merge() {
        let merged = merge_sampled_findings(
            vec![
                vec![finding("a", "src/lib.rs", Some(10), Severity::High)],
                vec![finding("b", "src/other.rs", Some(10), Severity::High)],
            ],
            2,
            2,
        );
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn a_group_takes_one_report_per_sample() {
        let merged = merge_sampled_findings(
            vec![
                vec![
                    finding("a", "src/lib.rs", Some(10), Severity::High),
                    finding("b", "src/lib.rs", Some(11), Severity::Low),
                ],
                vec![finding("c", "src/lib.rs", Some(10), Severity::High)],
            ],
            2,
            2,
        );
        assert_eq!(merged.len(), 2);
        let reported: Vec<u32> = merged
            .iter()
            .map(|f| f.sample_agreement.unwrap().reported)
            .collect();
        assert_eq!(reported.iter().sum::<u32>(), 3);
    }

    #[test]
    fn a_located_report_represents_a_line_less_one_with_the_same_fingerprint() {
        let merged = merge_sampled_findings(
            vec![
                vec![finding("a", "src/lib.rs", None, Severity::Critical)],
                vec![finding("a", "src/lib.rs", Some(7), Severity::Medium)],
            ],
            2,
            2,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].line, Some(7));
        assert_eq!(merged[0].sample_agreement.unwrap().reported, 2);
    }

    #[test]
    fn line_less_reports_merge_only_by_fingerprint() {
        let merged = merge_sampled_findings(
            vec![
                vec![finding("a", "src/lib.rs", None, Severity::High)],
                vec![finding("b", "src/lib.rs", None, Severity::High)],
            ],
            2,
            2,
        );
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merging_is_independent_of_sample_order() {
        let first = vec![finding("a", "src/lib.rs", Some(10), Severity::Medium)];
        let second = vec![finding("b", "src/lib.rs", Some(12), Severity::High)];
        let forward = merge_sampled_findings(vec![first.clone(), second.clone()], 2, 2);
        let backward = merge_sampled_findings(vec![second, first], 2, 2);
        assert_eq!(forward, backward);
    }

    #[test]
    fn agreement_counts_every_configured_sample_when_one_failed() {
        let merged = merge_sampled_findings(
            vec![vec![finding("a", "src/lib.rs", Some(10), Severity::High)]],
            3,
            2,
        );
        assert_eq!(
            merged[0].sample_agreement,
            Some(SampleAgreement {
                reported: 1,
                samples: 3,
                quorum: 2
            })
        );
    }

    #[test]
    fn the_default_quorum_is_a_strict_majority() {
        assert_eq!(default_sample_quorum(1), 1);
        assert_eq!(default_sample_quorum(2), 2);
        assert_eq!(default_sample_quorum(3), 2);
        assert_eq!(default_sample_quorum(5), 3);
    }
}
