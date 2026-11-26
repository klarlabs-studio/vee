//! Incremental review after a push (ADR 0022).
//!
//! CI keeps no state, so each review leaves a record on the pull request: the
//! content of every changed file it reviewed, its findings and its
//! configuration. The next review sends reviewers only the files whose
//! change differs from that record and carries the recorded findings on the
//! others. The gate is still evaluated over the whole change.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use vee_core::{digest, ChangeSet, Finding};

/// Marks the record in Vee's summary comment.
pub const RECORD_MARKER: &str = "<!-- vee:record:";
/// GitHub refuses comments over 65,536 characters; a larger record is left
/// out, and the next review is a full one.
const MAX_RECORD_CHARS: usize = 60_000;

/// The content of one changed file on both sides of the change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFile {
    /// Digest of the file at the base, or `None` when the change adds it.
    pub base: Option<String>,
    /// Digest of the file at the head, or `None` when the change deletes it.
    pub head: Option<String>,
}

/// What one review of a pull request covered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub schema_version: u32,
    pub repository: String,
    pub number: u64,
    pub head_oid: String,
    pub review_id: String,
    /// The review's effective configuration. A record made under another
    /// configuration carries nothing.
    pub config_digest: String,
    pub files: BTreeMap<String, ReviewedFile>,
    /// Each reviewer's findings, before findings of several reviewers at one
    /// location are merged.
    pub findings: Vec<Finding>,
    /// Vee's approval verdicts on this pull request, oldest first, with
    /// `--approve` (ADR 0025).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<ApprovalVerdict>,
}

/// Verdicts kept in a record; older ones are dropped first.
pub const MAX_APPROVAL_VERDICTS: usize = 50;

/// Whether one head was eligible for approval without a person, and whether
/// Vee approved it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVerdict {
    pub head_oid: String,
    pub review_id: String,
    pub eligible: bool,
    /// True when Vee approved the head on the host (`approval.mode: enforce`).
    pub approved: bool,
    /// The approval stages that failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_stages: Vec<String>,
}

/// `earlier` with `verdict` appended, replacing a verdict on the same head,
/// and at most [`MAX_APPROVAL_VERDICTS`] long.
pub fn append_verdict(
    mut earlier: Vec<ApprovalVerdict>,
    verdict: ApprovalVerdict,
) -> Vec<ApprovalVerdict> {
    earlier.retain(|kept| kept.head_oid != verdict.head_oid);
    earlier.push(verdict);
    let excess = earlier.len().saturating_sub(MAX_APPROVAL_VERDICTS);
    earlier.drain(..excess);
    earlier
}

/// An earlier review a new review may build on.
#[derive(Clone, Debug)]
pub struct CarriedReview {
    pub record: ReviewRecord,
}

/// What a review carried from an earlier one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedSummary {
    /// The head the earlier review covered.
    pub from_head: String,
    pub from_review: String,
    /// Changed files not sent to reviewers again, their change being the
    /// same as in the earlier review.
    pub paths: Vec<String>,
    /// Findings carried on those files.
    pub findings: usize,
}

/// Each changed file's base and head content.
pub fn reviewed_files(
    root: &Path,
    change_set: &ChangeSet,
) -> Result<BTreeMap<String, ReviewedFile>, String> {
    change_set
        .files
        .iter()
        .map(|file| {
            let path = Path::new(&file.path);
            let base = vee_git::read_snapshot_base_file(root, change_set, path)?;
            let head = vee_git::read_snapshot_file(root, change_set, path)?;
            Ok((
                file.path.clone(),
                ReviewedFile {
                    base: base.as_deref().map(digest),
                    head: head.as_deref().map(digest),
                },
            ))
        })
        .collect()
}

/// What a new review takes from an earlier one: the changed files whose
/// change is the same, and the earlier findings on them. `None` when nothing
/// can be carried: another configuration, no file the same, or an earlier
/// finding without a location, which could concern any file.
pub(crate) fn carry(
    carried: &CarriedReview,
    current: &BTreeMap<String, ReviewedFile>,
    config_digest: &str,
    selected_reviewers: &[String],
) -> Option<(BTreeSet<String>, Vec<Finding>, CarriedSummary)> {
    let record = &carried.record;
    if record.config_digest != config_digest
        || record
            .findings
            .iter()
            .any(|finding| finding.path.is_none() || finding.line.is_none())
    {
        return None;
    }
    let paths: BTreeSet<String> = current
        .iter()
        .filter(|(path, file)| record.files.get(*path) == Some(file))
        .map(|(path, _)| path.clone())
        .collect();
    if paths.is_empty() {
        return None;
    }
    let findings: Vec<Finding> = record
        .findings
        .iter()
        .filter(|finding| {
            finding
                .path
                .as_ref()
                .is_some_and(|path| paths.contains(path))
        })
        .filter(|finding| {
            finding
                .reviewer_ids
                .iter()
                .any(|reviewer| selected_reviewers.contains(reviewer))
        })
        .cloned()
        .collect();
    let summary = CarriedSummary {
        from_head: record.head_oid.clone(),
        from_review: record.review_id.clone(),
        paths: paths.iter().cloned().collect(),
        findings: findings.len(),
    };
    Some((paths, findings, summary))
}

/// The record as a hidden marker, or `None` when it is too large for a comment.
pub fn encode(record: &ReviewRecord) -> Option<String> {
    let json = serde_json::to_vec(record).ok()?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json);
    (encoded.len() <= MAX_RECORD_CHARS).then(|| format!("{RECORD_MARKER}{encoded} -->"))
}

/// The record in a comment's body, if it has a valid one.
pub fn decode(body: &str) -> Option<ReviewRecord> {
    let start = body.find(RECORD_MARKER)? + RECORD_MARKER.len();
    let end = body[start..].find(" -->")?;
    let json = base64::engine::general_purpose::STANDARD
        .decode(body[start..start + end].trim())
        .ok()?;
    let record: ReviewRecord = serde_json::from_slice(&json).ok()?;
    (record.schema_version == 1).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(path: Option<&str>, reviewer: &str) -> Finding {
        Finding {
            id: format!("f-{}", path.unwrap_or("none")),
            fingerprint: format!("fp-{}", path.unwrap_or("none")),
            category: "correctness".into(),
            severity: vee_core::Severity::High,
            confidence: Some(90),
            rationale: "Drops the result -- callers rely on it.".into(),
            path: path.map(str::to_owned),
            line: path.map(|_| 1),
            provenance: "model_inference".into(),
            reviewer_ids: vec![reviewer.into()],
            evidence_ids: vec![],
            rule_attributions: vec![],
            sample_agreement: None,
            advisory: false,
            suggestion: None,
        }
    }

    fn file(base: &str, head: &str) -> ReviewedFile {
        ReviewedFile {
            base: Some(base.into()),
            head: Some(head.into()),
        }
    }

    fn record(findings: Vec<Finding>) -> CarriedReview {
        CarriedReview {
            record: ReviewRecord {
                schema_version: 1,
                repository: "acme/app".into(),
                number: 9,
                head_oid: "h1".into(),
                review_id: "r1".into(),
                config_digest: "c".into(),
                files: BTreeMap::from([
                    ("a.rs".into(), file("a0", "a1")),
                    ("b.rs".into(), file("b0", "b1")),
                ]),
                findings,
                approvals: vec![],
            },
        }
    }

    #[test]
    fn only_files_whose_change_is_the_same_are_carried() {
        let earlier = record(vec![
            finding(Some("a.rs"), "correctness"),
            finding(Some("b.rs"), "correctness"),
        ]);
        let current = BTreeMap::from([
            ("a.rs".into(), file("a0", "a1")),
            ("b.rs".into(), file("b0", "b2")),
            ("c.rs".into(), file("c0", "c1")),
        ]);
        let (paths, findings, summary) =
            carry(&earlier, &current, "c", &["correctness".into()]).unwrap();
        assert_eq!(paths, BTreeSet::from(["a.rs".to_owned()]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path.as_deref(), Some("a.rs"));
        assert_eq!(summary.from_head, "h1");

        // A rebase that changes a file's base is a different change.
        let rebased = BTreeMap::from([("a.rs".into(), file("a9", "a1"))]);
        assert!(carry(&earlier, &rebased, "c", &["correctness".into()]).is_none());
    }

    #[test]
    fn nothing_is_carried_across_configurations_or_with_an_unlocated_finding() {
        let current = BTreeMap::from([("a.rs".into(), file("a0", "a1"))]);
        assert!(carry(&record(vec![]), &current, "other", &[]).is_none());
        assert!(carry(
            &record(vec![finding(None, "correctness")]),
            &current,
            "c",
            &["correctness".into()]
        )
        .is_none());
        // A reviewer no longer selected keeps none of its findings.
        let (_, findings, _) = carry(
            &record(vec![finding(Some("a.rs"), "security")]),
            &current,
            "c",
            &["correctness".into()],
        )
        .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn a_verdict_replaces_one_on_the_same_head_and_history_is_bounded() {
        let verdict = |head: &str, eligible: bool| ApprovalVerdict {
            head_oid: head.into(),
            review_id: "r".into(),
            eligible,
            approved: false,
            failed_stages: vec![],
        };
        let history = append_verdict(vec![verdict("h1", false)], verdict("h1", true));
        assert_eq!(history, vec![verdict("h1", true)]);
        let mut history = Vec::new();
        for index in 0..60 {
            history = append_verdict(history, verdict(&format!("h{index}"), true));
        }
        assert_eq!(history.len(), MAX_APPROVAL_VERDICTS);
        assert_eq!(history[0].head_oid, "h10");
    }

    #[test]
    fn the_record_survives_a_comment_and_a_large_one_is_left_out() {
        let earlier = record(vec![finding(Some("a.rs"), "correctness")]).record;
        let marker = encode(&earlier).unwrap();
        assert!(!marker[RECORD_MARKER.len()..marker.len() - 4].contains("--"));
        let body = format!("**Vee** summary\n\n{marker}\n");
        assert_eq!(decode(&body), Some(earlier.clone()));
        assert_eq!(decode("no record"), None);
        assert_eq!(decode(&format!("{RECORD_MARKER}not base64 -->")), None);
        let mut large = earlier;
        large.findings = (0..200)
            .map(|index| {
                let mut finding = finding(Some("a.rs"), "correctness");
                finding.rationale = format!("{index} {}", "x".repeat(400));
                finding
            })
            .collect();
        assert_eq!(encode(&large), None);
    }
}
