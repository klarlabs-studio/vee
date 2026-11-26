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

/// Context lines around each hunk. A later edit this close to a hunk changes
/// it, so the hunk is reviewed again.
const HUNK_CONTEXT: usize = 3;
/// A file whose diff is larger than this has no hunks recorded.
const MAX_HUNK_DIFF_BYTES: usize = 1 << 20;
/// Hex digits of a hunk's digest kept in the record. Hunks are only matched
/// within one file whose base is unchanged, so a short digest suffices and
/// keeps the record small.
const HUNK_DIGEST_CHARS: usize = 16;

/// The content of one changed file on both sides of the change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFile {
    /// Digest of the file at the base, or `None` when the change adds it.
    pub base: Option<String>,
    /// Digest of the file at the head, or `None` when the change deletes it.
    pub head: Option<String>,
    /// The change's hunks, when the file exists on both sides (ADR 0036).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunks: Vec<ReviewedHunk>,
}

impl ReviewedFile {
    fn same_content(&self, other: &Self) -> bool {
        self.base == other.base && self.head == other.head
    }
}

/// One hunk of a file's change, with three lines of context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedHunk {
    /// Digest of the hunk's rows, without their line numbers.
    pub digest: String,
    /// The first head line the hunk spans.
    pub start: u32,
    /// The head lines it spans; 0 when it only deletes.
    pub lines: u32,
}

impl ReviewedHunk {
    fn contains(&self, line: u32) -> bool {
        line >= self.start && line - self.start < self.lines
    }
}

/// The hunks of the change from `base` to `head`; none when either side is
/// missing, the diff is not textual, or it is too large.
pub(crate) fn change_hunks(
    base: Option<&[u8]>,
    head: Option<&[u8]>,
) -> Result<Vec<ReviewedHunk>, String> {
    if base.is_none() || head.is_none() || base == head {
        return Ok(Vec::new());
    }
    Ok(
        crate::text_diff(base, head, MAX_HUNK_DIFF_BYTES, HUNK_CONTEXT)?
            .map(|diff| parse_hunks(&diff))
            .unwrap_or_default(),
    )
}

fn parse_hunks(diff: &str) -> Vec<ReviewedHunk> {
    fn finish((start, lines, rows): (u32, u32, String)) -> ReviewedHunk {
        let digest = digest(rows.as_bytes());
        let hex = digest.trim_start_matches("sha256:");
        ReviewedHunk {
            digest: hex[..HUNK_DIGEST_CHARS.min(hex.len())].to_owned(),
            start,
            lines,
        }
    }
    let mut hunks = Vec::new();
    let mut current: Option<(u32, u32, String)> = None;
    for row in diff.lines() {
        if let Some(header) = row.strip_prefix("@@ ") {
            hunks.extend(current.take().map(finish));
            let Some((start, lines)) = head_range(header) else {
                return Vec::new();
            };
            current = Some((start, lines, String::new()));
        } else if let Some((_, _, rows)) = current.as_mut() {
            rows.push_str(row);
            rows.push('\n');
        }
    }
    hunks.extend(current.map(finish));
    hunks
}

/// The head range of a hunk header such as `-3,4 +5,6 @@ fn name`.
fn head_range(header: &str) -> Option<(u32, u32)> {
    let range = header
        .split_once(" @@")?
        .0
        .split_whitespace()
        .find_map(|range| range.strip_prefix('+'))?;
    let (start, lines) = match range.split_once(',') {
        Some((start, lines)) => (start.parse().ok()?, lines.parse().ok()?),
        None => (range.parse().ok()?, 1),
    };
    Some((start, lines))
}

/// The earlier and current hunks that are the same, each digest appearing
/// once on both sides.
fn matching_hunks<'a>(
    earlier: &'a [ReviewedHunk],
    current: &'a [ReviewedHunk],
) -> Vec<(&'a ReviewedHunk, &'a ReviewedHunk)> {
    let unique = |hunks: &'a [ReviewedHunk]| {
        let mut counts = BTreeMap::<&str, Vec<&'a ReviewedHunk>>::new();
        for hunk in hunks.iter().filter(|hunk| hunk.lines > 0) {
            counts.entry(hunk.digest.as_str()).or_default().push(hunk);
        }
        counts
            .into_iter()
            .filter_map(|(digest, hunks)| (hunks.len() == 1).then(|| (digest, hunks[0])))
            .collect::<BTreeMap<_, _>>()
    };
    let current = unique(current);
    unique(earlier)
        .into_iter()
        .filter_map(|(digest, earlier)| current.get(digest).map(|current| (earlier, *current)))
        .collect()
}

/// `finding` moved from an earlier hunk to the same hunk at the head, or
/// `None` when it is not inside one of `matches`.
fn shifted(finding: &Finding, matches: &[(&ReviewedHunk, &ReviewedHunk)]) -> Option<Finding> {
    let line = finding.line?;
    let (earlier, current) = matches.iter().find(|(earlier, _)| earlier.contains(line))?;
    let moved = |line: u32| line - earlier.start + current.start;
    let mut finding = finding.clone();
    finding.line = Some(moved(line));
    finding.suggestion = finding.suggestion.take().and_then(|mut suggestion| {
        earlier.contains(suggestion.end_line).then(|| {
            suggestion.end_line = moved(suggestion.end_line);
            suggestion
        })
    });
    Some(finding)
}

/// Whether `line` lies inside one of the inclusive `ranges`.
pub(crate) fn in_ranges(ranges: &[(u32, u32)], line: u32) -> bool {
    ranges
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&line))
}

/// `changed` without the ranges that lie inside a carried range.
pub(crate) fn uncarried_ranges(
    changed: Vec<(u64, u64)>,
    carried: &[(u32, u32)],
) -> Vec<(u64, u64)> {
    changed
        .into_iter()
        .filter(|(start, end)| {
            !carried
                .iter()
                .any(|(from, to)| u64::from(*from) <= *start && *end <= u64::from(*to))
        })
        .collect()
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
    /// The repository standards the review used (ADR 0028). A record made
    /// with other standards carries nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standards_digest: Option<String>,
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
    /// True when Vee did not approve an eligible head because it had reached
    /// `approval.max_per_day`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rate_limited: bool,
    /// The approval stages that failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_stages: Vec<String>,
    /// The approval-condition classification this verdict used, so a later
    /// run on the same head replays it instead of asking again (ADR 0035).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<crate::conditions::ConditionClassification>,
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
    /// Files reviewed again whose unchanged hunks kept their findings
    /// (ADR 0036).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_paths: Vec<String>,
    /// Findings carried on those files.
    pub findings: usize,
}

/// What a new review takes from an earlier one.
#[derive(Clone, Debug)]
pub(crate) struct Carry {
    /// Changed files not sent to reviewers again.
    pub paths: BTreeSet<String>,
    /// Files sent again, with the inclusive head line ranges of the hunks
    /// that are the same as before.
    pub lines: BTreeMap<String, Vec<(u32, u32)>>,
    pub findings: Vec<Finding>,
    pub summary: CarriedSummary,
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
                    hunks: change_hunks(base.as_deref(), head.as_deref())?,
                },
            ))
        })
        .collect()
}

/// What a new review takes from an earlier one:
///
/// - the changed files whose change is the same, and the earlier findings on
///   them;
/// - in files whose base is the same but whose head changed, the hunks that
///   are the same, and the earlier findings inside them, moved with the hunk
///   (ADR 0036).
///
/// `None` when nothing can be carried: another configuration, nothing the
/// same, or an earlier finding without a location, which could concern any
/// file.
pub(crate) fn carry(
    carried: &CarriedReview,
    current: &BTreeMap<String, ReviewedFile>,
    config_digest: &str,
    standards_digest: Option<&str>,
    selected_reviewers: &[String],
) -> Option<Carry> {
    let record = &carried.record;
    if record.config_digest != config_digest
        || record.standards_digest.as_deref() != standards_digest
        || record
            .findings
            .iter()
            .any(|finding| finding.path.is_none() || finding.line.is_none())
    {
        return None;
    }
    let mut paths = BTreeSet::new();
    let mut partial = BTreeMap::new();
    for (path, file) in current {
        let Some(earlier) = record.files.get(path) else {
            continue;
        };
        if earlier.same_content(file) {
            paths.insert(path.clone());
        } else if earlier.base.is_some() && earlier.base == file.base {
            let matches = matching_hunks(&earlier.hunks, &file.hunks);
            if !matches.is_empty() {
                partial.insert(path.clone(), matches);
            }
        }
    }
    if paths.is_empty() && partial.is_empty() {
        return None;
    }
    let findings: Vec<Finding> = record
        .findings
        .iter()
        .filter(|finding| {
            finding
                .reviewer_ids
                .iter()
                .any(|reviewer| selected_reviewers.contains(reviewer))
        })
        .filter_map(|finding| {
            let path = finding.path.as_ref()?;
            if paths.contains(path) {
                return Some(finding.clone());
            }
            shifted(finding, partial.get(path)?)
        })
        .collect();
    let lines = partial
        .iter()
        .map(|(path, matches)| {
            let ranges = matches
                .iter()
                .map(|(_, current)| (current.start, current.start + current.lines - 1))
                .collect();
            (path.clone(), ranges)
        })
        .collect();
    let summary = CarriedSummary {
        from_head: record.head_oid.clone(),
        from_review: record.review_id.clone(),
        paths: paths.iter().cloned().collect(),
        partial_paths: partial.keys().cloned().collect(),
        findings: findings.len(),
    };
    Some(Carry {
        paths,
        lines,
        findings,
        summary,
    })
}

/// The record as a hidden marker, or `None` when it is too large for a comment.
///
/// When the hunks make it too large, they are left out: the next review then
/// carries whole files only.
pub fn encode(record: &ReviewRecord) -> Option<String> {
    encode_exactly(record).or_else(|| {
        let mut smaller = record.clone();
        for file in smaller.files.values_mut() {
            file.hunks.clear();
        }
        encode_exactly(&smaller)
    })
}

fn encode_exactly(record: &ReviewRecord) -> Option<String> {
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
            hunks: vec![],
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
                standards_digest: None,
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
        let Carry {
            paths,
            findings,
            summary,
            ..
        } = carry(&earlier, &current, "c", None, &["correctness".into()]).unwrap();
        assert_eq!(paths, BTreeSet::from(["a.rs".to_owned()]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path.as_deref(), Some("a.rs"));
        assert_eq!(summary.from_head, "h1");

        // A rebase that changes a file's base is a different change.
        let rebased = BTreeMap::from([("a.rs".into(), file("a9", "a1"))]);
        assert!(carry(&earlier, &rebased, "c", None, &["correctness".into()]).is_none());
    }

    fn lines(count: usize, changed: &[(usize, &str)], inserted: Option<usize>) -> Vec<u8> {
        let mut rows: Vec<String> = (1..=count).map(|line| format!("line {line}")).collect();
        for (line, text) in changed {
            rows[line - 1] = (*text).to_owned();
        }
        if let Some(after) = inserted {
            rows.insert(after, "inserted".into());
        }
        (rows.join("\n") + "\n").into_bytes()
    }

    fn at(path: &str, line: u32) -> Finding {
        let mut finding = finding(Some(path), "correctness");
        finding.id = format!("f-{line}");
        finding.line = Some(line);
        finding
    }

    #[test]
    fn hunk_headers_give_the_head_lines() {
        assert_eq!(head_range("-3,4 +5,6 @@ fn name"), Some((5, 6)));
        assert_eq!(head_range("-3 +7 @@"), Some((7, 1)));
        assert_eq!(head_range("-3,2 +2,0 @@"), Some((2, 0)));
        assert_eq!(head_range("garbage"), None);
        assert!(change_hunks(None, Some(b"new\n")).unwrap().is_empty());
    }

    #[test]
    fn unchanged_hunks_of_a_changed_file_keep_their_findings_where_they_moved() {
        let base = lines(60, &[], None);
        let first = lines(60, &[(5, "first edit"), (40, "kept edit")], None);
        // The next push edits line 5 again and inserts a line above the
        // other hunk, moving it down by one.
        let second = lines(60, &[(5, "second edit"), (40, "kept edit")], Some(10));
        let earlier_hunks = change_hunks(Some(&base), Some(&first)).unwrap();
        let current_hunks = change_hunks(Some(&base), Some(&second)).unwrap();
        assert_eq!(earlier_hunks.len(), 2);
        let mut earlier = record(vec![at("a.rs", 5), at("a.rs", 40)]);
        earlier.record.files = BTreeMap::from([(
            "a.rs".into(),
            ReviewedFile {
                base: Some("a0".into()),
                head: Some("a1".into()),
                hunks: earlier_hunks,
            },
        )]);
        earlier.record.findings[1].suggestion = Some(vee_core::FindingSuggestion {
            end_line: 40,
            replacement: "fixed".into(),
        });
        let current = BTreeMap::from([(
            "a.rs".into(),
            ReviewedFile {
                base: Some("a0".into()),
                head: Some("a2".into()),
                hunks: current_hunks,
            },
        )]);
        let carry = carry(&earlier, &current, "c", None, &["correctness".into()]).unwrap();
        assert!(carry.paths.is_empty());
        assert_eq!(carry.lines["a.rs"], vec![(38, 44)]);
        assert_eq!(carry.findings.len(), 1);
        assert_eq!(carry.findings[0].line, Some(41));
        assert_eq!(carry.findings[0].suggestion.as_ref().unwrap().end_line, 41);
        assert_eq!(carry.summary.partial_paths, vec!["a.rs".to_owned()]);

        // After a rebase the base differs, and no hunk is carried.
        let mut rebased = current.clone();
        rebased.get_mut("a.rs").unwrap().base = Some("a9".into());
        assert!(super::carry(&earlier, &rebased, "c", None, &["correctness".into()]).is_none());
    }

    #[test]
    fn carried_ranges_are_not_pointed_out_again() {
        assert_eq!(
            uncarried_ranges(vec![(5, 5), (40, 40), (43, 50)], &[(38, 44)]),
            vec![(5, 5), (43, 50)]
        );
        assert!(in_ranges(&[(38, 44)], 44));
        assert!(!in_ranges(&[(38, 44)], 45));
    }

    #[test]
    fn nothing_is_carried_across_configurations_or_with_an_unlocated_finding() {
        let current = BTreeMap::from([("a.rs".into(), file("a0", "a1"))]);
        assert!(carry(&record(vec![]), &current, "other", None, &[]).is_none());
        // Other repository standards, as after merging a REVIEW.md change.
        assert!(carry(&record(vec![]), &current, "c", Some("sha256:new"), &[]).is_none());
        assert!(carry(
            &record(vec![finding(None, "correctness")]),
            &current,
            "c",
            None,
            &["correctness".into()]
        )
        .is_none());
        // A reviewer no longer selected keeps none of its findings.
        let Carry { findings, .. } = carry(
            &record(vec![finding(Some("a.rs"), "security")]),
            &current,
            "c",
            None,
            &["correctness".into()],
        )
        .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn a_verdict_replaces_one_on_the_same_head_and_history_is_bounded() {
        let verdict = |head: &str, eligible: bool| ApprovalVerdict {
            conditions: None,
            head_oid: head.into(),
            review_id: "r".into(),
            eligible,
            approved: false,
            rate_limited: false,
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

        // Hunks that do not fit are left out before the record is.
        let mut hunked = record(vec![]).record;
        hunked.files.get_mut("a.rs").unwrap().hunks = (0..3000)
            .map(|index| ReviewedHunk {
                digest: format!("{index:016x}"),
                start: index,
                lines: 7,
            })
            .collect();
        let decoded = decode(&encode(&hunked).unwrap()).unwrap();
        assert!(decoded.files.values().all(|file| file.hunks.is_empty()));
    }
}
