//! Team analytics without a server (roadmap item 13): one report over the
//! analytics documents a team collects from its repositories and CI runs.
//!
//! The inputs are documents Vee already writes:
//! - `quality-analytics` from `vee analytics --output json`;
//! - `approval-report` from `vee ci approvals --output json`;
//! - `rule-effectiveness` from `vee rules effectiveness --output json`.
//!
//! Counts are summed and every rate is recomputed from the summed numerator
//! and denominator, never averaged across sources. Nothing names a person:
//! the inputs hold no authors, and per-pull-request cases are left out.

use crate::analytics::{FeedbackRate, QualityAnalytics};
use crate::failure::usage_failure;
use crate::rule_candidates::{EffectivenessWindow, RuleEffectivenessReport};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const TEAM_ANALYTICS_SCHEMA_VERSION: u32 = 1;
/// The largest input document read.
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
/// The most input documents one report reads.
const MAX_SOURCES: usize = 1000;

/// What kind of analytics document a source is.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    QualityAnalytics,
    ApprovalReport,
    RuleEffectiveness,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QualityAnalytics => "quality analytics",
            Self::ApprovalReport => "approval report",
            Self::RuleEffectiveness => "rule effectiveness",
        }
    }
}

/// One document the report read, and its contribution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TeamSource {
    /// The repository an approval report names, or the label given with
    /// `NAME=PATH`, or the file name.
    pub label: String,
    pub path: String,
    pub kind: SourceKind,
    /// Saved reviews, for quality analytics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviews: Option<usize>,
    /// Latest gate decisions by status, for quality analytics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gate_decisions: BTreeMap<String, usize>,
    /// Pull requests with a head Vee called eligible, for approval reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
}

/// A file the report did not use, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedSource {
    pub path: String,
    pub reason: String,
}

/// Provider token use and estimated cost, summed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct TeamCost {
    pub reported_runs: usize,
    pub unreported_runs: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The sum over runs with a configured price; `None` when no run had one.
    pub estimated_cost_usd: Option<f64>,
    pub priced_runs: usize,
    pub unpriced_runs: usize,
}

/// Approval verdicts against what happened to the pull requests, summed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct TeamApprovals {
    pub repositories: usize,
    pub pull_requests_read: usize,
    pub with_verdicts: usize,
    /// The denominator of both rates.
    pub eligible: usize,
    pub outcomes: BTreeMap<String, usize>,
    pub agreement_rate: Option<f64>,
    pub override_rate: Option<f64>,
}

/// Feedback on approved rules' findings before and after activation, summed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TeamRules {
    pub rule_approvals: usize,
    pub baseline: EffectivenessWindow,
    pub after_activation: EffectivenessWindow,
}

/// `team-analytics-v1`: one report over many repositories' analytics.
#[derive(Debug, Serialize, Deserialize)]
pub struct TeamAnalytics {
    pub schema_version: u32,
    pub sources: Vec<TeamSource>,
    pub skipped: Vec<SkippedSource>,
    pub reviews: usize,
    pub reviews_without_gate_decision: usize,
    /// Latest gate decision per review, by status.
    pub gate_decisions: BTreeMap<String, usize>,
    pub findings_by_severity: BTreeMap<String, usize>,
    pub finding_accuracy: FeedbackRate,
    pub actionability: FeedbackRate,
    /// Verification runs by profile and result.
    pub verification_runs: BTreeMap<String, BTreeMap<String, usize>>,
    pub cost: TeamCost,
    pub approvals: TeamApprovals,
    pub rules: TeamRules,
    pub limitations: Vec<String>,
}

fn rate(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

fn add_counts(into: &mut BTreeMap<String, usize>, from: &BTreeMap<String, usize>) {
    for (key, count) in from {
        *into.entry(key.clone()).or_insert(0) += count;
    }
}

fn add_feedback(into: &mut FeedbackRate, from: &FeedbackRate) {
    into.positive_occurrences += from.positive_occurrences;
    into.negative_occurrences += from.negative_occurrences;
    into.disputed_occurrences += from.disputed_occurrences;
    into.denominator += from.denominator;
    into.observed_rate = rate(into.positive_occurrences, into.denominator);
}

fn add_window(into: &mut EffectivenessWindow, from: &EffectivenessWindow) {
    into.accuracy_denominator += from.accuracy_denominator;
    into.false_positive_count += from.false_positive_count;
    into.false_positive_rate = rate(into.false_positive_count, into.accuracy_denominator);
    into.actionability_denominator += from.actionability_denominator;
    into.not_actionable_count += from.not_actionable_count;
    into.not_actionable_rate = rate(into.not_actionable_count, into.actionability_denominator);
    into.disputed_occurrences += from.disputed_occurrences;
}

/// The files `inputs` name: each file, and each `.json` file directly in a
/// directory, in name order. An input may be `NAME=PATH` to label it.
fn expand(inputs: &[String]) -> Result<Vec<(Option<String>, PathBuf)>> {
    let mut files = Vec::new();
    for input in inputs {
        let (label, path) = match input.split_once('=') {
            Some((label, path)) if !label.is_empty() && !Path::new(input).exists() => {
                (Some(label.to_owned()), PathBuf::from(path))
            }
            _ => (None, PathBuf::from(input)),
        };
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|entry| {
                    entry.is_file()
                        && entry
                            .extension()
                            .is_some_and(|extension| extension == "json")
                })
                .collect();
            entries.sort();
            files.extend(entries.into_iter().map(|entry| (label.clone(), entry)));
        } else {
            files.push((label, path));
        }
    }
    if files.len() > MAX_SOURCES {
        return Err(usage_failure(format!(
            "{} documents is more than the {MAX_SOURCES} one report reads",
            files.len()
        )));
    }
    Ok(files)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("cannot open it: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read it: {error}"))?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("it is over 16 MiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "it is not JSON".into())
}

fn kind_of(document: &Value) -> Option<SourceKind> {
    let has = |key: &str| document.get(key).is_some();
    if has("review_count") && has("latest_gate_decisions") {
        Some(SourceKind::QualityAnalytics)
    } else if has("agreement_rate") && has("eligible") && has("outcomes") {
        Some(SourceKind::ApprovalReport)
    } else if has("approvals") && has("limitations") && !has("review_count") {
        Some(SourceKind::RuleEffectiveness)
    } else {
        None
    }
}

fn file_label(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// `vee analytics aggregate`: one report over the analytics documents in
/// `inputs` (files, directories of `.json` files, or `NAME=PATH`).
pub fn aggregate(inputs: &[String]) -> Result<TeamAnalytics> {
    if inputs.is_empty() {
        return Err(usage_failure(
            "name at least one analytics document or directory",
        ));
    }
    let mut report = TeamAnalytics {
        schema_version: TEAM_ANALYTICS_SCHEMA_VERSION,
        sources: Vec::new(),
        skipped: Vec::new(),
        reviews: 0,
        reviews_without_gate_decision: 0,
        gate_decisions: BTreeMap::new(),
        findings_by_severity: BTreeMap::new(),
        finding_accuracy: FeedbackRate::default(),
        actionability: FeedbackRate::default(),
        verification_runs: BTreeMap::new(),
        cost: TeamCost::default(),
        approvals: TeamApprovals::default(),
        rules: TeamRules::default(),
        limitations: vec![
            "Counts are summed and rates recomputed from the summed numerators and denominators; a document given twice is counted twice.".into(),
            "No person is named: the documents hold no authors, and per-pull-request cases are not copied.".into(),
            "Estimated cost covers only runs with explicit token usage and a configured price; see priced_runs and unpriced_runs.".into(),
            "Quality analytics cover the reviews saved where each document was written; CI runners keep no history unless their store is kept between runs.".into(),
        ],
    };
    let mut priced_cost = 0.0;
    for (label, path) in expand(inputs)? {
        let shown = path.display().to_string();
        let skip = |reason: String| SkippedSource {
            path: shown.clone(),
            reason,
        };
        let document = match read_json(&path) {
            Ok(document) => document,
            Err(reason) => {
                report.skipped.push(skip(reason));
                continue;
            }
        };
        let Some(kind) = kind_of(&document) else {
            report.skipped.push(skip(
                "it is not a quality analytics, approval report or rule effectiveness document"
                    .into(),
            ));
            continue;
        };
        let mut source = TeamSource {
            label: label.clone().unwrap_or_else(|| file_label(&path)),
            path: shown.clone(),
            kind,
            reviews: None,
            gate_decisions: BTreeMap::new(),
            eligible: None,
            agreement_rate: None,
            estimated_cost_usd: None,
        };
        match kind {
            SourceKind::QualityAnalytics => {
                let quality: QualityAnalytics = match serde_json::from_value(document) {
                    Ok(quality) => quality,
                    Err(error) => {
                        report
                            .skipped
                            .push(skip(format!("its quality analytics do not read: {error}")));
                        continue;
                    }
                };
                report.reviews += quality.review_count;
                report.reviews_without_gate_decision += quality.reviews_without_gate_decision;
                add_counts(&mut report.gate_decisions, &quality.latest_gate_decisions);
                add_counts(
                    &mut report.findings_by_severity,
                    &quality.findings_by_severity,
                );
                add_feedback(
                    &mut report.finding_accuracy,
                    &quality.reviewed_feedback_metrics.finding_accuracy,
                );
                add_feedback(
                    &mut report.actionability,
                    &quality.reviewed_feedback_metrics.actionability,
                );
                for (profile, results) in &quality.verification_runs_by_profile {
                    add_counts(
                        report.verification_runs.entry(profile.clone()).or_default(),
                        results,
                    );
                }
                let mut source_cost = None;
                for usage in quality.provider_usage.values() {
                    report.cost.reported_runs += usage.reported_runs;
                    report.cost.unreported_runs += usage.unreported_runs;
                    report.cost.input_tokens += usage.input_tokens;
                    report.cost.output_tokens += usage.output_tokens;
                    report.cost.priced_runs += usage.priced_runs;
                    report.cost.unpriced_runs += usage.unpriced_runs;
                    if let Some(cost) = usage.estimated_cost_usd {
                        priced_cost += cost;
                        *source_cost.get_or_insert(0.0) += cost;
                        report.cost.estimated_cost_usd = Some(priced_cost);
                    }
                }
                source.reviews = Some(quality.review_count);
                source.gate_decisions = quality.latest_gate_decisions;
                source.estimated_cost_usd = source_cost;
            }
            SourceKind::ApprovalReport => {
                let count = |key: &str| document[key].as_u64().unwrap_or(0) as usize;
                let eligible = count("eligible");
                report.approvals.repositories += 1;
                report.approvals.pull_requests_read += count("pull_requests_read");
                report.approvals.with_verdicts += count("with_verdicts");
                report.approvals.eligible += eligible;
                if let Some(outcomes) = document["outcomes"].as_object() {
                    for (outcome, value) in outcomes {
                        *report
                            .approvals
                            .outcomes
                            .entry(outcome.clone())
                            .or_insert(0) += value.as_u64().unwrap_or(0) as usize;
                    }
                }
                if label.is_none() {
                    if let Some(repository) = document["repository"].as_str() {
                        source.label = repository.to_owned();
                    }
                }
                source.eligible = Some(eligible);
                source.agreement_rate = document["agreement_rate"].as_f64();
            }
            SourceKind::RuleEffectiveness => {
                let rules: RuleEffectivenessReport = match serde_json::from_value(document) {
                    Ok(rules) => rules,
                    Err(error) => {
                        report.skipped.push(skip(format!(
                            "its rule effectiveness does not read: {error}"
                        )));
                        continue;
                    }
                };
                for rule in &rules.approvals {
                    report.rules.rule_approvals += 1;
                    add_window(&mut report.rules.baseline, &rule.baseline);
                    add_window(&mut report.rules.after_activation, &rule.after_activation);
                }
            }
        }
        report.sources.push(source);
    }
    let agreed = report
        .approvals
        .outcomes
        .get("merged_as_eligible")
        .copied()
        .unwrap_or(0);
    report.approvals.agreement_rate = rate(agreed, report.approvals.eligible);
    report.approvals.override_rate = rate(
        report.approvals.eligible.saturating_sub(agreed),
        report.approvals.eligible,
    );
    if report.sources.is_empty() {
        return Err(usage_failure(format!(
            "none of the {} document(s) is a Vee analytics document",
            report.skipped.len()
        )));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(directory: &Path, name: &str, value: Value) -> String {
        let path = directory.join(name);
        std::fs::write(&path, value.to_string()).unwrap();
        path.display().to_string()
    }

    fn quality(
        reviews: usize,
        pass: usize,
        positive: usize,
        denominator: usize,
        cost: Option<f64>,
    ) -> Value {
        serde_json::json!({
            "schema_version": 9, "review_count": reviews,
            "latest_gate_decisions": {"pass": pass, "block": reviews - pass},
            "reviews_without_gate_decision": 0,
            "findings_by_status": {}, "findings_by_severity": {"high": 2},
            "verification_runs_by_profile": {"tests": {"passed": 3}},
            "test_diagnostics_by_profile": {}, "test_diagnostics_limitations": [],
            "reviewed_feedback_by_label": {},
            "reviewed_feedback_metrics": {
                "finding_accuracy": {"positive_occurrences": positive, "negative_occurrences": denominator - positive, "disputed_occurrences": 0, "denominator": denominator, "observed_rate": null},
                "actionability": {"positive_occurrences": 0, "negative_occurrences": 0, "disputed_occurrences": 0, "denominator": 0, "observed_rate": null}
            },
            "provider_latency": {}, "provider_latency_history_complete": true, "provider_latency_note": "",
            "provider_usage": {"fake": {"reported_runs": 2, "unreported_runs": 0, "input_tokens": 100, "output_tokens": 10, "total_tokens": 110, "estimated_cost_usd": cost, "priced_runs": if cost.is_some() {2} else {0}, "unpriced_runs": if cost.is_some() {0} else {2}}},
            "provider_usage_note": ""
        })
    }

    #[test]
    fn rates_come_from_summed_counts_and_nothing_else_is_read() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        // 1 of 1 accurate in one repository and 1 of 3 in the other: 2 of 4,
        // not the 0.67 an average of the two rates would give.
        write(root, "service.json", quality(4, 3, 1, 1, Some(0.5)));
        write(root, "web.json", quality(2, 1, 1, 3, None));
        write(
            root,
            "approvals.json",
            serde_json::json!({
                "schema_version": 1, "repository": "team/service", "pull_requests_read": 10,
                "with_verdicts": 6, "eligible": 4,
                "outcomes": {"merged_as_eligible": 3, "reverted_after_eligible": 1, "never_eligible": 2},
                "agreement_rate": 0.75, "override_rate": 0.25,
                "cases": [{"number": 1, "outcome": "merged_as_eligible", "eligible_heads": [], "approved_heads": []}],
                "limitations": []
            }),
        );
        write(root, "notes.json", serde_json::json!({"hello": "world"}));
        std::fs::write(root.join("broken.json"), "{").unwrap();

        let report = aggregate(&[root.display().to_string()]).unwrap();
        assert_eq!(report.sources.len(), 3);
        assert_eq!(report.skipped.len(), 2);
        assert_eq!(report.reviews, 6);
        assert_eq!(report.gate_decisions["pass"], 4);
        assert_eq!(report.gate_decisions["block"], 2);
        assert_eq!(report.findings_by_severity["high"], 4);
        assert_eq!(report.verification_runs["tests"]["passed"], 6);
        assert_eq!(report.finding_accuracy.denominator, 4);
        assert_eq!(report.finding_accuracy.observed_rate, Some(0.5));
        assert_eq!(report.cost.input_tokens, 200);
        assert_eq!(report.cost.estimated_cost_usd, Some(0.5));
        assert_eq!((report.cost.priced_runs, report.cost.unpriced_runs), (2, 2));
        assert_eq!(report.approvals.eligible, 4);
        assert_eq!(report.approvals.agreement_rate, Some(0.75));
        assert_eq!(report.approvals.override_rate, Some(0.25));
        let approvals = report
            .sources
            .iter()
            .find(|source| source.kind == SourceKind::ApprovalReport)
            .unwrap();
        assert_eq!(approvals.label, "team/service");
        // No case is copied into the report.
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("eligible_heads"));
    }

    #[test]
    fn a_label_names_a_source_and_nothing_usable_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = write(directory.path(), "export.json", quality(1, 1, 0, 0, None));
        let report = aggregate(&[format!("payments={path}")]).unwrap();
        assert_eq!(report.sources[0].label, "payments");
        let junk = write(directory.path(), "junk.json", serde_json::json!([]));
        assert!(aggregate(&[junk]).is_err());
        assert!(aggregate(&[]).is_err());
    }
}
