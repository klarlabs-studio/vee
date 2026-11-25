//! Views for analysis documents: change impact, test recommendations,
//! verification diagnostics, and analyzer results.

use crate::tone;
use crate::view::{Cell, Span, Style, ToView, Tone, View};
use vee_application::test_recommendations::{
    ExecutionCoverageFile, ExecutionCoverageSummary, TestRecommendationReport,
};
use vee_application::verification_diagnosis::VerificationDiagnosis;
use vee_application::{ChangeRisk, ImpactAssessment, RiskTier};
use vee_core::{AnalyzerReport, SarifLevel};

fn coverage(complete: bool) -> Cell {
    if complete {
        Cell::badge(Tone::Success, "complete")
    } else {
        Cell::badge(Tone::Warning, "incomplete")
    }
}

/// Code spans joined by commas, for short identifier lists.
fn code_list(items: &[String]) -> Cell {
    let mut cell = Cell::default();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            cell.spans.push(Span::new(", ", Style::Plain));
        }
        cell.spans.push(Span::new(item, Style::Code));
    }
    cell
}

fn limitations_view(limitations: &[String]) -> View {
    if limitations.is_empty() {
        return View::new();
    }
    View::new()
        .section("Limitations")
        .list(limitations.iter().map(Cell::plain).collect())
}

impl ToView for ImpactAssessment {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title("Impact assessment", Some(coverage(self.coverage_complete)))
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Changed paths".into(),
                    Cell::plain(self.changed_paths.len().to_string()),
                ),
                (
                    "Changed symbols".into(),
                    if self.changed_symbols.is_empty() {
                        Cell::muted("none")
                    } else {
                        code_list(&self.changed_symbols)
                    },
                ),
            ]);
        if !self.coverage_complete {
            view = view.note(
                Tone::Warning,
                "Impact analysis is incomplete; affected paths may be missing.",
            );
        }
        if !self.analyzers.is_empty() {
            view = view.section("Analyzers").table(
                &["Analyzer", "Version", "Status"],
                self.analyzers
                    .iter()
                    .map(|analyzer| {
                        vec![
                            Cell::strong(&analyzer.id),
                            analyzer.version.as_deref().map_or_else(
                                || Cell::muted("–"),
                                |v| Cell::plain(short_version(v)),
                            ),
                            tone::status_text(&analyzer.status),
                        ]
                    })
                    .collect(),
            );
        }
        view = view.section(format!("Affected paths ({})", self.paths.len()));
        view = if self.paths.is_empty() {
            view.paragraph(Cell::muted("No affected paths found."))
        } else {
            view.table(
                &["Affected", "Changed", "Symbol", "Relationship", "Certainty"],
                self.paths
                    .iter()
                    .map(|edge| {
                        // A co-change edge has no line or symbol; its
                        // evidence is how often the files changed together.
                        let (location, via) = match edge.co_change {
                            Some(history) => (
                                Cell::code(&edge.affected_path),
                                Cell::muted(format!(
                                    "changed together in {} of {} commits",
                                    history.together, history.source_commits
                                )),
                            ),
                            None => (
                                Cell::code(format!(
                                    "{}:{}",
                                    edge.affected_path, edge.evidence_line
                                )),
                                Cell::code(&edge.symbol),
                            ),
                        };
                        vec![
                            location,
                            Cell::code(&edge.source_path),
                            via,
                            Cell::plain(&edge.relationship),
                            Cell::plain(&edge.certainty),
                        ]
                    })
                    .collect(),
            )
        };
        if !self.groups.is_empty() {
            view = view.section("Package groups").table(
                &["Package", "Changed", "Members", "Certainty"],
                self.groups
                    .iter()
                    .map(|group| {
                        vec![
                            Cell::code(&group.package_id),
                            Cell::plain(group.changed_paths.len().to_string()),
                            Cell::plain(group.member_paths.len().to_string()),
                            Cell::plain(&group.certainty),
                        ]
                    })
                    .collect(),
            );
        }
        view.extend(limitations_view(&self.limitations))
    }
}

impl ToView for TestRecommendationReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Test recommendations ({})", self.recommendations.len()),
                None,
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Impact coverage".into(), coverage(self.coverage_complete)),
            ]);
        if let Some(summary) = &self.execution_coverage {
            view = view.extend(execution_coverage_view(summary));
        }
        view = view.section("Recommendations");
        view = if self.recommendations.is_empty() {
            view.paragraph(Cell::muted(
                "No changed source file lacks a likely test reference.",
            ))
        } else {
            view.list(
                self.recommendations
                    .iter()
                    .map(|recommendation| {
                        Cell::code(&recommendation.changed_path)
                            .then(Span::new(&recommendation.action, Style::Plain))
                            .then(Span::new(&recommendation.rationale, Style::Muted))
                    })
                    .collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
    }
}

fn ratio(covered: u64, executable: u64, percent: Option<f64>) -> String {
    match percent {
        Some(percent) => format!("{covered}/{executable} ({percent:.1}%)"),
        None => format!("{covered}/{executable}"),
    }
}

fn changed_coverage(file: &ExecutionCoverageFile) -> Cell {
    match (file.changed_covered_lines, file.changed_executable_lines) {
        (Some(covered), Some(executable)) => {
            Cell::plain(ratio(covered, executable, file.changed_percent))
        }
        _ => Cell::muted("–"),
    }
}

fn execution_coverage_view(summary: &ExecutionCoverageSummary) -> View {
    let view = View::new().section("Execution coverage").fields(vec![
        ("Run".into(), Cell::id(&summary.run_id)),
        ("Profile".into(), Cell::plain(&summary.profile_id)),
        ("Status".into(), tone::status_text(&summary.status)),
    ]);
    let view = if summary.files.is_empty() {
        view.paragraph(Cell::muted("No coverage recorded for changed files."))
    } else {
        view.table(
            &["File", "Lines covered", "Changed lines covered", "Signal"],
            summary
                .files
                .iter()
                .map(|file| {
                    vec![
                        Cell::code(&file.path),
                        Cell::plain(ratio(
                            file.covered_lines,
                            file.executable_lines,
                            file.percent,
                        )),
                        changed_coverage(file),
                        Cell::plain(&file.signal),
                    ]
                })
                .collect(),
        )
    };
    view.list(summary.limitations.iter().map(Cell::muted).collect())
}

fn diagnosis_status(status: &str) -> Cell {
    match status {
        "timed_out" => Cell::badge(Tone::Danger, "timed out"),
        other => tone::status_text(other),
    }
}

impl ToView for VerificationDiagnosis {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Verification diagnosis {}", self.profile_id),
                Some(diagnosis_status(&self.status)),
            )
            .fields(vec![
                ("Run".into(), Cell::id(&self.run_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Targets".into(), code_list(&self.targets)),
            ])
            .section(format!("Diagnostics ({})", self.diagnostics.len()));
        view = if self.diagnostics.is_empty() {
            view.paragraph(Cell::muted("No recognized failure lines."))
        } else {
            view.list(
                self.diagnostics
                    .iter()
                    .map(|item| {
                        let mut cell = Cell::code(format!("{}:{}", item.stream, item.line))
                            .then(Span::new(&item.kind, Style::Strong))
                            .then(Span::new(&item.text, Style::Plain));
                        if !item.referenced_changed_paths.is_empty() {
                            cell = cell.then(Span::new("— changed paths:", Style::Muted));
                            for (index, path) in item.referenced_changed_paths.iter().enumerate() {
                                if index > 0 {
                                    cell.spans.push(Span::new(",", Style::Plain));
                                }
                                cell = cell.then(Span::new(path, Style::Code));
                            }
                        }
                        cell
                    })
                    .collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
            .next_step(format!("vee verification show {}", self.run_id))
    }
}

fn sarif_level(level: SarifLevel) -> Cell {
    match level {
        SarifLevel::Error => Cell::badge(Tone::Danger, "error"),
        SarifLevel::Warning => Cell::badge(Tone::Warning, "warning"),
        SarifLevel::Note => Cell::badge(Tone::Info, "note"),
        SarifLevel::None => Cell::badge(Tone::Neutral, "none"),
    }
}

impl ToView for AnalyzerReport {
    fn to_view(&self) -> View {
        let badge = if !self.parsed {
            Cell::badge(Tone::Danger, "not evaluable")
        } else if self.findings.is_empty() {
            Cell::badge(Tone::Success, "clean")
        } else {
            Cell::badge(
                Tone::Warning,
                format!("{} on changed lines", self.findings.len()),
            )
        };
        let mut view = View::new()
            .title(format!("Analyzer run {}", self.profile_id), Some(badge))
            .fields(vec![
                ("Run".into(), Cell::id(&self.run_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Tools".into(), Cell::plain(self.tools.join(", "))),
                (
                    "Results".into(),
                    Cell::plain(format!(
                        "{} total, {} on changed lines",
                        self.results_total,
                        self.findings.len()
                    )),
                ),
                (
                    "Elsewhere".into(),
                    Cell::plain(self.results_outside_changes.to_string())
                        .then(Span::new("pre-existing, never blocking", Style::Muted)),
                ),
                (
                    "Suppressed".into(),
                    Cell::plain(self.results_suppressed.to_string())
                        .then(Span::new("by the tool", Style::Muted)),
                ),
            ]);
        if let Some(problem) = &self.problem {
            view = view.note(
                Tone::Danger,
                Cell::plain(format!("Not evaluable: {problem}")),
            );
        }
        view = view.section("Findings on changed lines");
        view = if self.findings.is_empty() {
            view.paragraph(Cell::muted(if self.parsed {
                "No analyzer results on changed lines."
            } else {
                "No results; the run produced no valid SARIF."
            }))
        } else {
            // Analyzer messages have no detail view, so the table keeps them whole.
            view.table(
                &["Level", "Location", "Rule", "ID", "Message"],
                self.findings
                    .iter()
                    .map(|finding| {
                        vec![
                            sarif_level(finding.level),
                            Cell::code(format!("{}:{}", finding.path, finding.line)),
                            Cell::plain(&finding.rule_id),
                            Cell::id(&finding.id),
                            Cell::plain(&finding.message),
                        ]
                    })
                    .collect(),
            )
        };
        view = view.extend(limitations_view(&self.limitations));
        if !self.parsed {
            view = view.next_action(
                format!("vee verification diagnose {}", self.run_id),
                "diagnose_verification",
                serde_json::json!({"run_id": self.run_id}),
            );
        }
        view
    }
}

/// A tool version fit for a table cell. Some tools report build metadata
/// (gopls prints its whole JSON build info), so keep its `Version` field, or
/// the first line shortened.
pub(crate) fn short_version(version: &str) -> String {
    serde_json::from_str::<serde_json::Value>(version)
        .ok()
        .and_then(|info| {
            info.get("Version")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| crate::view::summary(version, 32))
}

fn risk_tier(tier: RiskTier) -> Cell {
    match tier {
        RiskTier::Low => Cell::badge(Tone::Success, "low"),
        RiskTier::Elevated => Cell::badge(Tone::Warning, "elevated"),
        RiskTier::High => Cell::badge(Tone::Danger, "high"),
    }
}

impl ToView for ChangeRisk {
    fn to_view(&self) -> View {
        let flagged = self.factors.iter().filter(|factor| factor.flagged).count();
        let view = View::new()
            .title("Change risk", Some(risk_tier(self.tier)))
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Flagged factors".into(),
                    Cell::plain(format!("{flagged} of {}", self.factors.len())),
                ),
            ])
            .section("Factors")
            .table(
                &["Factor", "Value", "Flag at", "Detail"],
                self.factors
                    .iter()
                    .map(|factor| {
                        let label = if factor.flagged {
                            Cell::badge(Tone::Warning, &factor.label)
                        } else {
                            Cell::plain(&factor.label)
                        };
                        vec![
                            label,
                            Cell::plain(factor.value.to_string()),
                            Cell::muted(format!("≥ {}", factor.threshold)),
                            if factor.detail.is_empty() {
                                Cell::muted("none")
                            } else {
                                Cell::plain(&factor.detail)
                            },
                        ]
                    })
                    .collect(),
            )
            .section("Basis")
            .list(
                self.factors
                    .iter()
                    .map(|factor| Cell::plain(format!("{}: {}", factor.label, factor.basis)))
                    .collect(),
            );
        view.extend(limitations_view(&self.limitations))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn analyzer_versions_reported_as_build_info_json_show_only_the_version() {
        let json = r#"{"GoVersion":"go1.26.2","Path":"golang.org/x/tools/gopls","Version":"v0.21.1","Deps":[]}"#;
        assert_eq!(super::short_version(json), "v0.21.1");
        assert_eq!(super::short_version("go1.23"), "go1.23");
        assert_eq!(super::short_version(&"x".repeat(50)).chars().count(), 32);
    }
}
