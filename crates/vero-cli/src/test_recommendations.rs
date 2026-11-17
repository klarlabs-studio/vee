use serde::Serialize;
use vero_application::ImpactAssessment;

#[derive(Clone, Debug, Serialize)]
pub struct TestRecommendationReport {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub coverage_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_coverage: Option<ExecutionCoverageSummary>,
    pub recommendations: Vec<TestRecommendation>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionCoverageSummary {
    pub run_id: String,
    pub profile_id: String,
    pub status: String,
    pub files: Vec<ExecutionCoverageFile>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionCoverageFile {
    pub path: String,
    pub covered_lines: u64,
    pub executable_lines: u64,
    pub percent: Option<f64>,
    pub changed_line_count: Option<u64>,
    pub changed_executable_lines: Option<u64>,
    pub changed_covered_lines: Option<u64>,
    pub changed_percent: Option<f64>,
    pub signal: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TestRecommendation {
    pub changed_path: String,
    pub rationale: String,
    pub action: String,
}

pub fn recommend_with_coverage(
    impact: &ImpactAssessment,
    coverage: Option<ExecutionCoverageSummary>,
) -> TestRecommendationReport {
    let mut recommendations = Vec::new();
    let mut limitations = impact.limitations.clone();
    for limitation in [
            "Recommendations use bounded Go/Rust/TypeScript/JavaScript/Python/Java impact references and do not measure executed test coverage.",
        "Dynamic dispatch, generated code, build tags, and references outside the scanned source may be missed.",
        "A missing likely-test edge does not establish that a change is untested.",
    ] {
        if !limitations.iter().any(|existing| existing == limitation) {
            limitations.push(limitation.into());
        }
    }
    for changed_path in &impact.changed_paths {
        if ![
            ".rs", ".go", ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".py", ".java",
        ]
        .iter()
        .any(|extension| changed_path.ends_with(extension))
        {
            continue;
        }
        let has_test_reference = impact.paths.iter().any(|edge| {
            edge.source_path == *changed_path && edge.relationship == "likely_test_reference"
        });
        if has_test_reference {
            continue;
        }
        let coverage_signal = coverage
            .as_ref()
            .and_then(|summary| summary.files.iter().find(|file| file.path == *changed_path));
        let (rationale, action) = match coverage_signal {
            Some(file) => {
                let file_coverage = if file.executable_lines > 0 {
                    format!(
                        "file-level executable coverage is {}/{} ({:.1}%)",
                        file.covered_lines,
                        file.executable_lines,
                        file.percent.unwrap_or(0.0)
                    )
                } else {
                    "the LCOV artifact reports no executable lines for this file".to_owned()
                };
                let changed_coverage = match (
                    file.changed_executable_lines,
                    file.changed_covered_lines,
                    file.changed_percent,
                ) {
                    (Some(executable), Some(covered), Some(percent)) => format!(
                        "changed executable-line coverage is {covered}/{executable} ({percent:.1}%) across {} added or modified lines",
                        file.changed_line_count.unwrap_or(0)
                    ),
                    (Some(0), Some(_), _) => format!(
                        "no changed executable lines were identified across {} added or modified lines",
                        file.changed_line_count.unwrap_or(0)
                    ),
                    _ => "changed-line coverage is unavailable for this file".to_owned(),
                };
                (
                    format!("No likely test reference was found; the selected snapshot-bound coverage run reports {file_coverage}, and {changed_coverage}. These are profile-specific signals, not proof that the change is adequately tested."),
                    "Investigate the changed behavior with the reported verification profile and add or update targeted tests if needed.".to_owned(),
                )
            }
            _ => (
                "No likely test reference was found by the available impact analyzers; this is a gap signal, not proof that coverage is absent.".to_owned(),
                "Review whether existing tests cover this change and add or update targeted tests where needed.".to_owned(),
            ),
        };
        recommendations.push(TestRecommendation {
            changed_path: changed_path.clone(),
            rationale,
            action,
        });
    }
    TestRecommendationReport {
        schema_version: 1,
        snapshot_id: impact.snapshot_id.clone(),
        coverage_complete: impact.coverage_complete,
        execution_coverage: coverage,
        recommendations,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vero_application::{ImpactAnalyzer, ImpactEdge, ImpactGroup};

    fn recommend(impact: &ImpactAssessment) -> TestRecommendationReport {
        recommend_with_coverage(impact, None)
    }

    fn impact(paths: Vec<ImpactEdge>, coverage_complete: bool) -> ImpactAssessment {
        ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:test".into(),
            coverage_complete,
            analyzers: vec![ImpactAnalyzer {
                id: "syn-rust".into(),
                version: None,
                status: "used".into(),
            }],
            changed_paths: vec!["src/lib.rs".into(), "README.md".into()],
            changed_symbols: vec!["important_fn".into()],
            groups: vec![ImpactGroup {
                package_id: "demo".into(),
                changed_paths: vec!["src/lib.rs".into()],
                member_paths: vec!["src/lib.rs".into()],
                certainty: "heuristic_package_membership".into(),
            }],
            paths,
            limitations: if coverage_complete {
                vec![]
            } else {
                vec!["synthetic impact scan limitation".into()]
            },
        }
    }

    fn test_edge(path: &str) -> ImpactEdge {
        ImpactEdge {
            source_path: "src/lib.rs".into(),
            affected_path: path.into(),
            relationship: "likely_test_reference".into(),
            symbol: "important_fn".into(),
            certainty: "inferred_syntax".into(),
            evidence_line: 12,
        }
    }

    #[test]
    fn recommends_only_when_no_likely_test_edge_is_observed() {
        let report = recommend(&impact(vec![], false));
        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(report.recommendations[0].changed_path, "src/lib.rs");
        assert!(!report.coverage_complete);
        assert!(report.recommendations[0].rationale.contains("not proof"));
        assert!(report
            .limitations
            .iter()
            .any(|limitation| limitation == "synthetic impact scan limitation"));

        let report = recommend(&impact(vec![test_edge("src/lib_test.rs")], true));
        assert!(report.recommendations.is_empty());
    }

    #[test]
    fn includes_supported_language_changes_in_gap_recommendations() {
        let mut assessment = impact(vec![], false);
        assessment.changed_paths.extend([
            "src/client.ts".into(),
            "src/widget.jsx".into(),
            "src/worker.py".into(),
            "src/Service.java".into(),
            "docs/usage.md".into(),
        ]);
        let report = recommend(&assessment);
        assert!(report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.changed_path == "src/client.ts"));
        assert!(report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.changed_path == "src/widget.jsx"));
        assert!(report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.changed_path == "src/worker.py"));
        assert!(report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.changed_path == "src/Service.java"));
        assert!(!report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.changed_path == "docs/usage.md"));
        assert!(report
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("Java") }));
    }
}
