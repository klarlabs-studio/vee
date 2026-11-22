use serde::de::DeserializeOwned;
use serde::Serialize;
use vee_application::test_recommendations::TestRecommendationReport;
use vee_application::verification_diagnosis::VerificationDiagnosis;
use vee_application::ImpactAssessment;
use vee_core::AnalyzerReport;
use vee_present::{ansi, markdown, ToView};

/// JSON → document → JSON must be lossless, so a transport can rebuild the document.
fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let value = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), value);
}

fn impact() -> ImpactAssessment {
    serde_json::from_value(serde_json::json!({
        "schema_version": 3,
        "snapshot_id": "sha256:snap",
        "coverage_complete": false,
        "analyzers": [
            {"id": "go-imports", "version": "go1.23", "status": "used"},
            {"id": "python-ast", "version": null, "status": "unavailable"},
        ],
        "changed_paths": ["domain/lockout.go"],
        "changed_symbols": ["Fail", "Reset"],
        "groups": [{
            "package_id": "example.com/domain",
            "changed_paths": ["domain/lockout.go"],
            "member_paths": ["domain/lockout.go", "domain/user.go"],
            "certainty": "inferred_package",
        }],
        "paths": [{
            "source_path": "domain/lockout.go",
            "affected_path": "api/login.go",
            "relationship": "syntactic_symbol_reference",
            "symbol": "Fail",
            "certainty": "inferred_syntax",
            "evidence_line": 42,
        }],
        "limitations": ["Python impact analysis needs python3 on PATH."],
    }))
    .unwrap()
}

#[test]
fn impact_shows_coverage_analyzers_and_affected_paths() {
    let impact = impact();
    let text = ansi::render(&impact.to_view(), false);
    assert!(
        text.starts_with("Impact assessment  ▲ incomplete\n"),
        "{text}"
    );
    assert!(text.contains("  Changed symbols  Fail, Reset\n"), "{text}");
    assert!(
        text.contains("  python-ast  –        ▲ unavailable\n"),
        "{text}"
    );
    assert!(
        text.contains("  api/login.go:42  domain/lockout.go  Fail    syntactic_symbol_reference  inferred_syntax\n"),
        "{text}"
    );
    assert!(
        text.contains("  example.com/domain  1        2        inferred_package\n"),
        "{text}"
    );
    assert!(
        text.contains("  • Python impact analysis needs python3 on PATH.\n"),
        "{text}"
    );
    let md = markdown::render(&impact.to_view());
    assert!(
        md.contains("| `api/login.go:42` | `domain/lockout.go` |"),
        "{md}"
    );
}

#[test]
fn impact_without_affected_paths_says_so() {
    let mut impact = impact();
    impact.paths.clear();
    impact.changed_symbols.clear();
    impact.coverage_complete = true;
    let text = ansi::render(&impact.to_view(), false);
    assert!(
        text.starts_with("Impact assessment  ✔ complete\n"),
        "{text}"
    );
    assert!(text.contains("No affected paths found."), "{text}");
    assert!(text.contains("  Changed symbols  none\n"), "{text}");
    assert!(!text.contains("may be missing"), "{text}");
}

#[test]
fn impact_round_trips_through_json() {
    assert_round_trip(&impact());
}

fn recommendations(with_coverage: bool) -> TestRecommendationReport {
    let mut value = serde_json::json!({
        "schema_version": 1,
        "snapshot_id": "sha256:snap",
        "coverage_complete": true,
        "recommendations": [{
            "changed_path": "domain/lockout.go",
            "rationale": "No likely test reference was found by the available impact analyzers; this is a gap signal, not proof that coverage is absent.",
            "action": "Review whether existing tests cover this change and add or update targeted tests where needed.",
        }],
        "limitations": [],
    });
    if with_coverage {
        value["execution_coverage"] = serde_json::json!({
            "run_id": "run_cov",
            "profile_id": "coverage",
            "status": "used",
            "files": [{
                "path": "domain/lockout.go",
                "covered_lines": 8,
                "executable_lines": 10,
                "percent": 80.0,
                "changed_line_count": 3,
                "changed_executable_lines": 2,
                "changed_covered_lines": 1,
                "changed_percent": 50.0,
                "signal": "partially_covered",
            }],
            "limitations": ["Coverage is profile-specific."],
        });
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn test_recommendations_list_paths_actions_and_coverage() {
    let report = recommendations(true);
    let text = ansi::render(&report.to_view(), false);
    assert!(text.starts_with("Test recommendations (1)\n"), "{text}");
    assert!(text.contains("  Impact coverage  ✔ complete\n"), "{text}");
    assert!(
        text.contains(
            "  domain/lockout.go  8/10 (80.0%)   1/2 (50.0%)            partially_covered\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  • domain/lockout.go Review whether existing tests cover this change"),
        "{text}"
    );
    assert!(
        text.contains("not proof that coverage is absent."),
        "{text}"
    );
    let md = markdown::render(&report.to_view());
    assert!(md.contains("- `domain/lockout.go` Review whether"), "{md}");
}

#[test]
fn empty_test_recommendations_say_so() {
    let mut report = recommendations(false);
    report.recommendations.clear();
    let text = ansi::render(&report.to_view(), false);
    assert!(
        text.contains("No changed source file lacks a likely test reference."),
        "{text}"
    );
    assert!(!text.contains("Execution coverage"), "{text}");
}

#[test]
fn test_recommendations_round_trip_through_json() {
    assert_round_trip(&recommendations(true));
    let without = recommendations(false);
    assert!(serde_json::to_value(&without)
        .unwrap()
        .get("execution_coverage")
        .is_none());
    assert_round_trip(&without);
}

fn diagnosis() -> VerificationDiagnosis {
    serde_json::from_value(serde_json::json!({
        "schema_version": 2,
        "run_id": "run_1",
        "snapshot_id": "sha256:snap",
        "profile_id": "unit",
        "status": "failed",
        "targets": ["./domain/..."],
        "changed_paths": ["domain/lockout.go"],
        "diagnostics": [{
            "provenance": "go_test_json",
            "stream": "stdout",
            "line": 14,
            "kind": "test_failure",
            "text": "--- FAIL: TestLockout (0.00s) domain/lockout.go:166",
            "referenced_changed_paths": ["domain/lockout.go"],
        }],
        "limitations": ["Diagnostics are capped at 200 lines."],
    }))
    .unwrap()
}

#[test]
fn diagnosis_lists_failure_lines_with_changed_paths() {
    let diagnosis = diagnosis();
    let text = ansi::render(&diagnosis.to_view(), false);
    assert!(
        text.starts_with("Verification diagnosis unit  ✖ failed\n"),
        "{text}"
    );
    assert!(text.contains("  Targets   ./domain/...\n"), "{text}");
    assert!(
        text.contains("  • stdout:14 test_failure --- FAIL: TestLockout (0.00s) domain/lockout.go:166 — changed paths: domain/lockout.go\n"),
        "{text}"
    );
    assert!(
        text.contains("  • Diagnostics are capped at 200 lines.\n"),
        "{text}"
    );
    assert!(text.ends_with("→ vee verification show run_1\n"), "{text}");
    let md = markdown::render(&diagnosis.to_view());
    assert!(md.contains("Next: `vee verification show run_1`"), "{md}");
}

#[test]
fn diagnosis_without_failures_says_so() {
    let mut diagnosis = diagnosis();
    diagnosis.diagnostics.clear();
    diagnosis.status = "timed_out".into();
    let text = ansi::render(&diagnosis.to_view(), false);
    assert!(
        text.starts_with("Verification diagnosis unit  ✖ timed out\n"),
        "{text}"
    );
    assert!(text.contains("No recognized failure lines."), "{text}");
}

#[test]
fn diagnosis_round_trips_through_json() {
    assert_round_trip(&diagnosis());
}

fn analyzer_report() -> AnalyzerReport {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "run_id": "run_lint",
        "profile_id": "clippy",
        "snapshot_id": "sha256:snap",
        "tools": ["clippy 0.1.83"],
        "parsed": true,
        "problem": null,
        "findings": [{
            "id": "analyzer:clippy:abc123",
            "fingerprint": "sha256:abc123",
            "rule_id": "clippy::unwrap_used",
            "level": "warning",
            "path": "src/lib.rs",
            "line": 12,
            "message": "used `unwrap()` on a `Result` value",
        }],
        "results_total": 5,
        "results_suppressed": 1,
        "results_outside_changes": 3,
        "limitations": [],
    }))
    .unwrap()
}

#[test]
fn analyzer_report_tables_results_on_changed_lines() {
    let report = analyzer_report();
    let text = ansi::render(&report.to_view(), false);
    assert!(
        text.starts_with("Analyzer run clippy  ▲ 1 on changed lines\n"),
        "{text}"
    );
    assert!(text.contains("  Tools       clippy 0.1.83\n"), "{text}");
    assert!(
        text.contains("  Results     5 total, 1 on changed lines\n"),
        "{text}"
    );
    assert!(
        text.contains("  Elsewhere   3 pre-existing, never blocking\n"),
        "{text}"
    );
    assert!(
        text.contains("  ▲ warning  src/lib.rs:12  clippy::unwrap_used  analyzer:clippy:abc123  used `unwrap()` on a `Result` value\n"),
        "{text}"
    );
    assert!(!text.contains("→"), "{text}");
    let md = markdown::render(&report.to_view());
    assert!(md.contains("| `src/lib.rs:12` |"), "{md}");
}

#[test]
fn unparsed_analyzer_report_explains_and_points_to_diagnosis() {
    let mut report = analyzer_report();
    report.parsed = false;
    report.problem = Some("stdout is not valid SARIF 2.1.0".into());
    report.findings.clear();
    let text = ansi::render(&report.to_view(), false);
    assert!(
        text.starts_with("Analyzer run clippy  ✖ not evaluable\n"),
        "{text}"
    );
    assert!(
        text.contains("✖ Not evaluable: stdout is not valid SARIF 2.1.0\n"),
        "{text}"
    );
    assert!(
        text.contains("No results; the run produced no valid SARIF."),
        "{text}"
    );
    assert!(
        text.ends_with("→ vee verification diagnose run_lint\n"),
        "{text}"
    );
    let md = markdown::render(&report.to_view());
    assert!(
        md.contains("Next: call `diagnose_verification` with `{\"run_id\":\"run_lint\"}`"),
        "{md}"
    );
}

#[test]
fn clean_analyzer_report_says_so() {
    let mut report = analyzer_report();
    report.findings.clear();
    let text = ansi::render(&report.to_view(), false);
    assert!(text.starts_with("Analyzer run clippy  ✔ clean\n"), "{text}");
    assert!(
        text.contains("No analyzer results on changed lines."),
        "{text}"
    );
}

#[test]
fn analyzer_report_round_trips_through_json() {
    assert_round_trip(&analyzer_report());
}

fn analyzer_run(exit_code: i32) -> vee_core::VerificationRun {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "run_id": "run_lint",
        "snapshot_id": "sha256:snap",
        "profile_id": "clippy",
        "targets": [],
        "command_digest": "sha256:cmd",
        "status": if exit_code == 0 { "passed" } else { "failed" },
        "exit_code": exit_code,
        "stdout_digest": "sha256:out",
        "stderr_digest": "sha256:err",
        "stdout_artifact": null,
        "stderr_artifact": null
    }))
    .unwrap()
}

#[test]
fn an_analyzer_run_is_judged_by_its_results_on_changed_lines_not_its_exit_code() {
    let mut report = analyzer_report();
    report.findings.clear();
    let result = vee_application::operations::VerificationResult {
        run: analyzer_run(1),
        analyzer: Some(report),
    };
    let text = ansi::render(&result.to_view(), false);
    assert!(
        text.starts_with("Verification clippy  ✔ clean on changed lines\n"),
        "{text}"
    );
    assert!(
        text.contains("5 results, 0 on changed lines, 3 pre-existing"),
        "{text}"
    );
    assert!(
        text.contains("A non-zero exit is how the analyzer reports results"),
        "{text}"
    );
    assert!(
        text.ends_with("→ vee verification findings run_lint\n"),
        "{text}"
    );
    assert!(markdown::render(&result.to_view()).contains("`get_analyzer_findings`"));
    // The document stays the run itself.
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(&result.run).unwrap()
    );
}

#[test]
fn a_run_without_an_analyzer_report_keeps_its_exit_status() {
    let result = vee_application::operations::VerificationResult {
        run: analyzer_run(1),
        analyzer: None,
    };
    let text = ansi::render(&result.to_view(), false);
    assert!(
        text.starts_with("Verification clippy  ✖ failed\n"),
        "{text}"
    );
}
