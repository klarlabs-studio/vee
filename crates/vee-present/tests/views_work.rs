use vee_application::finding_task::{
    FindingTask, FindingWorkPackage, SourceContext, TaskOwnership, TaskStandard,
};
use vee_application::ImpactEdge;
use vee_core::{FindingFeedback, FindingFeedbackLabel, FindingRecord};
use vee_present::{ansi, markdown, ToView};

fn record(id: &str, severity: &str, rationale: &str) -> FindingRecord {
    serde_json::from_value(serde_json::json!({
        "finding": {
            "id": id,
            "fingerprint": format!("fp_{id}"),
            "category": "concurrency",
            "severity": severity,
            "confidence": 80,
            "rationale": rationale,
            "path": "domain/lockout.go",
            "line": 166,
            "provenance": "reviewer:correctness",
            "reviewer_ids": ["correctness"],
            "evidence_ids": ["ev_1"],
        },
        "status": "open",
        "status_reason": null,
        "occurrence_count": 1,
        "first_seen": "2026-11-20",
        "last_seen": "2026-11-21",
        "occurrences": [],
    }))
    .unwrap()
}

fn task(id: &str, current: bool) -> FindingTask {
    FindingTask {
        schema_version: 3,
        task_id: format!("finding-task:sha256:{id}"),
        review_id: "rev_1".into(),
        snapshot_id: "sha256:snap".into(),
        snapshot_current: current,
        finding: record(
            id,
            "high",
            "Lost increment under concurrent failures.\n\nThe counter is read and written without a lock.",
        ),
        source_context: Some(SourceContext {
            path: "domain/lockout.go".into(),
            start_line: 165,
            end_line: 167,
            content: "   165 | func (l *Lockout) Fail() {\n   166 | \tl.count = l.count + 1\n   167 | }\n"
                .into(),
            classification: "untrusted_repository_source".to_string(),
        }),
        context_note: None,
        impact_paths: vec![ImpactEdge {
            source_path: "domain/lockout.go".into(),
            affected_path: "domain/lockout_test.go".into(),
            relationship: "likely_test_reference".into(),
            symbol: "Fail".into(),
            certainty: "inferred_heuristic".into(),
            evidence_line: 12,
        }],
        impact_coverage_complete: Some(true),
        evidence: vec![serde_json::from_value(serde_json::json!({
            "id": "ev_1",
            "kind": "source",
            "provenance": "snapshot",
            "source_path": "domain/lockout.go",
            "start_line": 165,
            "end_line": 167,
            "content_digest": "sha256:ev",
            "classification": "observed",
            "verification": "supported",
        }))
        .unwrap()],
        applicable_standards: vec![],
        standards_note: Some("No AGENTS.md or CONTRIBUTING.md applies to this path.".into()),
        ownership: Some(TaskOwnership {
            advisory_only: true,
            path: "domain/lockout.go".into(),
            status: "owned".into(),
            owners: vec!["@team-auth".into()],
            codeowners_path: Some(".github/CODEOWNERS".into()),
            codeowners_digest: Some("sha256:co".into()),
            report_digest: "sha256:rep".into(),
            coverage_complete: true,
            matching_rule_line: Some(3),
            matching_pattern: Some("domain/".into()),
            classification: "advisory_ownership_context".to_string(),
        }),
        ownership_note: None,
        instructions: "Investigate this finding against the exact snapshot.".to_string(),
    }
}

#[test]
fn finding_task_shows_finding_source_impact_and_verification_step() {
    let task = task("find_a", true);
    let text = ansi::render(&task.to_view(), false);
    assert!(
        text.starts_with("Task for finding find_a  ✖ high · concurrency\n"),
        "{text}"
    );
    assert!(
        text.contains("  Snapshot  sha256:snap ✔ current\n"),
        "{text}"
    );
    assert!(
        text.contains("  Owners    @team-auth (advisory)\n"),
        "{text}"
    );
    assert!(
        text.contains("The counter is read and written without a lock."),
        "full rationale is kept: {text}"
    );
    assert!(text.contains("domain/lockout.go:165-167\n"), "{text}");
    assert!(
        text.contains("  166    l.count = l.count + 1\n"),
        "numbered source lines: {text}"
    );
    assert!(
        text.contains(
            "  domain/lockout_test.go:12  Fail  likely_test_reference  inferred_heuristic\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  • domain/lockout.go:165-167 source ev_1\n"),
        "{text}"
    );
    assert!(text.contains("No applicable standards recorded."), "{text}");
    assert!(
        text.contains("● No AGENTS.md or CONTRIBUTING.md applies to this path."),
        "{text}"
    );
    assert!(
        text.contains("Investigate this finding against the exact snapshot."),
        "{text}"
    );
    assert!(!text.contains("changed since review"), "{text}");
    assert!(
        text.ends_with("→ vee verify find_a --profile <profile>\n"),
        "{text}"
    );

    let md = markdown::render(&task.to_view());
    assert!(
        md.contains("Next: call `verify_finding` with `{\"finding_id\":\"find_a\",\"profile_id\":\"<profile>\"}`"),
        "{md}"
    );
}

#[test]
fn finding_task_without_context_says_why() {
    let mut task = task("find_a", false);
    task.source_context = None;
    task.context_note = Some("Finding source file is absent from its snapshot.".into());
    task.impact_paths.clear();
    task.impact_coverage_complete = Some(false);
    task.evidence.clear();
    task.ownership = None;
    task.ownership_note = Some("Finding has no source path for ownership lookup.".into());
    let text = ansi::render(&task.to_view(), false);
    assert!(
        text.contains("sha256:snap ▲ changed since review"),
        "{text}"
    );
    assert!(
        text.contains("▲ The source changed since this review"),
        "{text}"
    );
    assert!(text.contains("No source context available."), "{text}");
    assert!(
        text.contains("● Finding source file is absent from its snapshot."),
        "{text}"
    );
    assert!(text.contains("No impact paths recorded."), "{text}");
    assert!(text.contains("▲ Impact analysis is incomplete"), "{text}");
    assert!(text.contains("No evidence recorded."), "{text}");
    assert!(
        text.contains("Owners    Finding has no source path for ownership lookup."),
        "{text}"
    );
}

#[test]
fn finding_task_lists_standards_with_integrity() {
    let mut task = task("find_a", true);
    task.applicable_standards = vec![TaskStandard {
        path: "AGENTS.md".into(),
        kind: "agents".into(),
        scope: "repository".into(),
        content_digest: "sha256:c".into(),
        source_digest: "sha256:s".into(),
        integrity: "local-content-hash".into(),
        content: "Use table-driven tests.".into(),
        truncated: true,
        classification: "repository_guidance_context".to_string(),
    }];
    let text = ansi::render(&task.to_view(), false);
    assert!(
        text.contains("  AGENTS.md  agents  repository  local-content-hash truncated\n"),
        "{text}"
    );
}

fn package(findings: Vec<FindingTask>) -> FindingWorkPackage {
    FindingWorkPackage {
        schema_version: 2,
        package_id: "finding-package:sha256:pkg".into(),
        review_id: "rev_1".into(),
        snapshot_id: "sha256:snap".into(),
        snapshot_current: findings.iter().all(|task| task.snapshot_current),
        findings,
        instructions: "Investigate these findings as one bounded work package.".to_string(),
    }
}

#[test]
fn work_package_tables_findings_and_points_to_the_first_task() {
    let mut second = task("find_b", true);
    second.finding = record("find_b", "low", "Unchecked index on an empty slice");
    let package = package(vec![task("find_a", true), second]);
    let text = ansi::render(&package.to_view(), false);
    assert!(text.starts_with("Work package (2 findings)\n"), "{text}");
    assert!(
        text.contains("  Package   finding-package:sha256:pkg\n"),
        "{text}"
    );
    assert!(
        text.contains("  ✖ high    ▲ open  domain/lockout.go:166  concurrency  Lost increment under concurrent failures.  find_a\n"),
        "{text}"
    );
    assert!(
        text.contains("  ● low     ▲ open  domain/lockout.go:166  concurrency  Unchecked index on an empty slice          find_b\n"),
        "{text}"
    );
    assert!(
        text.contains("Investigate these findings as one bounded work package."),
        "{text}"
    );
    assert!(text.ends_with("→ vee findings task find_a\n"), "{text}");

    let md = markdown::render(&package.to_view());
    assert!(
        md.contains("Next: call `get_finding_task` with `{\"finding_id\":\"find_a\"}` (CLI: `vee findings task find_a`)"),
        "{md}"
    );
}

#[test]
fn empty_work_package_says_so() {
    let text = ansi::render(&package(vec![]).to_view(), false);
    assert!(text.contains("No findings in this package."), "{text}");
    assert!(!text.contains("→"), "{text}");
}

fn feedback() -> FindingFeedback {
    FindingFeedback {
        schema_version: 1,
        feedback_id: "fb_1".into(),
        finding_id: "find_a".into(),
        snapshot_id: "sha256:snap".into(),
        label: FindingFeedbackLabel::FalsePositive,
        reason: "The lock is held by the caller.".into(),
        reviewer: "reviewer".into(),
        created_at: "2026-11-21T10:00:00Z".into(),
    }
}

#[test]
fn recorded_feedback_shows_label_and_how_to_list_it() {
    let feedback = feedback();
    let text = ansi::render(&feedback.to_view(), false);
    assert!(
        text.starts_with("Feedback recorded for finding find_a  ▲ false_positive\n"),
        "{text}"
    );
    assert!(text.contains("  Snapshot  sha256:snap\n"), "{text}");
    assert!(
        text.contains("  Reason    The lock is held by the caller.\n"),
        "{text}"
    );
    assert!(text.contains("  Reviewer  reviewer\n"), "{text}");
    assert!(
        text.ends_with("→ vee findings feedback list --finding find_a\n"),
        "{text}"
    );
    let md = markdown::render(&feedback.to_view());
    assert!(
        md.starts_with("## Feedback recorded for finding find_a"),
        "{md}"
    );
}

#[test]
fn feedback_round_trips_through_json() {
    let value = serde_json::to_value(feedback()).unwrap();
    let rebuilt: FindingFeedback = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(rebuilt).unwrap(), value);
}
