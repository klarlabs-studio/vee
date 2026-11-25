use vee_application::operations::{FindingsPage, GateHistory};
use vee_application::{ReviewResult, ReviewerOutcome};
use vee_core::{ChangeSet, Finding, GateStatus};
use vee_present::{ansi, markdown, ToView};

fn finding(
    id: &str,
    severity: &str,
    path: Option<&str>,
    line: Option<u32>,
    rationale: &str,
) -> Finding {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "fingerprint": format!("fp_{id}"),
        "category": "concurrency",
        "severity": severity,
        "confidence": 80,
        "rationale": rationale,
        "path": path,
        "line": line,
        "provenance": "reviewer:correctness",
        "reviewer_ids": ["correctness"],
    }))
    .unwrap()
}

fn review(findings: Vec<Finding>, blocking: Vec<String>, complete: bool) -> ReviewResult {
    let policy = vee_core::Policy {
        block_severities: vec![vee_core::Severity::High],
        minimum_confidence: 0,
        required_review_complete: true,
        required_verifications: vec![],
        analyzer_block_levels: Default::default(),
        severity_floors: Vec::new(),
    };
    let mut gate = vee_core::evaluate_gate(
        "sha256:snap",
        "config",
        "policy",
        &findings,
        &policy,
        complete,
        vee_core::GateEvidence {
            verification_runs: &[],
            source_evidence: &[],
            analyzer_reports: &[],
        },
    );
    if !blocking.is_empty() {
        gate.status = GateStatus::Block;
    }
    gate.blocking_findings = blocking;
    ReviewResult {
        schema_version: 2,
        review_id: "rev_1".into(),
        snapshot_id: "sha256:snap".into(),
        status: if gate.status == GateStatus::Pass {
            "pass"
        } else {
            "block"
        }
        .into(),
        findings,
        policy_findings: Some(vec![]),
        evidence: vec![],
        verification_runs: vec![],
        reviewer_outcomes: vec![ReviewerOutcome {
            reviewer_id: "correctness".into(),
            provider_id: "local".into(),
            provider_kind: vee_core::ProviderKind::OllamaNative,
            model: Some("gemma3:12b".into()),
            provider_version: None,
            status: "completed".into(),
            duration_ms: Some(65_000),
            usage: Some(vee_core::ProviderUsage {
                input_tokens: Some(1200),
                output_tokens: Some(80),
                total_tokens: None,
            }),
        }],
        reviewer_arbitration: vec![],
        analysis_complete: complete,
        reasons: gate.reasons.clone(),
        gate,
        change_set: ChangeSet::from_entries(None, None, "working_tree", vec![]),
        effective_config_digest: "config".into(),
        selected_reviewers: vec!["correctness".into()],
        reviewer_context: vec![],
        unreviewed_paths: vec!["core/lib.rs".into()],
        policy_profile: None,
        review_effort: None,
        work_item: None,
        work_item_token_env: None,
    }
}

#[test]
fn review_view_shows_gate_reviewers_findings_and_next_step() {
    let review = review(
        vec![
            finding(
                "find_a",
                "high",
                Some("domain/lockout.go"),
                Some(166),
                "Lost increment under concurrent failures.\nDetails follow.",
            ),
            finding("find_b", "low", None, None, "Unlocated note"),
        ],
        vec!["find_a".into()],
        true,
    );
    let text = ansi::render(&review.to_view(), false);
    assert!(text.starts_with("Review rev_1  ✖ block\n"), "{text}");
    assert!(
        text.contains("  correctness  ✔ completed  ollama_native · gemma3:12b  1m 05s  1200/80"),
        "{text}"
    );
    assert!(text.contains("✖ high blocks  domain/lockout.go:166  concurrency  Lost increment under concurrent failures."), "{text}");
    assert!(text.contains("● low          no location"), "{text}");
    assert!(
        !text.contains("Details follow"),
        "tables show the first line only"
    );
    assert!(text.contains("Not reviewed\n"), "{text}");
    assert!(text.contains("  • core/lib.rs"), "{text}");
    assert!(text.ends_with("→ vee findings show find_a\n"), "{text}");

    let md = markdown::render(&review.to_view());
    assert!(md.starts_with("## Review rev_1 · 🔴 **block**\n"), "{md}");
    assert!(
        md.contains("| 🔴 **high** **blocks** | `domain/lockout.go:166` | concurrency |"),
        "{md}"
    );
}

#[test]
fn incomplete_review_with_no_findings_says_findings_may_be_missing() {
    let text = ansi::render(&review(vec![], vec![], false).to_view(), false);
    assert!(
        text.contains("▲ Analysis did not complete; findings may be missing."),
        "{text}"
    );
    assert!(
        text.contains("No findings; analysis did not complete."),
        "{text}"
    );
    let complete = ansi::render(&review(vec![], vec![], true).to_view(), false);
    assert!(
        complete.contains("No findings were reported."),
        "{complete}"
    );
    assert!(!complete.contains("may be missing"), "{complete}");
}

#[test]
fn findings_page_paginates_with_a_runnable_next_step() {
    let record = |id: &str| -> vee_core::FindingRecord {
        serde_json::from_value(serde_json::json!({
            "finding": finding(id, "medium", Some("a.rs"), Some(3), "Unchecked index"),
            "status": "open",
            "status_reason": null,
            "occurrence_count": 1,
            "first_seen": "2026-11-20",
            "last_seen": "2026-11-21",
            "occurrences": [],
        }))
        .unwrap()
    };
    let page = FindingsPage {
        schema_version: 2,
        findings: vec![record("find_1"), record("find_2")],
        limit: 2,
        offset: 0,
        total: 5,
    };
    let text = ansi::render(&page.to_view(), false);
    assert!(text.starts_with("Findings (5)\n"), "{text}");
    assert!(
        text.contains("▲ medium  ▲ open  a.rs:3    Unchecked index  find_1"),
        "{text}"
    );
    assert!(text.contains("Showing 1–2 of 5."), "{text}");
    assert!(text.ends_with("→ vee findings list --offset 2\n"), "{text}");
}

#[test]
fn empty_documents_say_so_instead_of_printing_nothing() {
    let page = FindingsPage {
        schema_version: 2,
        findings: vec![],
        limit: 50,
        offset: 0,
        total: 0,
    };
    assert_eq!(
        ansi::render(&page.to_view(), false),
        "Findings (0)\n\nNo findings.\n"
    );
    let history = GateHistory {
        schema_version: 1,
        decisions: vec![],
    };
    assert!(ansi::render(&history.to_view(), false).contains("No gate decisions recorded."));
}

#[test]
fn markdown_report_adds_full_finding_details_without_an_interactive_next_step() {
    let review = review(
        vec![finding(
            "find_a",
            "high",
            Some("a.go"),
            Some(9),
            "First line.\nSecond line with detail.",
        )],
        vec!["find_a".into()],
        true,
    );
    let report = markdown::render(&vee_present::review_report(&review));
    assert!(report.contains("### Finding details"), "{report}");
    assert!(
        report.contains("Second line with detail."),
        "full rationale is kept: {report}"
    );
    assert!(!report.contains("Next:"), "{report}");
    let shared = markdown::render(&review.to_view());
    assert!(
        !shared.contains("Second line"),
        "the shared view stays compact"
    );
    assert!(
        shared.contains("Next: call `get_finding` with `{\"finding_id\":\"find_a\"}` (CLI: `vee findings show find_a`)"),
        "{shared}"
    );
}
