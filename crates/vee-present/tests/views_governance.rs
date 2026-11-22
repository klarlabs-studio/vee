use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use vee_application::acceptance::{
    AcceptanceCriterion, AcceptanceReport, TestReferenceCandidate, VerificationSummary,
    WorkItemReference,
};
use vee_application::ownership::OwnershipReport;
use vee_application::packs::PackList;
use vee_application::rule_candidates::{
    CandidateReport, FeedbackExample, RuleCandidate, RuleEffectivenessReport,
};
use vee_application::standards::StandardsReport;
use vee_core::{FindingFeedbackLabel, VerificationStatus};
use vee_present::{ansi, markdown, ToView};

/// Serializing, deserializing and serializing again yields the same JSON.
fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let first = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), first);
}

fn text<T: ToView>(document: &T) -> String {
    ansi::render(&document.to_view(), false)
}

fn md<T: ToView>(document: &T) -> String {
    markdown::render(&document.to_view())
}

fn standards() -> StandardsReport {
    serde_json::from_value(json!({
        "schema_version": 1,
        "target_path": "src/auth/login.rs",
        "sources": [
            {
                "path": "AGENTS.md",
                "kind": "agents_md",
                "precedence": 10,
                "scope": "repository",
                "content_digest": "sha256:aaa",
                "integrity": "local-content-hash",
                "content": "Prefer explicit errors.",
                "truncated": false
            },
            {
                "path": "src/auth/AGENTS.md",
                "kind": "agents_md",
                "precedence": 20,
                "scope": "src/auth",
                "content_digest": "sha256:bbb",
                "integrity": "local-content-hash",
                "content": "Never log tokens.",
                "truncated": true
            }
        ],
        "potential_conflicts": ["src/auth/AGENTS.md and AGENTS.md both set error handling"],
        "limitations": ["Remote standards are not refreshed automatically."]
    }))
    .unwrap()
}

#[test]
fn standards_view_lists_sources_conflicts_and_limitations() {
    let report = standards();
    let text = text(&report);
    assert!(
        text.starts_with("Applicable standards for src/auth/login.rs\n"),
        "{text}"
    );
    assert!(text.contains("Sources (2)\n"), "{text}");
    assert!(
        text.contains(
            "  src/auth/AGENTS.md  agents_md  20          src/auth    ▲ truncated  local-content-hash"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "▲ Potential conflict: src/auth/AGENTS.md and AGENTS.md both set error handling"
        ),
        "{text}"
    );
    assert!(
        text.contains("  • Remote standards are not refreshed automatically."),
        "{text}"
    );
    assert!(md(&report).contains("| `AGENTS.md` | agents\\_md | 10 |"));
    assert_round_trip(&report);
}

#[test]
fn standards_view_says_when_none_apply() {
    let report: StandardsReport = serde_json::from_value(json!({
        "schema_version": 1,
        "target_path": null,
        "sources": [],
        "potential_conflicts": [],
        "limitations": []
    }))
    .unwrap();
    assert_eq!(
        text(&report),
        "Applicable standards\n\nSources (0)\n\nNo standards found.\n"
    );
    assert_round_trip(&report);
}

fn candidate(id: &str, suggestion: &str) -> RuleCandidate {
    RuleCandidate {
        candidate_id: id.into(),
        source_kind: "vee_finding".into(),
        category: "error_handling".into(),
        feedback_label: FindingFeedbackLabel::FalsePositive,
        feedback_count: 3,
        feedback_event_count: 4,
        evidence_digest: "sha256:evidence".into(),
        feedback_ids: vec!["fb_1".into()],
        suggestion: suggestion.into(),
        feedback: vec![FeedbackExample {
            source_kind: "vee_finding".into(),
            finding_id: Some("find_1".into()),
            external_comment_id: None,
            archive_digest: None,
            provider: None,
            pull_request: None,
            snapshot_id: "sha256:snap".into(),
            reviewer: "dana".into(),
            reason: "the error is handled by the caller".into(),
        }],
        approval_status: "requires_human_review".to_string(),
    }
}

#[test]
fn rule_candidates_view_shows_candidates_full_suggestions_and_approval_step() {
    let report = CandidateReport {
        schema_version: 3,
        candidates: vec![candidate(
            "cand_1",
            "Do not report unchecked errors when the caller propagates them with ? and a context message.",
        )],
        disputed_findings_excluded: 1,
        disputed_external_comments_excluded: 0,
        feedback_without_saved_finding: 2,
        truncated: false,
        limitations: vec![],
    };
    let text = text(&report);
    assert!(text.starts_with("Rule candidates (1)\n"), "{text}");
    assert!(
        text.contains("  Disputed findings excluded      1\n"),
        "{text}"
    );
    assert!(
        text.contains("  cand_1     3 distinct (4 events)  error_handling  false_positive  vee_finding  ▲ requires_human_review  Do not report unchecked errors when the caller propagat…"),
        "{text}"
    );
    assert!(
        text.contains("cand_1 Do not report unchecked errors when the caller propagates them with ? and a context message.\n"),
        "{text}"
    );
    assert!(
        text.contains("● Suggestions require human review and are not active policy."),
        "{text}"
    );
    assert!(
        text.ends_with("→ vee rules approve cand_1 --evidence-digest sha256:evidence --scope <path> --instruction <guidance> --approver <name> --reason <why>\n"),
        "{text}"
    );
    let md = md(&report);
    assert!(
        md.contains("Next: call `approve_rule_candidate` with `{\"approver\":\"<name>\",\"candidate_id\":\"cand_1\""),
        "{md}"
    );
}

#[test]
fn rule_candidates_view_says_when_nothing_qualifies() {
    let report = CandidateReport {
        schema_version: 3,
        candidates: vec![],
        disputed_findings_excluded: 0,
        disputed_external_comments_excluded: 0,
        feedback_without_saved_finding: 0,
        truncated: true,
        limitations: vec![],
    };
    let text = text(&report);
    assert!(
        text.contains("No repeated feedback patterns qualify as rule candidates."),
        "{text}"
    );
    assert!(
        text.contains("▲ The feedback history was truncated"),
        "{text}"
    );
    assert!(!text.contains("→"), "{text}");
}

fn window(
    denominator: usize,
    false_positive_rate: Option<f64>,
    disputed: usize,
) -> serde_json::Value {
    json!({
        "accuracy_denominator": denominator,
        "false_positive_count": 1,
        "false_positive_rate": false_positive_rate,
        "actionability_denominator": denominator,
        "not_actionable_count": 0,
        "not_actionable_rate": null,
        "disputed_occurrences": disputed
    })
}

#[test]
fn rule_effectiveness_view_compares_before_and_after_activation() {
    let report: RuleEffectivenessReport = serde_json::from_value(json!({
        "schema_version": 1,
        "approvals": [{
            "approval_id": "appr_1",
            "version": 2,
            "status": "active",
            "source_feedback_ids": ["fb_1"],
            "evidence_digest": "sha256:evidence",
            "baseline": window(4, Some(0.25), 0),
            "after_activation": window(8, Some(0.125), 1)
        }],
        "limitations": ["Feedback is sparse."]
    }))
    .unwrap();
    let text = text(&report);
    assert!(text.starts_with("Rule effectiveness (1)\n"), "{text}");
    assert!(
        text.contains("  appr_1    v2       ✔ active  4 → 8            25.0% → 12.5%        4 → 8                 n/a → n/a"),
        "{text}"
    );
    assert!(
        text.contains("appr_1 0 → 1 disputed occurrences excluded"),
        "{text}"
    );
    assert!(
        text.ends_with("● Observational comparison only; it does not establish that guidance caused an outcome.\n"),
        "{text}"
    );
    assert_round_trip(&report);
}

#[test]
fn rule_effectiveness_view_points_to_candidates_when_nothing_is_approved() {
    let report: RuleEffectivenessReport = serde_json::from_value(json!({
        "schema_version": 1,
        "approvals": [],
        "limitations": []
    }))
    .unwrap();
    assert_eq!(
        text(&report),
        "Rule effectiveness (0)\n\nNo rule approvals to evaluate.\n\n→ vee rules candidates\n"
    );
    assert!(md(&report).contains("Next: call `list_rule_candidates` with `{}`"));
    assert_round_trip(&report);
}

fn owners() -> OwnershipReport {
    serde_json::from_value(json!({
        "schema_version": 1,
        "advisory_only": true,
        "repository_root": "/work/repo",
        "codeowners_path": ".github/CODEOWNERS",
        "codeowners_digest": "sha256:owners",
        "coverage_complete": true,
        "results": [
            {
                "path": "src/auth/login.rs",
                "status": "owned",
                "owners": ["@acme/security", "@dana"],
                "matching_rule_line": 7,
                "matching_pattern": "/src/auth/"
            },
            {
                "path": "README.md",
                "status": "unowned",
                "owners": [],
                "matching_rule_line": null,
                "matching_pattern": null
            }
        ],
        "limitations": ["Only GitHub-style CODEOWNERS patterns are recognized."],
        "digest": "sha256:report"
    }))
    .unwrap()
}

#[test]
fn owners_view_shows_matching_rules_and_unowned_paths() {
    let report = owners();
    let text = text(&report);
    assert!(text.starts_with("Owners (2 paths)  ✔ complete\n"), "{text}");
    assert!(
        text.contains("  Ownership rules  .github/CODEOWNERS sha256:owners\n"),
        "{text}"
    );
    assert!(
        text.contains("  src/auth/login.rs  ✔ owned    @acme/security, @dana  /src/auth/ line 7"),
        "{text}"
    );
    assert!(
        text.contains("  README.md          · unowned  none                   no matching rule"),
        "{text}"
    );
    assert!(text.contains("● Advisory only"), "{text}");
    assert_round_trip(&report);
}

#[test]
fn owners_view_says_when_no_codeowners_file_exists() {
    let mut value = serde_json::to_value(owners()).unwrap();
    value["codeowners_path"] = json!(null);
    value["codeowners_digest"] = json!(null);
    value["results"] = json!([]);
    let report: OwnershipReport = serde_json::from_value(value).unwrap();
    let text = text(&report);
    assert!(text.contains("  Ownership rules  none found\n"), "{text}");
    assert!(text.contains("No paths resolved."), "{text}");
}

fn packs(status: &str, problem: Option<&str>) -> PackList {
    serde_json::from_value(json!({
        "schema_version": 1,
        "packs": [
            {
                "path": ".vee/packs/acme-baseline",
                "pinned_digest": "sha256:pin1",
                "provider": "default",
                "status": "ok",
                "name": "acme-baseline",
                "version": "1.2.0",
                "problem": null
            },
            {
                "path": ".vee/packs/acme-security",
                "pinned_digest": "sha256:pin2",
                "provider": "local",
                "status": status,
                "name": "acme-security",
                "version": "0.3.0",
                "problem": problem
            }
        ]
    }))
    .unwrap()
}

#[test]
fn packs_view_flags_a_pack_that_differs_from_its_pin() {
    let list = packs("changed", Some("content digest is sha256:new"));
    let text = text(&list);
    assert!(
        text.starts_with("Pinned packs (2)  ✖ 1 differ from their pins\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  ▲ changed  acme-security 0.3.0  .vee/packs/acme-security  local     sha256:pin2"
        ),
        "{text}"
    );
    assert!(
        text.contains("▲ .vee/packs/acme-security content digest is sha256:new"),
        "{text}"
    );
    assert!(
        text.ends_with("→ vee packs add <pack-directory> --replace\n"),
        "{text}"
    );
    assert_round_trip(&list);
}

#[test]
fn packs_view_reports_matching_pins_and_empty_lists() {
    let list = packs("ok", None);
    let text = text(&list);
    assert!(
        text.starts_with("Pinned packs (2)  ✔ all match their pins\n"),
        "{text}"
    );
    assert!(!text.contains("→"), "{text}");
    let empty: PackList =
        serde_json::from_value(json!({"schema_version": 1, "packs": []})).unwrap();
    assert_eq!(
        self::text(&empty),
        "Pinned packs (0)\n\nNo packs are pinned in .vee.yaml.\n"
    );
    assert!(md(&empty).starts_with("## Pinned packs \\(0\\)\n"));
    assert_round_trip(&empty);
}

fn acceptance(criteria: Vec<AcceptanceCriterion>) -> AcceptanceReport {
    AcceptanceReport {
        schema_version: 1,
        review_id: "rev_1".into(),
        snapshot_id: "sha256:snap".into(),
        work_item: Some(WorkItemReference {
            url: "https://github.com/acme/app/issues/42".into(),
            content_digest: "sha256:issue".into(),
        }),
        criteria,
        changed_paths: vec!["src/auth/login.rs".into()],
        impact_snapshot_id: Some("sha256:snap".into()),
        impact_coverage_complete: Some(false),
        impact_analyzers: vec![],
        verification_runs: vec![VerificationSummary {
            run_id: "run_1".into(),
            profile_id: "unit".into(),
            status: VerificationStatus::Passed,
            targets: vec!["auth::tests".into()],
        }],
        limitations: vec!["Candidate links are lexical, not proof of satisfaction.".into()],
    }
}

#[test]
fn acceptance_view_traces_criteria_to_paths_tests_and_runs() {
    let report = acceptance(vec![AcceptanceCriterion {
        id: "AC-0123456789ab".into(),
        source_id: None,
        source_line: 12,
        text: "Locked accounts cannot log in until the lockout window expires.".into(),
        candidate_changed_paths: vec!["src/auth/login.rs".into()],
        candidate_test_references: vec![TestReferenceCandidate {
            changed_path: "src/auth/login.rs".into(),
            test_path: "tests/login.rs".into(),
            symbol: "login".into(),
            evidence_line: 30,
            certainty: "inferred".into(),
        }],
        status: "needs_human_review".to_string(),
    }]);
    let text = text(&report);
    assert!(
        text.starts_with("Acceptance traceability for review rev_1\n"),
        "{text}"
    );
    assert!(
        text.contains("  Work item        https://github.com/acme/app/issues/42 sha256:issue\n"),
        "{text}"
    );
    assert!(text.contains("▲ incomplete"), "{text}");
    assert!(
        text.contains("  AC-0123456789ab  12    ▲ needs_human_review  1      1      Locked accounts cannot log in until the lockout window…"),
        "{text}"
    );
    assert!(
        text.contains("Locked accounts cannot log in until the lockout window expires.\n"),
        "{text}"
    );
    assert!(
        text.contains("  • likely test tests/login.rs:30 login for src/auth/login.rs (inferred)"),
        "{text}"
    );
    assert!(
        text.contains("  run_1  unit     ✔ passed  auth::tests"),
        "{text}"
    );
    assert!(
        text.ends_with("→ vee acceptance validate --review rev_1 --mapping <mapping-file>\n"),
        "{text}"
    );
}

#[test]
fn acceptance_view_says_when_no_criteria_or_runs_exist() {
    let mut report = acceptance(vec![]);
    report.work_item = None;
    report.verification_runs = vec![];
    let text = text(&report);
    assert!(text.contains("  Work item        none\n"), "{text}");
    assert!(
        text.contains("No supported acceptance criteria were extracted."),
        "{text}"
    );
    assert!(
        text.contains("No verification runs recorded for this snapshot."),
        "{text}"
    );
    assert!(!text.contains("→"), "{text}");
}
