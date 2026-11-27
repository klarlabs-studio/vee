use super::*;
use std::process::Command;
use vee_core::ports::*;
use vee_store_sqlite::ReviewStore;

#[test]
fn review_prompt_requires_exact_changed_line_anchors() {
    let prompt = provider_request_prompt(
        &serde_json::json!({
            "context_files": [{"path":"src.rs", "changed_line_ranges":[[4, 6]]}]
        }),
        "Review the supplied change context.",
        "task request",
    )
    .unwrap();
    assert!(prompt.contains("Treat those ranges as exact one-based line numbers"));
    assert!(prompt.contains("omit the line number"));
    assert!(prompt.contains("local-analysis leads"));
    assert!(prompt.contains("not proof of a runtime call or defect"));
    assert!(prompt.contains("Do not include an `id` field"));
    assert!(prompt.contains("Vee assigns finding identities"));
}

#[test]
fn review_prompt_asks_for_one_concise_defect_per_finding_and_rates_severity_by_consequence() {
    let prompt = provider_request_prompt(
        &serde_json::json!({"context_files": []}),
        "Review the supplied change context.",
        "review request",
    )
    .unwrap();
    assert!(prompt.contains("Each finding reports one defect"));
    assert!(prompt.contains("The first sentence states what goes wrong"));
    assert!(prompt.contains("at most two further sentences"));
    assert!(prompt.contains("Set severity by the consequence"));
    assert!(prompt.contains("is at least medium"));
}

#[test]
fn provider_findings_schema_carries_the_writing_and_severity_rules() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/provider-findings-v1.schema.json"
    ))
    .unwrap();
    let finding = &schema["properties"]["findings"]["items"]["properties"];
    let severity = finding["severity"]["description"].as_str().unwrap();
    assert!(severity.contains("is at least medium"));
    let rationale = finding["rationale"]["description"].as_str().unwrap();
    assert!(rationale.starts_with("One defect."));
}

#[test]
fn task_prompts_do_not_receive_review_finding_rules() {
    let prompt = provider_request_prompt(
        &serde_json::json!({"task_instructions": "Summarize the change."}),
        "Review the supplied change context.",
        "task request",
    )
    .unwrap();
    assert!(!prompt.contains("Each finding reports one defect"));
}

#[test]
fn source_evidence_marks_unchanged_finding_lines_as_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(
        root.join("source.rs"),
        "fn before() {}\nfn unchanged() {}\n",
    )
    .unwrap();
    git(&["add", "source.rs"]);
    git(&["commit", "-qm", "baseline"]);
    let current = b"fn changed() {}\nfn unchanged() {}\n";
    std::fs::write(root.join("source.rs"), current).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let mut findings = vec![
        vee_core::Finding {
            suggestion: None,
            id: "changed".into(),
            fingerprint: "changed".into(),
            category: "correctness".into(),
            severity: Severity::High,
            confidence: Some(90),
            rationale: "changed line finding".into(),
            path: Some("source.rs".into()),
            line: Some(1),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        },
        vee_core::Finding {
            suggestion: None,
            id: "unchanged".into(),
            fingerprint: "unchanged".into(),
            category: "correctness".into(),
            severity: Severity::High,
            confidence: Some(90),
            rationale: "unchanged line finding".into(),
            path: Some("source.rs".into()),
            line: Some(2),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        },
    ];

    let evidence = attach_source_evidence(root, &snapshot, &mut findings)
        .unwrap()
        .evidence;

    assert_eq!(evidence.len(), 2);
    let classification_by_line: std::collections::BTreeMap<_, _> = evidence
        .iter()
        .map(|item| (item.start_line.unwrap(), item.classification))
        .collect();
    assert_eq!(classification_by_line[&1], EvidenceClassification::Observed);
    assert_eq!(classification_by_line[&2], EvidenceClassification::Unknown);
    let policy = vee_core::Policy {
        block_severities: vec![Severity::High],
        minimum_confidence: 80,
        required_review_complete: true,
        required_verifications: vec![],
        analyzer_block_levels: Default::default(),
        severity_floors: Vec::new(),
    };
    let decision = vee_core::evaluate_gate(
        "snapshot",
        "config",
        "policy",
        &findings,
        &policy,
        true,
        vee_core::GateEvidence {
            verification_runs: &[],
            source_evidence: &evidence,
            analyzer_reports: &[],
        },
    );
    assert_eq!(decision.status, vee_core::GateStatus::Incomplete);
    assert!(decision.reasons[0].contains("changed line"));
}

#[test]
fn invalid_finding_line_preserves_other_source_evidence_and_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn before() {}\n").unwrap();
    git(&["add", "source.rs"]);
    git(&["commit", "-qm", "baseline"]);
    std::fs::write(root.join("source.rs"), "fn after() {}\n").unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let make_finding = |id: &str, line| vee_core::Finding {
        suggestion: None,
        id: id.into(),
        fingerprint: id.into(),
        category: "correctness".into(),
        severity: Severity::High,
        confidence: Some(90),
        rationale: "reviewer report".into(),
        path: Some("source.rs".into()),
        line: Some(line),
        provenance: "model_inference".into(),
        reviewer_ids: Vec::new(),
        evidence_ids: Vec::new(),
        rule_attributions: Vec::new(),
        sample_agreement: None,
        advisory: false,
    };
    let mut findings = vec![make_finding("valid", 1), make_finding("invalid", 292)];

    let result = attach_source_evidence(root, &snapshot, &mut findings).unwrap();

    assert_eq!(result.evidence.len(), 1);
    assert_eq!(
        result.evidence[0].classification,
        EvidenceClassification::Observed
    );
    assert_eq!(
        findings[0].evidence_ids,
        vec![result.evidence[0].id.clone()]
    );
    assert!(findings[1].evidence_ids.is_empty());
    assert_eq!(result.invalid_locations, vec!["source.rs:292"]);
}

#[test]
fn legacy_review_without_policy_findings_falls_back_to_display_findings() {
    let policy = vee_core::Policy {
        block_severities: vec![vee_core::Severity::High],
        minimum_confidence: 80,
        required_review_complete: true,
        required_verifications: vec![],
        analyzer_block_levels: Default::default(),
        severity_floors: Vec::new(),
    };
    let finding = vee_core::Finding {
        suggestion: None,
        id: "legacy-blocker".into(),
        fingerprint: "legacy-fingerprint".into(),
        category: "correctness".into(),
        severity: vee_core::Severity::High,
        confidence: Some(99),
        rationale: "legacy finding".into(),
        path: Some("src/lib.rs".into()),
        line: Some(1),
        provenance: "model_inference".into(),
        reviewer_ids: Vec::new(),
        evidence_ids: vec!["ev_legacy_source".into()],
        rule_attributions: Vec::new(),
        sample_agreement: None,
        advisory: false,
    };
    let evidence = Evidence {
        id: "ev_legacy_source".into(),
        kind: EvidenceKind::Source,
        provenance: "source_snapshot".into(),
        source_path: "src/lib.rs".into(),
        start_line: Some(1),
        end_line: Some(1),
        content_digest: "sha256:legacy".into(),
        classification: EvidenceClassification::Observed,
        verification: EvidenceVerification::Unverified,
    };
    let gate = vee_core::evaluate_gate(
        "snapshot",
        "config",
        "policy",
        std::slice::from_ref(&finding),
        &policy,
        true,
        vee_core::GateEvidence {
            verification_runs: &[],
            source_evidence: std::slice::from_ref(&evidence),
            analyzer_reports: &[],
        },
    );
    let review = ReviewResult {
        standards_digest: None,
        carried: None,
        schema_version: 2,
        review_id: "rev_legacy".into(),
        snapshot_id: "snapshot".into(),
        status: "block".into(),
        findings: vec![finding],
        policy_findings: None,
        evidence: vec![evidence.clone()],
        verification_runs: vec![],
        reviewer_outcomes: vec![],
        reviewer_arbitration: vec![],
        analysis_complete: true,
        reasons: gate.reasons.clone(),
        gate,
        change_set: ChangeSet::from_entries(None, None, "working_tree", vec![]),
        effective_config_digest: "config".into(),
        selected_reviewers: vec![],
        reviewer_context: vec![],
        unreviewed_paths: Vec::new(),
        policy_profile: None,
        review_effort: None,
        work_item: None,
        work_item_token_env: None,
    };
    let mut payload = serde_json::to_value(review).unwrap();
    payload.as_object_mut().unwrap().remove("policy_findings");

    let stored = deserialize_review_result(&payload.to_string()).unwrap();

    assert!(stored.policy_findings.is_none());
    let reevaluated = vee_core::evaluate_gate(
        "snapshot",
        "config",
        "policy",
        stored
            .policy_findings
            .as_deref()
            .unwrap_or(&stored.findings),
        &policy,
        stored.analysis_complete,
        vee_core::GateEvidence {
            verification_runs: &[],
            source_evidence: &stored.evidence,
            analyzer_reports: &[],
        },
    );
    assert_eq!(reevaluated.status, GateStatus::Block);
    assert_eq!(reevaluated.blocking_findings, vec!["legacy-blocker"]);
}

#[test]
fn reviewer_impact_context_prioritizes_production_references_over_tests() {
    let edge = |relationship: &str, certainty: &str| ImpactEdge {
        source_path: "src/lib.rs".into(),
        affected_path: "src/other.rs".into(),
        relationship: relationship.into(),
        symbol: "changed".into(),
        certainty: certainty.into(),
        evidence_line: 1,
        co_change: None,
    };
    let ordered = [
        edge("resolved_symbol_reference", "resolved_semantic"),
        edge("syntactic_symbol_reference", "inferred_heuristic"),
        edge("textual_symbol_reference", "inferred_heuristic"),
        edge("likely_test_reference", "inferred_heuristic"),
        edge("shared_local_dependency", "inferred_import"),
    ];
    for pair in ordered.windows(2) {
        assert!(
            impact_context_edge_priority(&pair[0]) < impact_context_edge_priority(&pair[1]),
            "{} should rank before {}",
            pair[0].relationship,
            pair[1].relationship
        );
    }
    assert!(
        impact_context_edge_priority(&edge("resolved_symbol_reference", "resolved_semantic"))
            < impact_context_edge_priority(&edge(
                "resolved_symbol_reference",
                "inferred_heuristic"
            ))
    );

    let mut distant_caller = edge("syntactic_symbol_reference", "inferred_heuristic");
    distant_caller.affected_path = "api/handlers.go".into();
    let mut local_test = edge("likely_test_reference", "inferred_heuristic");
    local_test.affected_path = "src/lib_test.go".into();
    assert!(
        impact_context_edge_priority(&distant_caller) < impact_context_edge_priority(&local_test),
        "a production caller in another directory ranks before a same-directory test"
    );

    let mut distant_test = edge("likely_test_reference", "inferred_heuristic");
    distant_test.affected_path = "domain/workload_test.go".into();
    assert!(
        impact_context_edge_priority(&local_test) < impact_context_edge_priority(&distant_test)
    );
}

#[test]
fn provider_token_budget_replaces_lowest_priority_impact_source_with_omission() {
    let instructions = "Review the exact changed source and report evidence-backed defects.";
    let changed = serde_json::json!({
        "path": "src/lib.rs",
        "content": "pub fn changed() { call(); }",
        "context_role": "changed_file",
    });
    let impact = |path: &str, content: &str| {
        serde_json::json!({
            "path": path,
            "content": content,
            "context_role": "snapshot_impact_reference",
        })
    };
    let mut payload = serde_json::json!({
        "instructions": instructions,
        "output_schema": {"type": "object", "properties": {"findings": {"type": "array"}}},
        "context_files": [
            changed,
            impact("src/lib_test.rs", &"test body ".repeat(300)),
            impact("src/other.rs", &"caller body ".repeat(300)),
            impact("other/distant.rs", &"unrelated body ".repeat(300)),
        ],
        "context_complete": true,
        "impact_context_count": 3,
        "omitted_impact_context_count": 0,
        "omitted_context_file_count": 0,
    });
    let mut within_budget = payload.clone();
    within_budget["context_files"].as_array_mut().unwrap().pop();
    within_budget["impact_context_count"] = serde_json::json!(2);
    let kind = vee_core::ProviderKind::OpenAiCompatible;
    let budget = estimate_provider_input_tokens(&within_budget, instructions, kind).unwrap();

    let (estimate, omitted, over_budget) =
        fit_review_payload_to_provider_budget(&mut payload, instructions, kind, budget).unwrap();

    assert!(!over_budget, "estimated {estimate} against budget {budget}");
    assert!(omitted >= 1);
    assert_eq!(payload["impact_context_count"], 3 - omitted);
    assert_eq!(payload["omitted_impact_context_count"], omitted);
    assert_eq!(payload["omitted_context_file_count"], 0);
    assert_eq!(payload["context_complete"], true);
    assert_eq!(payload["impact_context_complete"], false);
    let files = payload["context_files"].as_array().unwrap();
    assert_eq!(files[0]["path"], "src/lib.rs");
    assert_eq!(files[0]["content"], "pub fn changed() { call(); }");
    assert_eq!(files[3]["path"], "other/distant.rs");
    assert!(files[3].get("content").is_none());
    assert!(files[3]["note"].as_str().unwrap().contains("token budget"));
}

#[test]
fn reviewer_receives_bounded_snapshot_impact_context_with_provenance() {
    use std::sync::{Arc, Mutex};

    struct CapturingProvider(Arc<Mutex<Option<serde_json::Value>>>);
    impl ReviewProvider for CapturingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() { old(); }\n").unwrap();
    std::fs::write(
        root.join("src/unrelated.rs"),
        "pub fn unrelated() { old(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/caller.rs"),
        "pub fn entry() { crate::changed(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/unrelated_caller.rs"),
        "pub fn other_entry() { crate::unrelated(); }\n",
    )
    .unwrap();
    std::fs::write(root.join("reviewer.md"), "Review changed behavior.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() { new(); }\n").unwrap();
    std::fs::write(
        root.join("src/unrelated.rs"),
        "pub fn unrelated() { new(); }\n",
    )
    .unwrap();
    let config_path = root.join(".vee.yaml");
    std::fs::write(
            &config_path,
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    include: [src/lib.rs]\npolicy:\n  on_incomplete: block\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&config_path).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let captured = Arc::new(Mutex::new(None));
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    run_review_with_provider(
        root,
        snapshot.clone(),
        &config,
        &mut store,
        &CapturingProvider(captured.clone()),
        None,
    )
    .unwrap();

    let input = captured.lock().unwrap().clone().unwrap();
    assert_eq!(input["impact_context_count"], 1);
    assert_eq!(input["omitted_impact_context_count"], 0);
    assert_eq!(input["impact_context_status"], "complete");
    assert_eq!(input["impact_context_complete"], true);
    assert_eq!(input["impact_context_snapshot_id"], snapshot.digest);
    assert_eq!(input["impact_context_coverage_complete"], true);
    assert!(!input["impact_context_analyzers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!input["impact_context_limitations"]
        .as_array()
        .unwrap()
        .is_empty());
    let context = input["context_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "src/caller.rs")
        .unwrap();
    assert!(!input["context_files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["path"] == "src/unrelated_caller.rs"));
    assert_eq!(context["content"], "pub fn entry() { crate::changed(); }\n");
    assert_eq!(context["context_role"], "snapshot_impact_reference");
    assert_eq!(context["impact_snapshot_id"], snapshot.digest);
    assert_eq!(context["impact_edges"][0]["source_path"], "src/lib.rs");
    assert_eq!(context["impact_edges"][0]["symbol"], "changed");
    assert_eq!(context["impact_edges"][0]["certainty"], "inferred_syntax");
    assert_eq!(context["impact_edges"][0]["evidence_line"], 1);
    assert!(input["impact_context_note"]
        .as_str()
        .unwrap()
        .contains("inferred"));
}

#[test]
fn omitted_optional_impact_context_does_not_incomplete_a_full_source_review() {
    use std::sync::{Arc, Mutex};

    struct CapturingProvider(Arc<Mutex<Option<serde_json::Value>>>);
    impl ReviewProvider for CapturingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() { old(); }\n").unwrap();
    std::fs::write(
        root.join("src/caller.rs"),
        "pub fn entry() { crate::changed(); }\n",
    )
    .unwrap();
    std::fs::write(root.join("reviewer.md"), "Review changed behavior.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() { new(); }\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nreview:\n  include: [src/lib.rs]\n  max_context_files: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    include: [src/lib.rs]\npolicy:\n  on_incomplete: block\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let captured = Arc::new(Mutex::new(None));
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let review = run_review_with_provider(
        root,
        snapshot,
        &config,
        &mut store,
        &CapturingProvider(captured.clone()),
        None,
    )
    .unwrap();

    assert!(review.analysis_complete);
    assert_eq!(review.status, "pass");
    assert_eq!(review.reviewer_outcomes[0].status, "completed");
    let request = captured.lock().unwrap().clone().unwrap();
    assert_eq!(request["context_complete"], true);
    assert_eq!(request["omitted_context_file_count"], 0);
    assert_eq!(request["impact_context_complete"], false);
    assert_eq!(request["omitted_impact_context_count"], 1);
    assert_eq!(review.reviewer_context[0].files[0].path, "src/lib.rs");
    assert_eq!(review.reviewer_context[0].files[0].status, "full_source");
    assert_eq!(
        review.reviewer_context[0].impact_context_complete,
        Some(false)
    );
    assert_eq!(
        review.reviewer_context[0].omitted_impact_context_count,
        Some(1)
    );
}

#[test]
fn reviewer_receives_go_shared_dependency_context_from_the_snapshot() {
    use std::sync::{Arc, Mutex};

    struct CapturingProvider(Arc<Mutex<Option<serde_json::Value>>>);
    impl ReviewProvider for CapturingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(
        root.join("go.mod"),
        "module example.invalid/fortify\n\ngo 1.24\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("errors")).unwrap();
    std::fs::create_dir_all(root.join("retry")).unwrap();
    std::fs::create_dir_all(root.join("circuitbreaker")).unwrap();
    std::fs::write(root.join("errors/errors.go"), "package errors\n").unwrap();
    std::fs::write(
        root.join("retry/retry.go"),
        "package retry\nimport \"example.invalid/fortify/errors\"\nfunc Retry() {}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("circuitbreaker/breaker.go"),
        "package circuitbreaker\nimport \"example.invalid/fortify/errors\"\nfunc Break() {}\n",
    )
    .unwrap();
    std::fs::write(root.join("reviewer.md"), "Review interactions.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(
        root.join("retry/retry.go"),
        "package retry\nimport \"example.invalid/fortify/errors\"\nfunc Retry() { _ = true }\n",
    )
    .unwrap();
    let config_path = root.join(".vee.yaml");
    std::fs::write(
            &config_path,
            "version: 1\nreview:\n  include: [\"**/*.go\"]\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\npolicy:\n  on_incomplete: block\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&config_path).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let captured = Arc::new(Mutex::new(None));
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    run_review_with_provider(
        root,
        snapshot.clone(),
        &config,
        &mut store,
        &CapturingProvider(captured.clone()),
        None,
    )
    .unwrap();

    let input = captured.lock().unwrap().clone().unwrap();
    let context = input["context_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "circuitbreaker/breaker.go")
        .unwrap();
    assert_eq!(context["context_role"], "snapshot_impact_reference");
    assert_eq!(context["impact_snapshot_id"], snapshot.digest);
    assert_eq!(
        context["impact_edges"][0]["relationship"],
        "shared_local_dependency"
    );
    assert_eq!(context["impact_edges"][0]["certainty"], "inferred_import");
    assert_eq!(context["impact_edges"][0]["evidence_line"], 2);
    assert!(input["impact_context_analyzers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|analyzer| analyzer["id"] == "local-go-imports" && analyzer["status"] == "used"));
}

#[test]
fn review_application_uses_provider_port_and_preserves_domain_decisions() {
    struct TestProvider;
    impl ReviewProvider for TestProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            let input: serde_json::Value =
                serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?;
            assert_eq!(input["reviewer_id"], "correctness");
            assert_eq!(input["context_complete"], false);
            let paths: Vec<_> = input["context_files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|file| file["path"].as_str().unwrap())
                .collect();
            assert_eq!(
                paths,
                vec!["binary.rs", "binary_replaced.rs", "large.rs", "source.rs"]
            );
            assert_eq!(
                input["context_files"][0]["note"],
                "binary or non-UTF-8 baseline/source omitted"
            );
            assert_eq!(
                input["context_files"][1]["base_content"],
                serde_json::Value::Null
            );
            assert_eq!(
                input["context_files"][1]["content"],
                serde_json::Value::Null
            );
            assert_eq!(input["context_files"][1]["truncated"], true);
            assert_eq!(
                input["context_files"][1]["note"],
                "binary or Git LFS content exceeded the context budget and was omitted"
            );
            assert_eq!(input["context_files"][2]["truncated"], true);
            assert_eq!(input["context_files"][3]["base_content"], "fn main() {}\n");
            assert_eq!(
                input["context_files"][3]["content"],
                "fn main() { broken(); }\n"
            );
            assert_eq!(
                input["context_files"][3]["changed_line_ranges"],
                serde_json::json!([[1, 1]])
            );
            Ok(ProviderResult {
                    stdout: br#"{"schema_version":1,"findings":[{"category":"correctness","severity":"high","confidence":95,"rationale":"The changed path has a defect.","path":"source.rs","line":1}]}"#.to_vec(),
                    stderr: Vec::new(),
                    exit_code: Some(0),
                usage: None,
                })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("binary_replaced.rs"), *b"\xff\x00").unwrap();
    git(&["add", "source.rs"]);
    git(&["add", "binary_replaced.rs"]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn main() { broken(); }\n").unwrap();
    let mut oversized_nul_text = vec![b'x'; 128 * 1024 + 1];
    oversized_nul_text.push(0);
    std::fs::write(root.join("binary_replaced.rs"), oversized_nul_text).unwrap();
    std::fs::write(root.join("large.rs"), vec![b'x'; 128 * 1024 + 1]).unwrap();
    std::fs::write(root.join("binary.rs"), *b"\xff\x00").unwrap();
    std::fs::create_dir_all(root.join("generated")).unwrap();
    std::fs::write(root.join("generated/output.rs"), "fn generated() {}\n").unwrap();
    std::fs::write(root.join("notes.txt"), "not in the review include set\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nreview:\n  include: [\"**/*.rs\"]\n  exclude: [\"**/generated/**\"]\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\npolicy:\n  block_severities: [high]\n  minimum_confidence: 80\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let review =
        run_review_with_provider(root, snapshot, &config, &mut store, &TestProvider, None).unwrap();

    assert!(!review.analysis_complete);
    assert_eq!(review.reviewer_outcomes[0].status, "context_limited");
    assert_eq!(review.reviewer_outcomes[0].provider_id, "p");
    assert_eq!(
        review.reviewer_outcomes[0].provider_kind,
        vee_core::ProviderKind::Cli
    );
    assert_eq!(review.reviewer_outcomes[0].model, None);
    assert!(review.reviewer_outcomes[0].duration_ms.is_some());
    assert_eq!(review.gate.status, GateStatus::Incomplete);
    assert_eq!(review.findings.len(), 1);
    assert_eq!(review.findings[0].provenance, "model_inference");
    assert!(review
        .change_set
        .files
        .iter()
        .any(|file| file.path == "generated/output.rs"));
    assert!(review
        .change_set
        .files
        .iter()
        .any(|file| file.path == "notes.txt"));

    let mut legacy = serde_json::to_value(&review).unwrap();
    legacy["schema_version"] = serde_json::json!(1);
    for outcome in legacy["reviewer_outcomes"].as_array_mut().unwrap() {
        let object = outcome.as_object_mut().unwrap();
        object.remove("provider_id");
        object.remove("provider_kind");
        object.remove("model");
        object.remove("provider_version");
        object.remove("duration_ms");
    }
    let upgraded = deserialize_review_result(&legacy.to_string()).unwrap();
    assert_eq!(upgraded.schema_version, 2);
    assert_eq!(upgraded.reviewer_outcomes[0].provider_id, "");
    assert_eq!(
        upgraded.reviewer_outcomes[0].provider_kind,
        vee_core::ProviderKind::Cli
    );
}

#[cfg(unix)]
#[test]
fn provider_cache_reuses_only_exact_versioned_tool_requests() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingProvider {
        count: AtomicUsize,
        instructions: std::sync::Mutex<Vec<String>>,
    }
    impl ReviewProvider for CountingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            self.count.fetch_add(1, Ordering::SeqCst);
            let payload: serde_json::Value =
                serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?;
            self.instructions.lock().unwrap().push(
                payload["instructions"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let provider_directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn source() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review carefully.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn source() { let _ = 1; }\n").unwrap();
    let executable = provider_directory.path().join("provider");
    let provider_script = "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'reviewer 1.0.0\\n'; exit 0; fi\nexit 0\n";
    std::fs::write(&executable, provider_script).unwrap();
    let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions.clone()).unwrap();
    let write_config = || {
        std::fs::write(
                root.join(".vee.yaml"),
                format!(
                    "version: 1\nproviders:\n  p:\n    kind: cli\n    executable: {}\n    version_args: [--version]\nreviewers:\n  correctness: {{ provider: p, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n",
                    executable.display()
                ),
            )
            .unwrap();
    };
    write_config();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    store
        .create_rule_approval(&vee_core::RuleApproval {
            schema_version: 2,
            approval_id: "approved-guidance".into(),
            version: 1,
            candidate_id: "candidate".into(),
            evidence_digest: format!("sha256:{}", "b".repeat(64)),
            source_feedback_ids: vec!["feedback-source".into()],
            activated_at_unix: None,
            category: "correctness".into(),
            feedback_label: vee_core::FindingFeedbackLabel::NotActionable,
            scope: "source.rs".into(),
            instruction: "Check the changed source for a concrete boundary example.".into(),
            approver: "maintainer".into(),
            approval_reason: "Repeated feedback confirms the scope.".into(),
            supersedes_approval_id: None,
            expires_at_unix: None,
            created_at: String::new(),
            status: vee_core::RuleApprovalStatus::Active,
            events: Vec::new(),
        })
        .unwrap();
    let provider = CountingProvider {
        count: AtomicUsize::new(0),
        instructions: std::sync::Mutex::new(Vec::new()),
    };

    let first =
        run_review_with_provider(root, snapshot.clone(), &config, &mut store, &provider, None)
            .unwrap();
    let second =
        run_review_with_provider(root, snapshot.clone(), &config, &mut store, &provider, None)
            .unwrap();
    assert_eq!(provider.count.load(Ordering::SeqCst), 1);
    assert!(provider.instructions.lock().unwrap()[0]
        .contains("Check the changed source for a concrete boundary example."));
    assert_eq!(first.reviewer_outcomes[0].status, "completed");
    assert_eq!(second.reviewer_outcomes[0].status, "cached");
    assert!(second.analysis_complete);
    assert_eq!(second.gate.status, GateStatus::Pass);

    std::fs::write(root.join("reviewer.md"), "Review differently.\n").unwrap();
    let changed_instructions = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let third = run_review_with_provider(
        root,
        snapshot.clone(),
        &changed_instructions,
        &mut store,
        &provider,
        None,
    )
    .unwrap();
    assert_eq!(provider.count.load(Ordering::SeqCst), 2);
    assert_eq!(third.reviewer_outcomes[0].status, "completed");

    std::fs::write(
        &executable,
        format!("{provider_script}# changed tool bytes\n"),
    )
    .unwrap();
    std::fs::set_permissions(&executable, permissions).unwrap();
    let fourth = run_review_with_provider(
        root,
        snapshot,
        &changed_instructions,
        &mut store,
        &provider,
        None,
    )
    .unwrap();
    assert_eq!(provider.count.load(Ordering::SeqCst), 3);
    assert_eq!(fourth.reviewer_outcomes[0].status, "completed");
}

#[test]
fn provider_environment_identity_changes_without_retaining_secret_values() {
    let config: RepositoryConfig = serde_yaml::from_str(
            "version: 1\nproviders:\n  p: { kind: cli, executable: tool, env_allowlist: [API_TOKEN] }\nreviewers:\n  correctness: { provider: p, instructions_file: review.md }\n",
        )
        .unwrap();
    let selected = vec!["correctness".to_string()];
    let first =
        provider_environment_digests(&config, &selected, |_| Some("secret-a".into())).unwrap();
    let second =
        provider_environment_digests(&config, &selected, |_| Some("secret-b".into())).unwrap();
    assert_ne!(first, second);
    assert!(!format!("{first:?}{second:?}").contains("secret-a"));
    assert!(!format!("{first:?}{second:?}").contains("secret-b"));
}

#[test]
fn source_and_context_change_during_provider_execution_cannot_pass_gate() {
    struct MutatingProvider {
        root: PathBuf,
    }
    impl ReviewProvider for MutatingProvider {
        fn execute(
            &self,
            _request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            std::fs::write(self.root.join("support.md"), "Changed context.\n")
                .map_err(|error| error.to_string())?;
            std::fs::write(
                self.root.join("source.rs"),
                "fn changed_after_capture() {}\n",
            )
            .map_err(|error| error.to_string())?;
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn original() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review changes.\n").unwrap();
    std::fs::write(root.join("support.md"), "Original context.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn captured_change() {}\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    context_files: [support.md]\npolicy:\n  required_reviewers: [correctness]\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let review = run_review_with_provider(
        root,
        snapshot,
        &config,
        &mut store,
        &MutatingProvider {
            root: root.to_path_buf(),
        },
        None,
    )
    .unwrap();

    assert!(!review.analysis_complete);
    assert_eq!(review.status, "incomplete");
    assert_eq!(review.gate.status, GateStatus::Incomplete);
    assert!(review.reviewer_outcomes.iter().any(|outcome| {
        outcome.reviewer_id == "vee.configuration_consistency"
            && outcome.status == "configuration_changed_during_review"
    }));
    assert!(review.reviewer_outcomes.iter().any(|outcome| {
        outcome.reviewer_id == "vee.snapshot_consistency"
            && outcome.status == "source_changed_during_review"
    }));
}

#[test]
fn reviewer_selection_is_persisted_and_missing_required_reviewer_is_incomplete() {
    struct TestProvider;
    impl ReviewProvider for TestProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            let input: serde_json::Value =
                serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?;
            assert_eq!(input["reviewer_id"], "correctness");
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn main() { let _ = 1; }\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\n  security: { provider: p, instructions_file: reviewer.md }\npolicy:\n  required_reviewers: [correctness, security]\n  on_incomplete: block\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let review = run_review_with_provider_and_selection(
        root,
        snapshot,
        &config,
        &mut store,
        &TestProvider,
        Some(&["correctness".into()]),
        None,
    )
    .unwrap();

    assert_eq!(review.selected_reviewers, vec!["correctness"]);
    assert_eq!(review.reviewer_outcomes.len(), 1);
    assert_eq!(review.reviewer_outcomes[0].reviewer_id, "correctness");
    assert!(!review.analysis_complete);
    assert_eq!(review.gate.status, GateStatus::Incomplete);
    assert!(resolve_reviewer_selection(&config, Some(&["unknown".into()])).is_err());
}

#[test]
fn work_item_context_reaches_reviewers_and_binds_effective_configuration() {
    use std::sync::{Arc, Mutex};

    struct CapturingProvider(Arc<Mutex<Option<serde_json::Value>>>);
    impl ReviewProvider for CapturingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Check correctness.\n").unwrap();
    std::fs::write(root.join("support.md"), "Stable repository contract.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn main() { let _ = 1; }\n").unwrap();
    let config_path = root.join(".vee.yaml");
    std::fs::write(
            &config_path,
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    context_files: [support.md]\npolicy:\n  on_incomplete: block\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&config_path).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let mut item = vee_hosting::WorkItemSnapshot {
        schema_version: 1,
        reference: vee_hosting::WorkItemRef {
            repository: vee_hosting::RepositoryRef {
                host: "github.com".into(),
                full_name: "org/repo".into(),
            },
            number: 42,
        },
        provider: "github".into(),
        api_base: "https://api.github.com/".into(),
        title: "Keep export stable".into(),
        body: Some("Acceptance: retain the existing output format.".into()),
        acceptance_criteria: None,
        url: "https://github.com/org/repo/issues/42".into(),
        state: "open".into(),
        updated_at: "2026-11-14T12:00:00Z".into(),
        labels: vec!["requirements".into()],
        content_digest: String::new(),
    };
    item.content_digest = vee_hosting::work_item_digest(&item);
    let captured = Arc::new(Mutex::new(None));
    let reviewer_ids = vec!["correctness".to_string()];
    let review = run_review_with_provider_and_selection_context(
        root,
        snapshot,
        &config,
        &mut store,
        ReviewRunOptions {
            provider_adapter: &CapturingProvider(captured.clone()),
            requested_reviewers: Some(&reviewer_ids),
            cancellation: None,
            work_item: Some(item.clone()),
            work_item_token_env: Some("CUSTOM_HOSTING_TOKEN".into()),
            progress: None,
            carried: None,
        },
    )
    .unwrap();

    let input = captured.lock().unwrap().clone().unwrap();
    assert_eq!(input["context_files"][0]["path"], "support.md");
    assert_eq!(
        input["context_files"][0]["content"],
        "Stable repository contract.\n"
    );
    assert_eq!(
        input["context_files"][0]["classification"],
        "untrusted_repository_source"
    );
    assert_eq!(
        input["context_files"][0]["context_role"],
        "reviewer_configured_supplemental"
    );
    assert_eq!(input["work_item_context"]["title"], "Keep export stable");
    assert_eq!(
        input["work_item_context"]["classification"],
        "untrusted_external_requirements_context"
    );
    assert_eq!(
        input["work_item_context"]["content_digest"],
        item.content_digest
    );
    assert!(input["security_note"]
        .as_str()
        .unwrap()
        .contains("external work item"));
    assert_eq!(review.work_item.as_ref(), Some(&item));
    assert_eq!(
        review.effective_config_digest,
        effective_review_config_digest_with_work_item(
            &config,
            root,
            &reviewer_ids,
            &[],
            Some(&item)
        )
        .unwrap()
    );
    let mut changed_item = item;
    changed_item.body = Some("Updated acceptance.".into());
    changed_item.content_digest = vee_hosting::work_item_digest(&changed_item);
    let changed_context_digest = effective_review_config_digest_with_work_item(
        &config,
        root,
        &reviewer_ids,
        &[],
        Some(&changed_item),
    )
    .unwrap();
    assert_ne!(review.effective_config_digest, changed_context_digest);
    let verification_runs = store
        .verifications_for_snapshot(&review.snapshot_id)
        .unwrap();
    let recheck = evaluate_and_persist_gate(
        &mut store,
        GateEvaluation {
            review_id: &review.review_id,
            reviewed_snapshot_id: &review.snapshot_id,
            current: &review.change_set,
            repository_root: root,
            reviewed_config_digest: &review.effective_config_digest,
            effective_config_digest: &changed_context_digest,
            config: &config,
            findings: &review.findings,
            policy_findings: review.policy_findings.as_deref(),
            reviewer_outcomes: &review.reviewer_outcomes,
            analysis_complete: review.analysis_complete,
            verification_runs: &verification_runs,
        },
    )
    .unwrap();
    assert_eq!(recheck.status, GateStatus::Incomplete);
    assert!(recheck
        .reasons
        .iter()
        .any(|reason| reason.contains("configuration changed")));
}

#[test]
fn reviewers_run_concurrently_with_stable_result_order() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ConcurrentProvider {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }
    impl ReviewProvider for ConcurrentProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(current, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(100));
            self.active.fetch_sub(1, Ordering::SeqCst);
            let input: serde_json::Value =
                serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?;
            let reviewer_id = input["reviewer_id"].as_str().unwrap();
            assert!(matches!(reviewer_id, "correctness" | "security"));
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("source.rs"), "fn source() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review carefully.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn source() { let _ = 1; }\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nreview:\n  max_concurrency: 2\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\n  security: { provider: p, instructions_file: reviewer.md }\npolicy:\n  required_reviewers: [correctness, security]\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let provider = ConcurrentProvider {
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
    };

    let review = run_review_with_provider_and_selection(
        root, snapshot, &config, &mut store, &provider, None, None,
    )
    .unwrap();

    assert!(review.analysis_complete);
    assert!(provider.maximum.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        review
            .reviewer_outcomes
            .iter()
            .map(|outcome| outcome.reviewer_id.as_str())
            .collect::<Vec<_>>(),
        vec!["correctness", "security"]
    );
}

#[test]
fn review_globs_match_root_and_nested_paths_and_exclusions_win() {
    let config = vee_core::ReviewConfig {
        include: vec!["**/*.rs".into()],
        exclude: vec!["**/generated/**".into()],
        ..vee_core::ReviewConfig::default()
    };
    assert!(review_path_is_included("main.rs", &config));
    assert!(review_path_is_included("src/lib.rs", &config));
    assert!(!review_path_is_included("src/generated/out.rs", &config));
    assert!(!review_path_is_included("README.md", &config));
}

#[test]
fn reviewer_scope_globs_match_and_exclude_paths() {
    let reviewer = vee_core::ReviewerConfig {
        provider: "p".into(),
        instructions_file: "reviewer.md".into(),
        context_files: Vec::new(),
        enabled: true,
        include: vec!["src/**/*.rs".into()],
        exclude: vec!["src/generated/**".into()],
        policy: vee_core::ReviewerPolicyConfig::default(),
        strategy: vee_core::ReviewStrategy::default(),
        advisory: false,
        effort: None,
        samples: None,
        sample_quorum: None,
        sample_grouping: None,
    };

    assert!(reviewer_path_is_included("src/lib.rs", &reviewer));
    assert!(reviewer_path_is_included("src/nested/lib.rs", &reviewer));
    assert!(!reviewer_path_is_included(
        "src/generated/out.rs",
        &reviewer
    ));
    assert!(!reviewer_path_is_included("README.md", &reviewer));
}

#[test]
fn reviewer_context_manifest_distinguishes_supplied_filtered_and_omitted_paths() {
    let snapshot_file = |path: &str| vee_core::SnapshotFile {
        path: path.into(),
        mode: 0o100644,
        content_digest: "sha256:content".into(),
        status: "modified".into(),
    };
    let change_set = ChangeSet::from_entries(
        None,
        None,
        "working_tree",
        vec![
            snapshot_file("src/full.rs"),
            snapshot_file("src/diff.rs"),
            snapshot_file("src/metadata.rs"),
            snapshot_file("src/global-excluded.rs"),
            snapshot_file("src/reviewer-excluded.rs"),
            snapshot_file("src/over-budget.rs"),
            snapshot_file("README.md"),
        ],
    );
    let review = vee_core::ReviewConfig {
        include: vec!["**/*.rs".into()],
        exclude: vec!["src/global-excluded.rs".into()],
        ..vee_core::ReviewConfig::default()
    };
    let reviewer = vee_core::ReviewerConfig {
        provider: "p".into(),
        instructions_file: "reviewer.md".into(),
        context_files: Vec::new(),
        enabled: true,
        include: vec!["src/**/*.rs".into()],
        exclude: vec!["src/reviewer-excluded.rs".into()],
        policy: vee_core::ReviewerPolicyConfig::default(),
        strategy: vee_core::ReviewStrategy::default(),
        advisory: false,
        effort: None,
        samples: None,
        sample_quorum: None,
        sample_grouping: None,
    };
    let context_files = vec![
        serde_json::json!({"path":"src/full.rs","content":"source", "base_content":"base", "truncated":false}),
        serde_json::json!({"path":"src/diff.rs","diff":"bounded diff", "truncated":false}),
        serde_json::json!({"path":"src/metadata.rs","content":"LFS pointer", "note":"Git LFS object was not fetched", "truncated":false}),
    ];

    let manifest = reviewer_context_manifest(
        "correctness",
        &change_set,
        &context_files,
        &review,
        &reviewer,
    );
    let status = |path: &str| {
        manifest
            .files
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
            .status
            .as_str()
    };
    assert_eq!(status("src/full.rs"), "full_source");
    assert_eq!(status("src/diff.rs"), "bounded_diff");
    assert_eq!(status("src/metadata.rs"), "metadata_only");
    assert_eq!(
        status("src/global-excluded.rs"),
        "excluded_by_review_filter"
    );
    assert_eq!(
        status("src/reviewer-excluded.rs"),
        "excluded_by_reviewer_filter"
    );
    assert_eq!(status("src/over-budget.rs"), "omitted_by_context_limit");
    assert_eq!(status("README.md"), "excluded_by_review_filter");
    assert!(manifest
        .files
        .iter()
        .filter(|entry| matches!(
            entry.status.as_str(),
            "full_source" | "bounded_diff" | "metadata_only"
        ))
        .all(|entry| entry
            .artifact_digest
            .as_deref()
            .is_some_and(|digest| digest.starts_with("sha256:"))));
}

#[test]
fn reviewer_instruction_paths_cannot_escape_repository() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join(".vee.yaml");
    std::fs::write(
            &config_path,
            "version: 1\nproviders:\n  local:\n    kind: cli\n    executable: cat\nreviewers:\n  security:\n    provider: local\n    instructions_file: ../outside.md\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&config_path).unwrap();

    assert!(effective_config_digest(&config, directory.path(), &[])
        .unwrap_err()
        .contains("path escapes repository root"));
}

#[test]
fn reviewer_context_file_paths_cannot_escape_repository() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join(".vee.yaml");
    std::fs::write(
            &config_path,
            "version: 1\nproviders:\n  local: { kind: cli, executable: cat }\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\n    context_files: [../outside.md]\n",
        )
        .unwrap();

    let error = RepositoryConfig::load(&config_path).unwrap_err();
    assert!(error.contains("unsafe context file path"));
}

#[test]
fn review_progress_reports_each_reviewer_run_as_it_finishes() {
    use std::sync::{Arc, Mutex};

    struct SplitProvider;
    impl ReviewProvider for SplitProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            let input = String::from_utf8_lossy(&request.stdin);
            if input.contains("Always fail.") {
                return Err("provider unavailable".into());
            }
            if input.contains("Exit non-zero.") {
                // Process adapters report a failed process as `Ok` with its exit code.
                return Ok(ProviderResult {
                    stdout: Vec::new(),
                    // Not a usage limit, which would skip the provider's other runs.
                    stderr: b"provider crashed".to_vec(),
                    exit_code: Some(1),
                    usage: None,
                });
            }
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }
    #[derive(Default)]
    struct Recorder(Mutex<Vec<ReviewProgress>>);
    impl ReviewProgressSink for Recorder {
        fn report(&self, progress: &ReviewProgress) {
            self.0.lock().unwrap().push(progress.clone());
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    std::fs::write(root.join("passing.md"), "Review the change.\n").unwrap();
    std::fs::write(root.join("failing.md"), "Always fail.\n").unwrap();
    std::fs::write(root.join("exiting.md"), "Exit non-zero.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  passing:\n    provider: p\n    instructions_file: passing.md\n    samples: 2\n  failing:\n    provider: p\n    instructions_file: failing.md\n  exiting:\n    provider: p\n    instructions_file: exiting.md\n",
    )
    .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let recorder = Arc::new(Recorder::default());

    run_review_with_provider_and_selection_context(
        root,
        snapshot,
        &config,
        &mut store,
        ReviewRunOptions {
            provider_adapter: &SplitProvider,
            requested_reviewers: None,
            cancellation: None,
            work_item: None,
            work_item_token_env: None,
            progress: Some(&*recorder),
            carried: None,
        },
    )
    .unwrap();

    let reports = recorder.0.lock().unwrap().clone();
    // One report when execution starts, then one per finished run.
    assert_eq!(reports.len(), 5, "{reports:?}");
    let reviewer = |report: &ReviewProgress, id: &str| {
        report
            .reviewers
            .iter()
            .find(|reviewer| reviewer.reviewer_id == id)
            .cloned()
            .unwrap()
    };
    let first = &reports[0];
    assert_eq!(reviewer(first, "passing").runs, 2);
    assert_eq!(reviewer(first, "failing").runs, 1);
    assert!(first
        .reviewers
        .iter()
        .all(|reviewer| reviewer.finished == 0));
    let last = reports.last().unwrap();
    assert!(last.reviewers.iter().all(ReviewerProgress::is_finished));
    assert_eq!(reviewer(last, "passing").failed, 0);
    assert_eq!(reviewer(last, "failing").failed, 1);
    assert_eq!(reviewer(last, "exiting").failed, 1);
}

/// After a provider reports a usage or rate limit, its runs that have not
/// started are skipped instead of each failing the same way; other
/// providers keep running.
#[test]
fn a_provider_usage_limit_skips_its_remaining_runs() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct LimitedProvider {
        limited_calls: AtomicUsize,
        other_calls: AtomicUsize,
    }
    impl ReviewProvider for LimitedProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            if request.executable == "limited" {
                self.limited_calls.fetch_add(1, Ordering::SeqCst);
                return Ok(ProviderResult {
                    stdout: Vec::new(),
                    stderr: b"Claude AI usage limit reached|1795440000".to_vec(),
                    exit_code: Some(1),
                    usage: None,
                });
            }
            self.other_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    for name in ["a", "b", "c", "d"] {
        std::fs::write(
            root.join(format!("{name}.md")),
            format!("Reviewer {name}.\n"),
        )
        .unwrap();
    }
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    // One worker, so runs start one after another.
    std::fs::write(
        root.join(".vee.yaml"),
        "version: 1\nreview:\n  max_concurrency: 1\nproviders:\n  limited: { kind: cli, executable: limited }\n  other: { kind: cli, executable: other }\nreviewers:\n  a: { provider: limited, instructions_file: a.md }\n  b: { provider: limited, instructions_file: b.md }\n  c: { provider: limited, instructions_file: c.md }\n  d: { provider: other, instructions_file: d.md }\n",
    )
    .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let provider = LimitedProvider {
        limited_calls: AtomicUsize::new(0),
        other_calls: AtomicUsize::new(0),
    };

    let review = run_review_with_provider_and_selection_context(
        root,
        snapshot,
        &config,
        &mut store,
        ReviewRunOptions {
            provider_adapter: &provider,
            requested_reviewers: None,
            cancellation: None,
            work_item: None,
            work_item_token_env: None,
            progress: None,
            carried: None,
        },
    )
    .unwrap();

    assert_eq!(provider.limited_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.other_calls.load(Ordering::SeqCst), 1);
    let outcome = |id: &str| {
        review
            .reviewer_outcomes
            .iter()
            .find(|outcome| outcome.reviewer_id == id)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(outcome("d"), "completed");
    for id in ["a", "b", "c"] {
        assert_eq!(outcome(id), "rate_limited", "{id}");
    }
    assert!(!review.analysis_complete);
}

#[test]
fn a_large_early_file_does_not_crowd_later_files_out_of_the_reviewer_context() {
    use std::sync::{Arc, Mutex};
    struct CapturingProvider(Arc<Mutex<Option<serde_json::Value>>>);
    impl ReviewProvider for CapturingProvider {
        fn execute(
            &self,
            request: &ProviderRequest,
            _cancellation: Option<&tokio_util::sync::CancellationToken>,
        ) -> Result<ProviderResult, String> {
            *self.0.lock().unwrap() =
                Some(serde_json::from_slice(&request.stdin).map_err(|error| error.to_string())?);
            Ok(ProviderResult {
                stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
                stderr: Vec::new(),
                exit_code: Some(0),
                usage: None,
            })
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    // 40-byte lines; `lines` lines with line `changed` edited when `edit`.
    let source = |name: &str, lines: usize, edit: bool| {
        (0..lines)
            .map(|line| {
                let marker = if edit && line == lines / 2 {
                    "new"
                } else {
                    "old"
                };
                format!("// {name} line {line:04} {marker:<20}\n")
            })
            .collect::<String>()
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    for (name, lines) in [("a", 100), ("b", 50), ("c", 50)] {
        std::fs::write(root.join(format!("{name}.rs")), source(name, lines, false)).unwrap();
    }
    std::fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    for (name, lines) in [("a", 100), ("b", 50), ("c", 50)] {
        std::fs::write(root.join(format!("{name}.rs")), source(name, lines, true)).unwrap();
    }
    // a.rs alone takes 8,000 of the 10,000 bytes in full; b.rs's diff
    // (its whole 50 lines) no longer fits after that.
    std::fs::write(
        root.join(".vee.yaml"),
        "version: 1\nreview:\n  include: [\"**/*.rs\"]\n  max_context_bytes: 10000\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\n",
    )
    .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let captured = Arc::new(Mutex::new(None));

    let review = run_review_with_provider(
        root,
        snapshot,
        &config,
        &mut store,
        &CapturingProvider(captured.clone()),
        None,
    )
    .unwrap();

    let input = captured.lock().unwrap().clone().unwrap();
    for file in input["context_files"].as_array().unwrap() {
        let supplied = file["content"].is_string() || file["diff"].is_string();
        assert!(supplied, "{} was left out: {}", file["path"], file["note"]);
    }
    assert_eq!(input["context_complete"], true);
    assert!(review.analysis_complete);
}

#[cfg(unix)]
/// Reviewer `correctness` on provider `p`, with exploration on, over a change
/// to `src/lib.rs` whose caller is `src/caller.rs`.
fn exploration_review(
    provider: &str,
    adapter: &dyn ReviewProvider,
) -> (tempfile::TempDir, ChangeSet, ReviewResult) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn charge(cents: u64) {}\n").unwrap();
    std::fs::write(
        root.join("src/caller.rs"),
        "fn pay() { crate::charge(1); }\n",
    )
    .unwrap();
    std::fs::write(root.join("reviewer.md"), "Review changed behavior.\n").unwrap();
    // A stand-in reviewer CLI that only answers the version probe.
    let cli = root.join("fake-cli");
    std::fs::write(&cli, "#!/bin/sh\necho '2.1.0 (Claude Code)'\n").unwrap();
    std::fs::set_permissions(&cli, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn charge(dollars: u64) {}\n").unwrap();
    let config_path = root.join(".vee.yaml");
    std::fs::write(
        &config_path,
        format!(
            "version: 1\nproviders:\n  p: {{ kind: {provider}, executable: {} }}\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    include: [src/**]\nreview:\n  exploration:\n    enabled: true\n    max_tool_calls: 5\npolicy:\n  on_incomplete: block\n",
            cli.display()
        ),
    )
    .unwrap();
    let config = RepositoryConfig::load(&config_path).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let result =
        run_review_with_provider(root, snapshot.clone(), &config, &mut store, adapter, None)
            .unwrap();
    (directory, snapshot, result)
}

#[cfg(unix)]
/// Records each request and, like a reviewer calling the snapshot server,
/// appends one `read_file` call to the request's exploration log.
struct ExploringProvider(std::sync::Arc<std::sync::Mutex<Vec<ProviderRequest>>>);

#[cfg(unix)]
impl ReviewProvider for ExploringProvider {
    fn execute(
        &self,
        request: &ProviderRequest,
        _cancellation: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<ProviderResult, String> {
        self.0.lock().unwrap().push(request.clone());
        if let Some(launch) = &request.exploration {
            let log = launch
                .args
                .iter()
                .skip_while(|arg| *arg != "--log")
                .nth(1)
                .unwrap();
            std::fs::write(
                log,
                r#"{"tool":"read_file","arguments":{"path":"src/caller.rs"},"paths":["src/caller.rs"],"bytes":40,"outcome":"ok"}
"#,
            )
            .unwrap();
        }
        Ok(ProviderResult {
            stdout: br#"{"schema_version":1,"findings":[]}"#.to_vec(),
            stderr: Vec::new(),
            exit_code: Some(0),
            usage: None,
        })
    }
}

#[cfg(unix)]
#[test]
fn exploring_reviewers_get_the_snapshot_server_and_their_reads_are_recorded() {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (_directory, snapshot, result) =
        exploration_review("claude_cli", &ExploringProvider(requests.clone()));

    let requests = requests.lock().unwrap();
    let launch = requests[0].exploration.clone().expect("exploration launch");
    assert_eq!(launch.args[..3], ["mcp", "snapshot", "--spec"]);
    assert_eq!(launch.args[4], "--log");
    assert!(
        launch.descriptor.contains("\"max_tool_calls\":5"),
        "{}",
        launch.descriptor
    );
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].stdin).unwrap();
    assert_eq!(
        payload["exploration"]["tools"],
        serde_json::json!(vee_core::EXPLORATION_TOOLS)
    );
    // The spec and logs live only as long as the review.
    assert!(!Path::new(&launch.args[3]).exists());

    let exploration = result.reviewer_context[0].exploration.clone().unwrap();
    assert_eq!(exploration.status, "used");
    assert_eq!(exploration.tool_calls, 1);
    assert_eq!(exploration.read_bytes, 40);
    assert_eq!(exploration.files, ["src/caller.rs"]);
    assert_eq!(result.change_set.digest, snapshot.digest);
}

#[cfg(unix)]
#[test]
fn providers_without_snapshot_tools_review_the_bundle_and_say_so() {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (_directory, _snapshot, result) =
        exploration_review("cli", &ExploringProvider(requests.clone()));

    let requests = requests.lock().unwrap();
    assert!(requests[0].exploration.is_none());
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].stdin).unwrap();
    assert!(payload.get("exploration").is_none());
    let exploration = result.reviewer_context[0].exploration.clone().unwrap();
    assert_eq!(exploration.status, "unsupported");
    assert!(result.analysis_complete, "{:?}", result.reasons);
}
