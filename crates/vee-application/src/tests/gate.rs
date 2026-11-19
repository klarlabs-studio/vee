use super::*;
use std::process::Command;
use vee_core::ports::*;
use vee_store_sqlite::ReviewStore;

#[test]
fn gate_result_exit_codes_match_cli_contract() {
    for (status, expected) in [
        (GateStatus::Pass, 0),
        (GateStatus::Block, 1),
        (GateStatus::Incomplete, 2),
    ] {
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision".into(),
            snapshot_id: "snapshot".into(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
            replay_inputs: None,
        };
        let result = GateCheckResult::from_decision("review", "snapshot", "snapshot", decision);
        assert_eq!(result.exit_code(), expected);
        assert_eq!(serde_json::to_value(result).unwrap()["schema_version"], 1);
    }
}

#[cfg(unix)]
#[test]
fn gate_rejects_verification_evidence_when_local_executable_changes() {
    use std::os::unix::fs::PermissionsExt;

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
    let executable = root.join("verify.sh");
    std::fs::write(&executable, "#!/bin/sh\ngrep -q reviewed source.rs\n").unwrap();
    let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&executable, permissions).unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn reviewed() {}\n").unwrap();
    let config_path = root.join(".vee.yaml");
    std::fs::write(
            &config_path,
            format!("version: 1\nverification:\n  unit: {{ executable: {}, timeout_seconds: 5, output_limit_bytes: 1024 }}\npolicy:\n  required_reviewers: []\n  required_verifications: [unit]\n  block_severities: []\n", executable.display()),
        )
        .unwrap();
    git(&["add", ".vee.yaml", "source.rs"]);
    git(&["commit", "-qm", "configure verifier and review change"]);
    let config = RepositoryConfig::load(&config_path).unwrap();
    let snapshot =
        capture_change_set(root, vee_git::ChangeScope::Commit { oid: "HEAD".into() }).unwrap();
    // The user's checkout can move on after the immutable commit snapshot
    // was selected. Verification must still see the committed file bytes.
    std::fs::write(root.join("source.rs"), "fn dirty_checkout() {}\n").unwrap();
    let config_digest = effective_review_config_digest(&config, root, &[], &[]).unwrap();
    let mut store = ReviewStore::open(&root.join("reviews.sqlite")).unwrap();
    store
        .save(
            "rev_local_verifier",
            &snapshot.digest,
            &config_digest,
            "complete",
            "{}",
        )
        .unwrap();

    let verification = run_verification(root, &snapshot, "unit", &config, &mut store).unwrap();
    let verification_runs = store.verifications_for_snapshot(&snapshot.digest).unwrap();
    let passing = evaluate_and_persist_gate(
        &mut store,
        GateEvaluation {
            review_id: "rev_local_verifier",
            reviewed_snapshot_id: &snapshot.digest,
            current: &snapshot,
            repository_root: root,
            reviewed_config_digest: &config_digest,
            effective_config_digest: &config_digest,
            config: &config,
            findings: &[],
            policy_findings: None,
            reviewer_outcomes: &[],
            analysis_complete: true,
            verification_runs: &verification_runs,
        },
    )
    .unwrap();
    assert_eq!(passing.status, GateStatus::Pass);
    assert_eq!(passing.verification_run_ids, vec![verification.run_id]);

    std::fs::write(&executable, "#!/bin/sh\nexit 1\n").unwrap();
    let stale_evidence = store.verifications_for_snapshot(&snapshot.digest).unwrap();
    let rejected = evaluate_and_persist_gate(
        &mut store,
        GateEvaluation {
            review_id: "rev_local_verifier",
            reviewed_snapshot_id: &snapshot.digest,
            current: &snapshot,
            repository_root: root,
            reviewed_config_digest: &config_digest,
            effective_config_digest: &config_digest,
            config: &config,
            findings: &[],
            policy_findings: None,
            reviewer_outcomes: &[],
            analysis_complete: true,
            verification_runs: &stale_evidence,
        },
    )
    .unwrap();

    assert_eq!(rejected.status, GateStatus::Incomplete);
    assert!(rejected.verification_run_ids.is_empty());
    assert!(rejected
        .reasons
        .iter()
        .any(|reason| reason.contains("unit")));
}

#[test]
fn reviewer_context_file_content_is_bound_to_effective_config_digest() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    std::fs::write(root.join("support.md"), "Original API contract.\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    context_files: [support.md]\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let initial = effective_config_digest(&config, root, &[]).unwrap();

    std::fs::write(root.join("support.md"), "Changed API contract.\n").unwrap();

    assert_ne!(
        initial,
        effective_config_digest(&config, root, &[]).unwrap()
    );
}

#[test]
fn analytics_only_provider_pricing_does_not_change_review_config_digest() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config_path = root.join(".vee.yaml");
    let config = |input_price: u32| {
        format!(
                "version: 1\nproviders:\n  api:\n    kind: openai_compatible\n    egress: local\n    endpoint: http://127.0.0.1:11434/v1/chat/completions\n    model: model-a\n    pricing:\n      model-a:\n        input_usd_per_million: {input_price}\n        output_usd_per_million: 10\n"
            )
    };
    std::fs::write(&config_path, config(2)).unwrap();
    let first = RepositoryConfig::load(&config_path).unwrap();
    let first_digest = effective_config_digest(&first, root, &[]).unwrap();
    std::fs::write(&config_path, config(3)).unwrap();
    let updated = RepositoryConfig::load(&config_path).unwrap();
    assert_eq!(
        first_digest,
        effective_config_digest(&updated, root, &[]).unwrap()
    );
}

#[test]
fn rechecked_gate_requires_successful_required_reviewer_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = ReviewStore::open(&directory.path().join("reviews.sqlite")).unwrap();
    let current = ChangeSet::from_entries(None, None, "working_tree", vec![]);
    store
        .save(
            "rev_missing_reviewer",
            &current.digest,
            "cfg",
            "incomplete",
            "{}",
        )
        .unwrap();
    let config: RepositoryConfig = serde_yaml::from_str(
        r#"
version: 1
providers: { p: { kind: cli, executable: fake } }
reviewers: { correctness: { provider: p, instructions_file: reviewer.md } }
policy: { required_reviewers: [correctness] }
"#,
    )
    .unwrap();
    std::fs::write(directory.path().join("reviewer.md"), "Review carefully.").unwrap();
    let config_digest = effective_config_digest(&config, directory.path(), &[]).unwrap();
    let decision = evaluate_and_persist_gate(
        &mut store,
        GateEvaluation {
            review_id: "rev_missing_reviewer",
            reviewed_snapshot_id: &current.digest,
            current: &current,
            repository_root: directory.path(),
            reviewed_config_digest: &config_digest,
            effective_config_digest: &config_digest,
            config: &config,
            findings: &[],
            policy_findings: None,
            reviewer_outcomes: &[],
            analysis_complete: true,
            verification_runs: &[],
        },
    )
    .unwrap();
    assert_eq!(decision.status, GateStatus::Incomplete);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("review did not complete")));
    let _ = &mut store;
}
