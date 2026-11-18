use super::*;
use vee_core::ports::*;
use vee_core::{ActorName, Reason};

#[test]
fn approved_guidance_is_scope_limited_and_bound_to_effective_config() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nproviders:\n  p: { kind: cli, executable: unused }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md }\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let before = effective_config_digest(&config, root, &[]).unwrap();
    let database = root.join(".vee/vee.sqlite");
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    let mut store = vee_store_sqlite::ReviewStore::open(&database).unwrap();
    store
        .create_rule_approval(&vee_core::RuleApproval {
            schema_version: 2,
            approval_id: "approval-scoped".into(),
            version: 1,
            candidate_id: "candidate".into(),
            evidence_digest: format!("sha256:{}", "a".repeat(64)),
            source_feedback_ids: vec!["feedback-source".into()],
            activated_at_unix: None,
            category: "correctness".into(),
            feedback_label: vee_core::FindingFeedbackLabel::NotActionable,
            scope: "src/parser".into(),
            instruction: "Ask for a concrete parser boundary example.".into(),
            approver: "maintainer".into(),
            approval_reason: "Repeated review feedback.".into(),
            supersedes_approval_id: None,
            expires_at_unix: None,
            created_at: String::new(),
            status: vee_core::RuleApprovalStatus::Active,
            events: Vec::new(),
        })
        .unwrap();
    let files = vec![vee_core::SnapshotFile {
        path: "src/parser/token.rs".into(),
        mode: 0o100644,
        content_digest: "digest".into(),
        status: "modified".into(),
    }];
    let guidance =
        applicable_rule_guidance(&active_rule_approvals(&store).unwrap(), &[], &files).unwrap();
    assert_eq!(guidance.len(), 1);
    assert_eq!(guidance[0].approval_id, "approval-scoped");
    let after_approval =
        effective_config_digest(&config, root, &active_rule_approvals(&store).unwrap()).unwrap();
    assert_ne!(before, after_approval);
    let unrelated = vec![vee_core::SnapshotFile {
        path: "src/api.rs".into(),
        ..files[0].clone()
    }];
    assert!(
        applicable_rule_guidance(&active_rule_approvals(&store).unwrap(), &[], &unrelated)
            .unwrap()
            .is_empty()
    );
    store
        .revoke_rule_approval(
            "approval-scoped",
            &ActorName::new("actor", "maintainer").unwrap(),
            &Reason::new("Replaced").unwrap(),
        )
        .unwrap();
    assert!(
        applicable_rule_guidance(&active_rule_approvals(&store).unwrap(), &[], &files)
            .unwrap()
            .is_empty()
    );
    assert_ne!(
        after_approval,
        effective_config_digest(&config, root, &active_rule_approvals(&store).unwrap()).unwrap()
    );
}
