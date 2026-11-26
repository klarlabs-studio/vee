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

fn approval(approval_id: &str) -> vee_core::RuleApproval {
    vee_core::RuleApproval {
        schema_version: 2,
        approval_id: approval_id.into(),
        version: 1,
        candidate_id: "candidate".into(),
        evidence_digest: format!("sha256:{}", "a".repeat(64)),
        source_feedback_ids: vec![],
        activated_at_unix: None,
        category: "style".into(),
        feedback_label: vee_core::FindingFeedbackLabel::FalsePositive,
        scope: "src".into(),
        instruction: "Flag only  mixed\nindentation.".into(),
        approver: "maintainer".into(),
        approval_reason: "Repeated review feedback.".into(),
        supersedes_approval_id: None,
        expires_at_unix: None,
        created_at: String::new(),
        status: vee_core::RuleApprovalStatus::Active,
        events: Vec::new(),
    }
}

fn attributed_record(index: usize, approval_id: &str) -> vee_core::FindingRecord {
    vee_core::FindingRecord {
        finding: vee_core::Finding {
            suggestion: None,
            id: format!("find_{index:012x}"),
            fingerprint: format!("fp-{index}"),
            category: "style".into(),
            severity: vee_core::Severity::Medium,
            confidence: Some(90),
            rationale: "Indentation".into(),
            path: Some("src/lib.rs".into()),
            line: Some(1),
            provenance: "model_inference".into(),
            reviewer_ids: vec![],
            evidence_ids: vec![],
            rule_attributions: vec![vee_core::RuleAttribution {
                rule_id: "candidate".into(),
                approval_id: approval_id.into(),
                reviewer_id: "correctness".into(),
            }],
            sample_agreement: None,
            advisory: false,
        },
        assessments: vec![],
        status: vee_core::FindingStatus::Open,
        status_reason: None,
        occurrence_count: 1,
        first_seen: String::new(),
        last_seen: String::new(),
        occurrences: vec![],
    }
}

fn rejection(index: usize, created_at: &str) -> vee_core::FindingFeedback {
    vee_core::FindingFeedback {
        schema_version: 1,
        feedback_id: format!("feedback-{index}-{created_at}"),
        finding_id: format!("find_{index:012x}"),
        snapshot_id: "s".into(),
        label: vee_core::FindingFeedbackLabel::FalsePositive,
        reason: "fine here".into(),
        reviewer: "dev".into(),
        created_at: created_at.into(),
    }
}

#[test]
fn a_rule_is_noisy_when_most_of_its_findings_are_rejected() {
    let rule = approval("approval-noisy");
    let records: Vec<_> = (0..8)
        .map(|index| attributed_record(index, "approval-noisy"))
        .collect();
    // Four of eight rejected: under the five-finding minimum.
    let four: Vec<_> = (0..4)
        .map(|index| rejection(index, "2026-11-20 10:00:00"))
        .collect();
    assert!(noisy_rules(std::slice::from_ref(&rule), &records, &four).is_empty());
    let five: Vec<_> = (0..5)
        .map(|index| rejection(index, "2026-11-20 10:00:00"))
        .collect();
    let noisy = noisy_rules(std::slice::from_ref(&rule), &records, &five);
    assert_eq!(noisy.len(), 1);
    assert_eq!((noisy[0].attributed, noisy[0].rejected), (8, 5));
    assert!(noisy[0]
        .reason()
        .contains("vee rules restore approval-noisy"));
    // Five of twelve is under half.
    let more: Vec<_> = (0..12)
        .map(|index| attributed_record(index, "approval-noisy"))
        .collect();
    assert!(noisy_rules(std::slice::from_ref(&rule), &more, &five).is_empty());

    // After a restore, only later rejections count.
    let mut restored = rule.clone();
    restored.events.push(vee_core::RuleApprovalEvent {
        event_id: "e".into(),
        event: "restored".into(),
        actor: "maintainer".into(),
        reason: "Narrowed the instruction.".into(),
        created_at: "2026-11-21 09:00:00".into(),
    });
    assert!(noisy_rules(std::slice::from_ref(&restored), &records, &five).is_empty());
}

#[test]
fn the_rules_section_replaces_itself_and_keeps_the_rest_of_the_file() {
    let rules = [approval("approval-a")];
    let section = rules_section(&rules);
    assert!(section.contains("- **style** in `src`: Flag only mixed indentation."));
    let document = "# Review rules\n\nWrite tests.\n";
    let once = with_rules_section(document, &section);
    assert!(once.starts_with(document));
    let twice = with_rules_section(&once, &rules_section(&[]));
    assert!(twice.starts_with(document));
    assert!(twice.contains("No rules are approved yet."));
    assert_eq!(twice.matches(RULES_SECTION_START).count(), 1);
    assert!(twice.ends_with(&format!("{RULES_SECTION_END}\n")));
}

#[test]
fn a_suspended_rule_stops_applying_until_restored() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("vee.sqlite");
    let mut store = vee_store_sqlite::ReviewStore::open(&database).unwrap();
    store.create_rule_approval(&approval("approval-s")).unwrap();
    let vee = ActorName::new("actor", "vee").unwrap();
    let reason = Reason::new("Rejected too often.").unwrap();
    store
        .set_rule_approval_suspended("approval-s", true, &vee, &reason)
        .unwrap();
    assert!(store
        .set_rule_approval_suspended("approval-s", true, &vee, &reason)
        .is_err());
    let listed = store.list_rule_approvals().unwrap();
    assert_eq!(listed[0].status, vee_core::RuleApprovalStatus::Suspended);
    assert!(active_rule_approvals(&store).unwrap().is_empty());
    let person = ActorName::new("actor", "maintainer").unwrap();
    store
        .set_rule_approval_suspended("approval-s", false, &person, &reason)
        .unwrap();
    assert_eq!(active_rule_approvals(&store).unwrap().len(), 1);
    let events: Vec<String> = store.list_rule_approvals().unwrap()[0]
        .events
        .iter()
        .map(|event| event.event.clone())
        .collect();
    assert_eq!(events, ["activated", "suspended", "restored"]);
}
