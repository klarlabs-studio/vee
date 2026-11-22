//! Views for the results of CLI actions: init, pack export and add, waiver
//! creation and patch application.

use serde::de::DeserializeOwned;
use serde::Serialize;
use vee_application::operations::PatchApplication;
use vee_application::packs::PackSummary;
use vee_application::setup::{DetectionReport, InitReport};
use vee_application::{ReviewResult, ReviewerOutcome};
use vee_core::{ChangeSet, GateStatus, Waiver};
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

fn init(repository_written: bool, provider_status: &str) -> InitReport {
    InitReport {
        schema_version: 1,
        repository_config: ".vee.yaml".into(),
        repository_config_status: if repository_written {
            "written"
        } else {
            "existing"
        }
        .into(),
        reviewer_instructions: "REVIEW.md".into(),
        reviewer_instructions_created: repository_written,
        user_config: "~/.config/vee/config.yaml".into(),
        provider_status: provider_status.into(),
        provider_id: "local".into(),
        candidate_id: Some("ollama".into()),
        egress: "local".into(),
        detection: DetectionReport {
            schema_version: 1,
            candidates: vec![],
            recommended: Some("ollama".into()),
        },
    }
}

#[test]
fn init_view_shows_what_was_created_and_the_next_commands() {
    let report = init(true, "written");
    let plain = text(&report);
    assert!(plain.starts_with("Vee initialized  ✔ ready"), "{plain}");
    assert!(plain.contains(".vee.yaml ✔ created"), "{plain}");
    assert!(plain.contains("REVIEW.md ✔ created"), "{plain}");
    assert!(plain.contains("local ✔ configured from ollama"), "{plain}");
    assert!(plain.contains("→ vee doctor"), "{plain}");
    assert!(plain.contains("→ vee review"), "{plain}");
    let markdown = md(&report);
    assert!(markdown.contains("`check_setup`"), "{markdown}");
    assert!(markdown.contains("`review_changes`"), "{markdown}");
    assert_round_trip(&report);
}

#[test]
fn init_view_says_when_the_repository_and_provider_already_existed() {
    let plain = text(&init(false, "existing"));
    assert!(plain.contains(".vee.yaml already present"), "{plain}");
    assert!(plain.contains("REVIEW.md already present"), "{plain}");
    assert!(plain.contains("local already configured"), "{plain}");
    assert!(!plain.contains("created"), "{plain}");
}

fn pack(pinned: bool, warnings: Vec<String>) -> PackSummary {
    PackSummary {
        schema_version: 1,
        name: "team-defaults".into(),
        version: "1.2.0".into(),
        path: "packs/team-defaults".into(),
        digest: "sha256:4fca0000000000000000000000000000000000000000000000000000000003314".into(),
        reviewers: vec!["correctness".into(), "security".into()],
        verification_profiles: vec![],
        policy_profiles: vec!["strict".into()],
        rules: 2,
        includes_policy: true,
        pinned,
        warnings,
    }
}

#[test]
fn pack_view_distinguishes_export_from_pin_and_lists_contents() {
    let exported = text(&pack(false, vec![]));
    assert!(
        exported.starts_with("Pack team-defaults 1.2.0  ● exported"),
        "{exported}"
    );
    assert!(exported.contains("correctness, security"), "{exported}");
    assert!(exported.contains("Verification     none"), "{exported}");
    assert!(exported.contains("→ vee packs list"), "{exported}");

    let pinned = pack(true, vec!["Approved rules were not exported.".into()]);
    let plain = text(&pinned);
    assert!(plain.contains("✔ pinned"), "{plain}");
    assert!(
        plain.contains("▲ Approved rules were not exported."),
        "{plain}"
    );
    assert!(md(&pinned).contains("🟢"));
    assert_round_trip(&pinned);
}

fn waiver() -> Waiver {
    Waiver {
        schema_version: 1,
        id: "waiver_0123456789abcdef0123".into(),
        finding_fingerprint: "fp_retry_bound".into(),
        snapshot_id: "sha256:snap".into(),
        reason: "The caller enforces the retry bound.".into(),
        author: "maintainer".into(),
        provenance: "local_cli".into(),
        created_at_unix: 1_795_348_631,
        expires_at_unix: 1_795_953_431,
    }
}

#[test]
fn waiver_view_shows_scope_expiry_and_reason() {
    let waiver = waiver();
    let plain = text(&waiver);
    assert!(
        plain.starts_with("Waiver waiver_0123456789abcdef0123  ▲ waived"),
        "{plain}"
    );
    assert!(plain.contains("fp_retry_bound"), "{plain}");
    assert!(plain.contains("1795953431"), "{plain}");
    assert!(
        plain.contains("The caller enforces the retry bound."),
        "{plain}"
    );
    assert!(
        plain.contains("only this finding in this snapshot"),
        "{plain}"
    );
    assert!(md(&waiver).contains("🟡"));
    assert_round_trip(&waiver);
}

fn passing_review() -> ReviewResult {
    let policy = vee_core::Policy {
        block_severities: vec![vee_core::Severity::High],
        minimum_confidence: 0,
        required_review_complete: true,
        required_verifications: vec![],
        analyzer_block_levels: Default::default(),
    };
    let gate = vee_core::evaluate_gate(
        "sha256:snap",
        "config",
        "policy",
        &[],
        &policy,
        true,
        vee_core::GateEvidence {
            verification_runs: &[],
            source_evidence: &[],
            analyzer_reports: &[],
        },
    );
    assert_eq!(gate.status, GateStatus::Pass);
    ReviewResult {
        schema_version: 2,
        review_id: "rev_follow_up".into(),
        snapshot_id: "sha256:snap".into(),
        status: "pass".into(),
        findings: vec![],
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
            duration_ms: Some(1_000),
            usage: None,
        }],
        reviewer_arbitration: vec![],
        analysis_complete: true,
        reasons: gate.reasons.clone(),
        gate,
        change_set: ChangeSet::from_entries(None, None, "working_tree", vec![]),
        effective_config_digest: "config".into(),
        selected_reviewers: vec!["correctness".into()],
        reviewer_context: vec![],
        unreviewed_paths: vec![],
        policy_profile: None,
        work_item: None,
        work_item_token_env: None,
    }
}

fn application(concurrent: bool) -> PatchApplication {
    PatchApplication {
        schema_version: 1,
        proposal_digest: "sha256:patch".into(),
        approved: true,
        application: "applied".into(),
        concurrent_mutation_detected: concurrent,
        review: passing_review(),
    }
}

#[test]
fn patch_application_view_shows_the_patch_then_the_follow_up_review() {
    let applied = application(false);
    let plain = text(&applied);
    assert!(plain.starts_with("Patch applied  ✔ applied"), "{plain}");
    assert!(plain.contains("sha256:patch"), "{plain}");
    let review_at = plain.find("rev_follow_up").expect("follow-up review shown");
    assert!(review_at > plain.find("sha256:patch").unwrap(), "{plain}");
    assert!(!plain.contains("concurrently"), "{plain}");
    let markdown = md(&applied);
    assert!(markdown.starts_with("## Patch applied"), "{markdown}");
    assert!(markdown.contains("## Review rev\\_follow\\_up"), "{markdown}");
    assert_round_trip(&applied);
}

#[test]
fn patch_application_view_warns_when_the_target_changed_concurrently() {
    let plain = text(&application(true));
    assert!(plain.contains("▲ target changed concurrently"), "{plain}");
    assert!(plain.contains("inspect the follow-up review"), "{plain}");
}
