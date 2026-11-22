use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use vee_application::acceptance::AcceptanceValidation;
use vee_application::attestation::AttestationVerification;
use vee_application::coverage::CoverageReport;
use vee_application::evidence_bundle::{BundleVerification, SignedBundle};
use vee_application::imported_history::{ImportedArchiveList, ImportedReview};
use vee_application::signing::SigningKeyPair;
use vee_core::VerificationRun;
use vee_present::{ansi, markdown, ToView};

/// JSON → document → JSON must be lossless, so a transport can rebuild the document.
fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let value = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), value);
}

fn text<T: ToView>(document: &T) -> String {
    ansi::render(&document.to_view(), false)
}

fn md<T: ToView>(document: &T) -> String {
    markdown::render(&document.to_view())
}

fn parse<T: DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

const SNAPSHOT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const MANIFEST: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const ARCHIVE: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_ARCHIVE: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";

fn verified_attestation() -> AttestationVerification {
    parse(json!({
        "schema_version": 1,
        "valid": true,
        "message": "signature verified; trust in the signer is determined by the supplied public key",
        "key_id": "release-key",
        "subjects": [
            {"name": "git-commit:abc123", "digest": {"gitCommit": "abc123"}},
            {"name": format!("vee-snapshot:{SNAPSHOT}"), "digest": {"sha256": "1111"}}
        ],
        "gate_status": "pass",
        "decision_id": "sha256:decision",
        "statement": {"_type": "https://in-toto.io/Statement/v1", "subject": []}
    }))
}

#[test]
fn verified_attestation_shows_gate_signer_and_subjects() {
    let report = verified_attestation();
    let text = text(&report);
    assert!(
        text.starts_with("Attestation verification  ✔ verified\n"),
        "{text}"
    );
    assert!(text.contains("✔ pass"), "{text}");
    assert!(text.contains("sha256:decision"), "{text}");
    assert!(text.contains("release-key"), "{text}");
    assert!(text.contains("Subjects (2)"), "{text}");
    assert!(
        text.contains("git-commit:abc123 gitCommit:abc123"),
        "{text}"
    );
    assert!(text.contains("trust in the signer"), "{text}");
    let markdown = md(&report);
    assert!(markdown.contains("`git-commit:abc123`"), "{markdown}");
    assert_round_trip(&report);
}

#[test]
fn rejected_attestation_shows_the_reason_only() {
    let report: AttestationVerification = parse(json!({
        "schema_version": 1,
        "valid": false,
        "message": "no signature verifies with the supplied public key"
    }));
    let text = text(&report);
    assert!(
        text.starts_with("Attestation verification  ✖ rejected\n"),
        "{text}"
    );
    assert!(
        text.contains("no signature verifies with the supplied public key"),
        "{text}"
    );
    assert!(!text.contains("Subjects"), "{text}");
    assert!(md(&report).contains("rejected"));
    assert_round_trip(&report);
    assert!(serde_json::to_value(&report)
        .unwrap()
        .get("key_id")
        .is_none());
}

fn bundle_verification(signature_valid: bool, replay_matches: Option<bool>) -> BundleVerification {
    parse(json!({
        "schema_version": 1,
        "valid": true,
        "signature_valid": signature_valid,
        "replay_status": if replay_matches.is_some() { "replayed" } else { "unavailable" },
        "replay_matches": replay_matches,
        "replay_message": match replay_matches {
            Some(true) => "deterministic gate replay matches the stored decision",
            Some(false) => "replayed gate decision differs from the stored decision",
            None => "bundle does not contain retained deterministic gate inputs",
        },
        "message": "bundle internal bindings are consistent but it is unsigned; this is not cryptographic tamper protection",
        "review_id": "review-1",
        "snapshot_id": SNAPSHOT,
        "gate_status": "block",
        "manifest_digest": MANIFEST
    }))
}

#[test]
fn unsigned_bundle_verification_shows_bindings_and_suggests_signing() {
    let report = bundle_verification(false, Some(true));
    assert!(report.passed());
    let text = text(&report);
    assert!(
        text.starts_with("Evidence bundle verification  ✔ valid\n"),
        "{text}"
    );
    for wanted in [
        "review-1",
        SNAPSHOT,
        MANIFEST,
        "✖ block",
        "▲ unsigned",
        "✔ matches",
        "not cryptographic tamper protection",
        "deterministic gate replay matches the stored decision",
        "→ vee reviews sign-bundle <bundle> --private-key <private-key> --key-id <key-id>",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    assert!(md(&report).contains(&format!("`{MANIFEST}`")));
    assert_round_trip(&report);
    assert_eq!(
        serde_json::to_value(&report).unwrap()["replay_matches"],
        true
    );
}

#[test]
fn bundle_replay_mismatch_and_unavailable_replay_are_flagged() {
    let mismatch = bundle_verification(true, Some(false));
    assert!(!mismatch.passed());
    let mismatch_text = text(&mismatch);
    assert!(
        mismatch_text.starts_with("Evidence bundle verification  ✖ replay mismatch\n"),
        "{mismatch_text}"
    );
    assert!(mismatch_text.contains("✖ differs"), "{mismatch_text}");
    assert!(!mismatch_text.contains("sign-bundle"), "{mismatch_text}");

    let unavailable = bundle_verification(false, None);
    assert!(unavailable.passed());
    assert!(text(&unavailable).contains("▲ unavailable"));
    assert_round_trip(&unavailable);
    assert!(serde_json::to_value(&unavailable).unwrap()["replay_matches"].is_null());
}

#[test]
fn invalid_bundle_shows_the_reason_without_bindings() {
    let report: BundleVerification = parse(json!({
        "schema_version": 1,
        "valid": false,
        "message": "manifest digest does not match"
    }));
    assert!(report.bindings.is_none());
    let text = text(&report);
    assert!(
        text.starts_with("Evidence bundle verification  ✖ invalid\n"),
        "{text}"
    );
    assert!(text.contains("manifest digest does not match"), "{text}");
    assert!(!text.contains("Manifest"), "{text}");
    assert!(md(&report).contains("manifest digest does not match"));
    assert_round_trip(&report);
}

#[test]
fn signed_bundle_names_the_key_and_the_verify_step() {
    let signed: SignedBundle = parse(json!({
        "path": "out/evidence bundle.json",
        "algorithm": "ed25519",
        "key_id": "release-key",
        "manifest_digest": MANIFEST
    }));
    let text = text(&signed);
    assert!(
        text.starts_with("Evidence bundle signed  ✔ signed\n"),
        "{text}"
    );
    assert!(
        text.contains("Signed evidence bundle with Ed25519 key release-key."),
        "{text}"
    );
    assert!(
        text.contains(
            "→ vee reviews verify-bundle 'out/evidence bundle.json' --public-key <public-key>"
        ),
        "{text}"
    );
    assert!(md(&signed).contains("`release-key`"));
    assert_round_trip(&signed);
}

#[test]
fn key_pair_view_shows_paths_and_never_key_material() {
    let pair: SigningKeyPair = parse(json!({
        "algorithm": "ed25519",
        "private_key": "keys/signing.der",
        "public_key": "keys/verify.bin"
    }));
    let text = text(&pair);
    assert!(text.starts_with("Signing key pair generated\n"), "{text}");
    assert!(
        text.contains("Keep keys/signing.der private and distribute keys/verify.bin to verifiers."),
        "{text}"
    );
    assert!(
        text.contains(
            "→ vee reviews sign-bundle <bundle> --private-key keys/signing.der --key-id <key-id>"
        ),
        "{text}"
    );
    assert!(md(&pair).contains("`keys/verify.bin`"));
    assert_round_trip(&pair);
}

#[test]
fn imported_review_is_marked_untrusted_with_next_steps() {
    let imported: ImportedReview = parse(json!({
        "schema_version": 1,
        "archive_digest": ARCHIVE,
        "review_id": "review-7",
        "snapshot_id": SNAPSHOT,
        "status": "block",
        "trust": "untrusted_external",
        "gate_eligible": false
    }));
    let text = text(&imported);
    assert!(
        text.starts_with("Imported review review-7  ▲ untrusted_external\n"),
        "{text}"
    );
    assert!(text.contains("excluded from gate evaluation"), "{text}");
    assert!(text.contains("Gate eligible  no"), "{text}");
    assert!(
        text.contains(&format!("→ vee reviews imported show {ARCHIVE}")),
        "{text}"
    );
    assert!(
        text.contains("→ vee reviews imported search <query>"),
        "{text}"
    );
    let markdown = md(&imported);
    assert!(
        markdown.contains("`search_imported_review_history`"),
        "{markdown}"
    );
    assert_round_trip(&imported);
}

#[test]
fn imported_archive_list_shows_reviews_and_discussions() {
    let list: ImportedArchiveList = parse(json!({
        "schema_version": 1,
        "reviews": [
            {
                "archive_digest": ARCHIVE,
                "archive_type": "review",
                "review_id": "review-7",
                "snapshot_id": SNAPSHOT,
                "status": "pass",
                "trust": "untrusted_external",
                "gate_eligible": false
            },
            {
                "archive_digest": OTHER_ARCHIVE,
                "archive_type": "provider_discussions",
                "provider": "github",
                "pull_request": {"repository": {"host": "github.com", "full_name": "example/service"}, "number": 9},
                "revision": "cccccccc",
                "complete": false,
                "issue_count": 3,
                "trust": "untrusted_external",
                "gate_eligible": false
            }
        ]
    }));
    let text = text(&list);
    assert!(text.starts_with("Imported review archives (2)\n"), "{text}");
    for wanted in [
        ARCHIVE,
        OTHER_ARCHIVE,
        "review-7",
        "✔ pass",
        "github discussion",
        "example/service #9",
        "3 issues ▲ partial",
        "untrusted_external",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    assert!(
        text.contains(&format!("→ vee reviews imported show {ARCHIVE}")),
        "{text}"
    );
    assert!(md(&list).contains("| Archive |"));
    assert_round_trip(&list);
    assert_eq!(
        serde_json::to_value(&list).unwrap()["reviews"][1]["archive_type"],
        "provider_discussions"
    );
}

#[test]
fn empty_imported_archive_list_says_so() {
    let list: ImportedArchiveList = parse(json!({"schema_version": 1, "reviews": []}));
    let text = text(&list);
    assert!(text.contains("No imported review archives."), "{text}");
    assert!(text.contains("→ vee reviews import <path>"), "{text}");
    assert!(md(&list).contains("No imported review archives"));
    assert_round_trip(&list);
}

#[test]
fn verification_show_lists_log_artifacts_with_digests() {
    let run: VerificationRun = parse(json!({
        "schema_version": 1,
        "run_id": "run-1",
        "snapshot_id": SNAPSHOT,
        "profile_id": "unit",
        "targets": [],
        "command_digest": "sha256:cmd",
        "status": "failed",
        "exit_code": 101,
        "stdout_digest": "sha256:out",
        "stderr_digest": "sha256:err",
        "stdout_artifact": {"digest": "sha256:out", "path": ".vee/artifacts/out.log", "size_bytes": 10},
        "stderr_artifact": null
    }));
    let text = text(&run);
    assert!(text.starts_with("Verification unit  ✖ failed\n"), "{text}");
    assert!(
        text.contains("stdout .vee/artifacts/out.log sha256:out"),
        "{text}"
    );
    assert!(md(&run).contains("`sha256:out`"));
}

fn coverage(files: serde_json::Value) -> CoverageReport {
    parse(json!({
        "schema_version": 1,
        "run_id": "run-cov",
        "snapshot_id": SNAPSHOT,
        "profile_id": "coverage",
        "stream": "stdout",
        "measured_scope": "file_and_changed_executable_lines",
        "files": files,
        "limitations": ["Changed-line coverage needs the captured base content."]
    }))
}

#[test]
fn coverage_shows_file_and_changed_line_coverage() {
    let report = coverage(json!([
        {"path": "src/lib.rs", "covered_lines": 17, "executable_lines": 20, "percent": 85.0,
         "changed_line_count": 6, "changed_executable_lines": 4, "changed_covered_lines": 3, "changed_percent": 75.0},
        {"path": "src/empty.rs", "covered_lines": 0, "executable_lines": 0, "percent": null,
         "changed_line_count": null, "changed_executable_lines": null, "changed_covered_lines": null, "changed_percent": null}
    ]));
    let text = text(&report);
    assert!(
        text.starts_with("Coverage for changed files (2)\n"),
        "{text}"
    );
    for wanted in [
        "run-cov",
        "85.0% (17/20)",
        "75.0% (3/4)",
        "no executable lines",
        "not measured",
        "Changed-line coverage needs the captured base content.",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    assert!(md(&report).contains("`src/lib.rs`"));
    assert_round_trip(&report);
}

#[test]
fn coverage_without_changed_files_says_so() {
    let report = coverage(json!([]));
    let text = text(&report);
    assert!(
        text.contains("No changed files appear in the coverage report."),
        "{text}"
    );
    assert_round_trip(&report);
}

fn validation(criteria: serde_json::Value, result: &str) -> AcceptanceValidation {
    parse(json!({
        "schema_version": 1,
        "review_id": "review-3",
        "snapshot_id": SNAPSHOT,
        "work_item_digest": "5555555555555555555555555555555555555555555555555555555555555555",
        "policy_digest": MANIFEST,
        "gate_status": "pass",
        "author": "maintainer",
        "recorded_at": "2026-01-02T03:04:05Z",
        "result": result,
        "assessment_complete": result == "all_attested_met",
        "criteria": criteria,
        "limitations": ["Mappings are human assertions."]
    }))
}

#[test]
fn acceptance_validation_shows_each_criterion_and_missing_evidence() {
    let report = validation(
        json!([
            {"id": "AC-aaaaaaaaaaaa", "source_id": "AC-1", "text": "Reject expired tokens",
             "assessment": "met", "rationale": "Covered by the token tests.",
             "changed_paths": ["src/token.rs"],
             "verification_runs": [{"run_id": "run-1", "profile_id": "unit", "status": "passed", "targets": []}],
             "evidence_satisfied": true, "evidence_reasons": []},
            {"id": "AC-bbbbbbbbbbbb", "text": "Keep the public API stable",
             "assessment": null, "rationale": null, "changed_paths": [], "verification_runs": [],
             "evidence_satisfied": false, "evidence_reasons": ["a passed verification run is required"]}
        ]),
        "incomplete",
    );
    let text = text(&report);
    assert!(
        text.starts_with("Acceptance assessment for review review-3  ▲ incomplete\n"),
        "{text}"
    );
    for wanted in [
        "maintainer",
        "human attestation",
        "Criteria (2)",
        "AC-aaaaaaaaaaaa",
        "✔ met",
        "▲ unassessed",
        "Covered by the token tests.",
        "path src/token.rs",
        "verification run-1 unit ✔ passed",
        "Evidence required: a passed verification run is required",
        "Mappings are human assertions.",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    assert!(md(&report).contains("`AC-aaaaaaaaaaaa`"));
    assert_round_trip(&report);
}

#[test]
fn acceptance_validation_without_criteria_says_so() {
    let report = validation(json!([]), "all_attested_met");
    let text = text(&report);
    assert!(text.contains("✔ all attested met"), "{text}");
    assert!(
        text.contains("The work item has no acceptance criteria."),
        "{text}"
    );
    assert_round_trip(&report);
}
