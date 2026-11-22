use serde::de::DeserializeOwned;
use serde::Serialize;
use vee_application::test_effectiveness::{CorpusEffectivenessReport, EffectivenessReport};
use vee_application::test_proposals::{
    PersistedAssessment, TestPatchProposal, TestProposalApplication, TestProposalVerification,
};
use vee_application::ImpactedTestPlan;
use vee_present::{ansi, markdown, ToView};

const PROPOSAL: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SNAPSHOT: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const APPLIED: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const DIGEST: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

/// JSON → document → JSON must be lossless, so a transport can rebuild the document.
fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let value = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), value);
}

fn plain(document: &impl ToView) -> String {
    ansi::render(&document.to_view(), false)
}

fn plan(invocations: serde_json::Value, targets: serde_json::Value) -> ImpactedTestPlan {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "snapshot_id": SNAPSHOT,
        "profile_id": "rust-unit",
        "profile_digest": DIGEST,
        "executable": "cargo",
        "targets": targets,
        "invocations": invocations,
        "impact_coverage_complete": true,
        "limitations": ["Rust test filters are name-based."],
        "execution_performed": false,
    }))
    .unwrap()
}

#[test]
fn plan_lists_each_command_and_target_without_running_them() {
    let plan = plan(
        serde_json::json!([["test", "--manifest-path", "Cargo.toml", "tests::uses api"]]),
        serde_json::json!(["tests::uses api"]),
    );
    let text = plain(&plan);
    assert!(
        text.starts_with("Impacted test plan for rust-unit  ● not run\n"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Snapshot         {SNAPSHOT}\n")),
        "{text}"
    );
    assert!(text.contains("  Executable       cargo\n"), "{text}");
    assert!(
        text.contains(
            "Commands (1)\n\n  • cargo test --manifest-path Cargo.toml 'tests::uses api'\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("Targets (1)\n\n  • tests::uses api\n"),
        "{text}"
    );
    assert!(
        text.contains("  • Rust test filters are name-based.\n"),
        "{text}"
    );
    assert!(text.contains("● No commands were executed"), "{text}");
    assert!(
        text.ends_with("→ vee verify --profile rust-unit --impacted-tests\n"),
        "{text}"
    );
    let markdown = markdown::render(&plan.to_view());
    assert!(
        markdown.starts_with("## Impacted test plan for rust\\-unit · 🔵 **not run**\n"),
        "{markdown}"
    );
    assert!(
        markdown.contains("`vee verify --profile rust-unit --impacted-tests`"),
        "{markdown}"
    );
    assert_round_trip(&plan);
}

#[test]
fn plan_without_impacted_tests_says_so() {
    let text = plain(&plan(serde_json::json!([]), serde_json::json!([])));
    assert!(
        text.contains("Commands (0)\n\nNo test command would run for this change.\n"),
        "{text}"
    );
    assert!(
        text.contains("Targets (0)\n\nNo impacted test targets.\n"),
        "{text}"
    );
}

fn proposal(refinement: Option<serde_json::Value>, scope: &str) -> TestPatchProposal {
    let mut value = serde_json::json!({
        "schema_version": 2,
        "proposal_id": PROPOSAL,
        "snapshot_id": SNAPSHOT,
        "source_scope": scope,
        "base_oid": null,
        "reviewer_id": "correctness",
        "provider_id": "local",
        "provider_kind": "cli",
        "model": "local-model",
        "provider_output_digest": DIGEST,
        "context_summary": {
            "context_digest": DIGEST,
            "context_complete": false,
            "context_budget": {
                "method": "bytes_div_4",
                "max_context_tokens": 2048,
                "estimated_prompt_tokens": 1900,
                "reserved_tokens": 64,
                "budget_metadata_reserve_tokens": 32,
                "within_budget": true,
                "omitted_content_file_count": 1,
                "omitted_impact_context_count": 0
            },
            "omitted_paths": null,
            "file_manifest": []
        },
        "patch_digest": DIGEST,
        "patch_path": "/repo/.vee/proposals/test-1111.patch",
        "validated_in_isolated_sandbox": true,
        "sandbox_input_digest": DIGEST,
        "sandbox_result_digest": DIGEST,
        "application": "not_applied",
        "tests_executed": false,
        "verification_runs": [],
        "approval_instruction": format!("Inspect the generated diff, then run `vee tests apply {PROPOSAL} --approve {PROPOSAL}`. Vee has not modified the worktree or run repository tests."),
    });
    if let Some(refinement) = refinement {
        value["refinement"] = refinement;
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn generated_proposal_shows_identity_sandbox_and_approval_step() {
    let proposal = proposal(None, "working_tree");
    let text = plain(&proposal);
    assert!(text.starts_with("Test proposal  ● not applied\n"), "{text}");
    assert!(
        text.contains(&format!("  Proposal        {PROPOSAL}\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Patch digest    {DIGEST}\n")),
        "{text}"
    );
    assert!(
        text.contains("  Provider        local (local-model)\n"),
        "{text}"
    );
    assert!(text.contains("  Context         ▲ partial\n"), "{text}");
    assert!(
        text.contains("  Context budget  1900 of 2048 estimated tokens\n"),
        "{text}"
    );
    assert!(
        text.contains("  Sandbox         ✔ validated in isolated copy\n"),
        "{text}"
    );
    assert!(
        text.contains("  Saved at        /repo/.vee/proposals/test-1111.patch\n"),
        "{text}"
    );
    assert!(
        text.contains("● Not applied: inspect the saved diff and approve it explicitly before running tests. Tests were not run.\n"),
        "{text}"
    );
    assert!(
        text.ends_with(&format!(
            "→ vee tests apply {PROPOSAL} --approve {PROPOSAL}\n"
        )),
        "{text}"
    );
    assert!(!text.contains("Refines"), "{text}");
    let markdown = markdown::render(&proposal.to_view());
    assert!(markdown.starts_with("## Test proposal"), "{markdown}");
    assert_round_trip(&proposal);
    let value = serde_json::to_value(&proposal).unwrap();
    assert!(value.get("refinement").is_none(), "{value}");
}

#[test]
fn refined_proposal_names_its_parent_and_failed_run() {
    let proposal = proposal(
        Some(
            serde_json::json!({"parent_proposal_id": APPLIED, "failed_run_id": "run_7", "attempt": 2}),
        ),
        "working_tree",
    );
    let text = plain(&proposal);
    assert!(
        text.starts_with("Refined test proposal  ● not applied\n"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Refines         {APPLIED}\n")),
        "{text}"
    );
    assert!(text.contains("  Failed run      run_7\n"), "{text}");
    assert!(text.contains("  Attempt         2\n"), "{text}");
    assert_round_trip(&proposal);
}

#[test]
fn commit_scope_proposal_is_inspection_only() {
    let text = plain(&proposal(None, "commit"));
    assert!(
        text.ends_with("▲ Commit-scope proposals are inspection-only and cannot be applied.\n"),
        "{text}"
    );
    assert!(!text.contains("→ vee tests apply"), "{text}");
}

fn application(concurrent: bool) -> TestProposalApplication {
    TestProposalApplication {
        schema_version: 1,
        proposal_id: PROPOSAL.into(),
        application: "applied".into(),
        snapshot_id: APPLIED.into(),
        concurrent_mutation_detected: concurrent,
    }
}

#[test]
fn application_points_to_a_trusted_run() {
    let application = application(false);
    let text = plain(&application);
    assert_eq!(
        text,
        format!(
            "Test proposal applied  ✔ applied\n\
             \n  Proposal             {PROPOSAL}\n  Current snapshot     {APPLIED}\n  Concurrent mutation  none\n\
             \n→ vee tests run {PROPOSAL} --profile <profile>\n"
        )
    );
    let markdown = markdown::render(&application.to_view());
    assert!(
        markdown.starts_with("## Test proposal applied"),
        "{markdown}"
    );
    assert_round_trip(&application);
}

#[test]
fn application_with_concurrent_change_warns_and_suggests_a_new_proposal() {
    let text = plain(&application(true));
    assert!(
        text.starts_with("Test proposal applied  ▲ concurrent change\n"),
        "{text}"
    );
    assert!(text.contains("  Concurrent mutation  detected\n"), "{text}");
    assert!(text.ends_with("→ vee tests generate\n"), "{text}");
}

fn verification(status: &str) -> TestProposalVerification {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "proposal_id": PROPOSAL,
        "verification_run": {
            "schema_version": 1,
            "run_id": "run_7",
            "snapshot_id": APPLIED,
            "profile_id": "unit",
            "finding_id": null,
            "command_digest": DIGEST,
            "status": status,
            "exit_code": 1,
            "stdout_digest": DIGEST,
            "stderr_digest": DIGEST,
            "stdout_artifact": {"digest": DIGEST, "path": ".vee/artifacts/sha256/4444", "size_bytes": 12},
            "stderr_artifact": null,
        },
    }))
    .unwrap()
}

#[test]
fn failed_verification_shows_the_run_and_suggests_refinement() {
    let verification = verification("failed");
    let text = plain(&verification);
    assert!(
        text.starts_with("Test proposal verification unit  ✖ failed\n"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Proposal   {PROPOSAL}\n  Run        run_7\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Snapshot   {APPLIED}\n")),
        "{text}"
    );
    assert!(
        text.contains("Logs\n\n  • stdout .vee/artifacts/sha256/4444\n"),
        "{text}"
    );
    assert!(
        text.ends_with(&format!("→ vee tests refine {PROPOSAL} --run run_7\n")),
        "{text}"
    );
    let markdown = markdown::render(&verification.to_view());
    assert!(
        markdown.starts_with("## Test proposal verification unit"),
        "{markdown}"
    );
    assert_round_trip(&verification);
}

#[test]
fn passed_verification_suggests_an_effectiveness_check() {
    let text = plain(&verification("passed"));
    assert!(text.contains("✔ passed"), "{text}");
    assert!(
        text.ends_with(&format!(
            "→ vee tests effectiveness {PROPOSAL} --profile unit --mutant-patch <patch>\n"
        )),
        "{text}"
    );
}

fn effectiveness(paths: serde_json::Value) -> PersistedAssessment<EffectivenessReport> {
    serde_json::from_value(serde_json::json!({
        "report": {
            "schema_version": 4,
            "proposal_id": PROPOSAL,
            "snapshot_id": APPLIED,
            "profile_id": "unit",
            "baseline_verification_run_id": "run_8",
            "verification_command_digest": DIGEST,
            "coverage_run": {"run_id": "run_8", "snapshot_id": APPLIED, "profile_id": "unit", "stream": "stdout"},
            "changed_line_coverage": [{
                "path": "src/retry.rs",
                "changed_line_count": 1,
                "changed_executable_lines": 1,
                "changed_covered_lines": 1,
                "changed_percent": 100.0
            }],
            "mutant_patch_digest": DIGEST,
            "mutant_snapshot_id": SNAPSHOT,
            "mutant_paths": paths,
            "baseline_status": "passed",
            "mutated_status": "failed",
            "outcome": "killed",
            "mutant_failure_signal": "rust_test_failure",
            "baseline_stdout_digest": DIGEST,
            "baseline_stderr_digest": DIGEST,
            "mutated_stdout_digest": DIGEST,
            "mutated_stderr_digest": DIGEST,
            "limitations": ["This single-mutant diagnostic is not a calibrated test-quality score."]
        },
        "artifact_path": "/repo/.vee/effectiveness/assessment-5555.json",
        "artifact_digest": DIGEST,
    }))
    .unwrap()
}

#[test]
fn effectiveness_shows_outcome_statuses_coverage_and_saved_report() {
    let assessment = effectiveness(serde_json::json!(["src/retry.rs"]));
    let text = plain(&assessment);
    assert!(
        text.starts_with("Mutation effectiveness  ✔ killed\n"),
        "{text}"
    );
    assert!(text.contains("  Profile          unit\n"), "{text}");
    assert!(
        text.contains(&format!("  Snapshot         {APPLIED}\n")),
        "{text}"
    );
    assert!(
        text.contains("  Baseline         ✔ passed run_8\n"),
        "{text}"
    );
    assert!(text.contains("  Mutant           failed\n"), "{text}");
    assert!(
        text.contains("  Failure signal   rust_test_failure\n"),
        "{text}"
    );
    assert!(text.contains("  Coverage run     run_8 stdout\n"), "{text}");
    assert!(
        text.contains("Mutated files (1)\n\n  File          Changed lines covered\n  src/retry.rs  1/1 (100.0%)\n"),
        "{text}"
    );
    assert!(text.contains("Limitations\n"), "{text}");
    assert!(
        text.contains("Saved report\n\n  Path    /repo/.vee/effectiveness/assessment-5555.json\n"),
        "{text}"
    );
    let markdown = markdown::render(&assessment.to_view());
    assert!(
        markdown.starts_with("## Mutation effectiveness"),
        "{markdown}"
    );
    assert_round_trip(&assessment);
}

#[test]
fn effectiveness_without_mutated_files_says_so() {
    let text = plain(&effectiveness(serde_json::json!([])));
    assert!(
        text.contains("Mutated files (0)\n\nThe mutant changed no production files.\n"),
        "{text}"
    );
}

fn corpus(
    results: serde_json::Value,
    killed: usize,
    survived: usize,
) -> PersistedAssessment<CorpusEffectivenessReport> {
    let sample_size = results.as_array().unwrap().len();
    serde_json::from_value(serde_json::json!({
        "report": {
            "schema_version": 6,
            "proposal_id": PROPOSAL,
            "snapshot_id": APPLIED,
            "profile_id": "unit",
            "baseline_verification_run_id": "run_8",
            "verification_command_digest": DIGEST,
            "coverage_run": null,
            "corpus_id": "retry-boundaries",
            "corpus_digest": DIGEST,
            "provenance": {"dataset_kind": "seeded", "source": "maintainer fixtures", "source_revision": "v1", "license": "Apache-2.0"},
            "sample_size": sample_size,
            "killed": killed,
            "survived": survived,
            "inconclusive": sample_size - killed - survived,
            "results": results,
            "limitations": ["Changed-line coverage could not be attached: no LCOV output"]
        },
        "artifact_path": "/repo/.vee/effectiveness/corpus-6666.json",
        "artifact_digest": DIGEST,
    }))
    .unwrap()
}

fn mutant(id: &str, outcome: &str, mutated: &str, signal: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "patch_digest": DIGEST,
        "mutant_snapshot_id": SNAPSHOT,
        "mutant_paths": ["src/retry.rs"],
        "outcome": outcome,
        "baseline_status": "passed",
        "mutated_status": mutated,
        "mutant_failure_signal": signal,
        "mutated_stdout_digest": DIGEST,
        "mutated_stderr_digest": DIGEST,
        "changed_line_coverage": []
    })
}

#[test]
fn corpus_shows_counts_provenance_and_each_mutant() {
    let assessment = corpus(
        serde_json::json!([
            mutant(
                "retry-off-by-one",
                "killed",
                "failed",
                Some("rust_test_failure")
            ),
            mutant("unrelated-constant", "survived", "passed", None),
        ]),
        1,
        1,
    );
    let text = plain(&assessment);
    assert!(
        text.starts_with("Mutant corpus retry-boundaries  ✖ 1/2 killed\n"),
        "{text}"
    );
    assert!(
        text.contains("  Outcomes       1 killed, 1 survived, 0 inconclusive of 2\n"),
        "{text}"
    );
    assert!(
        text.contains(&format!("  Corpus digest  {DIGEST}\n")),
        "{text}"
    );
    assert!(text.contains("  Dataset        seeded\n"), "{text}");
    assert!(
        text.contains("  Source         maintainer fixtures v1\n"),
        "{text}"
    );
    assert!(text.contains("  Coverage run   unavailable\n"), "{text}");
    assert!(
        text.contains("  ✔ killed    retry-off-by-one    passed    failed   src/retry.rs  rust_test_failure\n"),
        "{text}"
    );
    assert!(
        text.contains("  ✖ survived  unrelated-constant  passed    passed   src/retry.rs  –\n"),
        "{text}"
    );
    assert!(text.contains("Saved report\n"), "{text}");
    let markdown = markdown::render(&assessment.to_view());
    assert!(
        markdown.starts_with("## Mutant corpus retry\\-boundaries · 🔴 **1/2 killed**\n"),
        "{markdown}"
    );
    assert_round_trip(&assessment);
}

#[test]
fn empty_corpus_says_so() {
    let text = plain(&corpus(serde_json::json!([]), 0, 0));
    assert!(
        text.starts_with("Mutant corpus retry-boundaries  ▲ 0/0 killed\n"),
        "{text}"
    );
    assert!(
        text.contains("Mutants (0)\n\nThe corpus has no mutants.\n"),
        "{text}"
    );
}
