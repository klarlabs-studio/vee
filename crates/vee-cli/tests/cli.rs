use std::{fs, process::Command};
use vee_core::ports::*;
use vee_core::{ActorName, Reason};

mod support;
use support::vee;

fn accept_with_timeout(listener: &std::net::TcpListener) -> std::io::Result<std::net::TcpStream> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
#[test]
fn impacted_test_plan_emits_snapshot_bound_argv_without_execution() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    init_git(root);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"plan-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn changed_api() {}\n#[cfg(test)] mod tests { #[test] fn uses_api() { super::changed_api(); } }\n").unwrap();
    commit_all(root, "baseline");
    fs::write(root.join("src/lib.rs"), "pub fn changed_api() { let _ = true; }\n#[cfg(test)] mod tests { #[test] fn uses_api() { super::changed_api(); } }\n").unwrap();
    fs::write(root.join(".vee.yaml"), "version: 1\nverification:\n  rust-unit:\n    executable: cargo\n    args: [test, --manifest-path, Cargo.toml, \"{impacted_rust_test_filters}\"]\n").unwrap();

    let result = vee()
        .args([
            "tests",
            "plan",
            "--working-tree",
            "--profile",
            "rust-unit",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/impacted-test-plan-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
    assert_eq!(report["execution_performed"], false);
    assert_eq!(report["executable"], "cargo");
    assert_eq!(report["profile_digest"].as_str().unwrap().len(), 71);
    assert!(
        report["invocations"][0]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg == "tests::uses_api"),
        "unexpected planned invocation: {report}"
    );
}

fn publish_fixture_config_digest(root: &std::path::Path) -> String {
    support::isolate_process_environment();
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let config = vee_application::load_repository_config(root).unwrap();
    vee_application::effective_review_config_digest_with_work_item(&config, root, &[], &[], None)
        .unwrap()
}

#[cfg(unix)]
#[test]
fn pr_draft_uses_snapshot_context_and_emits_schema_valid_non_gating_output() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    init_git(root);
    fs::write(root.join("tracked.rs"), "fn before() {}\n").unwrap();
    fs::write(root.join("reviewer.md"), "Use concise wording.\n").unwrap();
    commit_all(root, "baseline");
    fs::write(root.join("tracked.rs"), "fn changed_behavior() {}\n").unwrap();

    let provider = root.join("fake-description-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ninput=$(/bin/cat)\ncase \"$input\" in *\"changed_behavior\"*) ;; *) exit 31 ;; esac\nprintf '%s' '{\"title\":\"Describe changed behavior\",\"body\":\"## Summary\\nDescribe the new behavior.\\n\\n## Testing\\nNot stated in supplied context.\"}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
        "version: 1\nproviders:\n  local:\n    kind: cli\n    egress: local\n    executable: {}\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\n",
            provider.display()
        ),
    )
    .unwrap();

    let result = vee()
        .args(["pr", "draft", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "status={} stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/pr-description-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
    assert_eq!(report["output"]["title"], "Describe changed behavior");
    assert_eq!(report["snapshot_id"].as_str().unwrap().len(), 71);
    assert!(report["output_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Draft generated"));
    assert!(!root.join(".vee/vee.sqlite").exists());
}

#[cfg(unix)]
#[test]
fn test_generation_saves_snapshot_bound_sandbox_checked_patch_without_applying() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    init_git(root);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed() -> bool { true }\n",
    )
    .unwrap();
    fs::write(root.join("src/lib_test.rs"), "// baseline test context\n").unwrap();
    fs::write(root.join("reviewer.md"), "Generate focused tests.\n").unwrap();
    commit_all(root, "baseline");
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed() -> bool { false }\n",
    )
    .unwrap();
    fs::write(root.join("src/lib_test.rs"), "// changed test context\n").unwrap();
    for index in 0..12 {
        fs::write(
            root.join(format!("src/changed_{index}.rs")),
            format!("// changed context file {index}\n{}\n", "x".repeat(1800)),
        )
        .unwrap();
    }

    let patch = "diff --git a/tests/changed_test.rs b/tests/changed_test.rs\nnew file mode 100644\n--- /dev/null\n+++ b/tests/changed_test.rs\n@@ -0,0 +1,4 @@\n+#[test]\n+fn changed_behavior() {\n+    assert!(!vee::changed());\n+}\n";
    let provider_directory = tempfile::tempdir().unwrap();
    let provider = provider_directory.path().join("fake-test-provider");
    let refined_patch = "diff --git a/tests/refined_test.rs b/tests/refined_test.rs\nnew file mode 100644\n--- /dev/null\n+++ b/tests/refined_test.rs\n@@ -0,0 +1,4 @@\n+#[test]\n+fn refined_behavior() {\n+    assert!(!vee::changed());\n+}\n";
    let provider_output = serde_json::json!({"patch": patch, "summary": "Add a regression test."});
    fs::write(
        &provider,
        format!(
            "#!/bin/sh\ninput=$(/bin/cat)\ncase \"$input\" in *\"src/lib_test.rs\"*) ;; *) exit 31 ;; esac\nprintf '%s' '{}'\n",
            provider_output,
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let verification_script = provider_directory.path().join("fake-test-runner");
    fs::write(&verification_script, "#!/bin/sh\nif test -f tests/refined_test.rs && grep -q 'false' src/lib.rs; then printf 'TN:\\nSF:src/lib.rs\\nDA:1,1\\nend_of_record\\n'; exit 0; else echo '--- FAIL: changed_behavior'; exit 1; fi\n").unwrap();
    let mut permissions = fs::metadata(&verification_script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&verification_script, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\ntest_generation:\n  max_context_tokens: 2048\nproviders:\n  local:\n    kind: cli\n    egress: local\n    executable: {}\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\nverification:\n  unit:\n    executable: {}\n    args: []\n    timeout_seconds: 5\n    output_limit_bytes: 4096\n",
            provider.display(), verification_script.display()
        ),
    )
    .unwrap();

    let result = vee()
        .args(["tests", "generate", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "status={} stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-patch-proposal-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&report));
    assert_eq!(report["application"], "not_applied");
    assert_eq!(report["tests_executed"], false);
    assert_eq!(report["validated_in_isolated_sandbox"], true);
    assert_eq!(
        report["context_summary"]["context_budget"]["within_budget"],
        true
    );
    assert!(
        report["context_summary"]["context_budget"]["estimated_prompt_tokens"]
            .as_u64()
            .unwrap()
            <= 2048
    );
    assert!(
        report["context_summary"]["context_budget"]["omitted_content_file_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(root
        .join(".vee/proposals")
        .join(format!(
            "test-{}.patch",
            &report["proposal_id"].as_str().unwrap()[7..]
        ))
        .is_file());
    assert!(!root.join("tests/changed_test.rs").exists());

    let proposal_id = report["proposal_id"].as_str().unwrap();
    let wrong_approval = vee()
        .args([
            "tests",
            "apply",
            proposal_id,
            "--approve",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!wrong_approval.status.success());
    assert!(!root.join("tests/changed_test.rs").exists());

    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed() -> bool { true }\n",
    )
    .unwrap();
    let stale_apply = vee()
        .args(["tests", "apply", proposal_id, "--approve", proposal_id])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!stale_apply.status.success());
    assert!(String::from_utf8_lossy(&stale_apply.stderr).contains("source snapshot is stale"));
    assert!(!root.join("tests/changed_test.rs").exists());
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed() -> bool { false }\n",
    )
    .unwrap();

    let apply = vee()
        .args([
            "tests",
            "apply",
            proposal_id,
            "--approve",
            proposal_id,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "status={} stdout={} stderr={}",
        apply.status,
        String::from_utf8_lossy(&apply.stdout),
        String::from_utf8_lossy(&apply.stderr)
    );
    let application: serde_json::Value = serde_json::from_slice(&apply.stdout).unwrap();
    let application_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-proposal-application-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&application_schema)
        .unwrap()
        .is_valid(&application));
    assert_eq!(application["application"], "applied");
    assert_eq!(application["concurrent_mutation_detected"], false);
    assert!(root.join("tests/changed_test.rs").is_file());
    assert!(!root.join("tests/refined_test.rs").exists());

    let run = vee()
        .args([
            "tests",
            "run",
            proposal_id,
            "--profile",
            "unit",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let failed_verification: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(failed_verification["verification_run"]["status"], "failed");

    fs::write(&provider, format!("#!/bin/sh\ninput=$(/bin/cat)\nprintf '%s' '{}'\n", serde_json::json!({"patch": refined_patch, "summary": "Add the missing regression assertion."}))).unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();

    let refine = vee()
        .args([
            "tests",
            "refine",
            proposal_id,
            "--run",
            failed_verification["verification_run"]["run_id"]
                .as_str()
                .unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        refine.status.success(),
        "status={} stdout={} stderr={}",
        refine.status,
        String::from_utf8_lossy(&refine.stdout),
        String::from_utf8_lossy(&refine.stderr)
    );
    let refined: serde_json::Value = serde_json::from_slice(&refine.stdout).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&refined));
    assert_eq!(refined["refinement"]["parent_proposal_id"], proposal_id);
    assert_eq!(
        refined["refinement"]["failed_run_id"],
        failed_verification["verification_run"]["run_id"]
    );
    assert_eq!(refined["refinement"]["attempt"], 1);

    let refined_id = refined["proposal_id"].as_str().unwrap();
    let refined_apply = vee()
        .args([
            "tests",
            "apply",
            refined_id,
            "--approve",
            refined_id,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        refined_apply.status.success(),
        "status={} stdout={} stderr={}",
        refined_apply.status,
        String::from_utf8_lossy(&refined_apply.stdout),
        String::from_utf8_lossy(&refined_apply.stderr)
    );
    assert!(root.join("tests/refined_test.rs").is_file());
    let refined_application: serde_json::Value =
        serde_json::from_slice(&refined_apply.stdout).unwrap();

    let run = vee()
        .args([
            "tests",
            "run",
            refined_id,
            "--profile",
            "unit",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "status={} stdout={} stderr={}",
        run.status,
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-verification-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&verification_schema)
        .unwrap()
        .is_valid(&verification));
    assert_eq!(verification["verification_run"]["status"], "passed");
    assert_eq!(
        verification["verification_run"]["snapshot_id"],
        refined_application["snapshot_id"]
    );
    let metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(
            root.join(".vee/proposals")
                .join(format!("test-{}.json", &proposal_id[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["tests_executed"], true);
    assert_eq!(metadata["verification_runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        metadata["last_verification_run_id"],
        failed_verification["verification_run"]["run_id"]
    );
    let refined_metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(
            root.join(".vee/proposals")
                .join(format!("test-{}.json", &refined_id[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        refined_metadata["last_verification_run_id"],
        verification["verification_run"]["run_id"]
    );

    let mutant_patch = provider_directory.path().join("mutant.patch");
    fs::write(&mutant_patch, "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-pub fn changed() -> bool { false }\n+pub fn changed() -> bool { true }\n").unwrap();
    let assessment = vee()
        .args([
            "tests",
            "effectiveness",
            refined_id,
            "--profile",
            "unit",
            "--mutant-patch",
        ])
        .arg(&mutant_patch)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        assessment.status.success(),
        "status={} stdout={} stderr={}",
        assessment.status,
        String::from_utf8_lossy(&assessment.stdout),
        String::from_utf8_lossy(&assessment.stderr)
    );
    let effectiveness: serde_json::Value = serde_json::from_slice(&assessment.stdout).unwrap();
    let effectiveness_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-effectiveness-v4.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&effectiveness_schema)
        .unwrap()
        .is_valid(&effectiveness));
    assert_eq!(effectiveness["baseline_status"], "passed");
    assert_eq!(effectiveness["mutated_status"], "failed");
    assert_eq!(effectiveness["outcome"], "killed");
    assert_eq!(effectiveness["profile_id"], "unit");
    assert_eq!(effectiveness["schema_version"], 4);
    assert_eq!(
        effectiveness["coverage_run"]["snapshot_id"], effectiveness["snapshot_id"],
        "{effectiveness:#}"
    );
    assert_eq!(
        effectiveness["changed_line_coverage"][0]["path"],
        "src/lib.rs"
    );
    assert_eq!(
        effectiveness["changed_line_coverage"][0]["changed_covered_lines"],
        1
    );
    assert_eq!(
        effectiveness["baseline_verification_run_id"],
        verification["verification_run"]["run_id"]
    );
    assert_eq!(
        effectiveness["verification_command_digest"],
        verification["verification_run"]["command_digest"]
    );
    assert!(effectiveness["mutant_failure_signal"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase()
        .contains("fail"));
    assert_eq!(
        effectiveness["snapshot_id"],
        refined_application["snapshot_id"]
    );

    let corpus_dir = provider_directory.path().join("mutant-corpus");
    fs::create_dir_all(&corpus_dir).unwrap();
    let reusable_corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/effectiveness/rust");
    fs::copy(
        reusable_corpus.join("kills.patch"),
        corpus_dir.join("kills.patch"),
    )
    .unwrap();
    fs::copy(
        reusable_corpus.join("survives.patch"),
        corpus_dir.join("survives.patch"),
    )
    .unwrap();
    let manifest_path = corpus_dir.join("manifest.json");
    fs::copy(reusable_corpus.join("manifest.json"), &manifest_path).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let manifest_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-mutant-corpus-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&manifest_schema)
        .unwrap()
        .is_valid(&manifest));
    let corpus = vee()
        .args([
            "tests",
            "effectiveness-corpus",
            refined_id,
            "--profile",
            "unit",
            "--manifest",
        ])
        .arg(&manifest_path)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        corpus.status.success(),
        "status={} stdout={} stderr={}",
        corpus.status,
        String::from_utf8_lossy(&corpus.stdout),
        String::from_utf8_lossy(&corpus.stderr)
    );
    let corpus_report: serde_json::Value = serde_json::from_slice(&corpus.stdout).unwrap();
    let corpus_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/test-effectiveness-corpus-v6.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&corpus_schema)
        .unwrap()
        .is_valid(&corpus_report));
    assert_eq!(corpus_report["sample_size"], 2);
    assert_eq!(corpus_report["schema_version"], 6);
    assert_eq!(corpus_report["corpus_id"], "rust-reviewed-behavior-v1");
    assert_eq!(corpus_report["provenance"]["dataset_kind"], "seeded");
    assert_eq!(
        corpus_report["provenance"]["source"],
        "Vee authored synthetic Rust behavior fixtures"
    );
    assert_eq!(
        corpus_report["provenance"]["source_revision"],
        "fixture-set-v1"
    );
    assert_eq!(
        corpus_report["verification_command_digest"],
        verification["verification_run"]["command_digest"]
    );
    assert_eq!(corpus_report["killed"], 1);
    assert_eq!(corpus_report["survived"], 1);
    assert_eq!(corpus_report["inconclusive"], 0);
    let corpus_results = corpus_report["results"].as_array().unwrap();
    assert_eq!(corpus_results.len(), 2);
    for result in corpus_results {
        assert!(result["mutant_snapshot_id"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(result["mutant_paths"], serde_json::json!(["src/lib.rs"]));
        assert_eq!(result["changed_line_coverage"][0]["path"], "src/lib.rs");
        assert_eq!(
            result["changed_line_coverage"][0]["changed_covered_lines"],
            1
        );
        assert!(result["mutated_stdout_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(result["mutated_stderr_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }
    assert_ne!(
        corpus_results[0]["mutant_snapshot_id"],
        corpus_results[1]["mutant_snapshot_id"]
    );
    assert_eq!(
        corpus_report["snapshot_id"],
        refined_application["snapshot_id"]
    );
    assert!(String::from_utf8_lossy(&corpus.stderr).contains("Effectiveness corpus artifact"));
    assert_eq!(
        fs::read_to_string(root.join("src/lib.rs")).unwrap(),
        "pub fn changed() -> bool { false }\n"
    );
    let artifacts = fs::read_dir(root.join(".vee/effectiveness"))
        .unwrap()
        .count();
    assert_eq!(artifacts, 2);
}

#[test]
fn owners_cli_emits_advisory_digest_bound_codeowners_report() {
    let repository = tempfile::tempdir().unwrap();
    init_git(repository.path());
    fs::create_dir_all(repository.path().join("src")).unwrap();
    fs::write(repository.path().join("src/lib.rs"), "pub fn run() {}\n").unwrap();
    fs::write(
        repository.path().join("CODEOWNERS"),
        "* @team/all\nsrc/** @team/rust\n",
    )
    .unwrap();
    let output = vee()
        .args(["owners", "--path", "src/lib.rs", "--output", "json"])
        .current_dir(repository.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/ownership-report-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&report));
    assert_eq!(report["advisory_only"], true);
    assert_eq!(report["results"][0]["owners"][0], "@team/rust");
    assert_eq!(report["results"][0]["matching_rule_line"], 2);
}

#[test]
fn repository_map_cli_reports_digest_bound_manifest_edges_deterministically() {
    let consumer = tempfile::tempdir().unwrap();
    let provider = tempfile::tempdir().unwrap();
    fs::write(
        consumer.path().join("Cargo.toml"),
        "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nprovider='*'\n",
    )
    .unwrap();
    fs::write(
        provider.path().join("Cargo.toml"),
        "[package]\nname='provider'\nversion='0.1.0'\n",
    )
    .unwrap();
    let run = || {
        vee()
            .args(["repos", "map"])
            .arg(consumer.path())
            .arg(provider.path())
            .args(["--output", "json"])
            .output()
            .unwrap()
    };
    let first = run();
    let second = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(second.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/repository-map-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&first));
    assert_eq!(first["schema_version"], 2);
    assert_eq!(first["dependencies"].as_array().unwrap().len(), 1);
    assert_eq!(
        first["dependencies"][0]["version_compatibility"],
        "satisfied"
    );
    assert_eq!(first["dependencies"][0]["from"], "consumer");
    assert_eq!(first["dependencies"][0]["to"], "provider");
    assert_eq!(first["digest"], second["digest"]);

    fs::write(
        consumer.path().join("Cargo.toml"),
        "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nprovider='^0.2'\n",
    )
    .unwrap();
    let mismatch = run();
    assert!(mismatch.status.success());
    let mismatch: serde_json::Value = serde_json::from_slice(&mismatch.stdout).unwrap();
    assert_eq!(
        mismatch["dependencies"][0]["version_compatibility"],
        "mismatch"
    );
    assert!(mismatch["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("requires `^0.2`")));

    fs::remove_file(consumer.path().join("Cargo.toml")).unwrap();
    fs::remove_file(provider.path().join("Cargo.toml")).unwrap();
    fs::write(
        consumer.path().join("go.mod"),
        "module example.com/consumer\n\ngo 1.23\n\nrequire example.com/provider/v2 v1.2.3\n",
    )
    .unwrap();
    fs::write(
        provider.path().join("go.mod"),
        "module example.com/provider/v2\n\ngo 1.23\n",
    )
    .unwrap();
    let go_mismatch = run();
    assert!(go_mismatch.status.success());
    let go_mismatch: serde_json::Value = serde_json::from_slice(&go_mismatch.stdout).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&go_mismatch));
    assert_eq!(
        go_mismatch["dependencies"][0]["version_compatibility"],
        "mismatch"
    );

    fs::write(
        consumer.path().join("go.mod"),
        "module example.com/consumer\n\ngo 1.23\n\nrequire example.com/provider/v2 v2.3.4\n",
    )
    .unwrap();
    let go_matching_major = run();
    assert!(go_matching_major.status.success());
    let go_matching_major: serde_json::Value =
        serde_json::from_slice(&go_matching_major.stdout).unwrap();
    assert_eq!(
        go_matching_major["dependencies"][0]["version_compatibility"],
        "not_evaluated"
    );

    let local_provider_path = format!(
        "../{}",
        provider.path().file_name().unwrap().to_string_lossy()
    );
    fs::write(
        consumer.path().join("go.mod"),
        format!("module example.com/consumer\n\ngo 1.23\n\nrequire (\n example.com/provider/v2 v2.3.4\n)\n\nreplace (\n example.com/provider/v2 => {local_provider_path}\n)\n"),
    )
    .unwrap();
    fs::write(
        provider.path().join("go.mod"),
        "module example.com/fork/v2\n\ngo 1.23\n",
    )
    .unwrap();
    let go_local_replace = run();
    assert!(go_local_replace.status.success());
    let go_local_replace: serde_json::Value =
        serde_json::from_slice(&go_local_replace.stdout).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&go_local_replace));
    assert_eq!(
        go_local_replace["dependencies"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        go_local_replace["dependencies"][0]["package"],
        "example.com/provider/v2"
    );
    assert_eq!(
        go_local_replace["dependencies"][0]["to"],
        "example.com/fork/v2"
    );
    assert_eq!(
        go_local_replace["dependencies"][0]["declared_path"],
        local_provider_path
    );
    assert_eq!(
        go_local_replace["dependencies"][0]["match_basis"],
        "resolved_path"
    );
    assert_eq!(
        go_local_replace["dependencies"][0]["version_compatibility"],
        "not_evaluated"
    );
}

#[test]
fn change_package_binds_dirty_repository_snapshots_and_dependency_edges() {
    let workspace = tempfile::tempdir().unwrap();
    let provider = workspace.path().join("provider");
    let consumer = workspace.path().join("consumer");
    fs::create_dir_all(&provider).unwrap();
    fs::create_dir_all(&consumer).unwrap();
    init_git(&provider);
    init_git(&consumer);
    fs::write(
        provider.join("Cargo.toml"),
        "[package]\nname='provider'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(provider.join("lib.rs"), "pub fn value() {}\n").unwrap();
    commit_all(&provider, "provider baseline");
    assert!(Command::new("git")
        .args(["checkout", "-qb", "feature"])
        .current_dir(&provider)
        .status()
        .unwrap()
        .success());
    fs::write(
        provider.join("lib.rs"),
        "pub fn value() { println!(\"committed change\"); }\n",
    )
    .unwrap();
    commit_all(&provider, "provider committed change");
    fs::write(consumer.join("Cargo.toml"), "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nprovider={path='../provider'}\n").unwrap();
    fs::write(consumer.join("main.rs"), "fn main() {}\n").unwrap();
    commit_all(&consumer, "consumer baseline");
    fs::write(
        provider.join("lib.rs"),
        "pub fn value() { println!(\"changed\"); }\n",
    )
    .unwrap();
    fs::write(consumer.join("new.rs"), "pub fn new_file() {}\n").unwrap();
    let run = || {
        vee()
            .args(["repos", "package"])
            .arg(&provider)
            .arg(&consumer)
            .args(["--base", "main"])
            .args(["--output", "json"])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let package: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/change-package-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&package));
    assert_eq!(package["schema_version"], 2);
    assert_eq!(
        package["dependency_edges"][0]["version_compatibility"],
        "not_specified"
    );
    assert_eq!(package["repositories"].as_array().unwrap().len(), 2);
    assert_eq!(package["dependency_edges"].as_array().unwrap().len(), 1);
    assert_eq!(package["readiness"], "incomplete");
    assert_eq!(package["priority_order"][0], "provider");
    let repositories = package["repositories"].as_array().unwrap();
    let provider_record = repositories
        .iter()
        .find(|entry| entry["repository_id"] == "provider")
        .unwrap();
    let consumer_record = repositories
        .iter()
        .find(|entry| entry["repository_id"] == "consumer")
        .unwrap();
    assert_eq!(provider_record["changed_files"][0]["path"], "lib.rs");
    assert_eq!(consumer_record["changed_files"][0]["path"], "new.rs");
    assert_eq!(provider_record["has_changes"], true);
    assert_eq!(provider_record["saved_gate_status"], "not_reviewed");
    assert_eq!(provider_record["gate_validity"], "not_available");
    assert_eq!(provider_record["downstream_repository_count"], 1);
    assert!(provider_record["priority_factors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| factor.as_str().unwrap().contains("directly_required_by_1")));
    assert!(provider_record["base_oid"].as_str().is_some());
    let second = run();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(package["package_id"], second["package_id"]);
    let linked = vee()
        .args(["repos", "package"])
        .arg(&provider)
        .arg(&consumer)
        .args(["--base", "main"])
        .args(["--link-pr", "provider=github.com/acme/provider#17"])
        .args(["--link-pr", "consumer=gitlab.example/group/consumer#29"])
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let linked: serde_json::Value = serde_json::from_slice(&linked.stdout).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&linked));
    assert_ne!(package["package_id"], linked["package_id"]);
    assert_eq!(
        linked["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["repository_id"] == "provider")
            .unwrap()["pull_requests"][0],
        serde_json::json!({
            "repository": {"host": "github.com", "full_name": "acme/provider"},
            "number": 17
        })
    );
    let invalid_link = vee()
        .args(["repos", "package"])
        .arg(&provider)
        .arg(&consumer)
        .args(["--link-pr", "missing=github.com/acme/missing#1"])
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(invalid_link.status.code(), Some(3));
    fs::write(
        provider.join("lib.rs"),
        "pub fn value() { println!(\"another edit\"); }\n",
    )
    .unwrap();
    let third = run();
    let third: serde_json::Value = serde_json::from_slice(&third.stdout).unwrap();
    assert_ne!(package["package_id"], third["package_id"]);
}

#[test]
fn change_package_discovers_only_local_pr_refs_matching_head() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = workspace.path().join("service");
    fs::create_dir_all(&repo).unwrap();
    init_git(&repo);
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname='service'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(repo.join("src.rs"), "pub fn value() {}\n").unwrap();
    commit_all(&repo, "baseline");
    Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "https://github.com/acme/service.git",
        ])
        .current_dir(&repo)
        .status()
        .unwrap();
    let head = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    Command::new("git")
        .args(["update-ref", "refs/pull/42/head", head.trim()])
        .current_dir(&repo)
        .status()
        .unwrap();
    let output = vee()
        .args([
            "repos",
            "package",
            repo.to_str().unwrap(),
            "--discover-linked-prs",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let package: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/change-package-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&package));
    assert_eq!(package["repositories"][0]["pull_requests"][0]["number"], 42);
    assert_eq!(
        package["repositories"][0]["discovered_pull_requests"][0]["number"],
        42
    );
    assert_eq!(package["remote_state_refreshed"], false);
    assert_eq!(package["pull_request_lifecycle"]["status"], "unrefreshed");
    assert!(package["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("local provider refs")));
}

#[cfg(unix)]
#[test]
fn change_package_explicitly_refreshes_and_binds_linked_provider_state() {
    use std::io::{Read, Write};
    use std::{
        net::TcpListener,
        time::{Duration, Instant},
    };

    let workspace = tempfile::tempdir().unwrap();
    let repo = workspace.path().join("service");
    fs::create_dir_all(&repo).unwrap();
    init_git(&repo);
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname='service'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(repo.join("src.rs"), "pub fn value() {}\n").unwrap();
    commit_all(&repo, "baseline");
    let head = Command::new("git")
        .args(["-C", repo.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .unwrap();
    let head = String::from_utf8(head.stdout).unwrap().trim().to_owned();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let remote_head = head.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("timed out waiting for provider request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request_deadline = Instant::now() + Duration::from_secs(15);
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    request.extend_from_slice(&chunk[..count]);
                    assert!(
                        request.len() <= 64 * 1024,
                        "provider request headers exceeded the fixture bound"
                    );
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && Instant::now() < request_deadline =>
                {
                    continue;
                }
                Err(error) => panic!("failed to read provider request: {error}"),
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET /repos/acme/service/pulls/42 "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token"));
        let body = format!(
            "{{\"number\":42,\"title\":\"change\",\"body\":null,\"state\":\"open\",\"merged\":false,\"base\":{{\"sha\":\"base123\"}},\"head\":{{\"sha\":\"{remote_head}\"}}}}"
        );
        write!(stream, "HTTP/1.1 200 OK\r\nETag: \"revision-7\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    fs::write(repo.join(".vee.yaml"), format!("version: 1\noffline: false\nhosting:\n  provider: github\n  host: 127.0.0.1\n  api_base: {api}\n  token_env: VEE_TEST_GH_TOKEN\n")).unwrap();
    let output = vee()
        .args([
            "repos",
            "package",
            repo.to_str().unwrap(),
            "--link-pr",
            "service=127.0.0.1/acme/service#42",
            "--refresh-pr-links",
            "--output",
            "json",
        ])
        .env("VEE_TEST_GH_TOKEN", "test-token")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/change-package-v2.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&package));
    assert_eq!(package["remote_state_refreshed"], true);
    assert_eq!(package["pull_request_lifecycle"]["status"], "all_open");
    assert_eq!(package["pull_request_lifecycle"]["linked_count"], 1);
    assert_eq!(package["pull_request_lifecycle"]["refreshed_count"], 1);
    let state = &package["repositories"][0]["remote_pull_requests"][0];
    assert_eq!(state["provider"], "github");
    assert_eq!(state["state"], "open");
    assert_eq!(state["head_oid"], head);
    assert_eq!(state["local_head_matches"], true);
    assert!(state["revision"].as_str().unwrap().contains("revision-7"));
}

#[cfg(unix)]
#[test]
fn change_package_refresh_routes_through_all_other_hosting_adapters() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    for provider in ["gitlab", "bitbucket", "azure-devops", "gerrit"] {
        let workspace = tempfile::tempdir().unwrap();
        let repo = workspace.path().join("service");
        fs::create_dir_all(&repo).unwrap();
        init_git(&repo);
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname='service'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(repo.join("src.rs"), "pub fn value() {}\n").unwrap();
        commit_all(&repo, "baseline");
        let head = Command::new("git")
            .args(["-C", repo.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap();
        let head = String::from_utf8(head.stdout).unwrap().trim().to_owned();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let api_base = match provider {
            "gitlab" => format!("http://{address}/api/v4/"),
            "bitbucket" => format!("http://{address}/2.0/"),
            _ => format!("http://{address}/"),
        };
        let (identity_host, repository_path) = if provider == "azure-devops" {
            (address.clone(), "org/project/service")
        } else {
            ("127.0.0.1".into(), "acme/service")
        };
        let base = "a".repeat(40);
        let body = match provider {
            "gitlab" => serde_json::json!({
                "iid": 42, "title": "Review", "description": null, "state": "opened",
                "diff_refs": { "base_sha": base.clone(), "start_sha": base.clone(), "head_sha": head.clone() }
            })
            .to_string(),
            "bitbucket" => serde_json::json!({
                "id": 42, "title": "Review", "description": null, "state": "OPEN",
                "updated_on": "2026-11-15T10:00:00Z",
                "source": { "commit": { "hash": head.clone() } },
                "destination": { "commit": { "hash": base.clone() } }
            })
            .to_string(),
            "azure-devops" => serde_json::json!({
                "pullRequestId": 42, "status": "active", "title": "Review",
                "lastMergeSourceCommit": { "commitId": head.clone() },
                "lastMergeTargetCommit": { "commitId": base.clone() }
            })
            .to_string(),
            "gerrit" => format!(
                ")]}}'\n{}",
                serde_json::json!({
                    "_number": 42, "project": repository_path, "status": "NEW", "subject": "Review",
                    "current_revision": head.clone(),
                    "revisions": { head.clone(): { "commit": { "parents": [{ "commit": base.clone() }], "message": "Review" } } }
                })
            ),
            _ => unreachable!(),
        };
        let expected_path = match provider {
            "gitlab" => "/api/v4/projects/acme%2Fservice/merge_requests/42",
            "bitbucket" => "/2.0/repositories/acme/service/pullrequests/42",
            "azure-devops" => {
                "/org/project/_apis/git/repositories/service/pullRequests/42?api-version=7.1"
            }
            "gerrit" => "/changes/42/detail?o=CURRENT_REVISION&o=CURRENT_COMMIT",
            _ => unreachable!(),
        };
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "provider made no HTTP request"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(
                request.starts_with(&format!("GET {expected_path} ")),
                "{request}"
            );
            let body = body;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let config_host = identity_host.clone();
        fs::write(
            repo.join(".vee.yaml"),
            format!(
                "version: 1\noffline: false\nhosting:\n  provider: {provider}\n  host: {config_host}\n  api_base: {api_base}\n  token_env: VEE_TEST_HOSTING_TOKEN\n"
            ),
        )
        .unwrap();
        let link = format!("service={identity_host}/{repository_path}#42");
        let output = vee()
            .args([
                "repos",
                "package",
                repo.to_str().unwrap(),
                "--link-pr",
                &link,
                "--refresh-pr-links",
                "--output",
                "json",
            ])
            .env("VEE_TEST_HOSTING_TOKEN", "test-token")
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "{provider}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let package: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let state = &package["repositories"][0]["remote_pull_requests"][0];
        assert_eq!(state["provider"], provider);
        assert_eq!(state["state"], "open");
        assert_eq!(state["head_oid"], head);
        assert_eq!(state["local_head_matches"], true);
    }
}

#[test]
fn cross_repository_impact_cli_reports_api_breaks_and_finds_code_references() {
    let workspace = tempfile::tempdir().unwrap();
    let producer = workspace.path().join("producer");
    let consumer = workspace.path().join("consumer");
    let app = workspace.path().join("app");
    fs::create_dir_all(&producer).unwrap();
    fs::create_dir_all(&consumer).unwrap();
    fs::create_dir_all(&app).unwrap();
    init_git(&producer);
    init_git(&consumer);
    init_git(&app);
    fs::write(
        producer.join("Cargo.toml"),
        "[package]\nname='producer'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(producer.join("lib.rs"), "pub fn old_api() {}\n").unwrap();
    fs::create_dir_all(producer.join("api")).unwrap();
    fs::write(
        producer.join("api/openapi.yaml"),
        "openapi: 3.0.3\ninfo: {title: Demo, version: '1'}\npaths:\n  /users/{id}:\n    get:\n      operationId: fetchUser\n  /status:\n    get:\n      operationId: getStatus\n      parameters:\n        - {name: region, in: query, required: false, style: form, explode: true, schema: {type: string, enum: [us, eu]}}\n        - {name: limit, in: query, required: false, schema: {type: integer, minimum: 1, maximum: 100}}\n        - {name: page, in: query, required: false, schema: {type: integer, nullable: true}}\n        - {name: token, in: query, required: false, schema: {type: string, minLength: 2, maxLength: 64}}\n        - {name: slug, in: query, required: false, schema: {type: string, pattern: '^[a-z]+$'}}\n        - {name: since, in: query, required: false, schema: {type: string, format: date}}\n        - {name: content-param, in: query, required: false, content: {text/plain: {schema: {type: string, enum: [alpha, beta]}}}}
        - {name: media-param, in: query, required: false, content: {text/plain: {schema: {type: string}}}}
        - {name: transition-param, in: query, required: false, schema: {type: string}}\n        - {name: mode, in: query, required: false, schema: {oneOf: [{type: string}, {type: integer}]}}\n      requestBody:\n        required: false\n        content:\n          application/json:\n            schema:\n              type: object\n              properties: {name: {type: string, pattern: '^[A-Z]+$'}, note: {type: string}, category: {type: string, enum: [alpha, beta]}, count: {type: integer, minimum: 0, maximum: 100}, profile: {type: object, properties: {nickname: {type: string}, title: {type: string, nullable: true}}}, tags: {type: array, items: {type: string}}}\n              required: [name]\n          application/xml: {schema: {type: object}}\n      responses:\n        '200':\n          description: status\n          content:\n            application/json:\n              schema:\n                type: object\n                properties: {id: {type: string}, name: {type: string}, state: {type: string, enum: [ok], maxLength: 16, pattern: '^[a-z]+$'}, score: {type: number, minimum: 0, maximum: 10}}\n                required: [id, name]\n  /linked:\n    post:\n      operationId: linkResource\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/NoSuchThing'}\n      responses:\n        '204': {description: linked}\n  /deep:\n    post:\n      operationId: postThing\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/Thing'}\n      responses:\n        '204': {description: stored}\n  /secure:\n    get:\n      operationId: getSecure\n      security: [{apiKey: []}]\n  /removed-secure:\n    get:\n      operationId: getLegacySecure\n      security: [{legacyKey: []}]\n  /composed:\n    post:\n      operationId: postComposed\n      requestBody:\n        content:\n          application/json:\n            schema: {allOf: [{type: object, properties: {id: {type: string}}}, {required: [id]}]}\n      responses:\n        '204': {description: stored}\n  /variants:\n    post:\n      operationId: postVariants\n      requestBody:\n        content:\n          application/json: {schema: {type: object, properties: {payload: {$ref: '#/components/schemas/RequestVariants'}}}}\n      responses:\n        '200': {description: variants, content: {application/json: {schema: {type: object, properties: {payload: {$ref: '#/components/schemas/ResponseVariants'}}}}}}\n  /version:\n    get:\n      operationId: getVersion\n      responses:\n        '200': {description: version, content: {text/plain: {schema: {type: string}}, text/csv: {schema: {type: string}}}}\ncomponents:\n  securitySchemes:\n    apiKey: {type: apiKey, name: key, in: header}\n    legacyKey: {type: apiKey, name: legacy, in: header}\n  schemas:\n    Thing:\n      type: object\n      properties: {id: {type: string}, label: {type: string}}\n    RequestVariants: {oneOf: [{type: string, enum: [stable, preview]}, {type: integer}]}\n    ResponseVariants: {oneOf: [{type: string, enum: [stable]}]}\n",
    )
    .unwrap();
    fs::write(
        producer.join("api/asyncapi.yaml"),
        "asyncapi: 2.6.0\ninfo: {title: Events, version: '1'}\nchannels:\n  user/signedup:\n    publish:\n      operationId: publishUserSignup\n      message: {name: UserSignedUp, payload: {type: object, properties: {id: {type: string}, state: {type: string, enum: [accepted]}}}}\n",
    )
    .unwrap();
    fs::write(
        producer.join("api/asyncapi3.yaml"),
        "asyncapi: 3.0.0\ninfo: {title: Events, version: '1'}\nchannels:\n  userSignedup:\n    address: user/signedup\n    messages:\n      UserSignedUp:\n        payload: {type: object, properties: {id: {type: string}, state: {type: string, enum: [accepted, queued]}}}\noperations:\n  receiveUserSignup:\n    action: receive\n    channel: {$ref: '#/channels/userSignedup'}\n    messages:\n      - {$ref: '#/channels/userSignedup/messages/UserSignedUp'}\n",
    )
    .unwrap();
    commit_all(&producer, "producer baseline");
    fs::write(producer.join("lib.rs"), "pub fn changed_api() {}\n").unwrap();
    fs::write(
        producer.join("api/openapi.yaml"),
        "openapi: 3.0.3\ninfo: {title: Demo, version: '2'}\npaths:\n  /status:\n    get:\n      operationId: getStatus\n      parameters:\n        - {name: region, in: query, required: true, style: pipeDelimited, explode: false, schema: {type: string, enum: [us]}}\n        - {name: limit, in: query, required: false, schema: {type: integer, minimum: 10, maximum: 50}}\n        - {name: page, in: query, required: false, schema: {type: string}}\n        - {name: token, in: query, required: false, schema: {type: string, minLength: 8, maxLength: 32}}\n        - {name: slug, in: query, required: false, schema: {type: string, pattern: '^[a-z0-9]+$'}}\n        - {name: since, in: query, required: false, schema: {type: string, format: date-time}}\n        - {name: content-param, in: query, required: false, content: {text/plain: {schema: {type: string, enum: [alpha]}}}}
        - {name: media-param, in: query, required: false, content: {application/json: {schema: {type: string}}}}
        - {name: transition-param, in: query, required: false, content: {text/plain: {schema: {type: string}}}}\n        - {name: mode, in: query, required: false, schema: {oneOf: [{type: integer}]}}\n      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              type: object\n              properties: {name: {type: string, pattern: '^[A-Z]{2,}$'}, region: {type: string}, category: {type: string, enum: [alpha]}, count: {type: integer, minimum: 10, maximum: 90}, profile: {type: object, properties: {title: {type: string}}, required: [title]}, tags: {type: array, minItems: 1, items: {type: integer}}}\n              required: [name, region]\n      responses:\n        '200':\n          description: status\n          content:\n            application/json:\n              schema:\n                type: object\n                properties: {id: {type: string}, state: {type: string, enum: [ok, unknown], nullable: true, maxLength: 32, pattern: '^[a-z0-9]+$'}, score: {type: number, minimum: -1, maximum: 11}}\n                required: [id]\n  /linked:\n    post:\n      operationId: linkResource\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/NoSuchThing'}\n      responses:\n        '204': {description: linked}\n  /deep:\n    post:\n      operationId: postThing\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/Thing'}\n      responses:\n        '204': {description: stored}\n  /secure:\n    get:\n      operationId: getSecure\n      security: [{apiKey: [], oauth: [read]}]\n  /removed-secure:\n    get:\n      operationId: getLegacySecure\n      security: [{legacyKey: []}]\n  /composed:\n    post:\n      operationId: postComposed\n      requestBody:\n        content:\n          application/json:\n            schema: {allOf: [{type: object, properties: {id: {type: integer}}}, {required: [id]}]}\n      responses:\n        '204': {description: stored}\n  /variants:\n    post:\n      operationId: postVariants\n      requestBody:\n        content:\n          application/json: {schema: {type: object, properties: {payload: {$ref: '#/components/schemas/RequestVariants'}}}}\n      responses:\n        '200': {description: variants, content: {application/json: {schema: {type: object, properties: {payload: {$ref: '#/components/schemas/ResponseVariants'}}}}}}\n  /version:\n    get:\n      operationId: getVersion\n      responses:\n        '200': {description: version, content: {text/plain: {schema: {type: string}}}}\ncomponents:\n  securitySchemes:\n    apiKey: {type: apiKey, name: key, in: query}\n    oauth: {type: oauth2, flows: {clientCredentials: {tokenUrl: /token, scopes: {read: read}}}}\n  schemas:\n    Thing:\n      type: object\n      properties: {id: {type: string}}\n    RequestVariants: {oneOf: [{type: string, enum: [stable]}]}\n    ResponseVariants: {oneOf: [{type: string, enum: [stable, preview]}, {type: integer}]}\n",
    )
    .unwrap();
    fs::write(
        producer.join("api/asyncapi.yaml"),
        "asyncapi: 2.6.0\ninfo: {title: Events, version: '2'}\nchannels:\n  user/signedup:\n    publish:\n      operationId: publishNewUserSignup\n      message: {name: UserSignedUp, payload: {type: object, properties: {id: {type: integer}, name: {type: string}, state: {type: string, enum: [accepted, queued]}}}}\n",
    )
    .unwrap();
    fs::write(
        producer.join("api/asyncapi3.yaml"),
        "asyncapi: 3.0.0\ninfo: {title: Events, version: '2'}\nchannels:\n  userSignedup:\n    address: user/registered\n    messages:\n      UserSignedUp:\n        payload: {type: object, properties: {id: {type: integer}, name: {type: string}, state: {type: string, enum: [accepted]}}}\noperations:\n  receiveUserSignup:\n    action: receive\n    channel: {$ref: '#/channels/userSignedup'}\n    messages:\n      - {$ref: '#/channels/userSignedup/messages/UserSignedUp'}\n",
    )
    .unwrap();
    fs::write(consumer.join("Cargo.toml"), "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nproducer={path='../producer'}\n").unwrap();
    fs::write(
        consumer.join("lib.rs"),
        "fn use_api() { changed_api(); }\nfn use_method(value: Thing) { value.changed_api(); }\nfn shadow() { let changed_api = 1; let _ = changed_api; }\n// changed_api()\nconst DOC: &str = \"changed_api()\";\n",
    )
    .unwrap();
    fs::write(
        consumer.join("client.ts"),
        "function changed_api() {}\nfunction useApi() { changed_api(); } // changed_api()\nconst doc = 'changed_api()';\n",
    )
    .unwrap();
    fs::write(
        consumer.join("client.py"),
        "def changed_api():\n    pass\ndef use_api():\n    changed_api()  # changed_api()\ndoc = \"changed_api()\"\n",
    )
    .unwrap();
    fs::write(
        consumer.join("client.go"),
        "package consumer\nfunc useAPI() { changed_api() }\n/* changed_api() */\nvar doc = `changed_api()`\n",
    )
    .unwrap();
    fs::write(consumer.join("Client.java"), "class Client { void use() { changed_api(); } // changed_api()\nString doc = \"changed_api()\"; }\n").unwrap();
    commit_all(&consumer, "consumer");
    fs::write(
        app.join("Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nconsumer={path='../consumer'}\n",
    )
    .unwrap();
    fs::write(app.join("main.rs"), "fn main() { changed_api(); }\n").unwrap();
    commit_all(&app, "application consumer");

    let output = vee()
        .args(["repos", "impact"])
        .arg(&producer)
        .arg(&consumer)
        .arg(&app)
        .args(["--base", "main", "--output", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/cross-repository-impact-v16.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limitation| limitation
                .as_str()
                .unwrap_or_default()
                .contains("changes between content and schema forms")),
        "unexpected limitations: {}",
        report["limitations"]
    );
    assert!(report["api_contract_changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|operation| operation["method"] == "PUBLISH"
            && operation["route"] == "user/signedup"
            && operation["operation_id"] == "publishNewUserSignup"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "parameter_enum_narrowed"
            && issue["component_path"]
                == "parameters[query:content-param].content.text/plain.schema.enum"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "parameter_content_media_type_changed"
                && issue["component_path"] == "parameters[query:media-param].content"
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "parameter_serialization_changed"
            && issue["route"] == "/status"
            && issue["component_path"] == "parameters[query:region].style"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "parameter_pattern_changed"
            && issue["component_path"] == "parameters[query:slug].schema.pattern"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_schema_pattern_changed"
            && issue["component_path"]
                == "requestBody.content.application/json.schema.properties.name.pattern"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_schema_pattern_changed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("content.application/json.schema.properties.state.pattern")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "parameter_size_range_narrowed"
            && issue["route"] == "/status"
            && issue["component_path"] == "parameters[query:token].schema.minLength"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "parameter_nullable_removed"
            && issue["route"] == "/status"
            && issue["component_path"] == "parameters[query:page].schema.nullable"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "request_composition_branch_removed"
                && issue["route"] == "/status"
                && issue["component_path"] == "parameters[query:mode].schema.oneOf.branch[0]"
        ));
    let parameter_coverage = report["api_contract_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|coverage| coverage["route"] == "/status")
        .unwrap();
    assert!(parameter_coverage["analyzed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|dimension| dimension == "parameter_composition_branch_changes"));
    assert!(parameter_coverage["not_analyzed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|dimension| dimension == "parameter_schema_constraints"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_nullable_removed"
            && issue["route"] == "/status"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("schema.properties.profile.properties.title.nullable")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_nullable_added"
            && issue["route"] == "/status"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("schema.properties.state.nullable")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_media_type_removed"
            && issue["method"] == "GET"
            && issue["route"] == "/status"
            && issue["component_path"] == "requestBody.content.application/xml"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "request_composition_branch_removed"
                && issue["route"] == "/variants"
                && issue["component_path"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("properties.payload.oneOf")
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "response_composition_branch_added"
                && issue["route"] == "/variants"
                && issue["component_path"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("properties.payload.oneOf")
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_enum_narrowed"
            && issue["route"] == "/variants"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("properties.payload.oneOf.branch[0].enum")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_enum_broadened"
            && issue["route"] == "/variants"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("properties.payload.oneOf.branch[0].enum")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_media_type_removed"
            && issue["method"] == "GET"
            && issue["route"] == "/version"
            && issue["component_path"] == "responses.200.content.text/csv"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "operation_id_changed"
            && issue["method"] == "PUBLISH"
            && issue["route"] == "user/signedup"
            && issue["previous_operation_id"] == "publishUserSignup"
            && issue["current_operation_id"] == "publishNewUserSignup"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_property_type_changed"
            && issue["method"] == "PUBLISH"
            && issue["route"] == "user/signedup"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("message.payload.properties.id.type")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_enum_broadened"
            && issue["method"] == "PUBLISH"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("message.payload.properties.state.enum")));
    assert!(report["api_contract_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|coverage| coverage["method"] == "PUBLISH"
            && coverage["route"] == "user/signedup"
            && coverage["analyzed"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("asyncapi_inline_message_schema"))
            && coverage["not_analyzed"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(
                    "asyncapi_message_variants_and_external_references"
                ))));
    assert!(report["api_contract_changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|operation| operation["method"] == "RECEIVE"
            && operation["route"] == "user/registered"
            && operation["operation_id"] == "receiveUserSignup"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "channel_address_changed"
            && issue["route"] == "user/signedup"
            && issue["component_path"] == "operations.receiveUserSignup.channel.address"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_property_type_changed"
            && issue["method"] == "RECEIVE"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("operations.receiveUserSignup.messages[0].payload.properties.id.type")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_enum_narrowed"
            && issue["method"] == "RECEIVE"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains(
                    "operations.receiveUserSignup.messages[0].payload.properties.state.enum"
                )));
    assert!(report["changed_symbols"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("changed_api")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_enum_narrowed" && issue["route"] == "/status"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_numeric_range_narrowed"
            && issue["route"] == "/status"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_enum_broadened" && issue["route"] == "/status"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_numeric_range_broadened"
            && issue["route"] == "/status"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "request_schema_size_range_narrowed"
                && issue["route"] == "/status"
                && issue["component_path"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("properties.tags.minItems")
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "response_schema_size_range_broadened"
                && issue["route"] == "/status"
                && issue["component_path"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("properties.state.maxLength")
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_property_type_changed"
            && issue["route"] == "/composed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("properties.id.type")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "security_scheme_definition_changed"
                && issue["route"] == "/secure"
                && issue["component_path"] == "components.securitySchemes.apiKey"
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "security_scheme_definition_removed"
                && issue["route"] == "/removed-secure"
                && issue["component_path"] == "components.securitySchemes.legacyKey"
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "schema_composition_changed"
            && issue["route"] == "/composed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .contains("allOf[0]")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "security_requirements_changed"
            && issue["route"] == "/secure"
            && issue["component_path"] == "security.requirements"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| {
            issue["issue"] == "operation_removed"
                && issue["route"] == "/users/{id}"
                && issue["previous_operation_id"] == "fetchUser"
        }));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_body_required"
            && issue["component_path"] == "requestBody.required"));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_required_property_added"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("required.region")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_property_removed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("properties.note")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_property_removed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("properties.profile.properties.nickname")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_required_property_added"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("properties.profile.required.title")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "request_schema_type_changed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("properties.tags.items.type")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["issue"] == "response_required_property_removed"
                && issue["component_path"] == "responses.200.required.name"
        ));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["issue"] == "response_property_removed"
            && issue["component_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("properties.name")));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| {
            issue["issue"] == "required_parameter_added"
                && issue["route"] == "/status"
                && issue["method"] == "GET"
        }));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| {
            issue["issue"] == "parameter_format_changed"
                && issue["route"] == "/status"
                && issue["component_path"] == "parameters[query:since].schema.format"
        }));
    assert!(report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| {
            issue["issue"] == "request_property_removed"
                && issue["route"] == "/deep"
                && issue["component_path"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with("properties.label")
        }));
    assert!(report["api_contract_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|coverage| {
            coverage["route"] == "/deep"
                && coverage["analyzed"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("local_schema_references"))
        }));
    assert!(report["api_contract_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|coverage| {
            coverage["method"] == "GET"
                && coverage["route"] == "/users/{id}"
                && coverage["status"] == "incomplete"
                && coverage["analyzed"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("route"))
                && coverage["not_analyzed"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("unresolved_schema_reference"))
        }));
    assert!(!report["api_contract_compatibility"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |issue| issue["route"] == "/version" && issue["issue"] != "response_media_type_removed"
        ));
    assert!(report["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limitation| limitation
            .as_str()
            .unwrap_or_default()
            .contains("POST /linked")
            && limitation
                .as_str()
                .unwrap_or_default()
                .contains("missing, external, cyclic")));
    assert_eq!(report["coverage_complete"], false);
    let references = report["references"].as_array().unwrap();
    assert_eq!(references.len(), 7);
    for path in [
        "lib.rs",
        "client.ts",
        "client.py",
        "client.go",
        "Client.java",
        "main.rs",
    ] {
        assert!(references.iter().any(|reference| reference["path"] == path));
    }
    let consumer_reference = references
        .iter()
        .find(|reference| reference["path"] == "lib.rs")
        .unwrap();
    assert_eq!(consumer_reference["consumer_package_id"], "consumer");
    assert_eq!(
        consumer_reference["dependency_status"],
        "declared_downstream"
    );
    assert_eq!(
        consumer_reference["dependency_paths"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let app_reference = references
        .iter()
        .find(|reference| reference["path"] == "main.rs")
        .unwrap();
    assert_eq!(app_reference["consumer_package_id"], "app");
    assert_eq!(
        app_reference["dependency_paths"][0]["packages"],
        serde_json::json!(["producer", "consumer", "app"])
    );
    assert!(references
        .iter()
        .any(|reference| reference["certainty"] == "inferred_syntax"));
    let rust_references = references
        .iter()
        .filter(|reference| reference["path"] == "lib.rs")
        .collect::<Vec<_>>();
    assert_eq!(rust_references.len(), 2);
    assert!(rust_references
        .iter()
        .any(|reference| reference["match_context"] == "function_call"));
    assert!(rust_references
        .iter()
        .any(|reference| reference["match_context"] == "method_call"));
    assert_eq!(
        references
            .iter()
            .filter(|reference| reference["certainty"] == "heuristic_lexical")
            .count(),
        3
    );
    assert!(references
        .iter()
        .filter(|reference| reference["certainty"] == "heuristic_lexical")
        .all(|reference| reference["match_context"] == "call"));
    assert!(!references.iter().any(|reference| reference["line"] == 1
        && matches!(reference["path"].as_str(), Some("client.ts" | "client.py"))));
    assert!(references.iter().any(|reference| {
        reference["path"] == "client.py"
            && reference["certainty"] == "inferred_syntax"
            && reference["match_context"] == "python_ast_reference"
    }));
    let coverage_complete = report["coverage_complete"].as_bool().unwrap();
    let limitations = report["limitations"].as_array().unwrap();
    assert!(
        coverage_complete
            || limitations.iter().any(|limitation| {
                limitation.as_str().is_some_and(|text| {
                    text.contains("gopls semantic resolution failed")
                        || text.contains("OpenAPI compatibility")
                })
            }),
        "incomplete coverage must identify the failing semantic analyzer: {report}"
    );
    let dependency_paths = report["dependency_paths"].as_array().unwrap();
    assert_eq!(dependency_paths.len(), 2);
    assert!(dependency_paths
        .iter()
        .any(|path| path["packages"] == serde_json::json!(["producer", "consumer"])));
    assert!(dependency_paths
        .iter()
        .any(|path| path["packages"] == serde_json::json!(["producer", "consumer", "app"])));
    assert!(report["dependency_paths"][0]["manifest_digests"][0]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[cfg(unix)]
#[test]
fn mcp_cross_repository_impact_matches_cli_and_rejects_paths_outside_server_root() {
    use mcp_rs::client::Client;
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    assert!(Command::new("git")
        .args(["-c", "init.defaultBranch=main", "init", "-q"])
        .current_dir(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join(".gitignore"), "consumer/\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='producer'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(root.join("lib.rs"), "pub fn old_api() {}\n").unwrap();
    assert!(Command::new("git")
        .args(["add", "-A"])
        .current_dir(root)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee@example.invalid",
            "commit",
            "-qm",
            "baseline"
        ])
        .current_dir(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join("lib.rs"), "pub fn changed_api() {}\n").unwrap();
    let consumer = root.join("consumer");
    fs::create_dir_all(consumer.join("src")).unwrap();
    init_git(&consumer);
    fs::write(
        consumer.join("Cargo.toml"),
        "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nproducer={path='..'}\n",
    )
    .unwrap();
    fs::write(
        consumer.join("src/lib.rs"),
        "pub fn call() { producer::changed_api(); }\n",
    )
    .unwrap();
    commit_all(&consumer, "consumer baseline");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut command = tokio::process::Command::from(vee());
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        use mcp_rs::protocol::ClientServiceExt;
        let client = Client::from_service(
            mcp_rs::model::ClientConfig::new(
                mcp_rs::model::ClientCapabilities::builder().build(),
                mcp_rs::model::Implementation::new("vee-cross-impact-test", "1"),
            )
            .serve_with_lifecycle(
                transport,
                mcp_rs::protocol::ClientLifecycleMode::Discover {
                    preferred_versions: vec![mcp_rs::model::ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let tools = client.peer().list_tools(None).await.unwrap();
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "analyze_cross_repository_impact"));
        let report: serde_json::Value = client
            .call(
                "analyze_cross_repository_impact",
                &serde_json::json!({
                    "base_ref": "main", "consumer_paths": ["consumer"]
                }),
            )
            .await
            .unwrap();
        assert_matches_schema(
            &report,
            include_str!("../../../schemas/cross-repository-impact-v16.schema.json"),
            "MCP cross-repository impact",
        );
        assert!(report["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| reference["symbol"] == "changed_api"));
        assert_eq!(report["dependency_paths"].as_array().unwrap().len(), 1);
        assert!(client
            .call::<_, serde_json::Value>(
                "analyze_cross_repository_impact",
                &serde_json::json!({
                    "base_ref": "main", "consumer_paths": ["../outside"]
                })
            )
            .await
            .is_err());
    });
}

fn init_git(path: &std::path::Path) {
    assert!(Command::new("git")
        .args(["-c", "init.defaultBranch=main", "init", "-q"])
        .current_dir(path)
        .status()
        .unwrap()
        .success());
}

fn commit_all(path: &std::path::Path, message: &str) {
    assert!(Command::new("git")
        .args(["add", "-A"])
        .current_dir(path)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee@example.invalid",
            "commit",
            "-qm",
            message
        ])
        .current_dir(path)
        .status()
        .unwrap()
        .success());
}

#[test]
fn webhook_retention_command_previews_then_prunes_completed_receipts() {
    let directory = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(directory.path())
        .status()
        .unwrap()
        .success());
    let vee_dir = directory.path().join(".vee");
    fs::create_dir_all(&vee_dir).unwrap();
    let database = vee_dir.join("vee.sqlite");
    let mut store = vee_store_sqlite::ReviewStore::open(&database).unwrap();
    let old_digest = vee_core::digest(b"old event");
    let vee_core::WebhookClaim::Acquired { lease_token } = store
        .claim_webhook_delivery("github", "old-event", "push", 1, &old_digest, 10, 30)
        .unwrap()
    else {
        panic!("old event should be claimed");
    };
    store
        .complete_webhook_delivery("github", "old-event", &lease_token, 11)
        .unwrap();
    let recent_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let recent_digest = vee_core::digest(b"recent event");
    let vee_core::WebhookClaim::Acquired { lease_token } = store
        .claim_webhook_delivery(
            "github",
            "recent-event",
            "push",
            1,
            &recent_digest,
            recent_time,
            30,
        )
        .unwrap()
    else {
        panic!("recent event should be claimed");
    };
    store
        .complete_webhook_delivery("github", "recent-event", &lease_token, recent_time + 1)
        .unwrap();

    let preview = vee()
        .args([
            "hosting",
            "prune-webhooks",
            "--older-than-days",
            "1",
            "--output",
            "json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/webhook-retention-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&preview));
    assert_eq!(preview["eligible_receipts"], 1);
    assert_eq!(preview["deleted_receipts"], 0);
    assert_eq!(preview["dry_run"], true);

    let applied = vee()
        .args([
            "hosting",
            "prune-webhooks",
            "--older-than-days",
            "1",
            "--apply",
            "--output",
            "json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&applied));
    assert_eq!(applied["eligible_receipts"], 1);
    assert_eq!(applied["deleted_receipts"], 1);
    assert_eq!(applied["dry_run"], false);
    assert_eq!(
        store
            .claim_webhook_delivery(
                "github",
                "recent-event",
                "push",
                2,
                &recent_digest,
                recent_time + 2,
                30,
            )
            .unwrap(),
        vee_core::WebhookClaim::AlreadyProcessed
    );
    assert!(matches!(
        store
            .claim_webhook_delivery(
                "github",
                "old-event",
                "push",
                2,
                &old_digest,
                recent_time + 2,
                30,
            )
            .unwrap(),
        vee_core::WebhookClaim::Acquired { .. }
    ));
}

#[test]
fn hosting_issue_context_documents_source_and_digest_options() {
    let output = vee()
        .args(["hosting", "issue-context", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--repository <OWNER/REPO>"));
    assert!(help.contains("--provider <PROVIDER>"));
    assert!(help.contains("--number <NUMBER>"));
    assert!(help.contains("--provider <PROVIDER>"));
    assert!(help.contains("--token-env <ENV_VAR>"));
}

#[test]
fn hosting_pr_context_documents_provider_options() {
    let output = vee()
        .args(["hosting", "pr-context", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--repository <ORGANIZATION/PROJECT/REPOSITORY>"));
    assert!(help.contains("--number <NUMBER>"));
    assert!(help.contains("--api-base <URL>"));
    assert!(help.contains("AZURE_DEVOPS_EXT_PAT"));
    assert!(help.contains("bitbucket"));
    assert!(help.contains("azure-devops"));
    assert!(help.contains("gerrit"));
    assert!(help.contains("--username <USERNAME>"));
}

#[test]
fn hosting_pr_issues_documents_provider_options() {
    let output = vee()
        .args(["hosting", "pr-issues", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--repository <OWNER/REPO>"));
    assert!(help.contains("--number <NUMBER>"));
    assert!(help.contains("--provider <PROVIDER>"));
    assert!(help.contains("GH_TOKEN"));
    assert!(help.contains("gitlab"));
    assert!(help.contains("bitbucket"));
    assert!(help.contains("gerrit"));
    assert!(help.contains("--username <USERNAME>"));
    assert!(help.contains("--archive"));
}

#[test]
fn github_pr_issues_are_available_as_untrusted_cli_tasks() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut requests: Vec<String> = Vec::new();
        let pr = r#"{"number":9,"title":"Review the branch","body":null,"state":"open","merged":false,"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        for body in [
            pr,
            r#"[{"id":42,"user":{"login":"reviewer"},"body":"Check retry bound","path":"src/retry.rs","line":18,"side":"RIGHT","html_url":"https://github.com/octo/repo/pull/9#discussion_r42"},{"id":43,"user":{"login":"reviewer"},"body":"Check retry bound","path":"src/retry.rs","line":19,"side":"RIGHT","html_url":"https://github.com/octo/repo/pull/9#discussion_r43"},{"id":44,"user":{"login":"reviewer"},"body":"Check retry bound","path":"src/retry.rs","line":20,"side":"RIGHT","html_url":"https://github.com/octo/repo/pull/9#discussion_r44"}]"#,
            pr,
        ] {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(directory.path())
        .status()
        .unwrap()
        .success());
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--repository",
            "octo/repo",
            "--number",
            "9",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/api/v3/"),
            "--token-env",
            "VEE_TEST_GITHUB_TOKEN",
            "--output",
            "json",
            "--archive",
        ])
        .env("VEE_TEST_GITHUB_TOKEN", "fixture-token")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}; stderr={}; stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "github");
    assert_eq!(report["archive_digest"].as_str().unwrap().len(), 71);
    assert_eq!(report["gate_eligible"], false);
    assert_eq!(report["issues"][0]["external_id"], "42");
    assert_eq!(
        report["issues"][0]["classification"],
        "untrusted_external_review"
    );
    let archives = vee()
        .args(["reviews", "imported", "list", "--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(archives.status.success());
    let archives: serde_json::Value = serde_json::from_slice(&archives.stdout).unwrap();
    assert_eq!(archives["reviews"].as_array().unwrap().len(), 1);
    assert_eq!(
        archives["reviews"][0]["archive_type"],
        "provider_discussions"
    );
    assert_eq!(archives["reviews"][0]["issue_count"], 3);
    assert_eq!(archives["reviews"][0]["gate_eligible"], false);
    let archive = vee()
        .args([
            "reviews",
            "imported",
            "show",
            report["archive_digest"].as_str().unwrap(),
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        archive.status.success(),
        "{}",
        String::from_utf8_lossy(&archive.stderr)
    );
    let archive: serde_json::Value = serde_json::from_slice(&archive.stdout).unwrap();
    assert_eq!(archive["archive_type"], "provider_discussions");
    assert_eq!(archive["issues"].as_array().unwrap().len(), 3);
    assert_eq!(archive["gate_eligible"], false);
    let searched = vee()
        .args([
            "reviews",
            "imported",
            "search",
            "retry bound",
            "--output",
            "json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        searched.status.success(),
        "{}",
        String::from_utf8_lossy(&searched.stderr)
    );
    let searched: serde_json::Value = serde_json::from_slice(&searched.stdout).unwrap();
    assert_eq!(searched["matches"].as_array().unwrap().len(), 3);
    assert_eq!(searched["matches"][0]["provider"], "github");
    assert_eq!(searched["matches"][0]["issue"]["external_id"], "42");
    assert_eq!(searched["matches"][0]["gate_eligible"], false);
    assert_matches_schema(
        &searched,
        include_str!("../../../schemas/imported-review-search-v3.schema.json"),
        "imported review search",
    );
    let mut last_feedback = serde_json::Value::Null;
    for external_id in ["42", "43", "44"] {
        let feedback = vee()
            .args([
                "reviews",
                "imported",
                "feedback",
                "set",
                report["archive_digest"].as_str().unwrap(),
                external_id,
                "--category",
                "correctness",
                "--label",
                "false-positive",
                "--reason",
                "This finding is already prevented by the repository's generated-file policy.",
                "--reviewer",
                "maintainer",
                "--output",
                "json",
            ])
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            feedback.status.success(),
            "{}",
            String::from_utf8_lossy(&feedback.stderr)
        );
        let feedback: serde_json::Value = serde_json::from_slice(&feedback.stdout).unwrap();
        assert_eq!(feedback["feedback"]["label"], "false_positive");
        assert_eq!(feedback["feedback"]["external_id"], external_id);
        assert_eq!(feedback["gate_eligible"], false);
        assert_matches_schema(
            &feedback["feedback"],
            include_str!("../../../schemas/external-review-feedback-v1.schema.json"),
            "external review feedback",
        );
        last_feedback = feedback;
    }
    let listed = vee()
        .args([
            "reviews",
            "imported",
            "feedback",
            "list",
            "--archive-digest",
            report["archive_digest"].as_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["feedback"].as_array().unwrap().len(), 3);
    assert!(listed["feedback"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["feedback_id"] == last_feedback["feedback"]["feedback_id"]));
    let candidates = vee()
        .args(["rules", "candidates", "--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        candidates.status.success(),
        "{}",
        String::from_utf8_lossy(&candidates.stderr)
    );
    let candidates: serde_json::Value = serde_json::from_slice(&candidates.stdout).unwrap();
    assert_eq!(candidates["candidates"].as_array().unwrap().len(), 1);
    let candidate = &candidates["candidates"][0];
    assert_eq!(candidate["source_kind"], "provider_discussions");
    assert_eq!(candidate["feedback_count"], 3);
    assert_eq!(candidate["approval_status"], "requires_human_review");
    assert_matches_schema(
        &candidates,
        include_str!("../../../schemas/rule-candidates-v3.schema.json"),
        "rule candidates",
    );
    let approved = vee()
        .args([
            "rules",
            "approve",
            candidate["candidate_id"].as_str().unwrap(),
            "--evidence-digest",
            candidate["evidence_digest"].as_str().unwrap(),
            "--scope",
            "src/retry.rs",
            "--instruction",
            "Inspect the retry bound and cite the relevant path.",
            "--approver",
            "maintainer",
            "--reason",
            "Reviewed the three archived discussion labels.",
            "--output",
            "json",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    let approved: serde_json::Value = serde_json::from_slice(&approved.stdout).unwrap();
    assert_eq!(approved["status"], "active");
    assert_eq!(approved["source_feedback_ids"].as_array().unwrap().len(), 3);
    let requests = server.join().unwrap();
    assert!(requests[1]
        .starts_with("GET /api/v3/repos/octo/repo/pulls/9/comments?per_page=100&page=1 HTTP/1.1"));
}

#[test]
fn gitlab_pr_issues_are_exposed_as_untrusted_revision_bound_context() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let merge_request = serde_json::json!({"iid":17,"title":"Review","description":null,"state":"opened",
        "diff_refs":{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","start_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","head_sha":"cccccccccccccccccccccccccccccccccccccccc"}}).to_string();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        let bodies = [
            (merge_request.clone(), None),
            (r#"[{"id":51,"body":"Please handle this error","author":{"username":"reviewer"},"position":{"new_path":"src/lib.rs","old_path":"src/lib.rs","new_line":24,"old_line":23},"web_url":"https://gitlab.example/group/project/-/merge_requests/17#note_51","created_at":"2026-11-15T10:00:00Z","updated_at":"2026-11-15T10:00:00Z","system":false}]"#.to_owned(), Some("2")),
            (r#"[{"id":52,"body":"Also check the fallback","author":{"username":"reviewer2"},"position":null,"web_url":"https://gitlab.example/group/project/-/merge_requests/17#note_52","created_at":"2026-11-15T10:01:00Z","updated_at":"2026-11-15T10:01:00Z","system":false}]"#.to_owned(), None),
            (merge_request, None),
        ];
        for (body, next_page) in bodies {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            let pagination = next_page
                .map(|page| format!("X-Next-Page: {page}\r\n"))
                .unwrap_or_default();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{pagination}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let api_base = format!("http://{address}/api/v4/");
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--provider",
            "gitlab",
            "--repository",
            "group/repo",
            "--number",
            "17",
            "--host",
            &address.ip().to_string(),
            "--api-base",
            &api_base,
            "--token-env",
            "VEE_FIXTURE_GITLAB_ISSUES_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_GITLAB_ISSUES_TOKEN", "fixture-token")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "gitlab");
    assert_eq!(report["revision"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:cccccccccccccccccccccccccccccccccccccccc");
    assert_eq!(report["complete"], true);
    assert_eq!(report["gate_eligible"], false);
    assert_eq!(report["issues"][0]["external_id"], "51");
    assert_eq!(report["issues"][0]["author"], "reviewer");
    assert_eq!(report["issues"][0]["path"], "src/lib.rs");
    assert_eq!(report["issues"][0]["line"], 24);
    assert_eq!(report["issues"][0]["side"], "new");
    assert_eq!(report["issues"].as_array().unwrap().len(), 2);
    assert_eq!(report["issues"][1]["external_id"], "52");
    assert_eq!(report["issues"][1]["path"], serde_json::Value::Null);
    assert_eq!(
        report["issues"][0]["classification"],
        "untrusted_external_review"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].contains("/merge_requests/17/notes?per_page=100&page=1"));
    assert!(requests[2].contains("/merge_requests/17/notes?per_page=100&page=2"));
}

#[test]
fn bitbucket_pr_issues_are_exposed_as_untrusted_revision_bound_context() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
    let comments = [
        r#"{"values":[{"id":81,"content":{"raw":"Check this branch"},"user":{"display_name":"Reviewer","nickname":"reviewer"},"inline":{"path":"src/lib.rs","from":12,"to":14},"links":{"html":{"href":"https://bitbucket.org/team/repo/pull-requests/7#comment-81"}},"created_on":"2026-11-15T10:00:00Z","updated_on":"2026-11-15T10:00:00Z"}],"next":"http://127.0.0.1/comments?page=2"}"#,
        r#"{"values":[{"id":82,"content":{"raw":"Please cover the empty case"},"user":{"display_name":"Reviewer Two","nickname":"reviewer-two"},"inline":null,"links":{"html":{"href":"https://bitbucket.org/team/repo/pull-requests/7#comment-82"}},"created_on":"2026-11-15T10:02:00Z","updated_on":"2026-11-15T10:02:00Z"}],"next":null}"#,
    ];
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for body in [pr, comments[0], comments[1], pr] {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let api_base = format!("http://{address}/2.0/");
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--provider",
            "bitbucket",
            "--repository",
            "team/repo",
            "--number",
            "7",
            "--host",
            &address.ip().to_string(),
            "--api-base",
            &api_base,
            "--token-env",
            "VEE_FIXTURE_BITBUCKET_ISSUES_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_BITBUCKET_ISSUES_TOKEN", "fixture-token")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "bitbucket");
    assert_eq!(
        report["revision"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:2026-11-15T10:00:00Z"
    );
    assert_eq!(report["complete"], true);
    assert_eq!(report["gate_eligible"], false);
    assert_eq!(report["issues"][0]["external_id"], "81");
    assert_eq!(report["issues"][0]["author"], "Reviewer");
    assert_eq!(report["issues"][0]["path"], "src/lib.rs");
    assert_eq!(report["issues"][0]["line"], 14);
    assert_eq!(report["issues"][0]["side"], "new");
    assert_eq!(report["issues"].as_array().unwrap().len(), 2);
    assert_eq!(report["issues"][1]["external_id"], "82");
    assert_eq!(report["issues"][1]["author"], "Reviewer Two");
    assert_eq!(
        report["issues"][0]["classification"],
        "untrusted_external_review"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].contains("/pullrequests/7/comments?pagelen=100&page=1"));
    assert!(requests[2].contains("/pullrequests/7/comments?pagelen=100&page=2"));
}

#[test]
fn gerrit_pr_issues_are_available_for_the_current_patch_set() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let revision = "a".repeat(40);
    let expected_revision = revision.clone();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for body in [
            format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{expected_revision}\"}}"),
            ")]}'\n{\"src/lib.rs\":[{\"id\":\"c1\",\"message\":\"Check bounds\",\"line\":23,\"side\":\"REVISION\",\"author\":{\"name\":\"Reviewer\"}}]}".to_owned(),
            format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{expected_revision}\"}}"),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--provider",
            "gerrit",
            "--repository",
            "team/repo",
            "--number",
            "17",
            "--host",
            &address.ip().to_string(),
            "--api-base",
            &format!("http://{address}/"),
            "--token-env",
            "VEE_TEST_GERRIT_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_TEST_GERRIT_TOKEN", "fixture-token")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "gerrit");
    assert_eq!(report["revision"], revision);
    assert_eq!(report["gate_eligible"], false);
    assert_eq!(report["issues"][0]["external_id"], "c1");
    assert_eq!(report["issues"][0]["path"], "src/lib.rs");
    let requests = server.join().unwrap();
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    }));
}

#[test]
fn bitbucket_pull_request_context_is_available_through_the_cli() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            let body = if requests.len() <= 2 {
                serde_json::json!({"id": 7, "title": "Improve validation", "description": "Details", "state": "OPEN", "updated_on": "2026-11-15T10:00:00Z", "source": {"commit": {"hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}, "destination": {"commit": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}).to_string()
            } else if requests.len() == 3 {
                serde_json::json!({"values": [{"status": "modified", "old": {"path": "src/lib.rs"}, "new": {"path": "src/lib.rs"}, "lines_added": 2, "lines_removed": 1}]}).to_string()
            } else {
                "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n-old\n+new\n".to_string()
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .args([
            "hosting",
            "pr-context",
            "--provider",
            "bitbucket",
            "--repository",
            "team/repo",
            "--number",
            "7",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/2.0/"),
            "--token-env",
            "VEE_TEST_BB_TOKEN",
        ])
        .env("VEE_TEST_BB_TOKEN", "fixture-token")
        .args(["--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "bitbucket");
    assert_eq!(report["snapshot"]["head_oid"], "b".repeat(40));
    assert_eq!(report["changed_files"][0]["path"], "src/lib.rs");
    assert!(report["changed_files"][0]["patch"]
        .as_str()
        .unwrap()
        .contains("+new"));
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("GET /2.0/repositories/team/repo/pullrequests/7 HTTP/1.1"));
    assert!(requests[1].starts_with("GET /2.0/repositories/team/repo/pullrequests/7 HTTP/1.1"));
    assert!(requests[2].starts_with(
        "GET /2.0/repositories/team/repo/pullrequests/7/diffstat?pagelen=100&page=1 HTTP/1.1"
    ));
    assert!(requests[3].starts_with("GET /2.0/repositories/team/repo/pullrequests/7/diff HTTP/1.1"));
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token")
    }));
}

#[cfg(unix)]
#[test]
fn finding_task_exports_bounded_snapshot_context_and_reports_staleness() {
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
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "fn value() {\n    let count = 1;\n}\n",
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Review changed code.\n").unwrap();
    fs::write(root.join("CODEOWNERS"), "src/** @team/rust\n").unwrap();
    fs::write(
        root.join("AGENTS.md"),
        "For arithmetic changes, add a focused boundary test.\n",
    )
    .unwrap();
    let provider = directory.path().join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"The count can overflow\",\"path\":\"src/lib.rs\",\"line\":2},{\"category\":\"security\",\"severity\":\"medium\",\"confidence\":90,\"rationale\":\"The value is not validated\",\"path\":\"src/lib.rs\",\"line\":2}]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(
        root.join("src/lib.rs"),
        "fn value() {\n    let count = risky_value();\n}\n",
    )
    .unwrap();

    let review = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        review.status.success(),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let finding_id = review["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("review has no findings array: {review}"))
        .iter()
        .find(|finding| finding["path"] == "src/lib.rs")
        .unwrap_or_else(|| panic!("review has no src/lib.rs finding: {review}"))["id"]
        .as_str()
        .unwrap();
    let task = vee()
        .args(["findings", "task", finding_id, "--context-lines", "1"])
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        task.status.success(),
        "{}",
        String::from_utf8_lossy(&task.stderr)
    );
    let task: serde_json::Value = serde_json::from_slice(&task.stdout).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/finding-task-v3.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&task));
    assert_eq!(task["schema_version"], 3);
    assert_eq!(task["ownership"]["advisory_only"], true);
    assert_eq!(task["ownership"]["owners"][0], "@team/rust");
    assert_eq!(
        task["ownership"]["classification"],
        "advisory_ownership_context"
    );
    assert_eq!(task["snapshot_current"], true);
    assert_eq!(task["source_context"]["path"], "src/lib.rs");
    assert_eq!(
        task["source_context"]["classification"],
        "untrusted_repository_source"
    );
    assert!(task["source_context"]["content"]
        .as_str()
        .unwrap()
        .contains("risky_value"));
    assert!(task["instructions"]
        .as_str()
        .unwrap()
        .contains("Do not claim"));
    assert!(task["impact_paths"].is_array());
    assert!(task["evidence"].is_array());
    assert!(task["applicable_standards"][0]["content"]
        .as_str()
        .unwrap()
        .contains("focused boundary test"));
    assert_eq!(
        task["applicable_standards"][0]["content_digest"],
        vee_core::digest(
            task["applicable_standards"][0]["content"]
                .as_str()
                .unwrap()
                .as_bytes()
        )
    );
    let finding_ids: Vec<_> = review["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(finding_ids.len(), 2);
    let mut package_args = vec!["findings", "package"];
    package_args.extend(finding_ids.iter().map(String::as_str));
    package_args.extend(["--output", "json"]);
    let package_output = vee().args(package_args).current_dir(root).output().unwrap();
    assert!(
        package_output.status.success(),
        "{}",
        String::from_utf8_lossy(&package_output.stderr)
    );
    let package: serde_json::Value = serde_json::from_slice(&package_output.stdout).unwrap();
    assert_matches_schema(
        &package,
        include_str!("../../../schemas/finding-work-package-v2.schema.json"),
        "finding work package",
    );
    assert_eq!(package["findings"].as_array().unwrap().len(), 2);
    assert_eq!(package["snapshot_id"], task["snapshot_id"]);
    assert!(package["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|task| task["snapshot_id"] == package["snapshot_id"]));

    fs::write(
        root.join("src/lib.rs"),
        "fn value() {\n    let count = 0;\n}\n",
    )
    .unwrap();
    let stale = vee()
        .args(["findings", "task", finding_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        stale.status.success(),
        "{}",
        String::from_utf8_lossy(&stale.stderr)
    );
    let stale: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(stale["snapshot_current"], false);
    // The reviewed source stays available from the copy kept at review time,
    // never the edited file.
    let content = stale["source_context"]["content"].as_str().unwrap();
    assert!(content.contains("risky_value()"), "{stale}");
    assert!(!content.contains("let count = 0"), "{stale}");
    assert!(stale["context_note"]
        .as_str()
        .unwrap()
        .contains("kept when the review ran"));
}

#[test]
fn hosting_publish_documents_snapshot_revision_requirements() {
    let output = vee()
        .args(["hosting", "publish", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--review <REVIEW_ID>"));
    assert!(help.contains("--repository <OWNER/REPO>"));
    assert!(help.contains("azure-devops"));
    assert!(help.contains("--provider <PROVIDER>"));
    assert!(help.contains("gerrit"));
    assert!(help.contains("--username <USERNAME>"));
}

#[test]
fn keygen_rejects_distinct_spellings_of_the_same_output_path() {
    let directory = tempfile::tempdir().unwrap();
    let output = vee()
        .args([
            "reviews",
            "keygen",
            "--private-key",
            "key.der",
            "--public-key",
            "./key.der",
        ])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!directory.path().join("key.der").exists());
}

#[cfg(unix)]
#[test]
fn hosting_publish_rejects_changed_base_before_fetching_diff_or_publishing() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
    fs::write(root.join("tracked.rs"), "fn initial() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "base"]);
    let base_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("tracked.rs"), "fn changed() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "head"]);
    let head_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base_oid}..{head_oid}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2,
        "review_id": "review-base-stale",
        "snapshot_id": change_set.digest,
        "status": "pass",
        "findings": [],
        "evidence": [],
        "verification_runs": [],
        "reviewer_outcomes": [],
        "analysis_complete": true,
        "reasons": [],
        "gate": {
            "schema_version": 1,
            "decision_id": "decision-base-stale",
            "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(),
            "policy_digest": "sha256:policy",
            "status": "pass",
            "blocking_findings": [],
            "verification_run_ids": [],
            "evidence_digest": "sha256:evidence",
            "reasons": []
        },
        "change_set": change_set,
        "effective_config_digest": config_digest.clone(),
        "selected_reviewers": [],
        "policy_profile": null,
        "work_item": null
    });
    store
        .save_review(
            "review-base-stale",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = format!(
            "{{\"number\":9,\"title\":\"Change\",\"body\":null,\"state\":\"open\",\"merged\":false,\"base\":{{\"sha\":\"{}\"}},\"head\":{{\"sha\":\"{}\"}}}}",
            "0".repeat(40),
            head_oid
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        String::from_utf8_lossy(&request).to_string()
    });

    let output = vee()
        .args([
            "hosting",
            "publish",
            "--review",
            "review-base-stale",
            "--repository",
            "octo/repo",
            "--number",
            "9",
            "--actor-login",
            "vee[bot]",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/api/v3/"),
            "--token-env",
            "VEE_FIXTURE_TOKEN",
        ])
        .env("VEE_FIXTURE_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("reviewed base does not match"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = requests.join().unwrap();
    assert!(request.starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
    assert!(!request.contains("/files"));
    assert!(!request.contains("/check-runs"));
}

#[cfg(unix)]
#[test]
fn gerrit_publish_command_emits_revision_bound_tagged_gate_summary() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "base"]);
    let base_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "head"]);
    let head_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base_oid}..{head_oid}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2,
        "review_id": "review-gerrit-publish",
        "snapshot_id": change_set.digest,
        "status": "pass",
        "findings": [],
        "evidence": [],
        "verification_runs": [],
        "reviewer_outcomes": [],
        "analysis_complete": true,
        "reasons": [],
        "gate": {
            "schema_version": 1,
            "decision_id": "decision-gerrit-publish",
            "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(),
            "policy_digest": "sha256:policy",
            "status": "pass",
            "blocking_findings": [],
            "verification_run_ids": [],
            "evidence_digest": "sha256:evidence",
            "reasons": []
        },
        "change_set": change_set,
        "effective_config_digest": config_digest.clone(),
        "selected_reviewers": [],
        "policy_profile": null,
        "work_item": null
    });
    store
        .save_review(
            "review-gerrit-publish",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_head = head_oid.clone();
    let expected_base = base_oid.clone();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        let mut idle_since = None;
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => {
                    idle_since = None;
                    connection
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let idle = idle_since.get_or_insert_with(std::time::Instant::now);
                    if idle.elapsed() > std::time::Duration::from_secs(3) {
                        break;
                    }
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accepting mock Gerrit request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before body");
                request.extend_from_slice(&chunk[..count]);
            }
            requests.push(String::from_utf8_lossy(&request).to_string());
            let request_line = String::from_utf8_lossy(&request[..header_end]);
            let body = if request_line.starts_with("GET ") && request_line.contains("/detail?") {
                format!(
                    ")]}}'\n{}",
                    serde_json::json!({
                        "_number": 17,
                        "project": "team/repo",
                        "status": "NEW",
                        "subject": "Review",
                        "current_revision": &expected_head,
                        "current_revision_number": 2,
                        "revisions": {
                            expected_head.clone(): {
                                "commit": {
                                    "parents": [{"commit": &expected_base}],
                                    "message": "Review\n"
                                }
                            }
                        }
                    })
                )
            } else if request_line.contains("/files/") {
                ")]}'\n{\"src/lib.rs\":{\"status\":\"M\",\"lines_inserted\":1,\"lines_deleted\":1}}"
                    .to_owned()
            } else if request_line.contains("/accounts/self") {
                ")]}'\n{\"_account_id\":100}".to_owned()
            } else if request_line.contains("/comments") {
                ")]}'\n{}".to_owned()
            } else if request_line.contains("/messages") {
                ")]}'\n[]".to_owned()
            } else {
                "{}".to_owned()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        requests
    });

    let output = vee()
        .args([
            "hosting",
            "publish",
            "--provider",
            "gerrit",
            "--review",
            "review-gerrit-publish",
            "--repository",
            "team/repo",
            "--number",
            "17",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/"),
            "--token-env",
            "VEE_FIXTURE_GERRIT_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_GERRIT_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["review_id"], "review-gerrit-publish");
    assert_eq!(receipt["revision"], head_oid);
    assert_eq!(receipt["provider_check_id"], head_oid);
    let requests = server.join().unwrap();
    assert!(requests.len() >= 11);
    assert!(requests
        .iter()
        .any(|request| request
            .starts_with("GET /changes/17/detail?o=CURRENT_REVISION&o=CURRENT_COMMIT")));
    assert!(requests
        .iter()
        .any(|request| request
            .starts_with(&format!("GET /changes/17/revisions/{}/files/", head_oid))));
    let publication = requests
        .iter()
        .find(|request| {
            request.starts_with(&format!("POST /changes/17/revisions/{}/review?", head_oid))
        })
        .expect("Gerrit review publication request");
    assert!(publication.contains("Vee gate: PASS"));
    assert!(publication.contains("autogenerated:vee:"));
}

#[cfg(unix)]
#[test]
fn github_publish_command_emits_snapshot_bound_check_run() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "base"]);
    let base_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "head"]);
    let head_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base_oid}..{head_oid}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2,
        "review_id": "review-github-publish",
        "snapshot_id": change_set.digest,
        "status": "pass",
        "findings": [],
        "evidence": [],
        "verification_runs": [],
        "reviewer_outcomes": [],
        "analysis_complete": true,
        "reasons": [],
        "gate": {
            "schema_version": 1,
            "decision_id": "decision-github-publish",
            "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(),
            "policy_digest": "sha256:policy",
            "status": "pass",
            "blocking_findings": [],
            "verification_run_ids": [],
            "evidence_digest": "sha256:evidence",
            "reasons": []
        },
        "change_set": change_set,
        "effective_config_digest": config_digest.clone(),
        "selected_reviewers": [],
        "policy_profile": null,
        "work_item": null
    });
    store
        .save_review(
            "review-github-publish",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_base = base_oid.clone();
    let expected_head = head_oid.clone();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..7 {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before body");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let body = if request.starts_with("GET ") && request.contains("/pulls/9/files?") {
                serde_json::json!([{
                    "filename": "src/lib.rs",
                    "status": "modified",
                    "previous_filename": null,
                    "patch": "@@ -1 +1 @@",
                    "additions": 1,
                    "deletions": 1
                }])
                .to_string()
            } else if request.starts_with("GET ") && request.contains("/pulls/9 ") {
                serde_json::json!({
                    "number": 9,
                    "title": "Review",
                    "body": null,
                    "state": "open",
                    "merged": false,
                    "base": {"sha": expected_base},
                    "head": {"sha": expected_head}
                })
                .to_string()
            } else if request.starts_with("GET ") && request.contains("check-runs?") {
                r#"{"check_runs":[]}"#.to_owned()
            } else if request.starts_with("POST ") && request.contains("/check-runs ") {
                r#"{"id":1234}"#.to_owned()
            } else {
                panic!(
                    "unexpected GitHub request: {}",
                    request.lines().next().unwrap_or("")
                );
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        requests
    });

    let output = vee()
        .args([
            "hosting",
            "publish",
            "--provider",
            "github",
            "--review",
            "review-github-publish",
            "--repository",
            "team/repo",
            "--number",
            "9",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/"),
            "--token-env",
            "VEE_FIXTURE_GITHUB_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_GITHUB_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["review_id"], "review-github-publish");
    assert_eq!(receipt["revision"], format!("{base_oid}:{head_oid}"));
    assert_eq!(receipt["provider_check_id"], "1234");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 7);
    assert!(requests[0].starts_with("GET /repos/team/repo/pulls/9 HTTP/1.1"));
    let check_run = requests
        .iter()
        .find(|request| request.starts_with("POST /repos/team/repo/check-runs "))
        .expect("GitHub check-run publication request");
    assert!(check_run.contains(&head_oid));
    assert!(check_run.contains("Vee passed"));
}

#[cfg(unix)]
#[test]
fn bitbucket_publish_command_emits_revision_bound_build_status() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "base"]);
    let base_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "head"]);
    let head_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base_oid}..{head_oid}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2,
        "review_id": "review-bitbucket-publish",
        "snapshot_id": change_set.digest,
        "status": "pass",
        "findings": [],
        "evidence": [],
        "verification_runs": [],
        "reviewer_outcomes": [],
        "analysis_complete": true,
        "reasons": [],
        "gate": {
            "schema_version": 1,
            "decision_id": "decision-bitbucket-publish",
            "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(),
            "policy_digest": "sha256:policy",
            "status": "pass",
            "blocking_findings": [],
            "verification_run_ids": [],
            "evidence_digest": "sha256:evidence",
            "reasons": []
        },
        "change_set": change_set,
        "effective_config_digest": config_digest.clone(),
        "selected_reviewers": [],
        "policy_profile": null,
        "work_item": null
    });
    store
        .save_review(
            "review-bitbucket-publish",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_base = base_oid.clone();
    let expected_head = head_oid.clone();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..9 {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before body");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let body = if request.starts_with("GET ")
                && request.contains("/pullrequests/9/diffstat?")
            {
                serde_json::json!({"values": [{
                    "status": "modified",
                    "old": {"path": "src/lib.rs"},
                    "new": {"path": "src/lib.rs"},
                    "lines_added": 1,
                    "lines_removed": 1
                }], "next": null})
                .to_string()
            } else if request.starts_with("GET ") && request.contains("/pullrequests/9/diff ") {
                "diff --git a/src/lib.rs b/src/lib.rs\nindex 1234567..abcdef0 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-pub fn initial() {}\n+pub fn changed() {}\n".to_owned()
            } else if request.starts_with("GET ") && request.contains("/pullrequests/9 ") {
                serde_json::json!({
                    "id": 9,
                    "title": "Review",
                    "description": null,
                    "state": "OPEN",
                    "source": {
                        "branch": {"name": "feature/review"},
                        "commit": {"hash": expected_head}
                    },
                    "destination": {
                        "branch": {"name": "main"},
                        "commit": {"hash": expected_base}
                    },
                    "updated_on": "2026-11-15T12:00:00Z"
                })
                .to_string()
            } else if request.starts_with("GET /2.0/user ") {
                r#"{"uuid":"{vee-bot}"}"#.to_owned()
            } else if request.starts_with("POST ") && request.contains("/statuses/build/") {
                r#"{"uuid":"{vee-status}"}"#.to_owned()
            } else if request.starts_with("GET ") && request.contains("/pullrequests/9/comments?") {
                r#"{"values":[],"next":null}"#.to_owned()
            } else {
                panic!(
                    "unexpected Bitbucket request: {}",
                    request.lines().next().unwrap_or("")
                );
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        requests
    });

    let output = vee()
        .args([
            "hosting",
            "publish",
            "--provider",
            "bitbucket",
            "--review",
            "review-bitbucket-publish",
            "--repository",
            "team/repo",
            "--number",
            "9",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/2.0/"),
            "--token-env",
            "VEE_FIXTURE_BITBUCKET_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_BITBUCKET_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["review_id"], "review-bitbucket-publish");
    assert_eq!(
        receipt["revision"],
        format!("{base_oid}:{head_oid}:2026-11-15T12:00:00Z")
    );
    assert_eq!(receipt["provider_check_id"], "{vee-status}");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 9);
    let status = requests
        .iter()
        .find(|request| {
            request.starts_with("POST /2.0/repositories/team/repo/commit/")
                && request.contains("/statuses/build/")
        })
        .expect("Bitbucket build status publication request");
    assert!(status.contains(&head_oid));
    assert!(status.contains("SUCCESSFUL"));
}

#[cfg(unix)]
#[test]
fn gitlab_publish_command_emits_revision_bound_commit_status() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "base"]);
    let base_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "head"]);
    let head_oid = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base_oid}..{head_oid}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2,
        "review_id": "review-gitlab-publish",
        "snapshot_id": change_set.digest,
        "status": "pass",
        "findings": [],
        "evidence": [],
        "verification_runs": [],
        "reviewer_outcomes": [],
        "analysis_complete": true,
        "reasons": [],
        "gate": {
            "schema_version": 1,
            "decision_id": "decision-gitlab-publish",
            "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(),
            "policy_digest": "sha256:policy",
            "status": "pass",
            "blocking_findings": [],
            "verification_run_ids": [],
            "evidence_digest": "sha256:evidence",
            "reasons": []
        },
        "change_set": change_set,
        "effective_config_digest": config_digest.clone(),
        "selected_reviewers": [],
        "policy_profile": null,
        "work_item": null
    });
    store
        .save_review(
            "review-gitlab-publish",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_base = base_oid.clone();
    let expected_head = head_oid.clone();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..8 {
            let mut stream = accept_with_timeout(&listener).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before body");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let body =
                if request.starts_with("GET ") && request.contains("/merge_requests/9/diffs?") {
                    serde_json::json!([{
                        "old_path": "src/lib.rs",
                        "new_path": "src/lib.rs",
                        "new_file": false,
                        "deleted_file": false,
                        "renamed_file": false,
                        "diff": "@@ -1 +1 @@\n-pub fn initial() {}\n+pub fn changed() {}"
                    }])
                    .to_string()
                } else if request.starts_with("GET ") && request.contains("/merge_requests/9 ") {
                    serde_json::json!({
                        "iid": 9,
                        "title": "Review",
                        "description": null,
                        "state": "opened",
                        "diff_refs": {
                            "base_sha": expected_base,
                            "start_sha": expected_base,
                            "head_sha": expected_head
                        }
                    })
                    .to_string()
                } else if request.contains("/statuses?") {
                    "[]".to_owned()
                } else if request.starts_with("POST ") && request.contains("/statuses/") {
                    r#"{"id":9876}"#.to_owned()
                } else {
                    panic!(
                        "unexpected GitLab request: {}",
                        request.lines().next().unwrap_or("")
                    );
                };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        requests
    });

    let output = vee()
        .args([
            "hosting",
            "publish",
            "--provider",
            "gitlab",
            "--review",
            "review-gitlab-publish",
            "--repository",
            "team/repo",
            "--number",
            "9",
            "--host",
            "127.0.0.1",
            "--api-base",
            &format!("http://{address}/api/v4/"),
            "--token-env",
            "VEE_FIXTURE_GITLAB_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_GITLAB_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["review_id"], "review-gitlab-publish");
    assert_eq!(
        receipt["revision"],
        format!("{base_oid}:{base_oid}:{head_oid}")
    );
    assert_eq!(receipt["provider_check_id"], "9876");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 8);
    let publication = requests
        .iter()
        .find(|request| request.starts_with("POST ") && request.contains("/statuses/"))
        .expect("GitLab commit status publication request");
    assert!(publication.contains(&head_oid));
    assert!(publication.contains("success"));
}

#[test]
fn azure_devops_publish_command_emits_revision_bound_status_and_added_line_thread() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    init_git(root);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    commit_all(root, "base");
    let base = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    commit_all(root, "head");
    let head = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let change_set = vee_application::capture_change_set(
        root,
        vee_git::commit_scope(&format!("{base}..{head}")).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let config_digest = publish_fixture_config_digest(root);
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let review = serde_json::json!({
        "schema_version": 2, "review_id": "review-azure-publish", "snapshot_id": change_set.digest,
        "status": "pass", "findings": [{
            "id": "FIND-AZURE-1", "fingerprint": "fp-azure-1", "category": "correctness",
            "severity": "medium", "confidence": 90, "rationale": "A fixture finding on the changed line.",
            "path": "src/lib.rs", "line": 1, "provenance": "model_inference",
            "reviewer_ids": [], "evidence_ids": []
        }], "evidence": [], "verification_runs": [],
        "reviewer_outcomes": [], "analysis_complete": true, "reasons": [],
        "gate": {"schema_version": 1, "decision_id": "decision-azure-publish", "snapshot_id": change_set.digest,
            "effective_config_digest": config_digest.clone(), "policy_digest": "sha256:policy", "status": "pass",
            "blocking_findings": [], "verification_run_ids": [], "evidence_digest": "sha256:evidence", "reasons": []},
        "change_set": change_set, "effective_config_digest": config_digest.clone(), "selected_reviewers": [],
        "policy_profile": null, "work_item": null
    });
    store
        .save_review(
            "review-azure-publish",
            &change_set.digest,
            &config_digest,
            "pass",
            &serde_json::to_string(&review).unwrap(),
            &[],
        )
        .unwrap();
    drop(store);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_head = head.clone();
    let expected_base = base.clone();
    let server = thread::spawn(move || {
        let mut requests: Vec<String> = Vec::new();
        let mut last_request = std::time::Instant::now();
        let started = std::time::Instant::now();
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => {
                    last_request = std::time::Instant::now();
                    connection
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let published = requests.iter().any(|request| request.starts_with("POST "));
                    if (published && last_request.elapsed() > std::time::Duration::from_secs(2))
                        || started.elapsed() > std::time::Duration::from_secs(20)
                    {
                        break;
                    }
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accepting Azure DevOps fixture request: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "request ended before body");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let request_line = request.lines().next().unwrap_or("");
            let body = if request_line.contains("/pullRequests/9?") {
                serde_json::json!({"pullRequestId":9,"title":"Review","status":"active",
                    "lastMergeTargetCommit":{"commitId":expected_base},"lastMergeSourceCommit":{"commitId":expected_head}}).to_string()
            } else if request_line.contains("/diffs/commits?") {
                r#"{"changes":[{"item":{"path":"/src/lib.rs"},"changeType":"edit"}]}"#.to_owned()
            } else if request_line.contains("/pullRequests/9/iterations?") {
                serde_json::json!({"value":[{"id":2,"sourceRefCommit":{"commitId":expected_head}}]})
                    .to_string()
            } else if request_line.contains("/iterations/2/changes?") {
                r#"{"changeEntries":[{"item":{"path":"/src/lib.rs"},"changeTrackingId":7}],"nextSkip":0}"#.to_owned()
            } else if request_line.starts_with("POST ")
                && request_line.contains("/pullRequests/9/threads?")
            {
                r#"{"id":55}"#.to_owned()
            } else if request_line.contains("/pullRequests/9/threads?") {
                r#"{"value":[]}"#.to_owned()
            } else if request_line.contains("/_apis/connectionData?") {
                r#"{"authenticatedUser":{"id":"actor-1"}}"#.to_owned()
            } else if request_line.starts_with("POST ")
                && request_line.contains("/pullRequests/9/statuses?")
            {
                r#"{"id":23}"#.to_owned()
            } else {
                panic!("unexpected Azure DevOps request: {request_line}");
            };
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
        requests
    });

    let api_base = format!("http://{address}/");
    let output = vee()
        .args([
            "hosting",
            "publish",
            "--provider",
            "azure-devops",
            "--review",
            "review-azure-publish",
            "--repository",
            "org/project/repo",
            "--number",
            "9",
            "--host",
            &address.to_string(),
            "--api-base",
            &api_base,
            "--token-env",
            "VEE_FIXTURE_AZURE_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_AZURE_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["review_id"], "review-azure-publish");
    assert_eq!(receipt["revision"], format!("{base}:{head}"));
    assert_eq!(receipt["provider_check_id"], "23");
    assert_eq!(receipt["thread_ids"]["fp-azure-1"], "55");
    let requests = server.join().unwrap();
    assert!(
        requests
            .iter()
            .filter(|request| request.contains("/pullRequests/9?"))
            .count()
            >= 2
    );
    assert!(requests.iter().any(
        |request| request.starts_with("POST ") && request.contains("/pullRequests/9/statuses?")
    ));
    let status = requests
        .iter()
        .find(|request| {
            request.starts_with("POST ") && request.contains("/pullRequests/9/statuses?")
        })
        .unwrap();
    assert!(status.contains("succeeded"));
    assert!(status.contains("\"genre\":\"vee\""));
    let thread = requests
        .iter()
        .find(|request| {
            request.starts_with("POST ") && request.contains("/pullRequests/9/threads?")
        })
        .unwrap();
    assert!(thread.contains("\"filePath\":\"/src/lib.rs\""));
    assert!(thread.contains("\"line\":1"));
    assert!(thread.contains("vee:fingerprint:fp-azure-1"));
}

#[test]
fn azure_devops_pr_issues_are_exposed_as_untrusted_revision_bound_context() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pr = serde_json::json!({"pullRequestId":9,"title":"Review","status":"active",
        "lastMergeTargetCommit":{"commitId":base},"lastMergeSourceCommit":{"commitId":head}})
    .to_string();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        let bodies = [
            pr,
            r#"{"value":[{"id":12,"threadContext":{"filePath":"/src/lib.rs","rightFileStart":{"line":7}},"comments":[{"id":34,"content":"Please explain this behavior.","author":{"displayName":"Reviewer"},"publishedDate":"2026-11-15T12:00:00Z","commentType":1}]}]}"#.to_owned(),
            serde_json::json!({"pullRequestId":9,"title":"Review","status":"active",
                "lastMergeTargetCommit":{"commitId":base},"lastMergeSourceCommit":{"commitId":head}}).to_string(),
        ];
        for body in bodies {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            requests.push(String::from_utf8_lossy(&request[..count]).to_string());
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
        requests
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let api_base = format!("http://{address}/");
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--provider",
            "azure-devops",
            "--repository",
            "org/project/repo",
            "--number",
            "9",
            "--host",
            &address.to_string(),
            "--api-base",
            &api_base,
            "--token-env",
            "VEE_FIXTURE_AZURE_ISSUES_TOKEN",
            "--output",
            "json",
        ])
        .env("VEE_FIXTURE_AZURE_ISSUES_TOKEN", "fixture-token")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["provider"], "azure-devops");
    assert_eq!(report["revision"], format!("{base}:{head}"));
    assert_eq!(report["complete"], true);
    assert_eq!(report["gate_eligible"], false);
    assert_eq!(report["issues"][0]["external_id"], "12:34");
    assert_eq!(report["issues"][0]["author"], "Reviewer");
    assert_eq!(report["issues"][0]["body"], "Please explain this behavior.");
    assert_eq!(report["issues"][0]["path"], "src/lib.rs");
    assert_eq!(report["issues"][0]["line"], 7);
    assert_eq!(report["issues"][0]["side"], "new");
    assert_eq!(
        report["issues"][0]["classification"],
        "untrusted_external_review"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[1]
        .starts_with("GET /org/project/_apis/git/repositories/repo/pullRequests/9/threads?"));
}

#[test]
fn gitlab_issue_context_is_available_through_the_cli() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..count]).to_string();
        let body = r#"{"title":"Add export","description":"Keep format stable.","web_url":"https://127.0.0.1/org/repo/-/issues/12","state":"opened","updated_at":"2026-11-14T12:00:00Z","labels":["feature"]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        request
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join(".vee.yaml"),
        format!(
            "version: 1\nhosting:\n  provider: gitlab\n  host: 127.0.0.1\n  api_base: http://{address}/api/v4/\n  token_env: VEE_TEST_GITLAB_TOKEN\n"
        ),
    )
    .unwrap();
    let output = vee()
        .args([
            "hosting",
            "issue-context",
            "--repository",
            "org/repo",
            "--number",
            "12",
        ])
        .env("VEE_TEST_GITLAB_TOKEN", "fixture-token")
        .args(["--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let item: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(item["provider"], "gitlab");
    assert_eq!(item["title"], "Add export");
    let request = server.join().unwrap();
    assert!(request.starts_with("GET /api/v4/projects/org%2Frepo/issues/12 HTTP/1.1"));
    assert!(request
        .to_ascii_lowercase()
        .contains("private-token: fixture-token"));
}

#[test]
fn azure_devops_work_item_context_is_available_through_the_cli() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..count]).to_string();
        let body = serde_json::json!({"id": 42, "fields": {
            "System.Title": "Harden API", "System.Description": "Keep input bounded.",
            "System.State": "Active", "System.ChangedDate": "2026-11-14T12:00:00Z",
            "System.Tags": "security; api"
        }})
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
        request
    });
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .args([
            "hosting",
            "issue-context",
            "--provider",
            "azure-devops",
            "--repository",
            "acme/platform",
            "--number",
            "42",
            "--host",
            &format!("127.0.0.1:{}", address.port()),
            "--api-base",
            &format!("http://{address}/"),
            "--token-env",
            "VEE_TEST_AZURE_TOKEN",
        ])
        .env("VEE_TEST_AZURE_TOKEN", "fixture-token")
        .args(["--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let item: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(item["provider"], "azure-devops");
    assert_eq!(item["title"], "Harden API");
    assert_eq!(item["labels"], serde_json::json!(["security", "api"]));
    let request = server.join().unwrap();
    assert!(
        request.starts_with("GET /acme/platform/_apis/wit/workitems/42?api-version=7.1 HTTP/1.1")
    );
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: basic "));
}

#[test]
fn review_documents_digest_bound_work_item_option() {
    let output = vee().args(["review", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--work-item <OWNER/REPO#NUMBER>"));
    assert!(help.contains("--hosting-api-base"));
}

#[cfg(unix)]
#[test]
fn gate_check_rejects_review_after_remote_work_item_changes() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        thread,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let api_base = format!("http://{address}/api/v4/");
    let server = thread::spawn(move || {
        for (body, expected_path) in [
            (
                r###"{"title":"Export","description":"## Acceptance Criteria\n- [ ] Keep format v1","web_url":"https://127.0.0.1/org/repo/-/issues/5","state":"opened","updated_at":"2026-11-14T12:00:00Z","labels":[]}"###,
                "/api/v4/projects/org%2Frepo/issues/5",
            ),
            (
                r#"{"title":"Export","description":"Keep format v2","web_url":"https://127.0.0.1/org/repo/-/issues/5","state":"opened","updated_at":"2026-11-14T12:05:00Z","labels":[]}"#,
                "/api/v4/projects/org%2Frepo/issues/5",
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).starts_with(&format!("GET {expected_path} ")));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        }
    });

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
    fs::write(root.join("tracked.rs"), "fn export() {}\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    fs::write(root.join("tracked.rs"), "fn export() { let _ = 1; }\n").unwrap();

    let provider = directory.path().join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\nhosting: {{ provider: gitlab, host: 127.0.0.1, api_base: {}, token_env: VEE_TEST_GITLAB_TOKEN }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n",
            provider.display(),
            api_base
        ),
    )
    .unwrap();

    let review = vee()
        .args([
            "review",
            "--working-tree",
            "--gate",
            "--output",
            "json",
            "--work-item",
            "org/repo#5",
        ])
        .env("VEE_TEST_GITLAB_TOKEN", "test-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(
        review["work_item"]["body"],
        "## Acceptance Criteria\n- [ ] Keep format v1"
    );
    let review_id = review["review_id"].as_str().unwrap();

    let acceptance = vee()
        .args([
            "acceptance",
            "report",
            "--review",
            review_id,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        acceptance.status.success(),
        "{}",
        String::from_utf8_lossy(&acceptance.stderr)
    );
    let acceptance: serde_json::Value = serde_json::from_slice(&acceptance.stdout).unwrap();
    let acceptance_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/acceptance-traceability-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&acceptance_schema)
        .unwrap()
        .is_valid(&acceptance));
    assert_eq!(acceptance["criteria"].as_array().unwrap().len(), 1);
    assert_eq!(acceptance["criteria"][0]["text"], "Keep format v1");
    assert_eq!(acceptance["criteria"][0]["status"], "needs_human_review");
    assert_eq!(acceptance["snapshot_id"], review["snapshot_id"]);
    let mapping_path = root.join(".vee/acceptance-mapping.json");
    let mapping = serde_json::json!({
        "schema_version": 1,
        "review_id": review_id,
        "snapshot_id": review["snapshot_id"],
        "work_item_digest": review["work_item"]["content_digest"],
        "author": "maintainer@example.invalid",
        "recorded_at": "2026-11-14T12:10:00Z",
        "assessments": [{
            "criterion_id": acceptance["criteria"][0]["id"],
            "assessment": "met",
            "rationale": "Reviewed the implementation and its changed source.",
            "changed_paths": [review["change_set"]["files"][0]["path"]],
            "verification_run_ids": []
        }]
    });
    let mapping_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/acceptance-mapping-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&mapping_schema)
        .unwrap()
        .is_valid(&mapping));
    fs::write(&mapping_path, serde_json::to_vec(&mapping).unwrap()).unwrap();
    let validation = vee()
        .args([
            "acceptance",
            "validate",
            "--review",
            review_id,
            "--mapping",
            mapping_path.to_str().unwrap(),
            "--output",
            "json",
            "--gate",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        validation.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let validation: serde_json::Value = serde_json::from_slice(&validation.stdout).unwrap();
    assert_eq!(validation["result"], "all_attested_met");
    assert_eq!(validation["criteria"][0]["assessment"], "met");
    let validation_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/acceptance-validation-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&validation_schema)
        .unwrap()
        .is_valid(&validation));

    let mut not_met_mapping = mapping.clone();
    not_met_mapping["assessments"][0]["assessment"] = serde_json::json!("not_met");
    fs::write(&mapping_path, serde_json::to_vec(&not_met_mapping).unwrap()).unwrap();
    let not_met = vee()
        .args([
            "acceptance",
            "validate",
            "--review",
            review_id,
            "--mapping",
            mapping_path.to_str().unwrap(),
            "--output",
            "json",
            "--gate",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(not_met.status.code(), Some(1));
    let not_met: serde_json::Value = serde_json::from_slice(&not_met.stdout).unwrap();
    assert_eq!(not_met["result"], "attention_required");

    let mut uncertain_mapping = mapping.clone();
    uncertain_mapping["assessments"][0]["assessment"] = serde_json::json!("uncertain");
    fs::write(
        &mapping_path,
        serde_json::to_vec(&uncertain_mapping).unwrap(),
    )
    .unwrap();
    let incomplete = vee()
        .args([
            "acceptance",
            "validate",
            "--review",
            review_id,
            "--mapping",
            mapping_path.to_str().unwrap(),
            "--output",
            "json",
            "--gate",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(incomplete.status.code(), Some(2));
    let incomplete: serde_json::Value = serde_json::from_slice(&incomplete.stdout).unwrap();
    assert_eq!(incomplete["result"], "incomplete");

    let mut stale_mapping = mapping.clone();
    stale_mapping["snapshot_id"] = serde_json::json!("sha256:stale");
    fs::write(&mapping_path, serde_json::to_vec(&stale_mapping).unwrap()).unwrap();
    let stale = vee()
        .args([
            "acceptance",
            "validate",
            "--review",
            review_id,
            "--mapping",
            mapping_path.to_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(3));
    let mut invalid_path_mapping = mapping;
    invalid_path_mapping["snapshot_id"] = review["snapshot_id"].clone();
    invalid_path_mapping["assessments"][0]["changed_paths"] = serde_json::json!(["../outside.rs"]);
    fs::write(
        &mapping_path,
        serde_json::to_vec(&invalid_path_mapping).unwrap(),
    )
    .unwrap();
    let invalid_path = vee()
        .args([
            "acceptance",
            "validate",
            "--review",
            review_id,
            "--mapping",
            mapping_path.to_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(invalid_path.status.code(), Some(3));

    let gate = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .env("VEE_TEST_GITLAB_TOKEN", "test-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(gate.status.code(), Some(2));
    let gate: serde_json::Value = serde_json::from_slice(&gate.stdout).unwrap();
    assert_eq!(gate["status"], "incomplete");
    assert!(gate["reasons"].as_array().unwrap().iter().any(|reason| {
        reason
            .as_str()
            .unwrap()
            .contains("effective configuration changed")
    }));
    server.join().unwrap();
}

#[test]
fn hosting_webhook_serve_documents_repository_and_network_binding() {
    let output = vee()
        .args(["hosting", "webhook-serve", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--repository <PATH>"));
    assert!(help.contains("azure-devops"));
    assert!(help.contains("gerrit"));
    assert!(help.contains("--webhook-secret-env"));
    assert!(help.contains("--allow-network"));
    assert!(help.contains("--username <USERNAME>"));
}

fn assert_matches_schema(value: &serde_json::Value, schema_json: &str, contract: &str) {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .unwrap_or_else(|error| panic!("{contract} schema is invalid: {error}"));
    let registry = jsonschema::Registry::new()
        .add(
            "https://vee.klarlabs.de/schemas/analyzer-report-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/analyzer-report-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/verification-run-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/verification-run-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/gate-decision-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/gate-decision-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/evidence-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/evidence-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/waiver-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/waiver-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/work-item-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/work-item-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/rule-approval-v2.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/rule-approval-v2.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/review-output-v2.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/review-output-v2.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap_or_else(|error| panic!("{contract} schema cannot be compiled: {error}"));
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{contract} violates its schema: {errors:#?}"
    );
}

#[cfg(unix)]
#[test]
fn repository_config_schema_accepts_initialized_and_configured_examples() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/repository-config-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let directory = tempfile::tempdir().unwrap();
    init_git(directory.path());
    // An isolated machine whose only AI backend is a fake Codex CLI.
    let machine = tempfile::tempdir().unwrap();
    let bin = machine.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let codex = bin.join("codex");
    fs::write(&codex, "#!/bin/sh\necho 'codex-cli 9.9.9'\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join("git"))
        .find(|candidate| candidate.is_file())
        .unwrap();
    std::os::unix::fs::symlink(git, bin.join("git")).unwrap();
    let init = vee()
        .current_dir(directory.path())
        .arg("init")
        .env("PATH", &bin)
        .env("VEE_CONFIG", machine.path().join("config.yaml"))
        .env("OLLAMA_HOST", "127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let initialized_yaml = fs::read_to_string(directory.path().join(".vee.yaml")).unwrap();
    let initialized = serde_yaml::from_str::<serde_json::Value>(&initialized_yaml).unwrap();
    let configured = serde_yaml::from_str::<serde_json::Value>(
        "version: 1\noffline: false\nreview:\n  max_concurrency: 4\nproviders:\n  codex: { kind: codex_cli, egress: network, executable: codex, model: gpt-5-codex, env_allowlist: [PATH, HOME] }\nreviewers:\n  correctness: { provider: codex, instructions_file: .vee/reviewers/correctness.md, include: [src/**/*.rs] }\nverification:\n  unit: { executable: cargo, args: [test], timeout_seconds: 120, output_limit_bytes: 65536, env_allowlist: [PATH] }\nhosting: { provider: gitlab, host: gitlab.com, api_base: https://gitlab.com/api/v4/, token_env: GL_TOKEN, webhook_secret_env: VEE_GITLAB_WEBHOOK_SECRET, actor_login: vee-bot }\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [unit]\n  block_severities: [critical, high]\n  minimum_confidence: 80\n  on_incomplete: block\npolicy_profiles:\n  strict:\n    required_reviewers: [correctness]\n    block_severities: [critical, high, medium]\n    minimum_confidence: 90\n    on_incomplete: block\n",
    )
    .unwrap();

    assert!(validator.is_valid(&initialized));
    assert!(validator.is_valid(&configured));
    let api_config = serde_yaml::from_str::<serde_json::Value>(
        "version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: http://127.0.0.1:11434/v1/chat/completions\n    model: qwen-local\n    env_allowlist: [OPENAI_API_KEY]\n",
    )
    .unwrap();
    assert!(validator.is_valid(&api_config));
    let api_yaml = serde_yaml::to_string(&api_config).unwrap();
    fs::write(directory.path().join("api.yaml"), api_yaml).unwrap();
    assert!(vee_core::RepositoryConfig::load(&directory.path().join("api.yaml")).is_ok());
    // The initialized repository config references this machine's `default` provider.
    vee_core::RepositoryConfig::load_with_provider_defaults_and_offline(
        &directory.path().join(".vee.yaml"),
        Some(&machine.path().join("config.yaml")),
        false,
    )
    .unwrap();
    let parsed = serde_yaml::from_str::<vee_core::RepositoryConfig>(
        &serde_yaml::to_string(&configured).unwrap(),
    );
    assert!(
        parsed.is_ok(),
        "schema fixture must also match domain config: {parsed:?}"
    );
    let invalid =
        serde_yaml::from_str::<serde_json::Value>("version: 1\nreview:\n  max_concurrency: 33\n")
            .unwrap();
    assert!(!validator.is_valid(&invalid));
}

#[test]
fn bundled_agent_skills_list_install_and_refuse_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(directory.path())
        .status()
        .unwrap()
        .success());
    let nested = directory.path().join("src/nested");
    fs::create_dir_all(&nested).unwrap();
    let executable = env!("CARGO_BIN_EXE_vee");
    let listed = Command::new(executable)
        .current_dir(&nested)
        .args(["skills", "list"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let names = String::from_utf8(listed.stdout).unwrap();
    for id in [
        "vee-codebase-context",
        "vee-standards",
        "vee-local-review",
        "vee-investigate-findings",
        "vee-resolve-findings",
        "vee-requirement-traceability",
    ] {
        assert!(names.lines().any(|name| name == id), "missing {id}");
    }

    let installed = Command::new(executable)
        .current_dir(&nested)
        .args(["skills", "install"])
        .output()
        .unwrap();
    assert!(installed.status.success());
    let skill = directory
        .path()
        .join(".agents/skills/vee-local-review/SKILL.md");
    let original = fs::read_to_string(&skill).unwrap();
    assert!(original.contains("vee review --base"));

    fs::write(&skill, "customized\n").unwrap();
    let refused = Command::new(executable)
        .current_dir(&nested)
        .args(["skills", "install"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(3));
    assert_eq!(fs::read_to_string(&skill).unwrap(), "customized\n");

    let replaced = Command::new(executable)
        .current_dir(&nested)
        .args(["skills", "install", "--force"])
        .output()
        .unwrap();
    assert!(replaced.status.success());
    assert_eq!(fs::read_to_string(skill).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn agent_skill_install_rejects_symlinked_destination() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(directory.path())
        .status()
        .unwrap()
        .success());
    fs::create_dir_all(directory.path().join(".agents")).unwrap();
    symlink(outside.path(), directory.path().join(".agents/skills")).unwrap();
    let result = vee()
        .current_dir(directory.path())
        .args(["skills", "install"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[test]
fn standards_command_resolves_scoped_sources_with_provenance_and_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::create_dir_all(root.join("src/module")).unwrap();
    fs::create_dir_all(root.join(".vee/reviewers")).unwrap();
    fs::create_dir_all(root.join(".github")).unwrap();
    fs::write(root.join("AGENTS.md"), "Root rules\n").unwrap();
    fs::write(root.join("src/AGENTS.md"), "Source rules\n").unwrap();
    fs::write(root.join(".vee/policy.yaml"), "policy: protected\n").unwrap();
    fs::write(root.join(".vee/reviewers/security.md"), "Security rules\n").unwrap();
    fs::write(
        root.join(".github/copilot-instructions.md"),
        "Copilot rules\n",
    )
    .unwrap();

    let output = vee()
        .args([
            "standards",
            "--path",
            "src/module/file.rs",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_matches_schema(
        &report,
        include_str!("../../../schemas/standards-resolution-v1.schema.json"),
        "standards resolution",
    );
    assert_eq!(report["target_path"], "src/module/file.rs");
    let sources = report["sources"].as_array().unwrap();
    let paths = sources
        .iter()
        .map(|source| source["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"AGENTS.md"));
    assert!(paths.contains(&"src/AGENTS.md"));
    assert!(paths.contains(&".vee/policy.yaml"));
    assert!(paths.contains(&".vee/reviewers/security.md"));
    assert!(paths.contains(&".github/copilot-instructions.md"));
    let root_precedence = sources
        .iter()
        .find(|source| source["path"] == "AGENTS.md")
        .unwrap()["precedence"]
        .as_u64()
        .unwrap();
    let nested_precedence = sources
        .iter()
        .find(|source| source["path"] == "src/AGENTS.md")
        .unwrap()["precedence"]
        .as_u64()
        .unwrap();
    assert!(nested_precedence > root_precedence);
    assert!(report["potential_conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("precedence 50")));
    assert_eq!(sources[0]["path"], ".vee/policy.yaml");

    let escaped = vee()
        .args(["standards", "--path", "../secrets.txt", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(escaped.status.code(), Some(3));
}

#[test]
fn offline_mode_blocks_remote_standards_before_network_access() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join(".vee.yaml"), "version: 1\noffline: true\n").unwrap();

    let output = vee()
        .args([
            "standards",
            "--sync-url",
            "https://standards.example/rules.md",
            "--source-id",
            "team-rules",
            "--source-scope",
            "team",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("offline: true"));
    assert!(!root.join(".vee/standards-cache").exists());
}

#[test]
fn vee_offline_environment_override_cannot_be_weakened_by_repository_config() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["add", "tracked.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee-test@example.invalid",
            "commit",
            "-qm",
            "baseline",
        ])
        .status()
        .unwrap()
        .success());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review this change.").unwrap();
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\noffline: false\nproviders:\n  hosted:\n    kind: cli\n    executable: /vee-test-provider-must-not-run\n    egress: network\nreviewers:\n  correctness:\n    provider: hosted\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
    )
    .unwrap();

    let output = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .env("VEE_OFFLINE", "1")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("offline mode rejects network provider hosted"));
    assert!(!root.join(".vee/vee.sqlite").exists());
}

#[test]
fn vee_offline_environment_override_rejects_network_verification_before_execution() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["add", "tracked.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee-test@example.invalid",
            "commit",
            "-qm",
            "baseline",
        ])
        .status()
        .unwrap()
        .success());
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\noffline: false\nverification:\n  unit:\n    executable: /vee-test-verification-must-not-run\n    egress: network\n",
    )
    .unwrap();

    let output = vee()
        .args([
            "verify",
            "--profile",
            "unit",
            "--working-tree",
            "--output",
            "json",
        ])
        .current_dir(root)
        .env("VEE_OFFLINE", "1")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("offline mode rejects network verification profile unit"));
    assert!(!root.join(".vee/vee.sqlite").exists());
}

#[test]
fn offline_mode_blocks_remote_review_and_hosting_commands_before_credentials_or_requests() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\noffline: true\nhosting:\n  api_base: http://127.0.0.1:1/\n  token_env: VEE_OFFLINE_TEST_TOKEN\n",
    )
    .unwrap();
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["add", "tracked.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["-C"])
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee-test@example.invalid",
            "commit",
            "-qm",
            "baseline",
        ])
        .status()
        .unwrap()
        .success());

    let cases: &[(&[&str], &str)] = &[
        (
            &["review", "--working-tree", "--work-item", "owner/repo#1"],
            "offline mode prevents fetching work item context",
        ),
        (
            &[
                "hosting",
                "pr-issues",
                "--repository",
                "owner/repo",
                "--number",
                "1",
            ],
            "offline mode prevents fetching pull request review issues",
        ),
        (
            &[
                "hosting",
                "pr-context",
                "--repository",
                "org/project/repo",
                "--number",
                "1",
            ],
            "offline mode prevents fetching pull request context",
        ),
        (
            &[
                "hosting",
                "issue-context",
                "--repository",
                "owner/repo",
                "--number",
                "1",
            ],
            "offline mode prevents fetching work item context",
        ),
        (
            &[
                "hosting",
                "publish",
                "--review",
                "rev_missing",
                "--repository",
                "owner/repo",
                "--number",
                "1",
            ],
            "offline mode prevents publishing to a Git hosting provider",
        ),
        (
            &[
                "hosting",
                "webhook-serve",
                "--repository",
                ".",
                "--port",
                "0",
            ],
            "offline mode prevents serving hosting webhooks",
        ),
    ];

    for (args, expected_message) in cases {
        let output = vee()
            .args(*args)
            .current_dir(root)
            .env_remove("VEE_OFFLINE_TEST_TOKEN")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostics.contains(expected_message),
            "{args:?} did not fail at the offline guard; got: {diagnostics}"
        );
        assert!(
            !diagnostics.contains("VEE_OFFLINE_TEST_TOKEN is not set"),
            "{args:?} tried credential resolution before its offline guard"
        );
    }
}

#[test]
fn rule_candidate_report_uses_versioned_schema_and_does_not_mutate_policy() {
    use vee_core::ports::*;
    use vee_core::{Finding, FindingFeedbackLabel, Severity};
    use vee_store_sqlite::ReviewStore;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    for index in 0..3 {
        let finding_id = format!("finding-{index}");
        let snapshot_id = format!("snapshot-{index}");
        let finding = Finding {
            id: finding_id.clone(),
            fingerprint: format!("fingerprint-{index}"),
            category: "Correctness".into(),
            severity: Severity::Medium,
            confidence: Some(80),
            rationale: "possible defect".into(),
            path: Some("src/lib.rs".into()),
            line: Some(index + 1),
            provenance: "model_inference".into(),
            reviewer_ids: vec!["correctness".into()],
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        };
        store
            .save_review(
                &format!("review-{index}"),
                &snapshot_id,
                "config",
                "block",
                "{}",
                &[finding],
            )
            .unwrap();
        store
            .add_finding_feedback(
                &finding_id,
                &snapshot_id,
                FindingFeedbackLabel::FalsePositive,
                &Reason::new("The reported path is unreachable in this configuration").unwrap(),
                &ActorName::new("reviewer", &format!("reviewer-{index}")).unwrap(),
            )
            .unwrap();
    }
    drop(store);
    let output = vee()
        .args(["rules", "candidates", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 3);
    assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(value["candidates"][0]["feedback_label"], "false_positive");
    assert_eq!(value["candidates"][0]["feedback_count"], 3);
    assert_eq!(
        value["candidates"][0]["approval_status"],
        "requires_human_review"
    );
    assert_matches_schema(
        &value,
        include_str!("../../../schemas/rule-candidates-v3.schema.json"),
        "rule candidates",
    );
    let candidate_id = value["candidates"][0]["candidate_id"].as_str().unwrap();
    let evidence_digest = value["candidates"][0]["evidence_digest"].as_str().unwrap();
    let stale_approval = vee()
        .args([
            "rules",
            "approve",
            candidate_id,
            "--evidence-digest",
            &"0".repeat(64),
            "--scope",
            "src/lib.rs",
            "--instruction",
            "Do not approve stale evidence.",
            "--approver",
            "maintainer",
            "--reason",
            "Test stale digest rejection.",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale_approval.status.code(), Some(3));
    let approval_output = vee()
        .args([
            "rules",
            "approve",
            candidate_id,
            "--evidence-digest",
            evidence_digest,
            "--scope",
            "src/lib.rs",
            "--instruction",
            "Ask for reachability evidence before reporting this pattern.",
            "--approver",
            "maintainer",
            "--reason",
            "Reviewed the three attributed examples.",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        approval_output.status.success(),
        "stdout={}; stderr={}",
        String::from_utf8_lossy(&approval_output.stdout),
        String::from_utf8_lossy(&approval_output.stderr)
    );
    let approval: serde_json::Value = serde_json::from_slice(&approval_output.stdout).unwrap();
    assert_eq!(approval["status"], "active");
    assert_eq!(approval["version"], 1);
    assert_eq!(
        approval["evidence_digest"],
        value["candidates"][0]["evidence_digest"]
    );
    assert_matches_schema(
        &approval,
        include_str!("../../../schemas/rule-approval-v2.schema.json"),
        "rule approval",
    );
    let approval_id = approval["approval_id"].as_str().unwrap();
    let list_output = vee()
        .args(["rules", "list", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&list_output.stdout).unwrap();
    assert_eq!(listed["schema_version"], 1);
    assert_eq!(listed["approvals"].as_array().unwrap().len(), 1);
    assert_matches_schema(
        &listed,
        include_str!("../../../schemas/rule-approval-list-v1.schema.json"),
        "rule approval list",
    );
    let replacement_output = vee()
        .args([
            "rules",
            "approve",
            candidate_id,
            "--evidence-digest",
            evidence_digest,
            "--scope",
            "src/lib.rs",
            "--instruction",
            "Require a concrete input and output example.",
            "--approver",
            "maintainer",
            "--reason",
            "Updated after another review.",
            "--supersedes",
            approval_id,
            "--expires-in-days",
            "30",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        replacement_output.status.success(),
        "{}",
        String::from_utf8_lossy(&replacement_output.stderr)
    );
    let replacement: serde_json::Value =
        serde_json::from_slice(&replacement_output.stdout).unwrap();
    assert_eq!(replacement["version"], 2);
    assert_eq!(replacement["supersedes_approval_id"], approval_id);
    assert!(replacement["expires_at_unix"].as_i64().is_some());
    assert_matches_schema(
        &replacement,
        include_str!("../../../schemas/rule-approval-v2.schema.json"),
        "replacement rule approval",
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    store
        .add_finding_feedback(
            "finding-0",
            "snapshot-0",
            FindingFeedbackLabel::Confirmed,
            &Reason::new("A later review verified the finding.").unwrap(),
            &ActorName::new("reviewer", "reviewer-later").unwrap(),
        )
        .unwrap();
    drop(store);
    let effectiveness_output = vee()
        .args([
            "rules",
            "effectiveness",
            "--approval-id",
            replacement["approval_id"].as_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        effectiveness_output.status.success(),
        "{}",
        String::from_utf8_lossy(&effectiveness_output.stderr)
    );
    let effectiveness: serde_json::Value =
        serde_json::from_slice(&effectiveness_output.stdout).unwrap();
    assert_eq!(effectiveness["schema_version"], 1);
    assert_eq!(effectiveness["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(
        effectiveness["approvals"][0]["approval_id"],
        replacement["approval_id"]
    );
    assert_eq!(
        effectiveness["approvals"][0]["after_activation"]["accuracy_denominator"],
        1
    );
    assert_eq!(
        effectiveness["approvals"][0]["after_activation"]["false_positive_count"],
        0
    );
    assert_matches_schema(
        &effectiveness,
        include_str!("../../../schemas/rule-effectiveness-v1.schema.json"),
        "rule effectiveness",
    );
    let replacement_id = replacement["approval_id"].as_str().unwrap();
    let revoke_output = vee()
        .args([
            "rules",
            "revoke",
            replacement_id,
            "--actor",
            "maintainer",
            "--reason",
            "Replaced by updated guidance.",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        revoke_output.status.success(),
        "{}",
        String::from_utf8_lossy(&revoke_output.stderr)
    );
    let revoked: serde_json::Value = serde_json::from_slice(&revoke_output.stdout).unwrap();
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["events"].as_array().unwrap().len(), 2);
    assert!(!root.join(".vee.yaml").exists());
    assert!(!root.join(".vee/reviewers").exists());
}

#[test]
fn test_recommendations_are_snapshot_bound_and_cautious_about_missing_edges() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    let source = root.join("src/lib.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(
        &source,
        "pub fn calculate(value: i32) -> i32 {\n    value + 1\n}\n",
    )
    .unwrap();
    for (key, value) in [
        ("user.email", "vee@example.test"),
        ("user.name", "Vee Test"),
    ] {
        assert!(Command::new("git")
            .args(["config", key, value])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }
    assert!(Command::new("git")
        .args(["add", "src/lib.rs"])
        .current_dir(root)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["commit", "-qm", "baseline"])
        .current_dir(root)
        .status()
        .unwrap()
        .success());
    fs::write(
        &source,
        "pub fn calculate(value: i32) -> i32 {\n    value.saturating_add(2)\n}\n",
    )
    .unwrap();

    let output = vee()
        .args(["tests", "recommend", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert!(!value["snapshot_id"].as_str().unwrap().is_empty());
    assert_eq!(value["recommendations"].as_array().unwrap().len(), 1);
    assert_eq!(value["recommendations"][0]["changed_path"], "src/lib.rs");
    assert!(value["recommendations"][0]["rationale"]
        .as_str()
        .unwrap()
        .contains("not proof"));

    let snapshot_id = value["snapshot_id"].as_str().unwrap().to_owned();
    let artifact = b"TN:\nSF:src/lib.rs\nDA:1,1\nDA:2,0\nend_of_record\n";
    let artifact_digest = vee_core::digest(artifact);
    let artifact_path = root
        .join(".vee/artifacts")
        .join("sha256")
        .join(&artifact_digest["sha256:".len()..]);
    fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
    fs::write(&artifact_path, artifact).unwrap();
    let artifact_relative_path = format!(
        ".vee/artifacts/sha256/{}",
        &artifact_digest["sha256:".len()..]
    );
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let change_set =
        vee_application::capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    assert_eq!(change_set.digest, snapshot_id);
    let manifest = serde_json::to_string(&(
        change_set.schema_version,
        change_set.base_oid.as_deref(),
        change_set.head_oid.as_deref(),
        change_set.scope.as_str(),
        &change_set.files,
    ))
    .unwrap();
    let decision = vee_core::GateDecision {
        schema_version: 1,
        decision_id: "decision-coverage-fixture".into(),
        snapshot_id: snapshot_id.clone(),
        effective_config_digest: "config".into(),
        policy_digest: "policy".into(),
        status: vee_core::GateStatus::Pass,
        blocking_findings: vec![],
        verification_run_ids: vec![],
        evidence_digest: "evidence".into(),
        reasons: vec![],
        replay_inputs: None,
    };
    store
        .save_review_with_decision(vee_core::ReviewWrite {
            id: "rev-coverage-fixture",
            snapshot_id: &snapshot_id,
            config_digest: "config",
            status: "pass",
            payload: "{}",
            findings: &[],
            evidence: &[],
            snapshot_manifest: &manifest,
            decision: &decision,
        })
        .unwrap();
    store
        .save_verification_with_artifacts(&vee_core::VerificationRun {
            schema_version: 1,
            run_id: "coverage-current".into(),
            snapshot_id: snapshot_id.clone(),
            profile_id: "unit-tests".into(),
            finding_id: None,
            targets: vec!["src/lib.rs".into()],
            command_digest: "sha256:command".into(),
            status: vee_core::VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: artifact_digest.clone(),
            stderr_digest: vee_core::digest(b""),
            stdout_artifact: Some(vee_core::ArtifactReference {
                digest: artifact_digest,
                path: artifact_relative_path,
                size_bytes: artifact.len() as u64,
            }),
            stderr_artifact: None,
        })
        .unwrap();
    drop(store);
    let listed = vee()
        .args([
            "verification",
            "list",
            "--snapshot",
            &snapshot_id,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        listed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["snapshot_id"], snapshot_id);
    assert_eq!(listed["runs"][0]["run_id"], "coverage-current");
    assert_eq!(listed["runs"][0]["has_stdout_artifact"], true);
    assert_matches_schema(
        &listed,
        include_str!("../../../schemas/verification-list-v1.schema.json"),
        "verification list",
    );
    let covered = vee()
        .args([
            "tests",
            "recommend",
            "--working-tree",
            "--coverage-run",
            "coverage-current",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        covered.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&covered.stdout),
        String::from_utf8_lossy(&covered.stderr)
    );
    let covered: serde_json::Value = serde_json::from_slice(&covered.stdout).unwrap();
    assert_eq!(covered["execution_coverage"]["run_id"], "coverage-current");
    assert_eq!(
        covered["execution_coverage"]["files"][0]["covered_lines"],
        1
    );
    assert_eq!(
        covered["execution_coverage"]["files"][0]["executable_lines"],
        2
    );
    assert_eq!(
        covered["execution_coverage"]["files"][0]["changed_line_count"],
        1
    );
    assert_eq!(
        covered["execution_coverage"]["files"][0]["changed_executable_lines"],
        1
    );
    assert_eq!(
        covered["execution_coverage"]["files"][0]["changed_covered_lines"],
        0
    );
    assert!(covered["recommendations"][0]["rationale"]
        .as_str()
        .unwrap()
        .contains("changed executable-line coverage is 0/1"));

    let measured = vee()
        .args([
            "verification",
            "coverage",
            "coverage-current",
            "--stream",
            "stdout",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(measured.status.code(), Some(0));
    let measured: serde_json::Value = serde_json::from_slice(&measured.stdout).unwrap();
    assert_eq!(measured["files"][0]["changed_line_count"], 1);
    assert_eq!(measured["files"][0]["changed_executable_lines"], 1);
    assert_eq!(measured["files"][0]["changed_covered_lines"], 0);
    assert_eq!(measured["files"][0]["changed_percent"], 0.0);
    assert_matches_schema(
        &measured,
        include_str!("../../../schemas/coverage-report-v1.schema.json"),
        "coverage report",
    );

    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    store
        .save_verification(&vee_core::VerificationRun {
            schema_version: 1,
            run_id: "stale-run".into(),
            snapshot_id: "sha256:stale-snapshot".into(),
            profile_id: "old-tests".into(),
            finding_id: None,
            targets: vec![],
            command_digest: "sha256:command".into(),
            status: vee_core::VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: vee_core::digest(b""),
            stderr_digest: vee_core::digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        })
        .unwrap();
    drop(store);
    let stale = vee()
        .args([
            "tests",
            "recommend",
            "--working-tree",
            "--coverage-run",
            "stale-run",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(3));
    let stale_error = format!(
        "{}{}",
        String::from_utf8_lossy(&stale.stdout),
        String::from_utf8_lossy(&stale.stderr)
    );
    assert!(
        stale_error.contains("different change snapshot"),
        "{stale_error}"
    );
    assert_matches_schema(
        &covered,
        include_str!("../../../schemas/test-recommendations-v1.schema.json"),
        "test recommendations",
    );
}

#[cfg(unix)]
#[test]
fn standards_resolver_does_not_follow_symlinked_rule_directories() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(directory.path())
        .status()
        .unwrap()
        .success());
    fs::write(outside.path().join("policy.yaml"), "secret: outside\n").unwrap();
    symlink(outside.path(), directory.path().join(".vee")).unwrap();
    let output = vee()
        .args(["standards", "--output", "json"])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!report["sources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|source| source["content"].as_str().unwrap().contains("outside")));
}

#[cfg(unix)]
#[test]
fn configured_openai_compatible_local_provider_runs_through_review_and_gate() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { let value = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Check correctness.\n").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let split = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let body: serde_json::Value = serde_json::from_slice(&request[split..]).unwrap();
        assert_eq!(body["model"], "local-test-model");
        assert_eq!(body["response_format"]["type"], "json_schema");
        let result =
            br#"{"choices":[{"message":{"content":"{\"schema_version\":1,\"findings\":[]}"}}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            result.len()
        )
        .unwrap();
        stream.write_all(result).unwrap();
    });
    fs::write(root.join(".vee.yaml"), format!("version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: {endpoint}\n    model: local-test-model\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n")).unwrap();
    let output = vee()
        .args(["review", "--working-tree", "--gate", "--output", "json"])
        .current_dir(&root)
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["gate"]["status"], "pass");
    assert_eq!(
        review["reviewer_outcomes"][0]["provider_kind"],
        "openai_compatible"
    );
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
}

#[test]
fn provider_findings_schema_matches_the_versioned_output_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/provider-findings-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let required_fields = schema["properties"]["findings"]["items"]["required"]
        .as_array()
        .unwrap();
    for field in ["category", "severity", "rationale"] {
        assert!(required_fields.iter().any(|required| required == field));
    }
    let valid = serde_json::json!({
        "schema_version": 1,
        "findings": [{
            "category": "correctness",
            "severity": "high",
            "confidence": 90,
            "rationale": "The bounds check permits an out of range access.",
            "path": "src/lib.rs",
            "line": 12
        }]
    });
    let forged_identity = serde_json::json!({
        "schema_version": 1,
        "findings": [{
            "id": "forged",
            "category": "correctness",
            "severity": "high",
            "rationale": "bug"
        }]
    });
    assert!(validator.is_valid(&valid));
    let legacy_v1 = serde_json::json!({
        "schema_version": 1,
        "findings": [{
            "category": "correctness",
            "severity": "high",
            "rationale": "Legacy provider finding without optional metadata."
        }]
    });
    assert!(validator.is_valid(&legacy_v1));
    assert!(!validator.is_valid(&forged_identity));
}

#[test]
fn gated_review_with_no_reviewer_is_incomplete_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let output = vee()
        .arg("review")
        .arg("--gate")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["selected_reviewers"], serde_json::json!([]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Review "));
    assert!(stderr.contains("Status: incomplete"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let output_dir = tempfile::tempdir().unwrap();
        let protected = output_dir.path().join("protected.md");
        let linked_report = output_dir.path().join("review.md");
        fs::write(&protected, "preserve this file\n").unwrap();
        symlink(&protected, &linked_report).unwrap();
        let rejected = vee()
            .arg("review")
            .arg("--gate")
            .arg("--markdown")
            .arg(&linked_report)
            .current_dir(root)
            .output()
            .unwrap();
        assert_ne!(rejected.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("refusing to overwrite non-regular Markdown report path"));
        assert_eq!(
            fs::read_to_string(&protected).unwrap(),
            "preserve this file\n"
        );
        assert!(fs::symlink_metadata(&linked_report)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/review-output-v2.schema.json"
    ))
    .unwrap();
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/verification-run-v1.schema.json"
    ))
    .unwrap();
    let evidence_schema: serde_json::Value = serde_json::from_str::<serde_json::Value>(
        include_str!("../../../schemas/evidence-v1.schema.json"),
    )
    .unwrap();
    let gate_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/gate-decision-v1.schema.json"
    ))
    .unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "https://vee.klarlabs.de/schemas/analyzer-report-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/analyzer-report-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/work-item-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/work-item-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/verification-run-v1.schema.json",
            verification_schema,
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/evidence-v1.schema.json",
            evidence_schema,
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/gate-decision-v1.schema.json",
            gate_schema,
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/waiver-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/waiver-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .prepare()
        .unwrap();
    assert!(jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap()
        .is_valid(&value));
    assert!(root.join(".vee/vee.sqlite").exists());
}

#[test]
fn json_mode_emits_versioned_error_document_for_invalid_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vee.yaml"), "version: [invalid\n").unwrap();

    let output = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["error"]["code"], "configuration_error");
    assert!(!value["error"]["message"].as_str().unwrap().is_empty());
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn pr_issues_rejects_unsupported_configured_provider_as_json_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\nhosting:\n  provider: unknown-host\n",
    )
    .unwrap();
    let output = vee()
        .args([
            "hosting",
            "pr-issues",
            "--repository",
            "owner/repo",
            "--number",
            "1",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "configuration_error");
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unsupported hosting provider"));
    assert!(output.stderr.is_empty());
}

#[test]
fn json_mode_emits_versioned_error_document_for_invalid_invocation() {
    let output = vee()
        .args(["review", "--output", "json", "--not-a-review-option"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "usage_error");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn commands_with_json_defaults_emit_json_for_argument_errors() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    for arguments in [
        vec!["findings", "task"],
        vec!["findings", "package"],
        vec!["hosting", "pr-issues"],
        vec!["hosting", "pr-context"],
        vec!["hosting", "issue-context"],
        vec!["reviews", "verify-bundle"],
        vec!["rules", "effectiveness", "--invalid"],
    ] {
        let output = vee().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(3), "{arguments:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{arguments:?} emitted invalid JSON: {error}"));
        assert_eq!(value["schema_version"], 1, "{arguments:?}");
        assert_eq!(value["error"]["code"], "usage_error", "{arguments:?}");
        assert!(
            jsonschema::validator_for(&schema).unwrap().is_valid(&value),
            "{arguments:?}"
        );
        assert!(output.stderr.is_empty(), "{arguments:?}");
    }

    let text = vee()
        .args(["findings", "task", "--output", "text"])
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(3));
    assert!(text.stdout.is_empty());
    assert!(String::from_utf8_lossy(&text.stderr).contains("required arguments"));
}

#[test]
fn json_mode_maps_repository_execution_failure_to_exit_code_two() {
    let dir = tempfile::tempdir().unwrap();
    let output = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "execution_failed");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn top_level_help_is_a_successful_cli_invocation() {
    let output = vee().arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn gate_check_unknown_review_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    assert!(Command::new("git")
        .args(["-C", root.to_str().unwrap(), "add", "tracked.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap(),
            "-c",
            "user.name=Vee test",
            "-c",
            "user.email=vee@example.invalid",
            "commit",
            "-qm",
            "initial",
        ])
        .status()
        .unwrap()
        .success());
    fs::create_dir_all(root.join(".vee")).unwrap();
    vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let output = vee()
        .args([
            "gate",
            "check",
            "--review",
            "rev_missing",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "usage_error");
}

#[test]
fn review_commit_uses_the_selected_commit_tree_not_dirty_worktree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("source.rs"), "fn original() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("source.rs"), "fn committed() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "selected commit"]).status.success());
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let selected_oid = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();
    fs::write(root.join("source.rs"), "fn dirty_worktree() {}\n").unwrap();

    let output = vee()
        .args(["review", "--commit", "HEAD~1..HEAD", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["change_set"]["head_oid"], selected_oid);
    assert_eq!(
        value["change_set"]["scope"],
        format!(
            "commit_range:{}..{selected_oid}",
            value["change_set"]["base_oid"].as_str().unwrap()
        )
    );
    assert_eq!(
        value["change_set"]["files"][0]["content_digest"],
        vee_core::digest(b"fn committed() {}\n")
    );
}

#[test]
fn protected_policy_requires_configured_reviewer_even_if_repository_policy_omits_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::create_dir_all(root.join(".vee")).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        r#"
version: 1
providers:
  local: { kind: cli, executable: /bin/true }
reviewers:
  correctness: { provider: local, instructions_file: reviewer.md, enabled: false }
policy:
  required_reviewers: []
  on_incomplete: allow
"#,
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Check correctness.").unwrap();
    fs::write(
        root.join(".vee/policy.yaml"),
        "required_reviewers: [correctness]\non_incomplete: block\n",
    )
    .unwrap();
    fs::write(root.join("source.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let output = vee()
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "incomplete");
}

#[test]
fn impact_cli_emits_snapshot_bound_evidence_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn changed_api() {}\n").unwrap();
    fs::write(
        root.join("src/caller.rs"),
        "fn caller() { changed_api(); }\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("web")).unwrap();
    fs::write(
        root.join("web/api.ts"),
        "export function changedClientApi() { return 1; }\n",
    )
    .unwrap();
    fs::write(
        root.join("web/api.test.ts"),
        "// changedClientApi() in a comment is not evidence\nconst label = 'changedClientApi';\nit('uses api', () => changedClientApi());\n",
    )
    .unwrap();
    git(&["add", "."]);
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed_api() { assert!(true); }\n",
    )
    .unwrap();
    fs::write(
        root.join("web/api.ts"),
        "export function changedClientApi() { return 2; }\n",
    )
    .unwrap();

    let output = vee()
        .args(["impact", "--working-tree", "--output", "json"])
        .current_dir(root)
        .env("VEE_TSSERVER", root.join("missing-tsserver"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let impact: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/impact-assessment-v3.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.is_valid(&impact),
        "{}",
        validator
            .iter_errors(&impact)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(impact["schema_version"], 3);
    assert_eq!(impact["changed_paths"][0], "src/lib.rs");
    assert!(impact["changed_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "web/api.ts"));
    assert!(impact["paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["affected_path"] == "src/caller.rs" && edge["evidence_line"] == 1));
    assert!(impact["analyzers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|analyzer| {
            analyzer["id"] == "typescript-language-service" && analyzer["status"] == "unavailable"
        }));
    assert!(impact["paths"].as_array().unwrap().iter().any(|edge| {
        edge["affected_path"] == "web/api.test.ts"
            && edge["relationship"] == "likely_test_reference"
            && edge["certainty"] == "inferred_heuristic"
    }));
    assert!(!impact["paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| { edge["affected_path"] == "web/api.test.ts" && edge["evidence_line"] == 1 }));
}

#[cfg(unix)]
#[test]
fn mcp_stdio_exposes_findings_tool_over_the_pinned_protocol() {
    use mcp_rs::client::Client;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn second_commit() {}\n").unwrap();
    fs::write(root.join("large.txt"), "x".repeat(100)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), "outside secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.join("outside-link")).unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "second"]).status.success());
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\npolicy_profiles:\n  strict:\n    minimum_confidence: 93\n",
    )
    .unwrap();
    fs::create_dir_all(root.join(".vee")).unwrap();
    let mut db = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    db.save_review(
        "review-for-status-test",
        "snapshot-for-status-test",
        "config-for-status-test",
        "block",
        "{}",
        &[vee_core::Finding {
            id: "finding-for-status-test".into(),
            fingerprint: "fingerprint-for-status-test".into(),
            category: "correctness".into(),
            severity: vee_core::Severity::High,
            confidence: Some(90),
            rationale: "fixture finding".into(),
            path: Some("tracked.rs".into()),
            line: Some(1),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: vec![],
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        }],
    )
    .unwrap();
    for (index, finding_id) in ["rule-finding-a", "rule-finding-b"].into_iter().enumerate() {
        let finding = vee_core::Finding {
            id: finding_id.into(),
            fingerprint: format!("rule-fingerprint-{index}"),
            category: "correctness".into(),
            severity: vee_core::Severity::Medium,
            confidence: Some(80),
            rationale: "fixture finding for rule governance".into(),
            path: Some("tracked.rs".into()),
            line: Some(index as u32 + 2),
            provenance: "model_inference".into(),
            reviewer_ids: vec!["correctness".into()],
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        };
        db.save_review(
            &format!("rule-review-{index}"),
            &format!("rule-snapshot-{index}"),
            "config",
            "pass",
            "{}",
            &[finding],
        )
        .unwrap();
    }
    db.save_verification(&vee_core::VerificationRun {
        schema_version: 1,
        run_id: "verification-for-diagnosis-test".into(),
        snapshot_id: "snapshot-for-status-test".into(),
        profile_id: "unit".into(),
        finding_id: None,
        targets: vec!["fixture::tests".into()],
        command_digest: "sha256:command".into(),
        status: vee_core::VerificationStatus::Failed,
        exit_code: Some(1),
        stdout_digest: vee_core::digest(b""),
        stderr_digest: vee_core::digest(b""),
        stdout_artifact: None,
        stderr_artifact: None,
    })
    .unwrap();
    drop(db);
    fs::create_dir_all(root.join(".vee/imports")).unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut command = tokio::process::Command::from(vee());
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        use mcp_rs::protocol::ClientServiceExt;
        let client = Client::from_service(
            mcp_rs::model::ClientConfig::new(
                mcp_rs::model::ClientCapabilities::builder()
                    .enable_tasks()
                    .build(),
                mcp_rs::model::Implementation::new("vee-integration-test", "1"),
            )
            .serve_with_lifecycle(
                transport,
                mcp_rs::protocol::ClientLifecycleMode::Discover {
                    preferred_versions: vec![mcp_rs::model::ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let tools = client.peer().list_tools(None).await.unwrap();
        assert!(tools.tools.iter().any(|tool| tool.name == "start_review"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "get_repository_context"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "get_finding_work_package"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "get_applicable_standards"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "acceptance_traceability"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "set_finding_status"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "record_finding_feedback"));
        for name in ["list_rule_candidates", "approve_rule_candidate", "list_rule_approvals", "revoke_rule_approval", "rule_effectiveness"] {
            assert!(tools.tools.iter().any(|tool| tool.name == name), "missing MCP tool {name}");
        }
        for (finding_id, snapshot_id) in [
            ("finding-for-status-test", "snapshot-for-status-test"),
            ("rule-finding-a", "rule-snapshot-0"),
            ("rule-finding-b", "rule-snapshot-1"),
        ] {
            let _: serde_json::Value = client.call("record_finding_feedback", &serde_json::json!({
                "finding_id": finding_id,
                "snapshot_id": snapshot_id,
                "label": "not_actionable",
                "reason": "Fixture requests more concrete evidence",
                "reviewer": "integration-test"
            })).await.unwrap();
        }
        let candidates: serde_json::Value = client.call("list_rule_candidates", &serde_json::json!({})).await.unwrap();
        assert_eq!(candidates["schema_version"], 3);
        assert_eq!(candidates["candidates"].as_array().unwrap().len(), 1);
        let candidate = &candidates["candidates"][0];
        let approved: serde_json::Value = client.call("approve_rule_candidate", &serde_json::json!({
            "candidate_id": candidate["candidate_id"],
            "evidence_digest": candidate["evidence_digest"],
            "scope": "tracked.rs",
            "instruction": "Ask for a concrete example before reporting this pattern.",
            "approver": "maintainer",
            "reason": "Reviewed all attributed examples"
        })).await.unwrap();
        assert_eq!(approved["status"], "active");
        let approvals: serde_json::Value = client.call("list_rule_approvals", &serde_json::json!({})).await.unwrap();
        assert_eq!(approvals["approvals"].as_array().unwrap().len(), 1);
        let effectiveness: serde_json::Value = client.call("rule_effectiveness", &serde_json::json!({ "approval_id": approved["approval_id"] })).await.unwrap();
        assert_eq!(effectiveness["schema_version"], 1);
        assert_eq!(effectiveness["approvals"].as_array().unwrap().len(), 1);
        let revoked: serde_json::Value = client.call("revoke_rule_approval", &serde_json::json!({
            "approval_id": approved["approval_id"],
            "actor": "maintainer",
            "reason": "Fixture review complete"
        })).await.unwrap();
        assert_eq!(revoked["status"], "revoked");
        assert_eq!(revoked["events"].as_array().unwrap().len(), 2);
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "search_imported_review_history"));
        assert!(tools.tools.iter().any(|tool| tool.name == "record_external_review_feedback"));
        assert!(tools.tools.iter().any(|tool| tool.name == "list_external_review_feedback"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "get_quality_analytics"));
        assert!(tools.tools.iter().any(|tool| tool.name == "diagnose_verification"));
        let feedback: serde_json::Value = client.call(
            "record_finding_feedback",
            &serde_json::json!({
                "finding_id": "finding-for-status-test",
                "snapshot_id": "snapshot-for-status-test",
                "label": "false_positive",
                "reason": "Fixture confirms the path is unreachable",
                "reviewer": "integration-test"
            }),
        ).await.unwrap();
        assert_eq!(feedback["schema_version"], 1);
        assert_eq!(feedback["label"], "false_positive");
        let diagnosis: serde_json::Value = client.call(
            "diagnose_verification",
            &serde_json::json!({ "run_id": "verification-for-diagnosis-test" }),
        ).await.unwrap();
        assert_eq!(diagnosis["schema_version"], 2);
        assert_eq!(diagnosis["status"], "failed");
        assert!(diagnosis["diagnostics"].as_array().unwrap().is_empty());
        assert_matches_schema(
            &diagnosis,
            include_str!("../../../schemas/verification-diagnosis-v2.schema.json"),
            "verification diagnosis",
        );
        let analytics: serde_json::Value = client
            .call("get_quality_analytics", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(analytics["schema_version"], 9);
        assert_eq!(analytics["review_count"], 3);
        assert_eq!(analytics["reviews_without_gate_decision"], 3);
        assert_eq!(analytics["findings_by_status"]["open"], 3);
        assert_eq!(analytics["reviewed_feedback_by_label"]["false_positive"], 1);
        assert_eq!(analytics["reviewed_feedback_metrics"]["finding_accuracy"]["denominator"], 1);
        assert_eq!(analytics["reviewed_feedback_metrics"]["finding_accuracy"]["observed_rate"], 0.0);
        assert_matches_schema(
            &analytics,
            include_str!("../../../schemas/quality-analytics-v9.schema.json"),
            "quality analytics",
        );
        let historical: serde_json::Value = client
            .call(
                "search_imported_review_history",
                &serde_json::json!({"query":"correctness"}),
            )
            .await
            .unwrap();
        assert_eq!(historical["schema_version"], 3);
        assert_eq!(historical["query"], "correctness");
        assert_eq!(historical["matches"], serde_json::json!([]));
        assert_eq!(historical["trust"], "untrusted_external");
        assert_eq!(historical["gate_eligible"], false);
        assert!(client
            .call::<_, serde_json::Value>(
                "search_imported_review_history",
                &serde_json::json!({"query":"correctness", "limit":101}),
            )
            .await
            .is_err());
        let disposition: serde_json::Value = client.call(
            "set_finding_status",
            &serde_json::json!({
                "finding_id": "finding-for-status-test",
                "status": "verified",
                "reason": "Maintainer confirmed the behavior against the implementation."
            }),
        ).await.unwrap();
        assert_eq!(disposition["schema_version"], 1);
        assert_eq!(disposition["status"], "verified");
        assert!(disposition["note"].as_str().unwrap().contains("waiver"));
        assert_matches_schema(
            &disposition,
            include_str!("../../../schemas/finding-status-update-v1.schema.json"),
            "finding status update",
        );
        let finding: serde_json::Value = client.call(
            "get_finding",
            &serde_json::json!({"finding_id":"finding-for-status-test"}),
        ).await.unwrap();
        assert_eq!(finding["finding"]["status"], "verified");
        assert_eq!(finding["finding"]["status_reason"], "Maintainer confirmed the behavior against the implementation.");
        assert!(client.call::<_, serde_json::Value>(
            "set_finding_status",
            &serde_json::json!({
                "finding_id": "finding-for-status-test",
                "status": "waived",
                "reason": "Use a scoped waiver instead."
            }),
        ).await.is_err());
        assert!(client.call::<_, serde_json::Value>(
            "set_finding_status",
            &serde_json::json!({
                "finding_id": "finding-for-status-test",
                "status": "refuted",
                "reason": "   "
            }),
        ).await.is_err());
        let standards: serde_json::Value = client
            .call("get_applicable_standards", &serde_json::json!({"path":"tracked.rs"}))
            .await
            .unwrap();
        assert_eq!(standards["schema_version"], 1);
        let task = match client
            .call_once(
                "start_review",
                &serde_json::json!({"scope":"working_tree", "policy_profile":"strict"}),
            )
            .await
            .unwrap()
        {
            mcp_rs::model::CallToolResponse::Task(task) => task,
            other => panic!("start_review did not return an MCP task: {other:?}"),
        };
        let task_id = task.task.task_id.clone();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let finished_task = loop {
            let state = client
                .peer()
                .get_task(mcp_rs::model::GetTaskParams::new(task_id.clone()))
                .await
                .unwrap()
                .task;
            if state.status().is_terminal() {
                break state;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "review task did not finish"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(finished_task.status(), mcp_rs::model::TaskStatus::Completed);
        let task_result = match finished_task.payload {
            mcp_rs::model::TaskPayload::Completed { result } => result,
            payload => panic!("unexpected review task payload: {payload:?}"),
        };
        let task_output = &task_result["structuredContent"];
        let review_id = task_output["review_id"].as_str().unwrap();
        assert_eq!(task_output["policy_profile"], "strict");
        let persisted_review: serde_json::Value = client
            .call("get_review", &serde_json::json!({"review_id": review_id}))
            .await
            .unwrap();
        assert_eq!(persisted_review["review_id"], review_id);
        let traceability: serde_json::Value = client
            .call("acceptance_traceability", &serde_json::json!({"review_id": review_id}))
            .await
            .unwrap();
        assert_eq!(traceability["snapshot_id"], task_output["snapshot_id"]);
        assert_eq!(traceability["impact_snapshot_id"], task_output["snapshot_id"]);
        assert_matches_schema(
            &traceability,
            include_str!("../../../schemas/acceptance-traceability-v1.schema.json"),
            "MCP acceptance traceability report",
        );
        let context: serde_json::Value = client
            .call(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":"tracked.rs","symbol":"second_commit"}),
            )
            .await
            .unwrap();
        assert_eq!(context["schema_version"], 2);
        assert_eq!(context["path"], "tracked.rs");
        assert_eq!(context["snapshot_id"], task_output["snapshot_id"]);
        assert_eq!(context["content_digest"].as_str().unwrap().len(), 71);
        assert_eq!(context["returned_bytes"], context["total_bytes"]);
        assert_eq!(context["matching_line_count"], 1);
        assert!(context["content"]
            .as_str()
            .unwrap()
            .contains("second_commit"));
        assert_eq!(context["matching_lines"], serde_json::json!([1]));
        assert_eq!(context["classification"], "untrusted_repository_source");
        fs::write(root.join("tracked.rs"), "fn modified_after_review() {}\n").unwrap();
        // Traceability reads the saved snapshot through digest-verified snapshot reads,
        // so later working-tree edits cannot change it; this matches `vee acceptance report`.
        let after_edit: serde_json::Value = client.call(
            "acceptance_traceability",
            &serde_json::json!({"review_id":review_id}),
        ).await.unwrap();
        assert_eq!(after_edit, traceability);
        let old_context: serde_json::Value = client.call(
            "get_repository_context",
            &serde_json::json!({"review_id":review_id,"path":"tracked.rs"}),
        ).await.unwrap();
        assert!(old_context["content"].as_str().unwrap().contains("second_commit"));
        assert!(!old_context["content"].as_str().unwrap().contains("modified_after_review"));
        fs::write(root.join("tracked.rs"), "fn second_commit() {}\n").unwrap();
        assert!(git(&["add", "large.txt"]).status.success());
        let large_review: serde_json::Value = client.call(
            "review_changes",
            &serde_json::json!({"scope":"working_tree"}),
        ).await.unwrap();
        let bounded_context: serde_json::Value = client
            .call(
                "get_repository_context",
                &serde_json::json!({"review_id":large_review["review_id"],"path":"large.txt","max_bytes":12}),
            )
            .await
            .unwrap();
        assert_eq!(bounded_context["content"].as_str().unwrap().len(), 12);
        assert_eq!(bounded_context["truncated"], true);
        assert_eq!(bounded_context["returned_bytes"], 12);
        assert!(bounded_context["total_bytes"].as_u64().unwrap() > 12);
        assert_eq!(bounded_context["snapshot_id"], large_review["snapshot_id"]);
        assert_eq!(bounded_context["content_digest"].as_str().unwrap().len(), 71);
        assert!(client
            .call::<_, serde_json::Value>(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":".vee/vee.sqlite"}),
            )
            .await
            .is_err());
        #[cfg(unix)]
        assert!(client
            .call::<_, serde_json::Value>(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":"outside-link/secret.txt"}),
            )
            .await
            .is_err());
        let result: serde_json::Value = client
            .call("list_findings", &serde_json::json!({"limit": 5}))
            .await
            .unwrap();
        assert_eq!(result["schema_version"], 2);
        assert_eq!(result["findings"].as_array().unwrap().len(), 3);
        assert_eq!(result["total"], 3);
        assert!(result["findings"].as_array().unwrap().iter().any(|finding| {
            finding["status"] == "verified"
        }));
        let review: serde_json::Value = client
            .call(
                "review_changes",
                &serde_json::json!({"scope":"working_tree"}),
            )
            .await
            .unwrap();
        assert_eq!(review["schema_version"], 2);
        assert_eq!(review["status"], "incomplete");
        assert!(review["review_id"].as_str().unwrap().starts_with("rev_"));
        assert!(review["snapshot_id"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        let impact: serde_json::Value = client
            .call(
                "analyze_impact",
                &serde_json::json!({"review_id":review["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(impact["schema_version"], 3);
        assert_eq!(impact["snapshot_id"], review["snapshot_id"]);
        let committed: serde_json::Value = client
            .call(
                "review_changes",
                &serde_json::json!({"scope":"commit", "commit":"HEAD~1..HEAD"}),
            )
            .await
            .unwrap();
        let stored: serde_json::Value = client
            .call(
                "get_review",
                &serde_json::json!({"review_id":committed["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(
            stored["change_set"]["scope"],
            format!(
                "commit_range:{}..{}",
                stored["change_set"]["base_oid"].as_str().unwrap(),
                stored["change_set"]["head_oid"].as_str().unwrap()
            )
        );
        fs::write(
            root.join("tracked.rs"),
            "fn changed_after_commit_review() {}\n",
        )
        .unwrap();
        let gate: serde_json::Value = client
            .call(
                "evaluate_gate",
                &serde_json::json!({"review_id":committed["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(gate["reviewed_snapshot_id"], gate["current_snapshot_id"]);
        client.close().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
fn mcp_gate_check_rejects_source_changed_after_review() {
    use mcp_rs::client::Client;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let reviewed = vee()
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(reviewed.status.code(), Some(2));
    let review: serde_json::Value = serde_json::from_slice(&reviewed.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap().to_owned();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 2; }\n").unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut command = tokio::process::Command::from(vee());
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        let client = Client::connect(transport).await.unwrap();
        let result: serde_json::Value = client
            .call(
                "evaluate_gate",
                &serde_json::json!({"review_id": review_id}),
            )
            .await
            .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/gate-check-v1.schema.json"))
                .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&result));
        assert_eq!(result["status"], "incomplete");
        assert!(result["reasons"][0]
            .as_str()
            .unwrap()
            .contains("source snapshot changed"));
        client.close().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
fn explicit_verification_profile_persists_failure_against_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vee.yaml"), "version: 1\nverification:\n  failing-check:\n    executable: /usr/bin/false\n    timeout_seconds: 2\n    output_limit_bytes: 64\n").unwrap();

    let output = vee()
        .args(["verify", "--profile", "failing-check", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["snapshot_id"].as_str().unwrap().len(), 71);
    assert_matches_schema(
        &value,
        include_str!("../../../schemas/verification-run-v1.schema.json"),
        "verification run",
    );
    assert!(root.join(".vee/vee.sqlite").exists());
    let run_id = value["run_id"].as_str().unwrap();
    let show = vee()
        .args(["verification", "show", run_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(show.status.code(), Some(0));
    let persisted: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_matches_schema(
        &persisted,
        include_str!("../../../schemas/verification-run-v1.schema.json"),
        "persisted verification run",
    );
    assert_eq!(persisted, value);
}

#[cfg(unix)]
#[test]
fn impacted_go_verification_expands_and_persists_package_targets() {
    if Command::new("go").arg("version").output().is_err() {
        return;
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
    fs::write(
        root.join("go.mod"),
        "module example.invalid/targeted\n\ngo 1.24\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("pkg")).unwrap();
    fs::write(root.join("pkg/api.go"), "package pkg\nfunc Changed() {}\n").unwrap();
    fs::write(
        root.join("pkg/api_test.go"),
        "package pkg\nimport \"testing\"\nfunc TestChanged(t *testing.T) { Changed() }\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "fixture"]);
    fs::write(
        root.join("pkg/api.go"),
        "package pkg\nfunc Changed() { _ = true }\n",
    )
    .unwrap();
    fs::write(
        root.join(".vee.yaml"),
        "version: 1\nverification:\n  impacted:\n    executable: go\n    args: [test, -json, \"{impacted_test_packages}\"]\n    env_allowlist: [PATH, HOME]\n",
    )
    .unwrap();

    let output = vee()
        .args([
            "verify",
            "--profile",
            "impacted",
            "--impacted-tests",
            "--working-tree",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let diagnostic = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|value| value["stdout_artifact"]["path"].as_str().map(str::to_owned))
        .and_then(|path| fs::read(root.join(path)).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={} stdout={} verification_log={diagnostic}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["targets"], serde_json::json!(["./pkg"]));
    assert_eq!(value["status"], "passed");
    assert_matches_schema(
        &value,
        include_str!("../../../schemas/verification-run-v1.schema.json"),
        "targeted verification run",
    );
}

#[cfg(unix)]
#[test]
fn p2_acceptance_review_impact_targeted_tests_gate_and_staleness() {
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
    git(&["config", "user.name", "Vee acceptance"]);
    fs::write(root.join(".gitignore"), "/target/\n/Cargo.lock\n/.vee/\n").unwrap();
    fs::write(
        root.join("go.mod"),
        "module example.invalid/vee-acceptance\n\ngo 1.20\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("go/pkg")).unwrap();
    fs::write(
        root.join("go/pkg/api.go"),
        "package pkg\nfunc Changed() int { return 40 + 2 }\n",
    )
    .unwrap();
    fs::write(root.join("go/pkg/api_test.go"), "package pkg\nimport \"testing\"\nfunc TestChanged(t *testing.T) { if Changed() != 42 { t.Fatal(\"unexpected value\") } }\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"vee-acceptance\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed() -> u32 { 40 + 2 }\n#[cfg(feature = \"optional\")]\nmod tests {\n    #[test]\n    fn optional_test() {}\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("tests/api_test.rs"),
        "use vee_acceptance::changed;\n#[test]\nfn api_contract() { assert_eq!(changed(), 42); }\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "acceptance baseline"]);
    fs::write(
        root.join("go/pkg/api.go"),
        "package pkg\nconst BASE = 40\nfunc Changed() int { return BASE + 2 }\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "const BASE: u32 = 40;\npub fn changed() -> u32 { BASE + 2 }\n#[cfg(feature = \"optional\")]\nmod tests {\n    #[test]\n    fn optional_test() {}\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("reviewer.md"),
        "Review the changed behavior for defects.\n",
    )
    .unwrap();
    let provider = root.join("fake-reviewer");
    fs::write(
        &provider,
        "#!/bin/sh\n/bin/cat >/dev/null\n/usr/bin/printf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let go_available = Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success());
    let go_verification = if go_available {
        "  go-targeted:\n    executable: go\n    args: [test, -json, \"{impacted_test_packages}\"]\n    env_allowlist: [PATH, HOME]\n    timeout_seconds: 120\n"
    } else {
        ""
    };
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  local:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\nverification:\n{}  rust-targeted:\n    executable: cargo\n    args: [test, --manifest-path, Cargo.toml, \"{{impacted_rust_test_filters}}\"]\n    env_allowlist: [PATH, HOME, CARGO_HOME, RUSTUP_HOME]\n    timeout_seconds: 120\n  unit:\n    executable: cargo\n    args: [test, --manifest-path, Cargo.toml]\n    env_allowlist: [PATH, HOME, CARGO_HOME, RUSTUP_HOME]\n    timeout_seconds: 120\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [unit]\n  block_severities: [high, critical]\n  minimum_confidence: 80\n  on_incomplete: block\n",
            provider.display(),
            go_verification
        ),
    )
    .unwrap();

    let run = |args: &[&str]| vee().args(args).current_dir(root).output().unwrap();
    let review = run(&["review", "--working-tree", "--gate", "--output", "json"]);
    assert_eq!(
        review.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(review["gate"]["status"], "incomplete");
    let snapshot_id = review["snapshot_id"].as_str().unwrap();
    let review_id = review["review_id"].as_str().unwrap();

    let impact = run(&["impact", "--working-tree", "--output", "json"]);
    assert_eq!(
        impact.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&impact.stderr)
    );
    let impact: serde_json::Value = serde_json::from_slice(&impact.stdout).unwrap();
    assert_eq!(impact["snapshot_id"], snapshot_id);
    assert!(impact["paths"].as_array().unwrap().iter().any(|edge| {
        edge["affected_path"] == "go/pkg/api_test.go"
            && edge["relationship"] == "likely_test_reference"
    }));
    assert!(impact["paths"].as_array().unwrap().iter().any(|edge| {
        edge["affected_path"] == "tests/api_test.rs"
            && edge["relationship"] == "likely_test_reference"
    }));

    let mut profiles = vec![("rust-targeted", "vee-acceptance::")];
    if go_available {
        profiles.insert(0, ("go-targeted", "./go/pkg"));
    }
    for (profile, expected_target) in profiles {
        let verified = run(&[
            "verify",
            "--profile",
            profile,
            "--impacted-tests",
            "--working-tree",
            "--output",
            "json",
        ]);
        if verified.status.code() != Some(0) {
            let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
            let artifact_text = |key: &str| {
                report[key]["path"]
                    .as_str()
                    .and_then(|path| fs::read(root.join(path)).ok())
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default()
            };
            panic!(
                "profile={profile} failed: stdout={} stderr={} stdout_artifact={} stderr_artifact={}",
                String::from_utf8_lossy(&verified.stdout),
                String::from_utf8_lossy(&verified.stderr),
                artifact_text("stdout_artifact"),
                artifact_text("stderr_artifact"),
            );
        }
        assert_eq!(
            verified.status.code(),
            Some(0),
            "profile={profile} stderr={} stdout={}",
            String::from_utf8_lossy(&verified.stderr),
            String::from_utf8_lossy(&verified.stdout)
        );
        let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(verified["snapshot_id"], snapshot_id);
        assert_eq!(verified["status"], "passed");
        assert!(
            verified["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|target| {
                    target.as_str().is_some_and(|target| {
                        if expected_target.ends_with("::") {
                            target.starts_with(expected_target)
                        } else {
                            target == expected_target
                        }
                    })
                }),
            "expected {expected_target}, got {}",
            verified["targets"]
        );
    }

    let targeted_only = run(&["gate", "check", "--review", review_id, "--output", "json"]);
    assert_eq!(targeted_only.status.code(), Some(2));
    let targeted_only: serde_json::Value = serde_json::from_slice(&targeted_only.stdout).unwrap();
    assert_eq!(targeted_only["status"], "incomplete");

    let full_suite = run(&[
        "verify",
        "--profile",
        "unit",
        "--working-tree",
        "--output",
        "json",
    ]);
    assert_eq!(
        full_suite.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&full_suite.stderr)
    );
    let full_suite: serde_json::Value = serde_json::from_slice(&full_suite.stdout).unwrap();
    assert_eq!(full_suite["snapshot_id"], snapshot_id);
    assert_eq!(full_suite["status"], "passed");
    let gate = run(&["gate", "check", "--review", review_id, "--output", "json"]);
    assert_eq!(
        gate.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&gate.stderr)
    );
    let gate: serde_json::Value = serde_json::from_slice(&gate.stdout).unwrap();
    assert_eq!(gate["status"], "pass");
    assert_eq!(gate["reviewed_snapshot_id"], snapshot_id);
    assert_eq!(gate["current_snapshot_id"], snapshot_id);

    fs::write(
        root.join("src/lib.rs"),
        "const BASE: u32 = 41;\npub fn changed() -> u32 { BASE + 2 }\n",
    )
    .unwrap();
    let stale_gate = run(&["gate", "check", "--review", review_id, "--output", "json"]);
    assert_eq!(stale_gate.status.code(), Some(2));
    let stale_gate: serde_json::Value = serde_json::from_slice(&stale_gate.stdout).unwrap();
    assert_eq!(stale_gate["status"], "incomplete");
    assert_ne!(stale_gate["current_snapshot_id"], snapshot_id);
}

#[cfg(unix)]
#[test]
fn required_verification_gate_uses_latest_result_for_exact_snapshot() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"verification-freshness-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "Cargo.toml", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join("reviewer.md"), "Review changed code.\n").unwrap();
    let marker = dir.path().with_extension("verification-marker");
    let verification_script = format!(
        "if [ -f '{}' ]; then exit 1; else touch '{}'; exit 0; fi",
        marker.display(),
        marker.display()
    );
    let config = format!(
        "version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\nverification:\n  unit:\n    executable: /bin/sh\n    args: [-c, \"{}\"]\n    timeout_seconds: 3\n    output_limit_bytes: 64\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [unit]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n",
        provider.display(),
        verification_script
    );
    fs::write(root.join(".vee.yaml"), config).unwrap();

    let run_verify = || {
        vee()
            .args(["verify", "--profile", "unit", "--output", "json"])
            .current_dir(root)
            .output()
            .unwrap()
    };
    let initial_review = vee()
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        initial_review.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&initial_review.stderr)
    );
    let initial_json: serde_json::Value = serde_json::from_slice(&initial_review.stdout).unwrap();
    assert_eq!(initial_json["status"], "incomplete");
    let review_id = initial_json["review_id"].as_str().unwrap();
    let initial_decision_id = initial_json["gate"]["decision_id"].as_str().unwrap();

    let first = run_verify();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let recheck = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        recheck.status.code(),
        Some(0),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&recheck.stderr),
        String::from_utf8_lossy(&recheck.stdout)
    );
    let recheck_json: serde_json::Value = serde_json::from_slice(&recheck.stdout).unwrap();
    assert_eq!(recheck_json["status"], "pass");
    assert_ne!(
        recheck_json["decision_id"].as_str().unwrap(),
        initial_decision_id
    );
    assert_eq!(
        recheck_json["verification_run_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let second = run_verify();
    assert_eq!(second.status.code(), Some(1));
    let package = vee()
        .args(["repos", "package"])
        .arg(root)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(package.status.code(), Some(0));
    let package_json: serde_json::Value = serde_json::from_slice(&package.stdout).unwrap();
    assert_eq!(package_json["repositories"][0]["saved_gate_status"], "pass");
    assert_eq!(
        package_json["repositories"][0]["gate_validity"],
        "stale_verification"
    );
    assert_eq!(package_json["readiness"], "incomplete");
    let revoked = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        revoked.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoked_json: serde_json::Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(revoked_json["status"], "incomplete");
    assert!(revoked_json["reasons"][0]
        .as_str()
        .unwrap()
        .contains("unit"));
    let history = vee()
        .args(["gate", "history", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(history.status.code(), Some(0));
    let decisions: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_matches_schema(
        &decisions,
        include_str!("../../../schemas/gate-history-v1.schema.json"),
        "gate history",
    );
    assert_eq!(decisions["schema_version"], 1);
    assert_eq!(decisions["decisions"].as_array().unwrap().len(), 3);
    assert_eq!(decisions["decisions"][0]["status"], "incomplete");
    assert_eq!(decisions["decisions"][1]["status"], "pass");
    assert_eq!(decisions["decisions"][2]["status"], "incomplete");
    let _ = fs::remove_file(marker);
}

#[cfg(unix)]
#[test]
fn configured_provider_finding_blocks_gate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { unsafe {} }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Look for correctness defects.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        r#"#!/bin/sh
request=$(cat)
reviewer=$(printf '%s' "$request" | sed -n 's/.*"reviewer_id":"\([^" ]*\)".*/\1/p')
case "$reviewer" in
  security) printf '%s' '{"schema_version":1,"findings":[{"category":"correctness","severity":"critical","confidence":40,"rationale":"unsafe operation","path":"tracked.rs","line":1}]}' ;;
  *) printf '%s' '{"schema_version":1,"findings":[{"category":"correctness","severity":"medium","confidence":95,"rationale":"potential defect","path":"tracked.rs","line":1}]}' ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let config = format!(
        "version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\n  security:\n    provider: fake\n    instructions_file: reviewer.md\n    policy:\n      block_severities: [critical]\n      minimum_confidence: 30\nverification:\n  unit:\n    executable: /usr/bin/true\npolicy:\n  required_reviewers: [correctness]\n  block_severities: []\n  minimum_confidence: 80\n  on_incomplete: block\npolicy_profiles:\n  strict:\n    required_reviewers: [correctness]\n    block_severities: []\n    minimum_confidence: 80\n    on_incomplete: block\n",
        provider.display()
    );
    fs::write(root.join(".vee.yaml"), config).unwrap();
    let report_dir = tempfile::tempdir().unwrap();
    let markdown_report = report_dir.path().join("review-report.md");
    let output = vee()
        .arg("review")
        .arg("--reviewer")
        .arg("correctness")
        .arg("--reviewer")
        .arg("security")
        .arg("--gate")
        .arg("--policy-profile")
        .arg("strict")
        .arg("--output")
        .arg("json")
        .arg("--markdown")
        .arg(&markdown_report)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_matches_schema(
        &value,
        include_str!("../../../schemas/review-output-v2.schema.json"),
        "reviewer arbitration review",
    );
    assert_eq!(value["status"], "block");
    assert_eq!(value["policy_profile"], "strict");
    assert_eq!(value["policy_findings"].as_array().unwrap().len(), 2);
    assert_eq!(value["findings"].as_array().unwrap().len(), 1);
    assert_eq!(value["findings"][0]["severity"], "critical");
    assert_eq!(
        value["findings"][0]["reviewer_ids"],
        serde_json::json!(["correctness", "security"])
    );
    assert_eq!(value["reviewer_arbitration"].as_array().unwrap().len(), 1);
    let arbitration = &value["reviewer_arbitration"][0];
    assert_eq!(arbitration["severity_disagreement"], true);
    assert_eq!(arbitration["confidence_disagreement"], true);
    assert_eq!(arbitration["rationale_disagreement"], true);
    assert_eq!(
        arbitration["applicable_policy_rules"],
        serde_json::json!(["reviewer:security"])
    );
    assert_eq!(arbitration["gate_blocking"], true);
    assert_eq!(
        value["gate"]["effective_config_digest"],
        value["effective_config_digest"]
    );
    let markdown = fs::read_to_string(markdown_report).unwrap();
    assert!(markdown.starts_with("## Review rev_"), "{markdown}");
    assert!(
        markdown
            .lines()
            .next()
            .unwrap()
            .ends_with(" · 🔴 **block**"),
        "{markdown}"
    );
    assert!(markdown.contains("unsafe operation"), "{markdown}");
    assert!(markdown.contains("### Reviewer disagreement"), "{markdown}");
    assert!(
        markdown.contains("disagree on severity, confidence, rationale"),
        "{markdown}"
    );
    assert!(markdown.contains("### Finding details"), "{markdown}");
    assert!(markdown.contains("### Reviewer reports"), "{markdown}");
    assert!(
        !markdown.contains("Next:"),
        "a shared report has no interactive next step"
    );
    assert_eq!(
        value["selected_reviewers"],
        serde_json::json!(["correctness", "security"])
    );
    assert_eq!(value["evidence"].as_array().unwrap().len(), 1);
    let evidence_id = value["evidence"][0]["id"].as_str().unwrap();
    assert_eq!(value["findings"][0]["evidence_ids"][0], evidence_id);
    assert_eq!(value["evidence"][0]["classification"], "observed");
    assert_eq!(value["evidence"][0]["verification"], "unverified");
    assert!(value["gate"]["blocking_findings"][0]
        .as_str()
        .unwrap()
        .starts_with("find_"));
    let finding_id = value["findings"][0]["id"].as_str().unwrap().to_owned();
    let snapshot_id = value["snapshot_id"].as_str().unwrap().to_owned();
    let review_id = value["review_id"].as_str().unwrap();
    let gate_check = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(gate_check.status.code(), Some(1));
    let gate_check: serde_json::Value = serde_json::from_slice(&gate_check.stdout).unwrap();
    assert_eq!(gate_check["status"], "block");
    assert_eq!(gate_check["blocking_findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        gate_check["effective_config_digest"],
        value["effective_config_digest"]
    );
    for (args, schema_text, key) in [
        (
            vec![
                "findings", "list", "--review", review_id, "--output", "json",
            ],
            include_str!("../../../schemas/findings-list-v2.schema.json"),
            "findings",
        ),
        (
            vec!["findings", "show", finding_id.as_str(), "--output", "json"],
            include_str!("../../../schemas/finding-detail-v2.schema.json"),
            "finding",
        ),
        (
            vec!["gate", "history", "--review", review_id, "--output", "json"],
            include_str!("../../../schemas/gate-history-v1.schema.json"),
            "decisions",
        ),
    ] {
        let result = vee().args(args).current_dir(root).output().unwrap();
        assert_eq!(result.status.code(), Some(0));
        let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_matches_schema(&response, schema_text, "CLI response");
        let schema: serde_json::Value = serde_json::from_str(schema_text).unwrap();
        assert_eq!(
            response["schema_version"],
            schema["properties"]["schema_version"]["const"]
        );
        assert!(!response[key].is_null());
    }
    let sarif = vee()
        .args(["reviews", "export", review_id, "--format", "sarif"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        sarif.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&sarif.stderr)
    );
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "Vee");
    assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "correctness");
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    assert_eq!(
        sarif["runs"][0]["results"][0]["partialFingerprints"]["vee/v1"],
        value["findings"][0]["fingerprint"]
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "tracked.rs"
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    let targeted_verification = vee()
        .args([
            "verify",
            finding_id.as_str(),
            "--profile",
            "unit",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        targeted_verification.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&targeted_verification.stderr)
    );
    let targeted_run: serde_json::Value =
        serde_json::from_slice(&targeted_verification.stdout).unwrap();
    assert_eq!(targeted_run["finding_id"], finding_id);
    assert_eq!(targeted_run["snapshot_id"], snapshot_id);
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/verification-run-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&verification_schema)
        .unwrap()
        .is_valid(&targeted_run));
    assert!(root
        .join(targeted_run["stdout_artifact"]["path"].as_str().unwrap())
        .exists());
    let detail = vee()
        .args(["findings", "show", finding_id.as_str(), "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(detail.status.success());
    let detail: serde_json::Value = serde_json::from_slice(&detail.stdout).unwrap();
    assert_eq!(detail["verification_runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        detail["verification_runs"][0]["run_id"],
        targeted_run["run_id"]
    );
    assert_eq!(detail["verification_runs"][0]["snapshot_id"], snapshot_id);
    let mcp_finding_id = finding_id.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        use mcp_rs::client::Client;
        let mut command = tokio::process::Command::from(vee());
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        let client = Client::connect(transport).await.unwrap();
        fs::write(
            root.join("tracked.rs"),
            "fn main() { unsafe { let _ = 1; } }\n",
        )
        .unwrap();
        let stale = client
            .call::<_, serde_json::Value>(
                "verify_finding",
                &serde_json::json!({"finding_id":mcp_finding_id,"profile_id":"unit"}),
            )
            .await;
        assert!(stale.is_err());
        fs::write(root.join("tracked.rs"), "fn main() { unsafe {} }\n").unwrap();
        let verification: serde_json::Value = client
            .call(
                "verify_finding",
                &serde_json::json!({"finding_id":mcp_finding_id,"profile_id":"unit"}),
            )
            .await
            .unwrap();
        assert_eq!(verification["schema_version"], 1);
        assert_eq!(verification["status"], "passed");
        assert_eq!(verification["snapshot_id"], snapshot_id);
        assert_eq!(verification["finding_id"], mcp_finding_id);
        let details: serde_json::Value = client
            .call(
                "get_finding",
                &serde_json::json!({"finding_id":mcp_finding_id}),
            )
            .await
            .unwrap();
        assert_eq!(details["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(details["evidence"][0]["kind"], "source");
        assert_eq!(details["verification_runs"].as_array().unwrap().len(), 1);
        assert_eq!(
            details["verification_runs"][0]["run_id"],
            verification["run_id"]
        );
        let page: serde_json::Value = client
            .call(
                "list_findings",
                &serde_json::json!({"review_id":review_id,"limit":1,"offset":0}),
            )
            .await
            .unwrap();
        assert_eq!(page["total"], 1);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["findings"].as_array().unwrap().len(), 1);
        assert_eq!(page["findings"][0]["finding"]["id"], mcp_finding_id);
        client.close().await.unwrap();
    });
    let list = vee()
        .args([
            "findings",
            "list",
            "--severity",
            "critical",
            "--status",
            "open",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(list.status.code(), Some(0));
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_matches_schema(
        &listed,
        include_str!("../../../schemas/findings-list-v2.schema.json"),
        "findings list",
    );
    assert_eq!(listed["schema_version"], 2);
    assert_eq!(listed["findings"].as_array().unwrap().len(), 1, "{listed}");
    let show = vee()
        .args(["findings", "show", finding_id.as_str(), "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(show.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_matches_schema(
        &shown,
        include_str!("../../../schemas/finding-detail-v2.schema.json"),
        "finding detail",
    );
    assert_eq!(shown["schema_version"], 2);
    assert_eq!(shown["finding"]["occurrence_count"], 1);
    let update = vee()
        .args([
            "findings",
            "set-status",
            finding_id.as_str(),
            "--status",
            "verified",
            "--reason",
            "confirmed in source",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(update.status.code(), Some(0));
    let verified = vee()
        .args([
            "findings", "list", "--status", "verified", "--output", "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let verified_json: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified_json["findings"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn approved_patch_is_digest_gated_and_reruns_the_original_review_scope() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/agent.patch\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "pub fn value() -> i32 { 0 }\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(root.join("src.rs"), "pub fn value() -> i32 { 1 }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let provider = root.join("provider");
    fs::write(
        &provider,
        "#!/bin/sh\nrequest=$(cat)\nif printf '%s' \"$request\" | grep -Fq 'pub fn value() -> i32 { 1 }'; then\n  printf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"The function returns the wrong value.\",\"path\":\"src.rs\",\"line\":1}]}'\nelse\n  printf '%s' '{\"schema_version\":1,\"findings\":[]}'\nfi\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs', '**/*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
        provider.display()
    )).unwrap();

    let review = vee()
        .args([
            "review",
            "--base",
            "HEAD",
            "--reviewer",
            "correctness",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        review.status.success(),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();
    assert_eq!(
        review["findings"].as_array().map(Vec::len),
        Some(1),
        "expected the synthetic defect finding, got: {review}"
    );
    let finding_id = review["findings"][0]["id"].as_str().unwrap();

    let task = vee()
        .args(["findings", "task", finding_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        task.status.success(),
        "{} {}",
        String::from_utf8_lossy(&task.stdout),
        String::from_utf8_lossy(&task.stderr)
    );
    let task: serde_json::Value = serde_json::from_slice(&task.stdout).unwrap();
    assert_eq!(task["finding"]["finding"]["id"], finding_id);
    assert_eq!(
        task["finding"]["finding"]["rationale"],
        "The function returns the wrong value."
    );
    assert!(task["evidence"].as_array().is_some());

    fs::create_dir_all(root.join("tools")).unwrap();
    let patch = root.join("agent.patch");
    fs::write(&patch, "diff --git a/src.rs b/src.rs\n--- a/src.rs\n+++ b/src.rs\n@@ -1 +1 @@\n-pub fn value() -> i32 { 1 }\n+pub fn value() -> i32 { 2 }\n").unwrap();
    let proposed = vee()
        .args(["findings", "propose-patch", "--review", review_id])
        .arg("../agent.patch")
        .args(["--output", "json"])
        .current_dir(root.join("tools"))
        .output()
        .unwrap();
    assert!(
        proposed.status.success(),
        "{} {}",
        String::from_utf8_lossy(&proposed.stdout),
        String::from_utf8_lossy(&proposed.stderr)
    );
    let proposed: serde_json::Value = serde_json::from_slice(&proposed.stdout).unwrap();
    assert_matches_schema(
        &proposed,
        include_str!("../../../schemas/patch-proposal-v1.schema.json"),
        "patch proposal",
    );
    let digest = proposed["patch_digest"].as_str().unwrap();
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 1 }\n"
    );

    let second_review = vee()
        .args([
            "review",
            "--base",
            "HEAD",
            "--reviewer",
            "correctness",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(second_review.status.success());
    let second_review: serde_json::Value = serde_json::from_slice(&second_review.stdout).unwrap();
    assert_ne!(second_review["review_id"], review_id);
    let colliding_proposal = vee()
        .args([
            "findings",
            "propose-patch",
            "--review",
            second_review["review_id"].as_str().unwrap(),
        ])
        .arg("../agent.patch")
        .args(["--output", "json"])
        .current_dir(root.join("tools"))
        .output()
        .unwrap();
    assert_eq!(colliding_proposal.status.code(), Some(2));
    let preserved_proposal: serde_json::Value = serde_json::from_slice(
        &fs::read(
            root.join(".vee/proposals")
                .join(format!("{}.json", &digest[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(preserved_proposal["review_id"], review_id);

    let apply_lock = root.join(".vee/proposals/apply.lock");
    fs::write(&apply_lock, "pid=another-process\n").unwrap();
    let concurrent_apply = vee()
        .args(["findings", "apply-patch", digest, "--approve", digest])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(concurrent_apply.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 1 }\n"
    );
    fs::remove_file(&apply_lock).unwrap();

    let instruction_path = root.join("reviewer.md");
    let original_instructions = fs::read_to_string(&instruction_path).unwrap();
    fs::write(&instruction_path, "The review instructions have changed.\n").unwrap();
    let stale_config = vee()
        .args(["findings", "apply-patch", digest, "--approve", digest])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale_config.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 1 }\n"
    );
    fs::write(&instruction_path, original_instructions).unwrap();

    let rejected = vee()
        .args([
            "findings",
            "apply-patch",
            digest,
            "--approve",
            "sha256:wrong",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(3));
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 1 }\n"
    );

    let applied = vee()
        .args([
            "findings",
            "apply-patch",
            digest,
            "--approve",
            digest,
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["application"], "applied");
    assert_ne!(applied["review"]["review_id"], review_id);
    assert_eq!(applied["review"]["findings"].as_array().unwrap().len(), 0);
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 2 }\n"
    );
    let proposal_record: serde_json::Value = serde_json::from_slice(
        &fs::read(
            root.join(".vee/proposals")
                .join(format!("{}.json", &digest[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(proposal_record["application"], "applied");
    assert_eq!(
        proposal_record["follow_up_review_id"],
        applied["review"]["review_id"]
    );
    let replay = vee()
        .args(["findings", "apply-patch", digest, "--approve", digest])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(root.join("src.rs")).unwrap(),
        "pub fn value() -> i32 { 2 }\n"
    );
}

#[cfg(unix)]
#[test]
fn an_incomplete_follow_up_review_says_why_in_text_output() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/agent.patch\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "pub fn value() -> i32 { 0 }\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(root.join("src.rs"), "pub fn value() -> i32 { 1 }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    // The provider reports a finding on the original change and fails on the
    // patched source, so the follow-up review is incomplete.
    let provider = root.join("provider");
    fs::write(
        &provider,
        "#!/bin/sh\nrequest=$(cat)\nif printf '%s' \"$request\" | grep -Fq 'pub fn value() -> i32 { 1 }'; then\n  printf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"The function returns the wrong value.\",\"path\":\"src.rs\",\"line\":1}]}'\nelse\n  echo 'provider unavailable' >&2\n  exit 1\nfi\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs', '**/*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
        provider.display()
    )).unwrap();

    let review = vee()
        .args(["review", "--base", "HEAD", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        review.status.success(),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();
    fs::write(root.join("agent.patch"), "diff --git a/src.rs b/src.rs\n--- a/src.rs\n+++ b/src.rs\n@@ -1 +1 @@\n-pub fn value() -> i32 { 1 }\n+pub fn value() -> i32 { 2 }\n").unwrap();
    let proposed = vee()
        .args(["findings", "propose-patch", "--review", review_id])
        .arg("agent.patch")
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        proposed.status.success(),
        "{}",
        String::from_utf8_lossy(&proposed.stderr)
    );
    let proposed: serde_json::Value = serde_json::from_slice(&proposed.stdout).unwrap();
    let digest = proposed["patch_digest"].as_str().unwrap();

    let applied = vee()
        .args(["findings", "apply-patch", digest, "--approve", digest])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        applied.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let stdout = String::from_utf8_lossy(&applied.stdout);
    assert!(stdout.contains("▲ incomplete"), "{stdout}");
    assert!(
        stdout.contains("• required review did not complete"),
        "the text output should say why the gate is incomplete: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("correctness") && line.contains("✖ failed")),
        "the text output should name the reviewer to rerun: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn user_provider_config_supplies_repo_reviewer_and_passes_gate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("source.rs"), "fn main() { let _ = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review for defects.\n").unwrap();

    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        r##"#!/bin/sh
cat >/dev/null
printf '%s' '{"schema_version":1,"findings":[]}'
"##,
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();

    fs::write(
        root.join(".vee.yaml"),
        "version: 1\nreviewers:\n  correctness:\n    provider: local-codex\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n",
    )
    .unwrap();
    let user_config_dir = tempfile::tempdir().unwrap();
    let user_config = user_config_dir.path().join("config.yaml");
    fs::write(
        &user_config,
        format!(
            "version: 1\nproviders:\n  local-codex:\n    kind: cli\n    executable: {}\n    egress: local\n",
            provider.display()
        ),
    )
    .unwrap();

    let output = vee()
        .args(["review", "--gate", "--output", "json"])
        .env("VEE_CONFIG", &user_config)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "pass");
    assert_eq!(
        value["selected_reviewers"],
        serde_json::json!(["correctness"])
    );

    let review_id = value["review_id"].as_str().unwrap();
    fs::write(
        &user_config,
        "version: 1\nproviders:\n  local-codex:\n    kind: cli\n    executable: /bin/true\n    egress: local\n",
    )
    .unwrap();
    let check = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .env("VEE_CONFIG", &user_config)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let check_value: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert!(
        check_value["reasons"][0]
            .as_str()
            .unwrap()
            .contains("effective configuration changed"),
        "{check_value}"
    );
}

#[cfg(unix)]
#[test]
fn configured_codex_cli_provider_completes_a_schema_bound_review() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.as_path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { let value = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    let provider = dir.path().join("fake-codex");
    fs::write(
        &provider,
        r##"#!/bin/sh
if [ "$1" = '--version' ]; then printf '%s\n' 'codex-cli 0.99.1-test'; exit 0; fi
schema=''
previous=''
for arg in "$@"; do if [ "$previous" = '--output-schema' ]; then schema="$arg"; fi; previous="$arg"; done
test -f "$schema" || exit 21
cat >/dev/null
printf '%s\n' '{"type":"item.completed","item":{"type":"agent_message","text":"{\"schema_version\":1,\"findings\":[]}"}}' '{"type":"turn.completed","usage":{"input_tokens":40,"output_tokens":8}}'
"##,
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  codex:\n    kind: codex_cli\n    executable: {}\n    model: test-model\nreviewers:\n  correctness:\n    provider: codex\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();

    let output = vee()
        .args(["review", "--working-tree", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["gate"]["status"], "pass");
    assert_eq!(review["schema_version"], 2);
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
    assert_eq!(
        review["reviewer_outcomes"][0]["provider_version"],
        "codex-cli 0.99.1-test"
    );
    assert_eq!(review["reviewer_outcomes"][0]["usage"]["input_tokens"], 40);
    assert_eq!(review["reviewer_outcomes"][0]["usage"]["output_tokens"], 8);
    assert!(review["reviewer_outcomes"][0]["usage"]["total_tokens"].is_null());

    fs::write(
        &provider,
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf '%s\\n' 'codex-cli 0.99.2-test'; exit 0; fi\nexit 90\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let check = vee()
        .args([
            "gate",
            "check",
            "--review",
            review["review_id"].as_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let checked: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(checked["status"], "incomplete");
    assert!(checked["reasons"][0]
        .as_str()
        .unwrap()
        .contains("effective configuration changed"));
}

#[cfg(unix)]
#[test]
fn snapshot_waiver_is_auditable_expires_and_only_applies_to_its_review() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { risky(); }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    let provider = root.join("fake-provider");
    let provider_output = "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"risky call\",\"path\":\"tracked.rs\",\"line\":1}]}'\n";
    fs::write(&provider, provider_output).unwrap();
    let second_provider = root.join("second-fake-provider");
    fs::write(
        &second_provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"critical\",\"confidence\":90,\"rationale\":\"unchecked dangerous call\",\"path\":\"tracked.rs\",\"line\":1}]}'\n",
    )
    .unwrap();
    for executable in [&provider, &second_provider] {
        let mut permissions = fs::metadata(executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(executable, permissions).unwrap();
    }
    fs::write(
        root.join(".vee.yaml"),
        format!("version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\n  second: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n  security: {{ provider: second, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [critical, high]\n  minimum_confidence: 80\npolicy_profiles:\n  strict:\n    required_reviewers: [correctness, security]\n    block_severities: [critical, high]\n    minimum_confidence: 80\n    on_incomplete: block\n", provider.display(), second_provider.display()),
    )
    .unwrap();

    let review_output = vee()
        .args([
            "review",
            "--working-tree",
            "--gate",
            "--policy-profile",
            "strict",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        review_output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&review_output.stdout),
        String::from_utf8_lossy(&review_output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review_output.stdout).unwrap();
    assert_eq!(review["policy_profile"], "strict");
    assert_eq!(
        review["selected_reviewers"],
        serde_json::json!(["correctness", "security"])
    );
    assert_eq!(review["reviewer_outcomes"].as_array().unwrap().len(), 2);
    let review_id = review["review_id"].as_str().unwrap();
    let finding_id = review["findings"][0]["id"].as_str().unwrap();
    assert_eq!(review["findings"].as_array().unwrap().len(), 1);
    assert_eq!(review["findings"][0]["severity"], "critical");
    assert_eq!(review["findings"][0]["confidence"], 90);
    assert!(review["findings"][0]["rationale"]
        .as_str()
        .unwrap()
        .contains("unchecked dangerous call"));

    let sarif = vee()
        .args(["reviews", "export", review_id, "--format", "sarif"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(sarif.status.code(), Some(0));
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        sarif["runs"][0]["results"][0]["partialFingerprints"]["vee/v1"],
        review["findings"][0]["fingerprint"]
    );

    // Waiver text follows the same bounds as every other recorded reason and actor.
    let too_long_author = "a".repeat(201);
    for (reason, author) in [
        ("   ", "maintainer"),
        ("Accepted", ""),
        ("Accepted", too_long_author.as_str()),
    ] {
        let rejected = vee()
            .args([
                "waivers", "create", finding_id, "--review", review_id, "--reason", reason,
                "--author", author,
            ])
            .current_dir(root)
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(3), "{reason:?} / {author:?}");
    }

    let created = vee()
        .args([
            "waivers",
            "create",
            finding_id,
            "--review",
            review_id,
            "--reason",
            "Accepted until the next maintenance window",
            "--author",
            "maintainer@example.invalid",
            "--expires-in-days",
            "2",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let waiver: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let waiver_schema: serde_json::Value = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../schemas/waiver-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&waiver_schema)
        .unwrap()
        .is_valid(&waiver));
    assert_eq!(waiver["snapshot_id"], review["snapshot_id"]);
    assert_eq!(waiver["author"], "maintainer@example.invalid");

    let checked = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        checked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let decision: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_matches_schema(
        &decision,
        include_str!("../../../schemas/gate-check-v1.schema.json"),
        "gate check",
    );
    assert_eq!(decision["status"], "pass");
    assert!(decision["reasons"][0]
        .as_str()
        .unwrap()
        .contains(waiver["id"].as_str().unwrap()));

    let listed = vee()
        .args(["waivers", "list", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0));
    let list: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_matches_schema(
        &list,
        include_str!("../../../schemas/waivers-list-v1.schema.json"),
        "waiver list",
    );
    assert_eq!(list["waivers"][0], waiver);
    let list_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/waivers-list-v1.schema.json")).unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "https://vee.klarlabs.de/schemas/analyzer-report-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/analyzer-report-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vee.klarlabs.de/schemas/waiver-v1.schema.json",
            waiver_schema,
        )
        .unwrap()
        .prepare()
        .unwrap();
    assert!(jsonschema::options()
        .with_registry(&registry)
        .build(&list_schema)
        .unwrap()
        .is_valid(&list));

    fs::write(root.join("tracked.rs"), "fn main() { safer(); }\n").unwrap();
    let stale = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(2));
    let stale_result: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(stale_result["status"], "incomplete");
}

#[cfg(unix)]
#[test]
fn malformed_provider_findings_make_the_gate_incomplete() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn changed() {}\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review changes.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(&provider, "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"id\":\"forged\",\"category\":\"correctness\",\"severity\":\"high\",\"rationale\":\"bug\"}]}'\n").unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!("version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n", provider.display())).unwrap();

    let output = vee()
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["status"], "incomplete");
    assert_eq!(review["findings"].as_array().unwrap().len(), 0);
    assert_eq!(review["reviewer_outcomes"][0]["status"], "invalid_findings");
}

#[cfg(unix)]
#[test]
fn gate_check_rejects_snapshot_after_source_edit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("reviewer.md"), "Review changes.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!("version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n", provider.display())).unwrap();
    let review = vee()
        .arg("review")
        .arg("--gate")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review_json: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review_json["review_id"].as_str().unwrap();
    let first_check = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(first_check.status.code(), Some(0));
    let config_path = root.join(".vee.yaml");
    let config_bytes = fs::read(&config_path).unwrap();
    let changed_config = String::from_utf8(config_bytes.clone())
        .unwrap()
        .replace("minimum_confidence: 80", "minimum_confidence: 79");
    fs::write(&config_path, changed_config).unwrap();
    let config_stale = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(config_stale.status.code(), Some(2));
    let config_stale_json: serde_json::Value =
        serde_json::from_slice(&config_stale.stdout).unwrap();
    assert!(
        config_stale_json["reasons"][0]
            .as_str()
            .unwrap()
            .contains("effective configuration changed"),
        "{config_stale_json}"
    );
    fs::write(&config_path, config_bytes).unwrap();
    fs::write(
        root.join("tracked.rs"),
        "fn main() { let _changed = true; }\n",
    )
    .unwrap();
    let stale_check = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale_check.status.code(), Some(2));
    let stale_json: serde_json::Value = serde_json::from_slice(&stale_check.stdout).unwrap();
    assert_eq!(stale_json["status"], "incomplete");
    assert_ne!(
        stale_json["reviewed_snapshot_id"],
        stale_json["current_snapshot_id"]
    );
}

#[test]
fn staged_snapshot_ignores_unstaged_edits_to_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("file.rs"), "base\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("file.rs"), "staged contents\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    fs::write(root.join("file.rs"), "unstaged contents one\n").unwrap();
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let run_review = || {
        let output = vee()
            .arg("review")
            .arg("--staged")
            .arg("--output")
            .arg("json")
            .current_dir(root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let first = run_review();
    assert_eq!(
        first["change_set"]["files"][0]["content_digest"],
        vee_core::digest(b"staged contents\n")
    );
    fs::write(root.join("file.rs"), "unstaged contents two\n").unwrap();
    let second = run_review();
    assert_eq!(first["snapshot_id"], second["snapshot_id"]);
}

#[test]
fn working_tree_scope_excludes_staged_only_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("staged.rs"), "base\n").unwrap();
    fs::write(root.join("working.rs"), "base\n").unwrap();
    assert!(git(&["add", "."]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("staged.rs"), "staged edit\n").unwrap();
    assert!(git(&["add", "staged.rs"]).status.success());
    fs::write(root.join("working.rs"), "unstaged edit\n").unwrap();
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .arg("review")
        .arg("--working-tree")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let paths: Vec<_> = review["change_set"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"working.rs"));
    assert!(!paths.contains(&"staged.rs"));
}

#[cfg(unix)]
#[test]
fn reviews_list_and_show_return_persisted_review_records() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
    fs::write(root.join("file.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("reviewer.md"), "Review the changed line.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"medium\",\"confidence\":70,\"rationale\":\"Historical query fixture\",\"path\":\"file.rs\",\"line\":1},{\"category\":\"security\",\"severity\":\"low\",\"confidence\":50,\"rationale\":\"A correctness edge case to revisit\",\"path\":\"file.rs\",\"line\":1}]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();
    fs::write(root.join("file.rs"), "fn main() { let x = 1; }\n").unwrap();

    let review = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(review.status.code(), Some(0));
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();
    let context = &review["reviewer_context"][0];
    assert_eq!(context["reviewer_id"], "correctness");
    assert!(context["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| { file["path"] == "file.rs" && file["status"] == "full_source" }));

    let listed = vee()
        .args(["reviews", "list", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        listed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/reviews-list-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&listed));
    assert_eq!(listed["schema_version"], 1);
    assert_eq!(listed["reviews"].as_array().unwrap().len(), 1);
    assert_eq!(listed["reviews"][0]["review_id"], review_id);

    let shown = vee()
        .args(["reviews", "show", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_matches_schema(
        &shown,
        include_str!("../../../schemas/review-output-v2.schema.json"),
        "review detail",
    );
    assert_eq!(shown["review_id"], review_id);
    assert_eq!(shown["snapshot_id"], review["snapshot_id"]);
    assert_eq!(shown["reviewer_context"], review["reviewer_context"]);

    let checked = vee()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        checked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let checked: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();

    let exported = vee()
        .args(["reviews", "export", review_id, "--format", "vee-json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let portable: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_matches_schema(
        &portable,
        include_str!("../../../schemas/review-output-v2.schema.json"),
        "portable review export",
    );

    let bundle_output = vee()
        .args([
            "reviews",
            "bundle",
            review_id,
            "--decision-id",
            checked["decision_id"].as_str().unwrap(),
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        bundle_output.status.success(),
        "{}",
        String::from_utf8_lossy(&bundle_output.stderr)
    );
    let bundle: serde_json::Value = serde_json::from_slice(&bundle_output.stdout).unwrap();
    assert_matches_schema(
        &bundle,
        include_str!("../../../schemas/evidence-bundle-v1.schema.json"),
        "evidence bundle",
    );
    assert_eq!(bundle["manifest"]["snapshot_id"], review["snapshot_id"]);
    assert_eq!(
        bundle["review"]["effective_config_digest"],
        review["effective_config_digest"]
    );
    let bundle_path = root.join("evidence-bundle.json");
    fs::write(&bundle_path, &bundle_output.stdout).unwrap();
    let verified = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        verified.status.code(),
        Some(0),
        "stderr={}; stdout={}",
        String::from_utf8_lossy(&verified.stderr),
        String::from_utf8_lossy(&verified.stdout)
    );
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["valid"], true);
    assert_eq!(verified["signature_valid"], false);
    assert_eq!(verified["replay_status"], "replayed");
    assert_eq!(verified["replay_matches"], true);

    let mut alternate_decision: vee_core::GateDecision =
        serde_json::from_value(review["gate"].clone()).unwrap();
    alternate_decision.decision_id = "sha256:alternate-config-decision".into();
    alternate_decision.effective_config_digest = "sha256:alternate-config".into();
    alternate_decision
        .replay_inputs
        .as_mut()
        .unwrap()
        .policy
        .minimum_confidence = 99;
    let mut store = vee_store_sqlite::ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    store
        .save_gate_decision(review_id, &alternate_decision)
        .unwrap();
    let mismatched_bundle = vee()
        .args(["reviews", "bundle", review_id, "--decision-id"])
        .arg(&alternate_decision.decision_id)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(mismatched_bundle.status.code(), Some(3));
    let mismatch_output = format!(
        "{}{}",
        String::from_utf8_lossy(&mismatched_bundle.stdout),
        String::from_utf8_lossy(&mismatched_bundle.stderr)
    );
    assert!(
        mismatch_output.contains("replay inputs not retained"),
        "{mismatch_output}"
    );

    let mut empty_review_bundle = bundle.clone();
    empty_review_bundle["review"] = serde_json::json!({});
    empty_review_bundle["manifest"] = serde_json::json!({
        "review_digest": vee_core::digest(&serde_json::to_vec(&empty_review_bundle["review"]).unwrap())
    });
    empty_review_bundle["manifest_digest"] = serde_json::json!(vee_core::digest(
        &serde_json::to_vec(&empty_review_bundle["manifest"]).unwrap()
    ));
    fs::write(
        &bundle_path,
        serde_json::to_vec(&empty_review_bundle).unwrap(),
    )
    .unwrap();
    let empty_rejected = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(empty_rejected.status.code(), Some(2));
    let empty_rejected: serde_json::Value = serde_json::from_slice(&empty_rejected.stdout).unwrap();
    assert_eq!(empty_rejected["valid"], false);
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let private_key = root.join("signing-key.der");
    let public_key = root.join("verify-key.bin");
    let generated = vee()
        .args(["reviews", "keygen", "--private-key"])
        .arg(&private_key)
        .args(["--public-key"])
        .arg(&public_key)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let signed = vee()
        .args(["reviews", "sign-bundle"])
        .arg(&bundle_path)
        .args(["--private-key"])
        .arg(&private_key)
        .args(["--key-id", "fixture-key"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let signed_verify = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--public-key"])
        .arg(&public_key)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        signed_verify.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&signed_verify.stdout)
    );
    let signed_verify: serde_json::Value = serde_json::from_slice(&signed_verify.stdout).unwrap();
    assert_eq!(signed_verify["signature_valid"], true);
    let signed_bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(&bundle_path).unwrap()).unwrap();
    assert_eq!(signed_bundle["signature"]["key_id"], "fixture-key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut tampered = signed_bundle;
    tampered["review"]["findings"][0]["rationale"] = serde_json::json!("tampered");
    fs::write(&bundle_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let rejected = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--public-key"])
        .arg(&public_key)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    let rejected: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["valid"], false);

    let mut inconsistent = bundle.clone();
    let original_status = inconsistent["review"]["gate"]["status"].as_str().unwrap();
    let changed_status = if original_status == "pass" {
        "block"
    } else {
        "pass"
    };
    inconsistent["review"]["gate"]["status"] = serde_json::json!(changed_status);
    inconsistent["manifest"]["gate_status"] = serde_json::json!(changed_status);
    inconsistent["manifest"]["review_digest"] = serde_json::json!(vee_core::digest(
        &serde_json::to_vec(&inconsistent["review"]).unwrap()
    ));
    inconsistent["manifest_digest"] = serde_json::json!(vee_core::digest(
        &serde_json::to_vec(&inconsistent["manifest"]).unwrap()
    ));
    fs::write(&bundle_path, serde_json::to_vec(&inconsistent).unwrap()).unwrap();
    let replay_rejected = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(replay_rejected.status.code(), Some(2));
    let replay_rejected: serde_json::Value =
        serde_json::from_slice(&replay_rejected.stdout).unwrap();
    assert_eq!(replay_rejected["valid"], true);
    assert_eq!(replay_rejected["replay_matches"], false);

    let mut mismatched_snapshot = bundle.clone();
    let fake_snapshot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    mismatched_snapshot["review"]["change_set"]["digest"] = serde_json::json!(fake_snapshot);
    mismatched_snapshot["review"]["gate"]["snapshot_id"] = serde_json::json!(fake_snapshot);
    mismatched_snapshot["manifest"]["snapshot_id"] = serde_json::json!(fake_snapshot);
    mismatched_snapshot["manifest"]["review_digest"] = serde_json::json!(vee_core::digest(
        &serde_json::to_vec(&mismatched_snapshot["review"]).unwrap()
    ));
    mismatched_snapshot["manifest_digest"] = serde_json::json!(vee_core::digest(
        &serde_json::to_vec(&mismatched_snapshot["manifest"]).unwrap()
    ));
    fs::write(
        &bundle_path,
        serde_json::to_vec(&mismatched_snapshot).unwrap(),
    )
    .unwrap();
    let snapshot_rejected = vee()
        .args(["reviews", "verify-bundle"])
        .arg(&bundle_path)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(snapshot_rejected.status.code(), Some(2));
    let snapshot_rejected: serde_json::Value =
        serde_json::from_slice(&snapshot_rejected.stdout).unwrap();
    assert_eq!(snapshot_rejected["valid"], false);

    let destination = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(destination.path())
        .status()
        .unwrap()
        .success());
    let transfer = destination.path().join("review.json");
    fs::write(&transfer, &exported.stdout).unwrap();
    let imported = vee()
        .args(["reviews", "import"])
        .arg(&transfer)
        .args(["--output", "json"])
        .current_dir(destination.path())
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
    let imported: serde_json::Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(imported["review_id"], review_id);
    assert_eq!(imported["trust"], "untrusted_external");
    assert_eq!(imported["gate_eligible"], false);
    let local_reviews = vee()
        .args(["reviews", "list", "--output", "json"])
        .current_dir(destination.path())
        .output()
        .unwrap();
    let local_reviews: serde_json::Value = serde_json::from_slice(&local_reviews.stdout).unwrap();
    assert_eq!(local_reviews["reviews"].as_array().unwrap().len(), 0);
    let history = vee()
        .args(["reviews", "imported", "list", "--output", "json"])
        .current_dir(destination.path())
        .output()
        .unwrap();
    assert!(
        history.status.success(),
        "{}",
        String::from_utf8_lossy(&history.stderr)
    );
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(history["reviews"].as_array().unwrap().len(), 1);
    assert_eq!(history["reviews"][0]["gate_eligible"], false);
    let searched = vee()
        .args([
            "reviews",
            "imported",
            "search",
            "correctness",
            "--output",
            "json",
        ])
        .current_dir(destination.path())
        .output()
        .unwrap();
    assert_eq!(
        searched.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&searched.stderr)
    );
    let searched: serde_json::Value = serde_json::from_slice(&searched.stdout).unwrap();
    let search_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/imported-review-search-v3.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&search_schema)
        .unwrap()
        .is_valid(&searched));
    assert_eq!(searched["schema_version"], 3);
    assert_eq!(searched["matches"].as_array().unwrap().len(), 2);
    assert_eq!(searched["matches"][0]["trust"], "untrusted_external");
    assert_eq!(searched["matches"][0]["gate_eligible"], false);
    assert_eq!(searched["matches"][0]["finding"]["category"], "correctness");
    assert_eq!(searched["matches"][0]["relevance_score"], 8);
    assert_eq!(
        searched["matches"][0]["matched_fields"],
        serde_json::json!(["category"])
    );
    assert_eq!(searched["matches"][1]["finding"]["category"], "security");
    assert_eq!(searched["matches"][1]["relevance_score"], 3);
    assert_eq!(searched["trust"], "untrusted_external");
    assert_eq!(searched["gate_eligible"], false);
    let limited = vee()
        .args([
            "reviews",
            "imported",
            "search",
            "correctness",
            "--limit",
            "0",
        ])
        .current_dir(destination.path())
        .output()
        .unwrap();
    assert_ne!(limited.status.code(), Some(0));
    let oversized = destination.path().join("oversized.json");
    fs::write(&oversized, vec![b' '; 10 * 1024 * 1024 + 1]).unwrap();
    let rejected = vee()
        .args(["reviews", "import"])
        .arg(&oversized)
        .current_dir(destination.path())
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("10 MiB limit"));
}

#[cfg(unix)]
#[test]
fn review_import_rejects_fifo_without_blocking() {
    use std::{
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    let directory = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(directory.path())
        .status()
        .unwrap()
        .success());
    let fifo = directory.path().join("review.fifo");
    let path_bytes = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path_bytes.as_ptr(), 0o600) }, 0);
    let mut child = vee()
        .args(["reviews", "import"])
        .arg(&fifo)
        .current_dir(directory.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("importing a FIFO blocked instead of rejecting it");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn mcp_tools_declare_titles_safety_annotations_and_documented_inputs() {
    use std::io::{BufRead, BufReader, Write};

    let directory = tempfile::tempdir().unwrap();
    init_git(directory.path());
    fs::write(directory.path().join("tracked.txt"), "fixture\n").unwrap();
    commit_all(directory.path(), "fixture");
    let mut child = vee()
        .args(["mcp", "serve", "--transport", "stdio"])
        .current_dir(directory.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut exchange = |value: serde_json::Value| {
        writeln!(input, "{}", serde_json::to_string(&value).unwrap()).unwrap();
        input.flush().unwrap();
        if value.get("id").is_none() {
            return serde_json::Value::Null;
        }
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };
    let initialized = exchange(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"vee-contract-test","version":"1"}}
    }));
    let instructions = initialized["result"]["instructions"].as_str().unwrap_or("");
    assert!(
        instructions.contains("evaluate_gate"),
        "server should explain the review workflow to agents: {initialized}"
    );
    exchange(serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
    let listed =
        exchange(serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
    let _ = child.kill();
    let _ = child.wait();

    let tools = listed["result"]["tools"].as_array().unwrap();
    let read_only: std::collections::BTreeSet<&str> = [
        "list_findings",
        "list_reviews",
        "list_finding_feedback",
        "list_verification_runs",
        "get_quality_analytics",
        "get_finding",
        "get_finding_task",
        "get_finding_work_package",
        "search_imported_review_history",
        "list_external_review_feedback",
        "list_rule_candidates",
        "list_rule_approvals",
        "rule_effectiveness",
        "get_review",
        "diagnose_verification",
        "analyze_impact",
        "analyze_cross_repository_impact",
        "acceptance_traceability",
        "get_repository_context",
        "get_applicable_standards",
        "check_setup",
        "recommend_tests",
        "draft_pr_description",
        "resolve_owners",
        "list_waivers",
        "get_gate_history",
        "get_analyzer_findings",
        "list_packs",
    ]
    .into_iter()
    .collect();
    let mut problems = Vec::new();
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        if tool["title"].as_str().is_none_or(str::is_empty) {
            problems.push(format!("{name}: missing title"));
        }
        let annotations = &tool["annotations"];
        match annotations["readOnlyHint"].as_bool() {
            None => problems.push(format!("{name}: missing readOnlyHint")),
            Some(flag) if flag != read_only.contains(name) => {
                problems.push(format!("{name}: readOnlyHint should be {}", !flag))
            }
            Some(false) if annotations["destructiveHint"].as_bool().is_none() => {
                problems.push(format!("{name}: write tool missing destructiveHint"))
            }
            Some(_) => {}
        }
        if annotations["openWorldHint"].as_bool().is_none() {
            problems.push(format!("{name}: missing openWorldHint"));
        }
        let properties = tool["inputSchema"]["properties"].as_object();
        for (property, schema) in properties.into_iter().flatten() {
            if schema["description"].as_str().is_none_or(str::is_empty) {
                problems.push(format!("{name}.{property}: undocumented input"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "MCP tool contract gaps:\n{}",
        problems.join("\n")
    );

    let enum_values = |tool: &str, property: &str| -> Vec<String> {
        let tool = tools.iter().find(|item| item["name"] == tool).unwrap();
        let schema = &tool["inputSchema"];
        let property_schema = &schema["properties"][property];
        let resolved = property_schema["$ref"]
            .as_str()
            .or_else(|| property_schema["anyOf"][0]["$ref"].as_str())
            .and_then(|reference| reference.rsplit('/').next())
            .map(|name| schema["$defs"][name].clone())
            .unwrap_or_else(|| property_schema.clone());
        resolved["enum"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(
        enum_values("review_changes", "scope"),
        ["working_tree", "staged", "base", "commit"]
    );
    assert_eq!(
        enum_values("list_findings", "severity"),
        ["critical", "high", "medium", "low", "info"]
    );
    assert_eq!(
        enum_values("record_finding_feedback", "label"),
        [
            "confirmed",
            "false_positive",
            "actionable",
            "not_actionable"
        ]
    );
}

#[cfg(unix)]
#[test]
fn mcp_stdio_supports_legacy_initialize_and_read_only_tool_calls() {
    use std::io::{BufRead, BufReader, Write};

    let directory = tempfile::tempdir().unwrap();
    init_git(directory.path());
    fs::write(directory.path().join("tracked.txt"), "fixture\n").unwrap();
    commit_all(directory.path(), "fixture");

    let mut child = vee()
        .args(["mcp", "serve", "--transport", "stdio"])
        .current_dir(directory.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let send = |input: &mut std::process::ChildStdin, value: serde_json::Value| {
        writeln!(input, "{}", serde_json::to_string(&value).unwrap()).unwrap();
        input.flush().unwrap();
    };
    let receive = |output: &mut BufReader<std::process::ChildStdout>| {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert!(
            !line.is_empty(),
            "MCP server closed stdout before responding"
        );
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    send(
        &mut input,
        serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize",
            "params":{"protocolVersion":"2025-03-26","capabilities":{},
                "clientInfo":{"name":"vee-legacy-compat-test","version":"1"}}
        }),
    );
    let initialized = receive(&mut output);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-03-26");
    send(
        &mut input,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );
    send(
        &mut input,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let listed = receive(&mut output);
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "list_findings"));

    send(
        &mut input,
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"list_findings","arguments":{"limit":5}}}),
    );
    let called = receive(&mut output);
    assert!(called.get("error").is_none(), "tool call failed: {called}");
    let text = called["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        text, "## Findings (0)\n\n_No findings._\n",
        "the text is the shared view"
    );
    assert_eq!(called["result"]["structuredContent"]["total"], 0);
    assert!(directory.path().join(".vee/vee.sqlite").exists());

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
#[test]
fn sampled_reviewer_merges_runs_and_blocks_only_findings_at_quorum() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/slots/\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(
        root.join("src.rs"),
        "fn a() { 1 }\nfn b() { 2 }\nfn c() { 3 }\nfn d() { 4 }\nfn e() { 5 }\n",
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let slots = root.join("slots");
    fs::create_dir(&slots).unwrap();
    let finding = |rationale: &str, line: u32| {
        format!("{{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"{rationale}\",\"path\":\"src.rs\",\"line\":{line}}}")
    };
    let output = |findings: &[String]| {
        format!(
            "{{\"schema_version\":1,\"findings\":[{}]}}",
            findings.join(",")
        )
    };
    let provider = root.join("provider");
    fs::write(
        &provider,
        format!(
            "#!/bin/sh\ncat >/dev/null\nmktemp {slots}/call.XXXXXX >/dev/null\ncase \"$VEE_SAMPLE_INDEX\" in\n  0) printf '%s' '{first}' ;;\n  1) printf '%s' '{second}' ;;\n  *) printf '%s' '{third}' ;;\nesac\n",
            slots = slots.display(),
            first = output(&[finding("a returns the wrong value", 1), finding("e overflows", 5)]),
            second = output(&[finding("the result of a is wrong", 2)]),
            third = output(&[]),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md, samples: 3 }}\npolicy:\n  block_severities: [high]\n  minimum_confidence: 80\n  required_reviewers: [correctness]\n",
        provider.display()
    )).unwrap();

    let review = vee()
        .args([
            "review",
            "--base",
            "HEAD",
            "--reviewer",
            "correctness",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&review.stdout);
    let stderr = String::from_utf8_lossy(&review.stderr).into_owned();
    let review: serde_json::Value =
        serde_json::from_slice(&review.stdout).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    assert_eq!(
        fs::read_dir(&slots).unwrap().count(),
        3,
        "each sample is a separate provider call; stderr: {stderr}; outcomes: {}",
        review["reviewer_outcomes"]
    );
    let findings = review["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{review}");
    let reported = |finding: &serde_json::Value| finding["sample_agreement"]["reported"].clone();
    let repeated = findings
        .iter()
        .find(|finding| reported(finding) == 2)
        .unwrap_or_else(|| panic!("no finding reported by two samples: {review}"));
    assert_eq!(
        repeated["sample_agreement"],
        serde_json::json!({"reported": 2, "samples": 3, "quorum": 2})
    );
    assert!(
        repeated["line"] == 1 || repeated["line"] == 2,
        "the reports at lines 1 and 2 merge: {review}"
    );
    let single = findings
        .iter()
        .find(|finding| finding["line"] == 5)
        .unwrap_or_else(|| panic!("no finding at line 5: {review}"));
    assert_eq!(reported(single), 1);
    assert_eq!(review["gate"]["status"], "block", "{review}");
    assert_eq!(
        review["gate"]["blocking_findings"],
        serde_json::json!([repeated["id"]]),
        "only the finding at quorum blocks"
    );
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
}

#[cfg(unix)]
#[test]
fn a_failed_sample_fails_the_sampled_reviewer() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/slots/\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(
        root.join("src.rs"),
        "fn a() { 1 }\nfn b() { 2 }\nfn c() { 3 }\nfn d() { 4 }\nfn e() { 5 }\n",
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let slots = root.join("slots");
    fs::create_dir(&slots).unwrap();
    let finding = |rationale: &str, line: u32| {
        format!("{{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"{rationale}\",\"path\":\"src.rs\",\"line\":{line}}}")
    };
    let output = |findings: &[String]| {
        format!(
            "{{\"schema_version\":1,\"findings\":[{}]}}",
            findings.join(",")
        )
    };
    let provider = root.join("provider");
    fs::write(
        &provider,
        format!(
            "#!/bin/sh\ncat >/dev/null\nmktemp {slots}/call.XXXXXX >/dev/null\ncase \"$VEE_SAMPLE_INDEX\" in\n  0) printf '%s' '{first}' ;;\n  1) exit 3 ;;\n  *) printf '%s' '{third}' ;;\nesac\n",
            slots = slots.display(),
            first = output(&[finding("a returns the wrong value", 1), finding("e overflows", 5)]),
            third = output(&[]),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md, samples: 3 }}\npolicy:\n  block_severities: [high]\n  minimum_confidence: 80\n  required_reviewers: [correctness]\n",
        provider.display()
    )).unwrap();

    let review = vee()
        .args([
            "review",
            "--base",
            "HEAD",
            "--reviewer",
            "correctness",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&review.stdout);
    let stderr = String::from_utf8_lossy(&review.stderr).into_owned();
    let review: serde_json::Value =
        serde_json::from_slice(&review.stdout).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    assert_eq!(
        fs::read_dir(&slots).unwrap().count(),
        3,
        "each sample is a separate provider call; stderr: {stderr}; outcomes: {}",
        review["reviewer_outcomes"]
    );
    assert_eq!(
        review["reviewer_outcomes"][0]["status"], "failed",
        "{review}"
    );
    assert_eq!(review["analysis_complete"], false, "{review}");
    assert!(
        review["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["sample_agreement"]["samples"] == 3),
        "agreement counts every configured sample: {review}"
    );
}

#[cfg(unix)]
#[test]
fn review_effort_flag_sets_the_runs_per_reviewer_and_is_recorded_in_the_config_digest() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/calls/\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(root.join("src.rs"), "fn a() { 1 }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let calls = root.join("calls");
    let provider = root.join("provider");
    fs::write(
        &provider,
        format!(
            "#!/bin/sh\ncat >/dev/null\nmktemp {}/call.XXXXXX >/dev/null\nprintf '%s' '{{\"schema_version\":1,\"findings\":[]}}'\n",
            calls.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
        provider.display()
    )).unwrap();
    let review = |effort: Option<&str>| {
        if calls.exists() {
            fs::remove_dir_all(&calls).unwrap();
        }
        fs::create_dir(&calls).unwrap();
        let mut args = vec!["review", "--working-tree", "--output", "json"];
        if let Some(effort) = effort {
            args.extend(["--effort", effort]);
        }
        let output = vee().args(&args).current_dir(root).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (fs::read_dir(&calls).unwrap().count(), review)
    };

    let (plain_calls, plain) = review(None);
    assert_eq!(plain_calls, 1);
    let (medium_calls, medium) = review(Some("medium"));
    assert_eq!(medium_calls, 3);
    let (high_calls, _) = review(Some("high"));
    assert_eq!(high_calls, 5);
    assert_ne!(
        plain["effective_config_digest"], medium["effective_config_digest"],
        "the effort used is part of the recorded configuration"
    );
    assert_eq!(medium["reviewer_outcomes"][0]["status"], "completed");

    let rejected = vee()
        .args(["review", "--working-tree", "--effort", "max"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
}

#[cfg(unix)]
#[test]
fn advisory_reviewer_findings_show_but_block_only_when_a_blocking_reviewer_agrees() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/architecture.md\n/correctness.md\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
    git(&["add", ".gitignore", "src.rs"]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(root.join("src.rs"), "fn a() { 1 }\n").unwrap();
    fs::write(root.join("architecture.md"), "ARCHITECTURE review.\n").unwrap();
    fs::write(root.join("correctness.md"), "CORRECTNESS review.\n").unwrap();
    let finding = "{\"schema_version\":1,\"findings\":[{\"category\":\"maintainability\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"a mixes layers\",\"path\":\"src.rs\",\"line\":1}]}";
    let provider = root.join("provider");
    fs::write(
        &provider,
        format!(
            "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in\n  *ARCHITECTURE*|*AGREES*) printf '%s' '{finding}' ;;\n  *) printf '%s' '{{\"schema_version\":1,\"findings\":[]}}' ;;\nesac\n"
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vee.yaml"), format!(
        "version: 1\nreview:\n  include: ['*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  architecture: {{ provider: fake, instructions_file: architecture.md, advisory: true }}\n  correctness: {{ provider: fake, instructions_file: correctness.md }}\npolicy:\n  block_severities: [high]\n  minimum_confidence: 80\n",
        provider.display()
    )).unwrap();
    let review = || {
        let output = vee()
            .args(["review", "--working-tree", "--output", "json"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let advisory_only = review();
    assert_eq!(advisory_only["gate"]["status"], "pass", "{advisory_only}");
    assert_eq!(advisory_only["findings"].as_array().unwrap().len(), 1);
    assert_eq!(advisory_only["findings"][0]["advisory"], true);

    fs::write(
        root.join("correctness.md"),
        "CORRECTNESS review that AGREES.\n",
    )
    .unwrap();
    let agreed = review();
    assert_eq!(agreed["gate"]["status"], "block", "{agreed}");
    let merged = &agreed["findings"][0];
    assert!(merged.get("advisory").is_none(), "{agreed}");
    assert_eq!(
        merged["reviewer_ids"],
        serde_json::json!(["architecture", "correctness"])
    );
}

#[cfg(unix)]
#[test]
fn changed_files_no_reviewer_received_leave_the_gate_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::create_dir_all(root.join("api")).unwrap();
    fs::create_dir_all(root.join("core")).unwrap();
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/.vee.yaml\n",
    )
    .unwrap();
    fs::write(root.join("api/handler.rs"), "fn h() {}\n").unwrap();
    fs::write(root.join("core/lib.rs"), "fn c() {}\n").unwrap();
    fs::write(root.join("notes.txt"), "outside the review filter\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(root.join("api/handler.rs"), "fn h() { 1 }\n").unwrap();
    fs::write(root.join("core/lib.rs"), "fn c() { 2 }\n").unwrap();
    fs::write(root.join("notes.txt"), "still outside\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let provider = root.join("provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let configure = |extra_policy: &str| {
        fs::write(
            root.join(".vee.yaml"),
            format!(
                "version: 1\nreview:\n  include: ['**/*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  api: {{ provider: fake, instructions_file: reviewer.md, include: ['api/**'] }}\npolicy:\n  required_reviewers: [api]\n{extra_policy}",
                provider.display()
            ),
        )
        .unwrap();
    };
    let review = || {
        vee()
            .args(["review", "--working-tree", "--gate", "--output", "json"])
            .current_dir(root)
            .output()
            .unwrap()
    };

    configure("");
    let output = review();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "incomplete");
    assert_eq!(result["analysis_complete"], false);
    assert_eq!(
        result["unreviewed_paths"],
        serde_json::json!(["core/lib.rs"])
    );
    assert_eq!(result["reviewer_outcomes"][0]["status"], "completed");
    assert_matches_schema(
        &result,
        include_str!("../../../schemas/review-output-v2.schema.json"),
        "review output with unreviewed paths",
    );

    let text = vee()
        .args(["review", "--working-tree"])
        .current_dir(root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("Not reviewed\n"), "{text}");
    assert!(text.contains("• core/lib.rs"), "{text}");
    assert!(text.contains("policy.on_unreviewed: allow"), "{text}");

    configure("  on_unreviewed: allow\n");
    let output = review();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "pass");
    assert_eq!(
        result["unreviewed_paths"],
        serde_json::json!(["core/lib.rs"]),
        "allow still reports what no reviewer saw"
    );

    configure("  on_unreviewed: sometimes\n");
    let rejected = review();
    assert!(!rejected.status.success());
    let reported = format!(
        "{}{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(reported.contains("on_unreviewed"), "{reported}");
}

#[cfg(unix)]
#[test]
fn a_finding_task_shows_the_reviewed_source_after_the_file_changes() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    fs::write(
        root.join(".gitignore"),
        "/.vee/\n/provider\n/reviewer.md\n/.vee.yaml\n",
    )
    .unwrap();
    fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    fs::write(
        root.join("src.rs"),
        "fn a() {}\nfn b() { panic!(\"reviewed\") }\n",
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Review the changed code.\n").unwrap();
    let provider = root.join("provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"b panics.\",\"path\":\"src.rs\",\"line\":2}]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nreview:\n  include: ['*.rs']\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
            provider.display()
        ),
    )
    .unwrap();
    let output = vee()
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding_id = review["findings"][0]["id"].as_str().unwrap().to_owned();

    // The developer fixes the code; the review's snapshot no longer matches.
    fs::write(
        root.join("src.rs"),
        "fn a() {}\nfn b() -> Result<(), ()> { Err(()) }\n",
    )
    .unwrap();
    let output = vee()
        .args(["findings", "task", &finding_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let task: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(task["snapshot_current"], false);
    let content = task["source_context"]["content"]
        .as_str()
        .unwrap_or_default();
    assert!(content.contains("panic!(\"reviewed\")"), "{task}");
    assert!(
        !content.contains("Err(())"),
        "the reviewed source, not the current file: {task}"
    );
    assert!(
        task["context_note"]
            .as_str()
            .unwrap_or_default()
            .contains("kept when the review ran"),
        "{task}"
    );
}

#[test]
fn cross_repository_impact_rejects_unbounded_input_like_the_mcp_tool() {
    let directory = tempfile::tempdir().unwrap();
    let long_base = "b".repeat(257);
    let output = vee()
        .args(["repos", "impact", ".", "consumer", "--base", &long_base])
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("base_ref must contain 1 to 256 characters"),
        "{output:?}"
    );
    let consumers: Vec<String> = (0..129).map(|index| format!("consumer-{index}")).collect();
    let output = vee()
        .args(["repos", "impact", ".", "--base", "main"])
        .args(&consumers)
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("between 1 and 128"),
        "{output:?}"
    );
}
