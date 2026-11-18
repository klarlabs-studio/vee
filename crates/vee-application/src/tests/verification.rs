use super::*;
use std::process::Command;
use vee_core::ports::*;
use vee_store_sqlite::ReviewStore;

#[test]
fn cargo_targeted_verification_requires_a_reported_test_execution() {
    assert!(cargo_output_reports_executed_tests(
            b"running 2 tests\ntest module::wanted ... ok\ntest module::wanted_extra ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored\n",
            b"",
            "wanted"
        ));
    assert!(!cargo_output_reports_executed_tests(
            b"running 2 tests\ntest module::wanted ... ignored\ntest module::wanted_extra ... ok\ntest result: ok. 1 passed; 0 failed; 1 ignored\n",
            b"",
            "wanted"
        ));
    assert!(cargo_output_reports_executed_tests(
            b"running 1 test\ntest module::wanted::case_1 ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            "wanted"
        ));
    assert!(cargo_output_reports_executed_tests(
            b"running 1 test\ntest wanted::case_1 ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            "wanted"
        ));
    assert!(!cargo_output_reports_executed_tests(
            b"running 1 test\ntest module::wanted_extra ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            "wanted"
        ));
    assert!(!cargo_output_reports_executed_tests(
            b"running 1 test\ntest other::checks ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            "affected::checks"
        ));
    assert!(cargo_output_reports_executed_tests(
            b"running 1 test\ntest affected::checks ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            "affected::checks"
        ));
    assert!(!cargo_output_reports_executed_tests(b"", b"", "wanted"));
    assert!(cargo_output_reports_executed_tests(
            b"running 1 test\ntest api_contract ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
            b"",
            ""
        ));
    assert_eq!(
        ensure_cargo_test_output_format(vec![
            "test".into(),
            "--quiet".into(),
            "--".into(),
            "--format=terse".into(),
            "--nocapture".into(),
        ]),
        vec!["test", "--quiet", "--", "--nocapture", "--format=pretty"]
    );
}

#[test]
fn go_targeted_verification_requires_a_test_package_result() {
    let package_a = vec!["./pkg".to_string()];
    let package_a_and_b = vec!["./pkg".to_string(), "./other".to_string()];
    let root_package = Some("example.com/project");
    let hidden_package = vec!["./.internal".to_string()];
    assert!(go_output_reports_executed_tests(
            b"{\"Action\":\"run\",\"Package\":\"example.com/project/.internal\",\"Test\":\"TestRun\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/.internal\",\"Test\":\"TestRun\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/.internal\"}\n",
            b"",
            &hidden_package,
            root_package,
        ));
    assert!(!go_output_reports_executed_tests(
        b"ok\texample.com/project/pkg\t0.003s\n",
        b"",
        &package_a,
        None
    ));
    assert!(!go_output_reports_executed_tests(
        b"ok example.com/project/pkg (cached)\n",
        b"",
        &package_a,
        None
    ));
    assert!(go_output_reports_executed_tests(
            b"{\"Time\":\"2026-11-14T00:00:00Z\",\"Action\":\"run\",\"Package\":\"example.com/project/pkg\",\"Test\":\"TestRun\"}\n{\"Time\":\"2026-11-14T00:00:00Z\",\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Test\":\"TestRun\",\"Elapsed\":0.003}\n{\"Time\":\"2026-11-14T00:00:00Z\",\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Elapsed\":0.003}\n",
            b"",
            &package_a,
            root_package
        ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Test\":\"TestRun\",\"Elapsed\":0.003}\n",
            b"",
            &package_a,
            None
        ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"output\",\"Package\":\"example.com/project/pkg\",\"Output\":\"testing: warning: no tests to run\\n\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Elapsed\":0.003}\n",
            b"",
            &package_a,
            None
        ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"skip\",\"Package\":\"example.com/project/pkg\",\"Test\":\"TestOnlySkipped\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Elapsed\":0.003}\n",
            b"",
            &package_a,
            None
        ));
    assert!(!go_output_reports_executed_tests(
        b"?\texample.com/project/pkg\t[no test files]\n",
        b"",
        &package_a,
        None
    ));
    assert!(!go_output_reports_executed_tests(
        b"ok\texample.com/project/pkg\t0.003s [no tests to run]\n",
        b"",
        &package_a,
        None
    ));
    assert!(!go_output_reports_executed_tests(
        b"ok\texample.com/project/a\t0.003s\n",
        b"",
        &package_a_and_b,
        None
    ));
    assert!(!go_output_reports_executed_tests(
        b"ok\texample.com/project/a\t0.003s\nok\texample.com/project/b\t0.004s\n",
        b"",
        &package_a_and_b,
        None
    ));
    assert!(!go_output_reports_executed_tests(
        b"", b"", &package_a, None
    ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"pass\",\"Package\":\"example.com/project/other\",\"Test\":\"TestOther\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/other\"}\n",
            b"",
            &package_a_and_b,
            None
        ));
    assert!(go_output_reports_executed_tests(
            b"{\"Action\":\"pass\",\"Package\":\"example.com/project\",\"Test\":\"TestRoot\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project\"}\n",
            b"",
            &["./".to_string()],
            root_package
        ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\",\"Test\":\"TestSubpackage\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\"}\n",
            b"",
            &["./".to_string(), "./pkg".to_string()],
            root_package
        ));
    assert!(!go_output_reports_executed_tests(
            b"{\"Action\":\"pass\",\"Package\":\"example.com/project/other/pkg\",\"Test\":\"TestOther\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/other/pkg\"}\n",
            b"",
            &["./pkg".to_string(), "./other/pkg".to_string()],
            root_package
        ));
}

#[test]
fn go_verification_does_not_pass_when_no_tests_ran() {
    assert!(go_test_output_reports_no_tests(
        b"ok\texample.com/project/pkg\t0.003s [no tests to run]\n",
        b""
    ));
    assert!(go_test_output_reports_no_tests(
        b"?\texample.com/project/pkg\t[no test files]\n",
        b""
    ));
    assert!(go_test_output_reports_no_tests(
            b"{\"Action\":\"output\",\"Package\":\"example.com/project/pkg\",\"Output\":\"testing: warning: no tests to run\\n\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/pkg\"}\n",
            b""
        ));
    assert!(!go_test_output_reports_no_tests(
            b"{\"Action\":\"output\",\"Package\":\"example.com/project/empty\",\"Output\":\"testing: warning: no tests to run\\n\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/empty\"}\n{\"Action\":\"run\",\"Package\":\"example.com/project/tests\",\"Test\":\"TestBehavior\"}\n{\"Action\":\"pass\",\"Package\":\"example.com/project/tests\",\"Test\":\"TestBehavior\"}\n",
            b""
        ));
    assert!(!go_test_output_reports_no_tests(
        b"ok\texample.com/project/pkg\t0.003s\n",
        b""
    ));

    let stdout = b"ok\texample.com/project/pkg\t0.003s [no tests to run]\n".to_vec();
    let mut execution = vee_core::VerificationExecution {
        run: VerificationRun {
            schema_version: 1,
            run_id: "old-run-id".into(),
            snapshot_id: "snapshot-id".into(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: vec![],
            command_digest: "command-digest".into(),
            status: vee_core::VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(&stdout),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        },
        stdout,
        stderr: vec![],
    };
    mark_verification_incomplete(
        &mut execution,
        1024,
        "Vee: Go reported that no tests ran for this verification profile.\n",
    )
    .unwrap();
    assert_eq!(
        execution.run.status,
        vee_core::VerificationStatus::Incomplete
    );
    assert_eq!(execution.run.exit_code, Some(2));
    assert_ne!(execution.run.run_id, "old-run-id");
    assert_eq!(execution.run.stderr_digest, digest(&execution.stderr));
}

#[cfg(unix)]
#[test]
fn verification_that_mutates_its_reviewed_snapshot_is_not_saved_as_evidence() {
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
    std::fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn reviewed() {}\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nverification:\n  mutate: { executable: /bin/sh, args: [-c, 'printf changed > source.rs'] }\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let result = run_verification(root, &snapshot, "mutate", &config, &mut store);

    assert!(result
        .unwrap_err()
        .contains("verification changed the reviewed source snapshot"));
    assert!(store
        .verifications_for_snapshot(&snapshot.digest)
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[test]
fn verification_persists_bounded_logs_as_content_addressed_artifacts() {
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
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn reviewed() {}\n").unwrap();
    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nverification:\n  logs: { executable: /bin/sh, args: [-c, 'printf stdout-evidence; printf stderr-evidence >&2'] }\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    let snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let run = run_verification(root, &snapshot, "logs", &config, &mut store).unwrap();

    let stdout = run.stdout_artifact.as_ref().expect("stdout artifact ref");
    let stderr = run.stderr_artifact.as_ref().expect("stderr artifact ref");
    assert_eq!(
        std::fs::read(root.join(&stdout.path)).unwrap(),
        b"stdout-evidence"
    );
    assert_eq!(
        std::fs::read(root.join(&stderr.path)).unwrap(),
        b"stderr-evidence"
    );
    assert_eq!(stdout.digest, run.stdout_digest);
    assert_eq!(stderr.digest, run.stderr_digest);
    assert_eq!(
        store.verification_artifact(&run.run_id, "stdout").unwrap(),
        Some(stdout.clone())
    );
    assert_eq!(
        store.verification_artifact(&run.run_id, "stderr").unwrap(),
        Some(stderr.clone())
    );
}

#[cfg(unix)]
#[test]
fn artifact_persistence_rejects_symlinked_storage_directories() {
    use std::os::unix::fs::symlink;

    let repository = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repository.path().join(".vee")).unwrap();
    symlink(outside.path(), repository.path().join(".vee/artifacts")).unwrap();

    let result = persist_artifact(
        repository.path(),
        b"verification output",
        &digest(b"verification output"),
    );

    assert!(result
        .unwrap_err()
        .contains("artifact directory is not a real directory"));
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn staged_verification_refuses_working_tree_bytes_that_differ_from_the_index() {
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
    git(&["add", "."]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn staged() {}\n").unwrap();
    git(&["add", "source.rs"]);
    let snapshot = capture_change_set(root, vee_git::ChangeScope::Staged).unwrap();
    std::fs::write(root.join("source.rs"), "fn unstaged() {}\n").unwrap();
    let marker = root.join("verification-ran");
    std::fs::write(
            root.join(".vee.yaml"),
            format!("version: 1\nverification:\n  mark: {{ executable: /bin/sh, args: [-c, 'touch {}'] }}\n", marker.display()),
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();

    let result = run_verification(root, &snapshot, "mark", &config, &mut store);

    assert!(result
        .unwrap_err()
        .contains("working tree matching the Git index"));
    assert!(
        !marker.exists(),
        "verification must not run on mismatched bytes"
    );
}
