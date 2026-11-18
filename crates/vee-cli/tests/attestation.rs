//! In-toto attestations of gate decisions: commit binding, DSSE signing, and
//! verification with the published schemas.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;
use support::vee as vee_command;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn vee(root: &Path, args: &[&str]) -> Output {
    vee_command().args(args).current_dir(root).output().unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "not JSON ({error}): {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_schema(document: &Value, name: &str) {
    let schemas = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
    let mut registry = jsonschema::Registry::new();
    for entry in fs::read_dir(&schemas).unwrap() {
        let schema: Value =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();
        if let Some(id) = schema["$id"].as_str() {
            registry = registry.add(id, schema.clone()).unwrap();
        }
    }
    let registry = registry.prepare().unwrap();
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(schemas.join(format!("{name}.schema.json"))).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::options()
        .offline()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{name}: {errors:#?}\n{document:#}");
}

struct Repository {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

fn repository() -> Repository {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_path_buf();
    git(&root, &["init", "-q"]);
    let provider = root.join("provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("reviewer.md"), "Review.\n").unwrap();
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  p:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n",
            provider.display()
        ),
    )
    .unwrap();
    fs::write(root.join("lib.rs"), "pub fn a() {}\n").unwrap();
    git(&root, &["add", "."]);
    git(&root, &["commit", "-qm", "baseline"]);
    Repository {
        _directory: directory,
        root,
    }
}

#[test]
fn a_commit_review_attestation_binds_the_commit_and_verifies() {
    let repository = repository();
    let root = &repository.root;
    fs::write(root.join("lib.rs"), "pub fn a() -> u8 { 1 }\n").unwrap();
    git(root, &["commit", "-qam", "change"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    let review = json(&vee(
        root,
        &["review", "--commit", &head, "--gate", "--output", "json"],
    ));
    assert_eq!(review["gate"]["status"], "pass", "{review:#}");
    let review_id = review["review_id"].as_str().unwrap();

    let statement = vee(
        root,
        &["reviews", "attest", review_id, "--format", "statement"],
    );
    assert!(statement.status.success());
    let statement = json(&statement);
    assert_schema(&statement, "review-gate-attestation-v1");
    assert_eq!(
        statement["subject"][0]["digest"]["gitCommit"],
        head.as_str()
    );
    assert_eq!(
        statement["subject"][1]["digest"]["sha256"],
        review["snapshot_id"]
            .as_str()
            .unwrap()
            .trim_start_matches("sha256:")
    );
    assert_eq!(
        statement["predicate"]["decision"]["decision_id"],
        review["gate"]["decision_id"]
    );

    let keys = tempfile::tempdir().unwrap();
    let private_key = keys.path().join("key.pk8");
    let public_key = keys.path().join("key.pub");
    assert!(vee(
        root,
        &[
            "reviews",
            "keygen",
            "--private-key",
            private_key.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap()
        ]
    )
    .status
    .success());
    // DSSE needs a key; the requirement is enforced by the CLI.
    assert_eq!(
        vee(root, &["reviews", "attest", review_id]).status.code(),
        Some(3)
    );

    let envelope = vee(
        root,
        &[
            "reviews",
            "attest",
            review_id,
            "--private-key",
            private_key.to_str().unwrap(),
            "--key-id",
            "ci-2026",
        ],
    );
    assert!(
        envelope.status.success(),
        "{}",
        String::from_utf8_lossy(&envelope.stderr)
    );
    let envelope_path = keys.path().join("attestation.json");
    fs::write(&envelope_path, &envelope.stdout).unwrap();
    assert_eq!(
        json(&envelope)["payloadType"],
        "application/vnd.in-toto+json"
    );

    let verified = vee(
        root,
        &[
            "reviews",
            "verify-attestation",
            envelope_path.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
            "--output",
            "json",
        ],
    );
    assert_eq!(verified.status.code(), Some(0));
    let verified = json(&verified);
    assert_schema(&verified, "attestation-verification-v1");
    assert_eq!(verified["key_id"], "ci-2026");
    assert_eq!(verified["gate_status"], "pass");
    assert_eq!(verified["statement"], statement);

    // Any edit to the signed envelope fails verification.
    let mut tampered = json(&envelope);
    tampered["payload"] = Value::from(tampered["payload"].as_str().unwrap().replacen('e', "f", 1));
    fs::write(&envelope_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let rejected = vee(
        root,
        &[
            "reviews",
            "verify-attestation",
            envelope_path.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
            "--output",
            "json",
        ],
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(json(&rejected)["valid"], false);
}

#[test]
fn an_uncommitted_review_attests_only_the_snapshot() {
    let repository = repository();
    let root = &repository.root;
    fs::write(root.join("lib.rs"), "pub fn a() -> u8 { 2 }\n").unwrap();
    let review = json(&vee(
        root,
        &["review", "--working-tree", "--gate", "--output", "json"],
    ));
    let statement = json(&vee(
        root,
        &[
            "reviews",
            "attest",
            review["review_id"].as_str().unwrap(),
            "--format",
            "statement",
        ],
    ));
    assert_schema(&statement, "review-gate-attestation-v1");
    let subjects = statement["subject"].as_array().unwrap();
    assert_eq!(
        subjects.len(),
        1,
        "an uncommitted snapshot is not a commit: {statement:#}"
    );
    assert!(subjects[0]["digest"]["gitCommit"].is_null());
}
