use std::{fs, process::Command};

fn vero() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vero"))
}

#[test]
fn init_creates_a_loadable_repository_config_and_refuses_to_overwrite_it() {
    let directory = tempfile::tempdir().unwrap();

    let initialized = vero()
        .arg("init")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&initialized.stdout).trim(),
        "Created .vero.yaml"
    );

    let config_path = directory.path().join(".vero.yaml");
    assert!(config_path.is_file());
    let config = vero_application::load_repository_config(directory.path()).unwrap();
    assert_eq!(config.version, 1);
    assert!(config.reviewers.is_empty());
    assert!(config.policy.block_severities.contains(&"high".to_owned()));

    let original = fs::read(&config_path).unwrap();
    let repeated = vero()
        .arg("init")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(repeated.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("already exists"));
    assert_eq!(fs::read(config_path).unwrap(), original);
}

#[test]
fn installed_binary_version_flag_is_a_successful_cli_call() {
    let output = vero().arg("--version").output().unwrap();
    assert!(
        output.status.success(),
        "--version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "vero 0.1.0");
}

#[test]
fn gate_check_rejects_a_passing_review_after_source_changes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
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
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(
        root.join("tracked.rs"),
        "fn main() { let _changed = true; }\n",
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Review the supplied change.\n").unwrap();
    let provider = if cfg!(windows) { "python" } else { "python3" };
    let python_version = Command::new(provider).arg("--version").output().unwrap();
    assert!(
        python_version.status.success(),
        "Python provider unavailable: {}",
        String::from_utf8_lossy(&python_version.stderr)
    );
    let script = root.join("fake_provider.py");
    fs::write(
        &script,
        "import sys\nsys.stdin.read()\nprint('{\"schema_version\":1,\"findings\":[]}')\n",
    )
    .unwrap();
    let script_argument = serde_yaml::to_string(&script.display().to_string()).unwrap();
    fs::write(
        root.join(".vero.yaml"),
        format!(
            "version: 1\nproviders:\n  local:\n    kind: cli\n    egress: local\n    executable: {provider}\n    args: [{script_argument}]\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n"
        ),
    )
    .unwrap();

    let review = vero()
        .args(["review", "--working-tree", "--gate", "--output", "json"])
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
    assert_eq!(review["gate"]["status"], "pass");
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
    let review_id = review["review_id"].as_str().unwrap();

    fs::write(
        root.join("tracked.rs"),
        "fn main() { let _changed = false; }\n",
    )
    .unwrap();
    let check = vero()
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(check["status"], "incomplete");
    assert_ne!(check["reviewed_snapshot_id"], check["current_snapshot_id"]);
    assert!(check["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap().contains("snapshot")));
}
