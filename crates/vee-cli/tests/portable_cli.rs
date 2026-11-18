use std::{fs, process::Command};

mod support;
use support::vee;

/// A machine whose only AI backend is a fake Codex CLI: an isolated user config,
/// a PATH containing just that CLI, and an Ollama port nothing listens on.
#[cfg(unix)]
struct FakeMachine {
    _home: tempfile::TempDir,
    bin: std::path::PathBuf,
    user_config: std::path::PathBuf,
}

#[cfg(unix)]
impl FakeMachine {
    fn with_codex() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let codex = bin.join("codex");
        fs::write(&codex, "#!/bin/sh\necho 'codex-cli 9.9.9'\n").unwrap();
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o755)).unwrap();
        let git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("git"))
            .find(|candidate| candidate.is_file())
            .expect("git is required for Vee");
        std::os::unix::fs::symlink(git, bin.join("git")).unwrap();
        let user_config = home.path().join("vee/config.yaml");
        Self {
            _home: home,
            bin,
            user_config,
        }
    }

    fn repository(&self) -> tempfile::TempDir {
        let repository = tempfile::tempdir().unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(repository.path())
            .status()
            .unwrap();
        assert!(status.success());
        repository
    }

    fn vee(&self, root: &std::path::Path, args: &[&str]) -> std::process::Output {
        vee()
            .args(args)
            .current_dir(root)
            .env("PATH", &self.bin)
            .env("VEE_CONFIG", &self.user_config)
            .env("OLLAMA_HOST", "127.0.0.1:9")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("GEMINI_API_KEY")
            .output()
            .unwrap()
    }
}

#[cfg(unix)]
#[test]
fn init_configures_detected_backend_and_doctor_reports_ready() {
    let machine = FakeMachine::with_codex();
    let repository = machine.repository();
    let root = repository.path();

    let detected = machine.vee(root, &["providers", "detect", "--output", "json"]);
    assert!(
        detected.status.success(),
        "{}",
        String::from_utf8_lossy(&detected.stderr)
    );
    let detected: serde_json::Value = serde_json::from_slice(&detected.stdout).unwrap();
    assert_eq!(detected["recommended"], "codex");
    assert_eq!(detected["candidates"][0]["candidate_id"], "ollama");
    assert_eq!(detected["candidates"][0]["available"], false);

    let initialized = machine.vee(root, &["init", "--output", "json"]);
    assert!(
        initialized.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["candidate_id"], "codex");
    assert_eq!(report["provider_status"], "written");
    assert_eq!(report["repository_config_status"], "written");
    assert!(root.join(".vee.yaml").is_file());
    assert!(root.join(".vee/reviewers/correctness.md").is_file());
    assert!(fs::read_to_string(&machine.user_config)
        .unwrap()
        .contains("codex_cli"));

    let doctor = machine.vee(root, &["doctor", "--output", "json"]);
    let diagnosis: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doctor.status.code(), Some(0), "{diagnosis:#}");
    assert_eq!(diagnosis["ready"], true);
    assert_eq!(diagnosis["reviewers"][0]["reviewer_id"], "correctness");
    assert_eq!(diagnosis["reviewers"][0]["kind"], "codex_cli");
    assert_eq!(diagnosis["reviewers"][0]["detail"], "codex-cli 9.9.9");

    let original = fs::read(root.join(".vee.yaml")).unwrap();
    let repeated = machine.vee(root, &["init"]);
    assert_eq!(repeated.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("already set up"));
    assert_eq!(fs::read(root.join(".vee.yaml")).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn init_without_any_backend_explains_options_and_writes_nothing() {
    let machine = FakeMachine::with_codex();
    fs::remove_file(machine.bin.join("codex")).unwrap();
    let repository = machine.repository();
    let output = machine.vee(repository.path(), &["init"]);
    assert_eq!(output.status.code(), Some(3));
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("no AI backend found"), "{message}");
    assert!(!repository.path().join(".vee.yaml").exists());
    assert!(!machine.user_config.exists());

    let doctor = machine.vee(repository.path(), &["doctor"]);
    assert_eq!(doctor.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("Run `vee init`"));
}

#[test]
fn installed_binary_version_flag_is_a_successful_cli_call() {
    let output = vee().arg("--version").output().unwrap();
    assert!(
        output.status.success(),
        "--version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "vee 0.1.0");
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
    assert!(git(&["config", "user.email", "vee@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vee test"]).status.success());
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
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  local:\n    kind: cli\n    egress: local\n    executable: {provider}\n    args: [{script_argument}]\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n"
        ),
    )
    .unwrap();

    let review = vee()
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
    let check = vee()
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
