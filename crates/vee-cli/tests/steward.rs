//! `vee steward` end to end, with a fake reviewer model (ADR 0042).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn vee() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vee"));
    command.env("NO_COLOR", "1").env_remove("VEE_HOSTING_HOSTS");
    command
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// How the fake model answers a request to fix a problem.
#[derive(Clone, Copy)]
enum FixAnswer {
    /// Replace `BUG` with `fixed()`, which the review accepts.
    Good,
    /// Rename the function and leave `BUG`, which the review still reports.
    Useless,
}

struct Repository {
    _outside: tempfile::TempDir,
    directory: tempfile::TempDir,
}

impl Repository {
    fn root(&self) -> &Path {
        self.directory.path()
    }

    /// A repository whose `main` has `src/lib.rs`, with `feature` checked out.
    /// `extra_config` is appended to `.vee.yaml`; `verify` adds a required
    /// verification profile that always passes.
    fn new(answer: FixAnswer, verify: bool) -> Self {
        let outside = tempfile::tempdir().unwrap();
        let provider = outside.path().join("provider");
        let (old, new) = match answer {
            FixAnswer::Good => ("BUG", "fixed()"),
            FixAnswer::Useless => ("changed", "renamed"),
        };
        std::fs::write(
            &provider,
            format!(
                "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in\n  *'Git merge conflicts'*)\n    printf '%s' '{{\"schema_version\":1,\"summary\":\"Kept both functions.\",\"resolved\":true,\"content\":\"pub fn changed() {{}}\\npub fn other() {{}}\\n\"}}' ;;\n  *'Fix the supplied problem'*)\n    printf '{{\"schema_version\":1,\"summary\":\"Use the result.\",\"edits\":[{{\"old\":\"{old}\",\"new\":\"{new}\"}}]}}' ;;\n  *BUG*) printf '%s' '{{\"schema_version\":1,\"findings\":[{{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":90,\"rationale\":\"BUG drops the result.\",\"path\":\"src/lib.rs\",\"line\":1}}]}}' ;;\n  *) printf '%s' '{{\"schema_version\":1,\"findings\":[]}}' ;;\nesac\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
        let check = outside.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        git(root, &["init", "-q", "-b", "main"]);
        git(root, &["config", "user.name", "Vee test"]);
        git(root, &["config", "user.email", "vee@example.invalid"]);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
        std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
        std::fs::write(root.join(".gitignore"), ".vee/\n").unwrap();
        let verification = if verify {
            format!(
                "verification:\n  check: {{ executable: {} }}\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [check]\n",
                check.display()
            )
        } else {
            String::new()
        };
        std::fs::write(
            root.join(".vee.yaml"),
            format!(
                "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n{verification}",
                provider.display()
            ),
        )
        .unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "base"]);
        git(root, &["checkout", "-q", "-b", "feature"]);
        Self {
            _outside: outside,
            directory,
        }
    }

    fn commit(&self, content: &str, message: &str) -> String {
        std::fs::write(self.root().join("src/lib.rs"), content).unwrap();
        git(self.root(), &["commit", "-qam", message]);
        git(self.root(), &["rev-parse", "HEAD"])
    }

    /// Move `main` on with a change to the same line, so merging conflicts.
    fn conflicting_main(&self) {
        git(self.root(), &["checkout", "-q", "main"]);
        self.commit("pub fn other() {}\n", "main moves on");
        git(self.root(), &["checkout", "-q", "feature"]);
    }

    fn steward(&self) -> (Option<i32>, serde_json::Value, String) {
        let output = vee()
            .args(["steward", "--base", "main", "--output", "json"])
            .current_dir(self.root())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "exit {:?}\nstdout: {}\nstderr: {stderr}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout)
            )
        });
        (output.status.code(), report, stderr)
    }
}

#[test]
fn the_steward_keeps_a_fix_the_review_accepts() {
    let repository = Repository::new(FixAnswer::Good, false);
    let start = repository.commit("pub fn changed() { BUG }\n", "change");
    let (code, report, stderr) = repository.steward();
    assert_eq!(code, Some(0), "{report:#}\n{stderr}");
    assert_eq!(report["gate"], "pass");
    assert_eq!(report["start_head"], start);
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "{report:#}");
    assert_eq!(steps[0]["kind"], "finding");
    assert_eq!(steps[0]["kept"], true);
    let head = git(repository.root(), &["rev-parse", "HEAD"]);
    assert_eq!(report["head"], head);
    assert_eq!(steps[0]["commit"], head);
    assert_eq!(steps[0]["undo"], format!("git revert {head}"));
    assert_eq!(
        std::fs::read_to_string(repository.root().join("src/lib.rs")).unwrap(),
        "pub fn changed() { fixed() }\n"
    );
    let message = git(repository.root(), &["log", "-1", "--format=%B"]);
    assert!(message.contains("Vee-Steward: finding find_"), "{message}");
    assert!(
        message.contains("the person who ran `vee steward`"),
        "{message}"
    );
    // Nothing was pushed: the branch has no upstream to push to.
    assert_eq!(report["pushed"], false);
}

#[test]
fn the_steward_undoes_a_fix_that_does_not_solve_the_problem() {
    let repository = Repository::new(FixAnswer::Useless, false);
    let start = repository.commit("pub fn changed() { BUG }\n", "change");
    let (code, report, _) = repository.steward();
    assert_eq!(code, Some(1), "{report:#}");
    assert_eq!(report["head"], start);
    let step = &report["steps"][0];
    assert_eq!(step["kept"], false);
    assert!(
        step["summary"]
            .as_str()
            .unwrap()
            .contains("but Vee did not keep it"),
        "{report:#}"
    );
    assert_eq!(git(repository.root(), &["rev-parse", "HEAD"]), start);
    assert_eq!(
        git(
            repository.root(),
            &["status", "--porcelain", "--untracked-files=no"]
        ),
        ""
    );
}

#[test]
fn the_steward_leaves_an_unverifiable_conflict_to_a_person() {
    let repository = Repository::new(FixAnswer::Good, false);
    let start = repository.commit("pub fn changed() {}\n", "change");
    repository.conflicting_main();
    let (_, report, _) = repository.steward();
    let step = &report["steps"][0];
    assert_eq!(step["kind"], "merge_conflict", "{report:#}");
    assert_eq!(step["kept"], false);
    assert!(
        step["summary"]
            .as_str()
            .unwrap()
            .contains("a person resolves"),
        "{report:#}"
    );
    assert_eq!(git(repository.root(), &["rev-parse", "HEAD"]), start);
    assert!(!repository.root().join(".git/MERGE_HEAD").exists());
}

#[test]
fn the_steward_resolves_a_conflict_that_verification_checks() {
    let repository = Repository::new(FixAnswer::Good, true);
    repository.commit("pub fn changed() {}\n", "change");
    repository.conflicting_main();
    let (code, report, stderr) = repository.steward();
    let step = &report["steps"][0];
    assert_eq!(step["kind"], "merge_conflict", "{report:#}\n{stderr}");
    assert_eq!(step["kept"], true, "{report:#}\n{stderr}");
    assert_eq!(code, Some(0), "{report:#}");
    let head = git(repository.root(), &["rev-parse", "HEAD"]);
    assert_eq!(step["undo"], format!("git revert -m 1 {head}"));
    // A merge commit: the change and main.
    assert_eq!(
        git(
            repository.root(),
            &["rev-list", "--parents", "-n", "1", "HEAD"]
        )
        .split_whitespace()
        .count(),
        3
    );
    assert_eq!(
        std::fs::read_to_string(repository.root().join("src/lib.rs")).unwrap(),
        "pub fn changed() {}\npub fn other() {}\n"
    );
}

#[test]
fn the_steward_refuses_uncommitted_changes() {
    let repository = Repository::new(FixAnswer::Good, false);
    repository.commit("pub fn changed() { BUG }\n", "change");
    std::fs::write(repository.root().join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let output = vee()
        .args(["steward", "--base", "main"])
        .current_dir(repository.root())
        .output()
        .unwrap();
    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("commit or stash your changes first"));
}
