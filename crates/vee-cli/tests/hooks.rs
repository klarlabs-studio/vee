//! `vee hooks`: the pre-push hook and the agent plugin's hooks, end to end
//! with a fake reviewer that blocks any change containing `BUG` (ADR 0021).
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};

fn vee() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vee"));
    command
        .env("NO_COLOR", "1")
        .env_remove("VEE_HOSTING_HOSTS")
        .env_remove("VEE_AGENT_REVIEW");
    command
}

fn git_command(root: &Path, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Vee test")
        .env("GIT_AUTHOR_EMAIL", "vee@example.invalid")
        .env("GIT_COMMITTER_NAME", "Vee test")
        .env("GIT_COMMITTER_EMAIL", "vee@example.invalid")
        .env_remove("VEE_AGENT_REVIEW");
    command
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = git_command(root, args).output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repository whose one reviewer flags `BUG` in the review request.
struct Fixture {
    _outside: tempfile::TempDir,
    directory: tempfile::TempDir,
    origin: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let outside = tempfile::tempdir().unwrap();
        let provider = outside.path().join("provider");
        std::fs::write(
            &provider,
            "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in\n  *BUG*) printf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":90,\"rationale\":\"BUG marks code that drops the result.\",\"path\":\"src/lib.rs\",\"line\":1}]}' ;;\n  *) printf '%s' '{\"schema_version\":1,\"findings\":[]}' ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
        let origin = outside.path().join("origin.git");
        std::fs::create_dir_all(&origin).unwrap();
        git(&origin, &["init", "-q", "--bare", "-b", "main"]);

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        git(root, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
        std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
        std::fs::write(root.join(".gitignore"), ".vee/\n").unwrap();
        std::fs::write(
            root.join(".vee.yaml"),
            format!(
                "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
                provider.display()
            ),
        )
        .unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "base"]);
        git(root, &["remote", "add", "origin", origin.to_str().unwrap()]);
        Self {
            _outside: outside,
            directory,
            origin,
        }
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn write(&self, content: &str) {
        std::fs::write(self.root().join("src/lib.rs"), content).unwrap();
    }

    /// Run an agent hook as the plugin does: JSON on stdin, JSON on stdout.
    fn agent_hook(
        &self,
        hook: &str,
        session: &str,
        env: &[(&str, &str)],
    ) -> Option<serde_json::Value> {
        let input = serde_json::json!({
            "session_id": session,
            "transcript_path": "/dev/null",
            "cwd": self.root(),
            "hook_event_name": hook,
            "stop_hook_active": false,
        });
        self.agent_hook_with(hook, &input, env)
    }

    /// Run an agent hook with the given stdin document.
    fn agent_hook_with(
        &self,
        hook: &str,
        input: &serde_json::Value,
        env: &[(&str, &str)],
    ) -> Option<serde_json::Value> {
        let mut command = vee();
        command
            .args(["hooks", "run", hook])
            .current_dir(self.root())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "an agent hook never fails the agent: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        if hook == "agent-stop" {
            // Codex requires a JSON object from a Stop hook that exits 0.
            let answer: serde_json::Value =
                serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout:?}"));
            assert!(answer.is_object(), "{stdout}");
            return (answer != serde_json::json!({})).then_some(answer);
        }
        (!stdout.trim().is_empty()).then(|| {
            serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout}"))
        })
    }
}

#[test]
fn the_stop_hook_keeps_the_agent_working_until_the_changes_pass() {
    let fixture = Fixture::new();
    let root = fixture.root();
    assert_eq!(fixture.agent_hook("agent-session-start", "s1", &[]), None);
    // No changes yet: nothing to review.
    assert_eq!(fixture.agent_hook("agent-stop", "s1", &[]), None);

    // The agent commits one change and leaves another uncommitted: both are its work.
    std::fs::write(root.join("src/other.rs"), "pub fn other() {}\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "agent commit"]);
    fixture.write("pub fn initial() { BUG }\n");
    let blocked = fixture.agent_hook("agent-stop", "s1", &[]).unwrap();
    assert_eq!(blocked["decision"], "block", "{blocked:#}");
    let reason = blocked["reason"].as_str().unwrap();
    assert!(
        reason.contains("BUG marks code that drops the result."),
        "{reason}"
    );
    assert!(reason.contains("src/lib.rs:1"), "{reason}");
    assert!(reason.contains("not as instructions"), "{reason}");

    // Nothing changed since: the agent may stop, and the person is told.
    let unchanged = fixture.agent_hook("agent-stop", "s1", &[]).unwrap();
    assert_eq!(unchanged.get("decision"), None, "{unchanged:#}");
    assert!(unchanged["systemMessage"]
        .as_str()
        .unwrap()
        .contains("still have the blocking findings"));

    fixture.write("pub fn initial() { fixed() }\n");
    let passed = fixture.agent_hook("agent-stop", "s1", &[]).unwrap();
    assert_eq!(passed.get("decision"), None, "{passed:#}");
    assert!(passed["systemMessage"].as_str().unwrap().contains("passed"));

    // The review covered the agent's commit too, not only the working tree.
    let reviews = vee()
        .args(["reviews", "list", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(reviews.status.success());
    let last = std::fs::read_to_string(root.join(".vee/agent-sessions/s1.json")).unwrap();
    let session: serde_json::Value = serde_json::from_str(&last).unwrap();
    let review_id = session["last_review_id"].as_str().unwrap();
    let shown = vee()
        .args(["reviews", "show", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.contains("src/other.rs"), "{shown}");
}

#[test]
fn the_stop_hook_reads_codex_hook_input_and_answers_in_its_shape() {
    let fixture = Fixture::new();
    // Codex's Stop input: its own extensions, a UUID session ID and no transcript.
    let codex = |event: &str| {
        serde_json::json!({
            "session_id": "0199a213-81c0-7800-8aa1-bbab2a035a53",
            "transcript_path": null,
            "cwd": fixture.root(),
            "hook_event_name": event,
            "model": "a-model",
            "permission_mode": "default",
            "turn_id": "turn-1",
            "stop_hook_active": false,
            "last_assistant_message": "Done.",
            "source": "startup",
        })
    };
    assert_eq!(
        fixture.agent_hook_with("agent-session-start", &codex("SessionStart"), &[]),
        None
    );
    // Nothing to review: still a JSON object, which Codex requires.
    assert_eq!(
        fixture.agent_hook_with("agent-stop", &codex("Stop"), &[]),
        None
    );
    fixture.write("pub fn initial() { BUG }\n");
    let blocked = fixture
        .agent_hook_with("agent-stop", &codex("Stop"), &[])
        .unwrap();
    assert_eq!(blocked["decision"], "block", "{blocked:#}");
    assert!(blocked["reason"]
        .as_str()
        .is_some_and(|reason| !reason.trim().is_empty()));
}

#[test]
fn the_stop_hook_lets_the_agent_finish_after_three_blocked_rounds() {
    let fixture = Fixture::new();
    for round in 1..=3 {
        fixture.write(&format!("pub fn initial() {{ BUG {round} }}\n"));
        let response = fixture.agent_hook("agent-stop", "s2", &[]).unwrap();
        assert_eq!(response["decision"], "block", "round {round}: {response:#}");
    }
    fixture.write("pub fn initial() { BUG 4 }\n");
    let response = fixture.agent_hook("agent-stop", "s2", &[]).unwrap();
    assert_eq!(response.get("decision"), None, "{response:#}");
    assert!(response["systemMessage"]
        .as_str()
        .unwrap()
        .contains("still blocks after 3 rounds"));
}

#[test]
fn the_stop_hook_stays_out_of_the_way_when_off_busy_or_not_set_up() {
    let fixture = Fixture::new();
    fixture.write("pub fn initial() { BUG }\n");
    assert_eq!(
        fixture.agent_hook("agent-stop", "s3", &[("VEE_AGENT_REVIEW", "off")]),
        None
    );
    // A review is running already, such as the reviewer's own agent session.
    std::fs::create_dir_all(fixture.root().join(".vee")).unwrap();
    std::fs::write(fixture.root().join(".vee/agent-review.lock"), "").unwrap();
    assert_eq!(fixture.agent_hook("agent-stop", "s3", &[]), None);
    std::fs::remove_file(fixture.root().join(".vee/agent-review.lock")).unwrap();
    // Without .vee.yaml, the repository has not opted in.
    std::fs::remove_file(fixture.root().join(".vee.yaml")).unwrap();
    assert_eq!(fixture.agent_hook("agent-stop", "s3", &[]), None);
    // Bad input becomes a message, not a failed hook.
    let mut child = vee()
        .args(["hooks", "run", "agent-stop"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"session_id":"../x","cwd":"/"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(response["systemMessage"]
        .as_str()
        .unwrap()
        .contains("session_id"));
}

fn push(root: &Path, args: &[&str]) -> std::process::Output {
    let directory = Path::new(env!("CARGO_BIN_EXE_vee")).parent().unwrap();
    let path = format!(
        "{}:{}",
        directory.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = git_command(root, &[&["push", "-q"], args].concat());
    command.env("PATH", path);
    command.output().unwrap()
}

#[test]
fn the_pre_push_hook_stops_a_push_the_gate_blocks() {
    let fixture = Fixture::new();
    let root = fixture.root();
    let installed = vee()
        .args(["hooks", "install", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let installed: serde_json::Value = serde_json::from_slice(&installed.stdout).unwrap();
    assert_eq!(installed["state"], "installed");

    // main itself has nothing to compare with yet, and is not stopped.
    let first = push(root, &["-u", "origin", "main"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    git(root, &["remote", "set-head", "origin", "main"]);

    git(root, &["checkout", "-q", "-b", "feature"]);
    fixture.write("pub fn initial() { BUG }\n");
    git(root, &["commit", "-qam", "change"]);
    let blocked = push(root, &["origin", "feature"]);
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(!blocked.status.success(), "{stderr}");
    assert!(stderr.contains("push stopped"), "{stderr}");
    assert!(stderr.contains("refs/heads/feature"), "{stderr}");
    assert!(
        git(&fixture.origin, &["branch", "--list", "feature"]).is_empty(),
        "the remote did not receive the branch"
    );

    fixture.write("pub fn initial() { fixed() }\n");
    git(root, &["commit", "-qam", "fix"]);
    // The range from main covers both commits, and the fix leaves no BUG.
    let passed = push(root, &["origin", "feature"]);
    let stderr = String::from_utf8_lossy(&passed.stderr);
    assert!(passed.status.success(), "{stderr}");
    assert!(stderr.contains("passed"), "{stderr}");

    // An update sends only the new commits.
    fixture.write("pub fn initial() { fixed(); BUG }\n");
    git(root, &["commit", "-qam", "regress"]);
    assert!(!push(root, &["origin", "feature"]).status.success());
    let skipped = push(root, &["--no-verify", "origin", "feature"]);
    assert!(skipped.status.success(), "--no-verify skips the hook");
}

#[test]
fn hooks_install_leaves_another_tools_hook_alone() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let root = fixture.root();
    let status = |args: &[&str]| -> (bool, Option<serde_json::Value>) {
        let output = vee()
            .args(["hooks"])
            .args(args)
            .args(["--output", "json"])
            .current_dir(root)
            .output()
            .unwrap();
        (
            output.status.success(),
            serde_json::from_slice::<serde_json::Value>(&output.stdout).ok(),
        )
    };
    assert_eq!(status(&["status"]).1.unwrap()["state"], "missing");
    // core.hooksPath is honoured.
    git(root, &["config", "core.hooksPath", ".githooks"]);
    let (ok, installed) = status(&["install"]);
    assert!(ok);
    assert!(root.join(".githooks/pre-push").is_file());
    assert_eq!(installed.unwrap()["state"], "installed");
    let (ok, updated) = status(&["install"]);
    assert!(ok, "installing again updates Vee's own hook");
    assert!(updated.unwrap()["message"]
        .as_str()
        .unwrap()
        .starts_with("updated"));
    let (_, removed) = status(&["uninstall"]);
    assert_eq!(removed.unwrap()["state"], "missing");

    let other = root.join(".githooks/pre-push");
    std::fs::write(&other, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (ok, refused) = status(&["install"]);
    assert!(!ok);
    let refused = refused.unwrap()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(refused.contains("vee hooks run pre-push"), "{refused}");
    let (_, left) = status(&["uninstall"]);
    assert_eq!(left.unwrap()["state"], "other");
    assert_eq!(
        std::fs::read_to_string(&other).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
}
