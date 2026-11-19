//! Policy packs: export from one repository, pin into another, and enforce the
//! pack's reviewers, rules, and policy there. A changed pack fails closed.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;
use support::vee as vee_command;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee@example.invalid",
        ])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

struct Machine {
    _home: tempfile::TempDir,
    user_config: PathBuf,
}

/// A user config whose `default` provider emits a high-confidence finding only
/// when the pack's approved rule reaches the prompt.
fn machine() -> Machine {
    let home = tempfile::tempdir().unwrap();
    let provider = home.path().join("provider");
    fs::write(
        &provider,
        concat!(
            "#!/bin/sh\ninput=$(cat)\n",
            "case \"$input\" in\n",
            "  *'Never call unwrap in library code'*) printf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":75,\"rationale\":\"unwrap in library code\",\"path\":\"src/lib.rs\",\"line\":1}]}' ;;\n",
            "  *) printf '%s' '{\"schema_version\":1,\"findings\":[]}' ;;\n",
            "esac\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o755)).unwrap();
    let user_config = home.path().join("config.yaml");
    fs::write(
        &user_config,
        format!(
            "version: 1\nproviders:\n  default:\n    kind: cli\n    executable: {}\n",
            provider.display()
        ),
    )
    .unwrap();
    Machine {
        _home: home,
        user_config,
    }
}

fn vee(machine: &Machine, root: &Path, args: &[&str]) -> (Option<i32>, Value) {
    let output = vee_command()
        .args(args)
        .args(["--output", "json"])
        .env("VEE_CONFIG", &machine.user_config)
        .current_dir(root)
        .output()
        .unwrap();
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "vee {args:?} did not print JSON ({error}): {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), document)
}

fn repository(config: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    fs::write(root.join(".vee.yaml"), config).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "baseline"]);
    directory
}

const RULE: &str = r#"
  - schema_version: 2
    approval_id: rule_no_unwrap
    version: 1
    candidate_id: candidate_no_unwrap
    evidence_digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
    source_feedback_ids: []
    activated_at_unix: 1700000000
    category: correctness
    feedback_label: confirmed
    scope: src
    instruction: Never call unwrap in library code.
    approver: security-team
    approval_reason: Panics in libraries crash callers.
    supersedes_approval_id: null
    expires_at_unix: null
    created_at: "2026-11-01T00:00:00Z"
    status: active
    events: []
"#;

#[test]
fn an_exported_pack_enforces_its_reviewers_rules_and_policy_elsewhere() {
    let machine = machine();
    // The source repository defines the organization's reviewer and policy.
    let source = repository(
        "version: 1\nreviewers:\n  org-correctness:\n    provider: default\n    instructions_file: .vee/reviewers/org.md\npolicy:\n  required_reviewers: [org-correctness]\n  block_severities: [high]\n  minimum_confidence: 70\n  on_incomplete: block\n",
    );
    fs::create_dir_all(source.path().join(".vee/reviewers")).unwrap();
    fs::write(
        source.path().join(".vee/reviewers/org.md"),
        "Review for correctness.\n",
    )
    .unwrap();
    let exported = tempfile::tempdir().unwrap();
    let pack_dir = exported.path().join("org-baseline");
    let (code, summary) = vee(
        &machine,
        source.path(),
        &[
            "packs",
            "export",
            pack_dir.to_str().unwrap(),
            "--name",
            "org-baseline",
            "--version",
            "1.0.0",
        ],
    );
    assert_eq!(code, Some(0), "{summary:#}");
    assert_eq!(summary["reviewers"], serde_json::json!(["org-correctness"]));
    assert_eq!(summary["includes_policy"], true);
    // Add an approved rule, as a security team would before publishing the pack.
    let manifest = fs::read_to_string(pack_dir.join("pack.yaml")).unwrap();
    fs::write(
        pack_dir.join("pack.yaml"),
        format!("{manifest}rules:{RULE}"),
    )
    .unwrap();

    // The target repository tries to loosen policy: it would not block at 75.
    let target = repository(
        "version: 1\npolicy:\n  block_severities: [critical]\n  minimum_confidence: 95\n  on_incomplete: allow\n",
    );
    let root = target.path();
    let (code, added) = vee(
        &machine,
        root,
        &["packs", "add", pack_dir.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "{added:#}");
    assert_eq!(added["pinned"], true);
    assert_eq!(added["rules"], 1);
    let config = fs::read_to_string(root.join(".vee.yaml")).unwrap();
    assert!(config.contains("packs:\n  - path: .vee/packs/org-baseline\n    digest: sha256:"));
    assert!(root
        .join(".vee/packs/org-baseline/reviewers/org-correctness.md")
        .is_file());

    let (code, listed) = vee(&machine, root, &["packs", "list"]);
    assert_eq!(code, Some(0));
    assert_eq!(listed["packs"][0]["status"], "ok");
    assert_eq!(listed["packs"][0]["version"], "1.0.0");

    // Re-adding identical content is idempotent.
    let (code, _) = vee(
        &machine,
        root,
        &["packs", "add", pack_dir.to_str().unwrap()],
    );
    assert_eq!(code, Some(0));
    assert_eq!(fs::read_to_string(root.join(".vee.yaml")).unwrap(), config);

    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "pin org pack"]);
    fs::write(
        root.join("src/lib.rs"),
        "pub fn a() { None::<u8>.unwrap(); }\n",
    )
    .unwrap();
    let (code, review) = vee(&machine, root, &["review", "--working-tree", "--gate"]);
    assert_eq!(code, Some(1), "pack policy and rule must block: {review:#}");
    assert_eq!(review["gate"]["status"], "block");
    assert_eq!(
        review["reviewer_outcomes"][0]["reviewer_id"],
        "org-correctness"
    );

    // Tampering with the installed pack fails closed until it is re-pinned.
    let installed = root.join(".vee/packs/org-baseline/pack.yaml");
    let tampered = fs::read_to_string(&installed)
        .unwrap()
        .replace("minimum_confidence: 70", "minimum_confidence: 99");
    fs::write(&installed, tampered).unwrap();
    let (code, error) = vee(&machine, root, &["review", "--working-tree", "--gate"]);
    assert_eq!(code, Some(3), "{error:#}");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("changed"));
    let (code, listed) = vee(&machine, root, &["packs", "list"]);
    assert_eq!(code, Some(2));
    assert_eq!(listed["packs"][0]["status"], "changed");
}

#[test]
fn adding_different_content_for_an_installed_pack_requires_replace() {
    let machine = machine();
    let target = repository("version: 1\n");
    let root = target.path();
    let source = tempfile::tempdir().unwrap();
    let pack = source.path().join("p");
    fs::create_dir_all(&pack).unwrap();
    fs::write(
        pack.join("pack.yaml"),
        "schema_version: 1\nname: p\nversion: '1'\n",
    )
    .unwrap();
    assert_eq!(
        vee(&machine, root, &["packs", "add", pack.to_str().unwrap()]).0,
        Some(0)
    );

    fs::write(
        pack.join("pack.yaml"),
        "schema_version: 1\nname: p\nversion: '2'\n",
    )
    .unwrap();
    let (code, error) = vee(&machine, root, &["packs", "add", pack.to_str().unwrap()]);
    assert_eq!(code, Some(3), "{error:#}");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--replace"));

    let (code, upgraded) = vee(
        &machine,
        root,
        &["packs", "add", "--replace", pack.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "{upgraded:#}");
    assert_eq!(upgraded["version"], "2");
    let config = fs::read_to_string(root.join(".vee.yaml")).unwrap();
    assert_eq!(
        config.matches("- path: .vee/packs/p").count(),
        1,
        "{config}"
    );
    assert!(config.contains(upgraded["digest"].as_str().unwrap()));
}
