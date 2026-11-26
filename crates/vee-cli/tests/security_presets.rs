//! `vee init` sets up the security scanners it finds, and the `security` and
//! `regulated` policy profiles use them (ADR 0029).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Vee test")
        .env("GIT_AUTHOR_EMAIL", "vee@example.invalid")
        .env("GIT_COMMITTER_NAME", "Vee test")
        .env("GIT_COMMITTER_EMAIL", "vee@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn init_sets_up_found_scanners_and_their_profiles_gate_the_change() {
    let outside = tempfile::tempdir().unwrap();
    let bin = outside.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // A nox that reports each line containing SECRET at `error` and, like
    // the real one, exits 1 when it reports anything; and an osv-scanner
    // Vee cannot use.
    executable(
        &bin.join("nox"),
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "nox 1.70.0"; exit 0; fi
results=$(grep -n SECRET config.py 2>/dev/null | cut -d: -f1 | while read line; do
  printf '{"ruleId":"SEC-001","level":"error","message":{"text":"secret"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config.py"},"region":{"startLine":%s}}}]},' "$line"
done)
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"nox"}},"results":[%s]}]}' "${results%,}"
[ -z "$results" ]
"#,
    );
    executable(&bin.join("osv-scanner"), "#!/bin/sh\necho 2.0.0\n");
    executable(
        &bin.join("reviewer"),
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    );
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let user_config = outside.path().join("config.yaml");
    let vee = |root: &Path, args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
            .current_dir(root)
            .env("NO_COLOR", "1")
            .env("PATH", &path)
            .env("VEE_CONFIG", &user_config)
            .env("ANTHROPIC_API_KEY", "test-key")
            .args(args)
            .output()
            .unwrap()
    };

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q", "-b", "main"]);
    let init = vee(
        root,
        &[
            "init",
            "--provider",
            "anthropic-api",
            "--model",
            "model-id",
            "--output",
            "json",
        ],
    );
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    // The report embeds provider detection; bundle that schema so the
    // validator never fetches it.
    let mut schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/init-report-v1.schema.json")).unwrap();
    let mut detection: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/provider-detection-v1.schema.json"
    ))
    .unwrap();
    detection.as_object_mut().unwrap().remove("$schema");
    schema
        .as_object_mut()
        .unwrap()
        .entry("$defs")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .unwrap()
        .insert("provider-detection-v1.schema.json".into(), detection);
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let scanners: Vec<(&str, &str)> = report["security_scanners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|scanner| {
            (
                scanner["id"].as_str().unwrap(),
                scanner["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        scanners,
        [("nox", "configured"), ("osv-scanner", "unsupported")]
    );
    let config = std::fs::read_to_string(root.join(".vee.yaml")).unwrap();
    assert!(config.contains("  nox:\n    executable: nox"), "{config}");
    assert!(!config.contains("osv-scanner:"));

    // Reviews run on a fake reviewer, so only the scanner decides.
    std::fs::write(
        &user_config,
        format!(
            "version: 1\nproviders:\n  default: {{ kind: cli, executable: {} }}\n",
            bin.join("reviewer").display()
        ),
    )
    .unwrap();
    std::fs::write(root.join(".gitignore"), ".vee/\n").unwrap();
    std::fs::write(root.join("config.py"), "name = 'app'\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    std::fs::write(root.join("config.py"), "name = 'app'\ntoken = 'SECRET'\n").unwrap();

    let verify = vee(
        root,
        &[
            "verify",
            "--profile",
            "nox",
            "--base",
            &base,
            "--output",
            "json",
        ],
    );
    assert!(
        verify.status.code().is_some(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let gate = |profile: &str| {
        let output = vee(
            root,
            &[
                "review",
                "--base",
                &base,
                "--gate",
                "--policy-profile",
                profile,
                "--output",
                "json",
            ],
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)))
    };
    let security = gate("security");
    assert_eq!(security["gate"]["status"], "block", "{security:#}");
    assert!(security["gate"]["blocking_findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id.as_str().unwrap().starts_with("analyzer:nox:")));

    // Without the secret the regulated gate passes, but a person approves.
    std::fs::write(root.join("config.py"), "name = 'app'\nretries = 3\n").unwrap();
    let verify = vee(root, &["verify", "--profile", "nox", "--base", &base]);
    assert!(verify.status.code().is_some());
    let regulated = gate("regulated");
    assert_eq!(regulated["gate"]["status"], "pass", "{regulated:#}");
    let approval = vee(
        root,
        &[
            "gate",
            "approval",
            "--review",
            regulated["review_id"].as_str().unwrap(),
            "--output",
            "json",
        ],
    );
    let approval: serde_json::Value = serde_json::from_slice(&approval.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&approval.stderr)));
    assert_eq!(approval["eligible"], false, "{approval:#}");
    let policy = approval["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == "policy" || stage["id"] == "policy")
        .unwrap_or_else(|| panic!("no policy stage in {approval:#}"));
    assert_eq!(policy["passed"], false, "{policy:#}");
}
