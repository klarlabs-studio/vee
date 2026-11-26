//! `vee rules export` writes the approved rules into a standards file's own
//! section, and only inside the repository (ADR 0031).

fn vee(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
        .current_dir(root)
        .env("NO_COLOR", "1")
        .env("VEE_CONFIG", root.join("no-user-config.yaml"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn rules_export_keeps_the_rest_of_the_file_and_stays_in_the_repository() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["init", "-q"])
        .status()
        .unwrap()
        .success());
    std::fs::write(root.join("REVIEW.md"), "# Review rules\n\nWrite tests.\n").unwrap();

    let printed = vee(root, &["rules", "export"]);
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert!(String::from_utf8_lossy(&printed.stdout).contains("No rules are approved yet."));

    let written = vee(
        root,
        &[
            "rules",
            "export",
            "--write",
            "REVIEW.md",
            "--output",
            "json",
        ],
    );
    assert!(
        written.status.success(),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&written.stdout).unwrap();
    assert_eq!(report["path"], "REVIEW.md");
    let review = std::fs::read_to_string(root.join("REVIEW.md")).unwrap();
    assert!(
        review.starts_with("# Review rules\n\nWrite tests.\n"),
        "{review}"
    );
    assert!(review.contains("<!-- vee:rules:start -->"));
    // Writing again replaces the section instead of adding another.
    assert!(vee(root, &["rules", "export", "--write", "REVIEW.md"])
        .status
        .success());
    let again = std::fs::read_to_string(root.join("REVIEW.md")).unwrap();
    assert_eq!(again.matches("<!-- vee:rules:start -->").count(), 1);

    for outside in ["../REVIEW.md", "/tmp/REVIEW.md", "notes.txt"] {
        let refused = vee(root, &["rules", "export", "--write", outside]);
        assert!(!refused.status.success(), "{outside} was accepted");
    }
}
