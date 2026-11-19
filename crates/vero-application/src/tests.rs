use super::*;
use std::process::Command;

#[test]
fn shared_capture_service_uses_git_adapter_for_worktree_scope() {
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
    git(&["config", "user.email", "vero@example.invalid"]);
    git(&["config", "user.name", "Vero test"]);
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    git(&["add", "source.rs"]);
    git(&["commit", "-qm", "initial"]);
    std::fs::write(root.join("source.rs"), "fn main() { let _ = 1; }\n").unwrap();

    let snapshot = capture_change_set(root, vero_git::ChangeScope::WorkingTree).unwrap();

    assert_eq!(snapshot.scope, "working_tree");
    assert_eq!(snapshot.files.len(), 1);
    assert_eq!(snapshot.files[0].path, "source.rs");
}
