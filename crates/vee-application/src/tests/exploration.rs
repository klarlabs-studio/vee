use crate::exploration::{ExplorationSpec, SnapshotExplorer};
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    assert!(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap()
        .success());
}

/// A repository whose HEAD has `src/billing.rs`, `src/caller.rs`, a tracked
/// `.env` and `config/secrets.yaml`, and ignores `notes.txt`. The working
/// tree then changes `src/caller.rs`, adds `src/new.rs` (untracked files are
/// part of a working-tree change) and writes the ignored `notes.txt`.
fn repository() -> (tempfile::TempDir, vee_core::ChangeSet) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "vee@example.invalid"]);
    git(root, &["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("config")).unwrap();
    std::fs::write(
        root.join("src/billing.rs"),
        "pub fn charge(cents: u64) {}\n// charge in cents\n",
    )
    .unwrap();
    std::fs::write(root.join("src/caller.rs"), "fn pay() { charge(1); }\n").unwrap();
    std::fs::write(root.join(".env"), "API_TOKEN=tracked-secret\n").unwrap();
    std::fs::write(root.join("config/secrets.yaml"), "token: x\n").unwrap();
    std::fs::write(root.join(".gitignore"), "notes.txt\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "initial"]);
    std::fs::write(
        root.join("src/caller.rs"),
        "fn pay() { charge(dollars_to_cents(1)); }\n",
    )
    .unwrap();
    std::fs::write(root.join("src/new.rs"), "fn helper() { charge(2); }\n").unwrap();
    std::fs::write(root.join("notes.txt"), "untracked charge notes\n").unwrap();
    let change_set = vee_git::capture(root, vee_git::ChangeScope::WorkingTree).unwrap();
    (directory, change_set)
}

fn explorer(
    root: &Path,
    change_set: &vee_core::ChangeSet,
    review: &vee_core::ReviewConfig,
) -> SnapshotExplorer {
    SnapshotExplorer::new(ExplorationSpec::new(root, change_set, review))
}

#[test]
fn reviewers_list_and_read_snapshot_files_but_never_untracked_or_denied_ones() {
    let (directory, change_set) = repository();
    let root = directory.path();
    let mut explorer = explorer(root, &change_set, &vee_core::ReviewConfig::default());

    let listing = explorer.list_files(None, None);
    assert!(
        listing.contains("src/billing.rs") && listing.contains("src/new.rs"),
        "{listing}"
    );
    assert!(
        !listing.contains("notes.txt"),
        "ignored files are not in the snapshot: {listing}"
    );
    assert!(
        !listing.contains(".env") && !listing.contains("secrets.yaml"),
        "{listing}"
    );

    let billing = explorer.read_file("src/billing.rs", None, None);
    assert!(
        billing.contains("     1| pub fn charge(cents: u64) {}"),
        "{billing}"
    );
    // The changed file is read as captured, not as it is now.
    std::fs::write(root.join("src/caller.rs"), "edited after capture\n").unwrap();
    let caller = explorer.read_file("src/caller.rs", None, None);
    assert!(
        caller.contains("snapshot file changed after capture"),
        "{caller}"
    );

    for refused in [
        ".env",
        "config/secrets.yaml",
        "notes.txt",
        "../outside",
        "/etc/passwd",
        "src/../../x",
    ] {
        let text = explorer.read_file(refused, None, None);
        assert!(
            !text.contains("tracked-secret") && !text.contains("untracked"),
            "{refused}: {text}"
        );
    }
    let outcomes = explorer
        .calls()
        .iter()
        .map(|call| call.outcome.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        [
            "ok",
            "ok",
            "invalid",
            "denied",
            "denied",
            "not_found",
            "invalid",
            "invalid",
            "invalid"
        ]
    );
    assert_eq!(explorer.calls()[1].paths, ["src/billing.rs"]);
}

#[test]
fn search_covers_changed_and_unchanged_snapshot_files() {
    let (directory, change_set) = repository();
    let root = directory.path();
    let mut explorer = explorer(root, &change_set, &vee_core::ReviewConfig::default());

    let found = explorer.search("charge(", None, false, None);
    assert!(
        found.contains("src/billing.rs:1: pub fn charge(cents: u64) {}"),
        "{found}"
    );
    // Changed and added files are searched as captured.
    assert!(
        found.contains("src/caller.rs:1: fn pay() { charge(dollars_to_cents(1)); }"),
        "{found}"
    );
    assert!(found.contains("src/new.rs:1:"), "{found}");
    assert!(!found.contains("notes.txt"), "{found}");

    let scoped = explorer.search("CHARGE", Some("src/billing.rs"), true, None);
    assert!(scoped.starts_with("2 of 2 matching lines"), "{scoped}");
    let secret = explorer.search("tracked-secret", None, false, None);
    assert!(
        secret.starts_with("0 of 0"),
        "denied files are not searched: {secret}"
    );
}

#[test]
fn line_ranges_and_budgets_bound_what_a_reviewer_reads() {
    let (directory, change_set) = repository();
    let root = directory.path();
    let mut review = vee_core::ReviewConfig::default();
    review.exploration.max_tool_calls = 3;
    let mut explorer = explorer(root, &change_set, &review);

    let second = explorer.read_file("src/billing.rs", Some(2), Some(2));
    assert_eq!(second, "src/billing.rs\n     2| // charge in cents\n");
    explorer.list_files(Some("src/**"), Some(1));
    explorer.list_files(None, None);
    let exhausted = explorer.read_file("src/billing.rs", None, None);
    assert!(exhausted.contains("budget exhausted"), "{exhausted}");
    assert_eq!(explorer.calls().last().unwrap().outcome, "budget_exhausted");

    let mut review = vee_core::ReviewConfig::default();
    review.exploration.max_read_bytes = 40;
    let mut small = explorer_with(root, &change_set, &review);
    let partial = small.read_file("src/billing.rs", None, None);
    assert!(
        partial.contains("[truncated after line 1; call read_file with start_line 2 to continue]"),
        "{partial}"
    );
}

fn explorer_with(
    root: &Path,
    change_set: &vee_core::ChangeSet,
    review: &vee_core::ReviewConfig,
) -> SnapshotExplorer {
    explorer(root, change_set, review)
}

#[test]
fn configured_deny_globs_add_to_the_built_in_list() {
    let (directory, change_set) = repository();
    let mut review = vee_core::ReviewConfig::default();
    review.exploration.deny = vec!["src/billing.rs".into()];
    let mut explorer = explorer(directory.path(), &change_set, &review);
    assert!(explorer
        .read_file("src/billing.rs", None, None)
        .contains("may not be read"));
    assert!(!explorer.list_files(None, None).contains("billing"));
}

#[test]
fn a_reviewer_explores_only_the_paths_its_own_filters_allow() {
    let (directory, change_set) = repository();
    let root = directory.path();
    let reviewer: vee_core::ReviewerConfig = serde_yaml::from_str(
        "provider: p\ninstructions_file: r.md\nexclude: [\"src/billing.rs\"]\n",
    )
    .unwrap();
    let spec = ExplorationSpec::new(root, &change_set, &vee_core::ReviewConfig::default())
        .for_reviewer(&reviewer);
    assert!(spec.descriptor().contains("src/billing.rs"));
    let mut explorer = SnapshotExplorer::new(spec);
    let listing = explorer.list_files(None, None);
    assert!(
        !listing.contains("billing.rs") && listing.contains("src/caller.rs"),
        "{listing}"
    );
    let read = explorer.read_file("src/billing.rs", None, None);
    assert!(!read.contains("charge in cents"), "{read}");
    let found = explorer.search("charge in cents", None, false, None);
    assert!(!found.contains("billing.rs"), "{found}");
}
