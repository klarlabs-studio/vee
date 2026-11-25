use super::*;

#[test]
fn oversized_text_file_uses_a_bounded_diff_with_change_context() {
    let baseline = (0..20_000)
        .map(|line| format!("let value_{line} = {line};\n"))
        .collect::<String>();
    let current = baseline.replacen("let value_10000 = 10000;", "let value_10000 = 7;", 1);
    assert!(baseline.len() + current.len() > MAX_CONTEXT_FILE_BYTES);

    let diff = bounded_text_diff(
        Some(baseline.as_bytes()),
        Some(current.as_bytes()),
        MAX_CONTEXT_FILE_BYTES,
    )
    .unwrap()
    .unwrap();

    assert!(diff.len() < MAX_CONTEXT_FILE_BYTES);
    assert!(diff.contains("@@"));
    assert!(diff.contains("-let value_10000 = 10000;"));
    assert!(diff.contains("+let value_10000 = 7;"));
    assert!(diff.contains("let value_9999 = 9999;"));
}

#[test]
fn changed_line_numbers_tracks_insertions_and_replacements() {
    let changed = changed_line_numbers(
        Some(b"first\nold\nthird\n"),
        Some(b"added\nfirst\nnew\nthird\n"),
        1024,
    )
    .unwrap()
    .unwrap();
    assert_eq!(changed, [1, 3].into_iter().collect());
    assert_eq!(
        changed_line_numbers(Some(b"same\n"), Some(b"same\n"), 1024)
            .unwrap()
            .unwrap(),
        std::collections::BTreeSet::new()
    );
}

#[test]
fn binary_diff_without_text_hunks_is_reported_as_unavailable() {
    let diff =
        bounded_text_diff(Some(b"before\0"), Some(b"after\0"), MAX_CONTEXT_FILE_BYTES).unwrap();
    assert!(diff.is_none());
}

#[test]
fn snapshot_code_anchors_keep_fingerprints_stable_across_line_shifts() {
    fn parse(
        root: &std::path::Path,
        source: &str,
        line: u32,
        rationale: &str,
    ) -> vee_core::Finding {
        std::fs::write(root.join("source.rs"), source).unwrap();
        let change_set = vee_core::ChangeSet::from_entries(
            None,
            None,
            "working_tree",
            vec![vee_core::SnapshotFile {
                path: "source.rs".into(),
                mode: 0o100644,
                content_digest: vee_core::digest(source.as_bytes()),
                status: "modified".into(),
            }],
        );
        let input = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "findings": [{
                "category": "correctness",
                "severity": "high",
                "confidence": 90,
                "rationale": rationale,
                "path": "source.rs",
                "line": line
            }]
        }))
        .unwrap();
        vee_core::parse_provider_findings_with_anchor(&input, root, |finding| {
            snapshot_code_anchor(root, &change_set, finding)
        })
        .unwrap()
        .remove(0)
    }

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let original = parse(
        root,
        "fn run() {\n    unsafe_call();\n}\n",
        2,
        "unsafe call can panic",
    );
    let shifted = parse(
        root,
        "// new comment\nfn run() {\n    unsafe_call();\n}\n",
        3,
        "dangerous operation may panic",
    );
    let distinct = parse(
        root,
        "fn run() {\n    safe_call();\n}\n",
        2,
        "unsafe call can panic",
    );

    assert_eq!(original.fingerprint, shifted.fingerprint);
    assert_ne!(original.fingerprint, distinct.fingerprint);
}

#[test]
fn the_hunk_covering_a_flagged_line_is_returned_with_both_sides() {
    let baseline = (1..=30).map(|n| format!("line {n}\n")).collect::<String>();
    let current = baseline
        .replace("line 5\n", "line five\n")
        .replace("line 20\n", "line 20\nline 20b\n");
    let diff = text_diff(
        Some(baseline.as_bytes()),
        Some(current.as_bytes()),
        65_536,
        2,
    )
    .unwrap()
    .unwrap();

    let hunk = hunk_at_line("src/a.rs", &diff, 21).unwrap();
    assert!(
        hunk.header.starts_with("@@ -19,4 +19,5 @@"),
        "{}",
        hunk.header
    );
    let added: Vec<_> = hunk
        .lines
        .iter()
        .filter(|line| line.kind == "added")
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].text, "line 20b");
    assert_eq!(added[0].line, Some(21));
    assert_eq!(added[0].base_line, None);
    assert_eq!(hunk.lines[0].line, Some(19));
    assert_eq!(hunk.lines[0].base_line, Some(19));

    let first = hunk_at_line("src/a.rs", &diff, 5).unwrap();
    let removed: Vec<_> = first
        .lines
        .iter()
        .filter(|line| line.kind == "removed")
        .collect();
    assert_eq!(removed[0].text, "line 5");
    assert_eq!(removed[0].base_line, Some(5));
    assert!(!first.truncated);

    assert_eq!(
        hunk_at_line("src/a.rs", &diff, 12),
        None,
        "line 12 is unchanged"
    );
}
