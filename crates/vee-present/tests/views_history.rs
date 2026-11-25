use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use vee_application::operations::{
    ExternalFeedbackList, ExternalFeedbackRecorded, RepositoryContext,
};
use vee_present::{ansi, markdown, ToView};

fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let first = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), first);
}

fn text<T: ToView>(document: &T) -> String {
    ansi::render(&document.to_view(), false)
}

fn md<T: ToView>(document: &T) -> String {
    markdown::render(&document.to_view())
}

const ARCHIVE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn feedback(external_id: &str) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "feedback_id": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "archive_digest": ARCHIVE,
        "provider": "github",
        "pull_request": {"repository": {"host": "github.com", "full_name": "example/service"}, "number": 9},
        "revision": "cccccccc",
        "external_id": external_id,
        "category": "correctness",
        "label": "false_positive",
        "reason": "The caller enforces the retry bound.",
        "reviewer": "maintainer",
        "recorded_at_unix": 1_700_000_000
    })
}

#[test]
fn recorded_external_feedback_view_shows_provenance_and_list_step() {
    let recorded: ExternalFeedbackRecorded = serde_json::from_value(json!({
        "schema_version": 1,
        "feedback": feedback("42"),
        "trust": "human_labeled_external_context",
        "gate_eligible": false
    }))
    .unwrap();
    let text = text(&recorded);
    assert!(
        text.starts_with("Feedback recorded for comment 42  ▲ false_positive\n"),
        "{text}"
    );
    assert!(
        text.contains("example/service #9 on github.com (github)"),
        "{text}"
    );
    assert!(
        text.contains("The caller enforces the retry bound."),
        "{text}"
    );
    assert!(text.contains("never gate eligible"), "{text}");
    assert!(
        text.contains(&format!(
            "→ vee reviews imported feedback list --archive-digest {ARCHIVE}"
        )),
        "{text}"
    );
    let markdown = md(&recorded);
    assert!(
        markdown.contains("`list_external_review_feedback`"),
        "{markdown}"
    );
    assert!(markdown.contains(&format!("`{ARCHIVE}`")), "{markdown}");
    assert_round_trip(&recorded);
}

#[test]
fn external_feedback_list_view_tabulates_labels_and_says_when_none_exist() {
    let list: ExternalFeedbackList = serde_json::from_value(json!({
        "schema_version": 1,
        "feedback": [feedback("42"), feedback("43")],
        "gate_eligible": false
    }))
    .unwrap();
    let rendered = text(&list);
    assert!(
        rendered.starts_with("External review feedback (2)\n"),
        "{rendered}"
    );
    assert!(rendered.contains("▲ false_positive  43"), "{rendered}");
    assert!(rendered.contains("sha256:aaaaaaaaaaaa\n"), "{rendered}");
    assert!(rendered.ends_with("→ vee rules candidates\n"), "{rendered}");
    assert!(md(&list).contains("| 🟡 **false_positive** | `42` | example/service #9 |"));
    assert_round_trip(&list);

    let empty: ExternalFeedbackList = serde_json::from_value(json!({
        "schema_version": 1, "feedback": [], "gate_eligible": false
    }))
    .unwrap();
    assert_eq!(
        text(&empty),
        "External review feedback (0)\n\n● Human labels on untrusted external comments are advisory history; never gate eligible.\n\nNo labels recorded for archived provider comments.\n"
    );
}

fn context(
    content: Option<&str>,
    matching_lines: Vec<usize>,
    truncated: bool,
) -> RepositoryContext {
    RepositoryContext {
        schema_version: 2,
        path: "src/lib.rs".into(),
        snapshot_id: "sha256:snapshot".into(),
        content_digest: "sha256:content".into(),
        returned_bytes: content.map_or(4, str::len),
        total_bytes: if truncated {
            100
        } else {
            content.map_or(4, str::len)
        },
        matching_line_count: matching_lines.len(),
        content: content.map(str::to_owned),
        matching_lines,
        truncated,
        classification: "untrusted_repository_source".into(),
        note: content
            .is_none()
            .then(|| "file is binary or contains non-UTF8 bytes".into()),
    }
}

#[test]
fn repository_context_view_numbers_source_lines_and_marks_matches() {
    let document = context(Some("fn main() {\n    run();\n}\n"), vec![2], false);
    let text = text(&document);
    assert!(
        text.starts_with("Repository context for src/lib.rs  ✔ complete\n"),
        "{text}"
    );
    assert!(text.contains("1 (lines 2)"), "{text}");
    assert!(text.contains("untrusted_repository_source"), "{text}");
    assert!(text.contains("▲ Untrusted repository source"), "{text}");
    assert!(text.contains("Source\n"), "{text}");
    assert!(text.contains("● 2   ") || text.contains("● 2  "), "{text}");
    assert!(text.contains("    run();"), "{text}");
    let markdown = md(&document);
    assert!(markdown.contains("| _1_ | `fn main() {` |"), "{markdown}");
    assert!(markdown.contains("| 🔵 **2** |"), "{markdown}");
    assert_round_trip(&document);
}

#[test]
fn repository_context_view_reports_truncation_binary_and_empty_files() {
    let truncated = text(&context(Some("abcd"), Vec::new(), true));
    assert!(truncated.contains("▲ truncated"), "{truncated}");
    assert!(
        truncated.contains("Showing the first 4 of 100 bytes."),
        "{truncated}"
    );

    let binary = text(&context(None, Vec::new(), false));
    assert!(binary.contains("▲ not text"), "{binary}");
    assert!(
        binary.contains("▲ file is binary or contains non-UTF8 bytes"),
        "{binary}"
    );
    assert!(!binary.contains("Source"), "{binary}");

    let empty = text(&context(Some(""), Vec::new(), false));
    assert!(empty.ends_with("Source\n\nThe file is empty.\n"), "{empty}");
}
