use vee_present::{ansi, markdown, summary, Cell, Span, Style, Tone, View};

fn sample() -> View {
    View::new()
        .title("Review rev_1", Some(Cell::badge(Tone::Danger, "block")))
        .fields(vec![
            ("Snapshot".into(), Cell::code("sha256:abc")),
            ("Empty".into(), Cell::plain("")),
            ("Reviewers".into(), Cell::plain("2")),
        ])
        .section("Findings")
        .table(
            &["Severity", "Location", "Finding"],
            vec![
                vec![
                    Cell::badge(Tone::Danger, "high"),
                    Cell::code("a.go:12"),
                    Cell::plain("Lost increment"),
                ],
                vec![
                    Cell::badge(Tone::Warning, "medium"),
                    Cell::code("long/path.go:3"),
                    Cell::plain("Race"),
                ],
            ],
        )
        .note(Tone::Warning, "Analysis did not complete")
        .next_step("vee findings show find_1")
}

#[test]
fn plain_terminal_output_aligns_columns_and_keeps_status_symbols() {
    let text = ansi::render(&sample(), false);
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_eq!(
        text,
        "Review rev_1  ✖ block\n\
         \n  Snapshot   sha256:abc\n  Reviewers  2\n\
         \nFindings\n\
         \n  Severity  Location        Finding\n  ✖ high    a.go:12         Lost increment\n  ▲ medium  long/path.go:3  Race\n\
         \n▲ Analysis did not complete\n\
         \n→ vee findings show find_1\n"
    );
}

#[test]
fn colored_terminal_output_styles_badges_by_tone() {
    let text = ansi::render(&sample(), true);
    assert!(
        text.contains("\u{1b}[1m\u{1b}[31m✖ block\u{1b}[0m"),
        "danger badge is bold red: {text:?}"
    );
    assert!(text.contains("\u{1b}[33m"), "warning is yellow: {text:?}");
    assert!(text.contains("\u{1b}[36m"), "code is cyan: {text:?}");
    let stripped: String = strip_ansi(&text);
    assert_eq!(
        stripped,
        ansi::render(&sample(), false),
        "color only adds styling"
    );
}

#[test]
fn terminal_output_neutralizes_escape_sequences_and_bidi_overrides() {
    let view = View::new().paragraph(Cell::plain(
        "evil\u{1b}[2J\u{1b}]0;owned\u{7}\u{202E}txt.exe\nnext",
    ));
    let text = ansi::render(&view, true);
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{202E}') && !text.contains('\u{7}'));
    assert_eq!(text, "evil[2J]0;ownedtxt.exe next\n");
}

#[test]
fn markdown_output_uses_tables_markers_and_escapes_untrusted_text() {
    let text = markdown::render(&sample());
    assert!(
        text.starts_with("## Review rev\\_1 · 🔴 **block**\n"),
        "{text}"
    );
    assert!(text.contains("| Severity | Location | Finding |\n|---|---|---|\n| 🔴 **high** | `a.go:12` | Lost increment |"), "{text}");
    assert!(text.contains("> 🟡 Analysis did not complete"), "{text}");
    assert!(text.contains("Next: `vee findings show find_1`"), "{text}");
    assert!(!text.contains("Empty"), "empty fields are dropped");
}

#[test]
fn markdown_output_cannot_be_given_structure_by_untrusted_text() {
    let view = View::new()
        .table(
            &["Finding"],
            vec![vec![Cell::plain(
                "x | y\n## forged <img src=x> [link](http://e)",
            )]],
        )
        .paragraph(Cell::code("a`b|c"));
    let text = markdown::render(&view);
    assert!(
        text.contains("x \\| y \\#\\# forged \\<img src=x\\> \\[link\\]\\(http://e\\)"),
        "{text}"
    );
    assert!(text.contains("``a`b\\|c``"), "{text}");
    assert_eq!(
        text.matches('\n').count(),
        5,
        "one table row, no injected lines: {text}"
    );
}

#[test]
fn summary_takes_the_first_line_and_shortens_with_an_ellipsis() {
    assert_eq!(summary("\n  first line  \nsecond", 40), "first line");
    assert_eq!(summary("abcdefghij", 6), "abcde…");
    assert_eq!(summary("", 6), "");
}

#[test]
fn cells_join_spans_with_single_spaces() {
    let cell = Cell::code("a.go").then(Span::new("(new)", Style::Muted));
    assert_eq!(
        ansi::render(&View::new().paragraph(cell.clone()), false),
        "a.go (new)\n"
    );
    assert_eq!(
        markdown::render(&View::new().paragraph(cell)),
        "`a.go` _\\(new\\)_\n"
    );
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(character);
        }
    }
    out
}

#[test]
fn markdown_escaping_keeps_model_text_inert_and_code_intact() {
    assert_eq!(
        markdown::inline("[click](https://example.invalid)"),
        "\\[click\\]\\(https://example\\.invalid\\)"
    );
    assert_eq!(
        markdown::inline("title\n## forged section"),
        "title \\#\\# forged section"
    );
    assert_eq!(markdown::code("file`name.rs"), "``file`name.rs``");
    assert_eq!(markdown::code("`edge"), "`` `edge ``");
}
