//! Views for imported review history.

use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use vee_application::imported_history::{ImportedHistorySearch, ImportedMatch};

impl ToView for ImportedHistorySearch {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(
                format!(
                    "Imported history matching “{}” ({})",
                    self.query,
                    self.matches.len()
                ),
                None,
            )
            .note(
                Tone::Info,
                "Untrusted historical context from imported archives; never gate eligible.",
            );
        if self.matches.is_empty() {
            return view.paragraph(Cell::muted("No imported findings or comments match."));
        }
        view.table(
            &["Score", "Source", "Location", "Text", "Archive"],
            self.matches
                .iter()
                .map(|item| match item {
                    ImportedMatch::Finding(found) => vec![
                        Cell::plain(found.relevance_score.to_string()),
                        tone::severity(found.finding.severity).then(Span::new(
                            format!("finding · {}", found.review_id),
                            Style::Muted,
                        )),
                        tone::location(found.finding.path.as_deref(), found.finding.line),
                        Cell::plain(summary(&found.finding.rationale, 56)),
                        Cell::id(short_digest(&found.archive_digest)),
                    ],
                    ImportedMatch::Discussion(comment) => vec![
                        Cell::plain(comment.relevance_score.to_string()),
                        Cell::plain(format!(
                            "{} #{} comment",
                            comment.pull_request.repository.full_name, comment.pull_request.number
                        )),
                        tone::location(
                            comment.issue.path.as_deref(),
                            comment.issue.line.and_then(|line| u32::try_from(line).ok()),
                        ),
                        Cell::plain(summary(&comment.issue.body, 56)),
                        Cell::id(short_digest(&comment.archive_digest)),
                    ],
                })
                .collect(),
        )
    }
}

/// `sha256:` plus the first 12 hex digits: enough to tell archives apart in a table.
fn short_digest(digest: &str) -> String {
    match digest.strip_prefix("sha256:") {
        Some(hex) if hex.len() > 12 => format!("sha256:{}", &hex[..12]),
        _ => digest.to_owned(),
    }
}
