//! Views for imported review history and human labels on archived comments.

use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::work::feedback_label;
use vee_application::imported_history::{
    ExternalReviewFeedback, ImportedHistorySearch, ImportedMatch,
};
use vee_application::operations::{ExternalFeedbackList, ExternalFeedbackRecorded};

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

/// `owner/name #number`: the pull request an archived comment belongs to.
fn pull_request(feedback: &ExternalReviewFeedback) -> String {
    format!(
        "{} #{}",
        feedback.pull_request.repository.full_name, feedback.pull_request.number
    )
}

const UNTRUSTED_LABEL_NOTE: &str =
    "Human labels on untrusted external comments are advisory history; never gate eligible.";

impl ToView for ExternalFeedbackRecorded {
    fn to_view(&self) -> View {
        let feedback = &self.feedback;
        View::new()
            .title(
                format!("Feedback recorded for comment {}", feedback.external_id),
                Some(feedback_label(feedback.label)),
            )
            .fields(vec![
                ("Archive".into(), Cell::id(&feedback.archive_digest)),
                (
                    "Pull request".into(),
                    Cell::plain(pull_request(feedback)).then(Span::new(
                        format!(
                            "on {} ({})",
                            feedback.pull_request.repository.host, feedback.provider
                        ),
                        Style::Muted,
                    )),
                ),
                ("Revision".into(), Cell::code(&feedback.revision)),
                ("Category".into(), Cell::plain(&feedback.category)),
                ("Reason".into(), Cell::plain(&feedback.reason)),
                ("Reviewer".into(), Cell::plain(&feedback.reviewer)),
                (
                    "Recorded (unix)".into(),
                    Cell::plain(feedback.recorded_at_unix.to_string()),
                ),
                ("Feedback".into(), Cell::id(&feedback.feedback_id)),
            ])
            .note(Tone::Info, UNTRUSTED_LABEL_NOTE)
            .next_action(
                format!(
                    "vee reviews imported feedback list --archive-digest {}",
                    feedback.archive_digest
                ),
                "list_external_review_feedback",
                serde_json::json!({"archive_digest": feedback.archive_digest}),
            )
    }
}

impl ToView for ExternalFeedbackList {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(
                format!("External review feedback ({})", self.feedback.len()),
                None,
            )
            .note(Tone::Info, UNTRUSTED_LABEL_NOTE);
        if self.feedback.is_empty() {
            return view.paragraph(Cell::muted(
                "No labels recorded for archived provider comments.",
            ));
        }
        view.table(
            &[
                "Label",
                "Comment",
                "Pull request",
                "Category",
                "Reviewer",
                "Recorded (unix)",
                "Reason",
                "Archive",
            ],
            self.feedback
                .iter()
                .map(|item| {
                    vec![
                        feedback_label(item.label),
                        Cell::id(&item.external_id),
                        Cell::plain(pull_request(item)),
                        Cell::plain(&item.category),
                        Cell::plain(&item.reviewer),
                        Cell::plain(item.recorded_at_unix.to_string()),
                        Cell::plain(summary(&item.reason, 56)),
                        Cell::id(short_digest(&item.archive_digest)),
                    ]
                })
                .collect(),
        )
        .next_action(
            "vee rules candidates",
            "list_rule_candidates",
            serde_json::json!({}),
        )
    }
}
