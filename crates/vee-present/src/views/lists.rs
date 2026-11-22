//! Views for list documents: saved reviews, verification runs and feedback.

use crate::tone;
use crate::view::{summary, Cell, ToView, View};
use crate::views::verification::verification_status;
use crate::views::work::feedback_label;
use vee_application::operations::{FindingFeedbackList, ReviewsList, VerificationList};

impl ToView for ReviewsList {
    fn to_view(&self) -> View {
        let view = View::new().title(format!("Reviews ({})", self.reviews.len()), None);
        if self.reviews.is_empty() {
            return view
                .paragraph(Cell::muted("No reviews saved in this repository."))
                .next_step("vee review");
        }
        let view = view.table(
            &["Status", "Review", "Created", "Snapshot"],
            self.reviews
                .iter()
                .map(|review| {
                    vec![
                        tone::status_text(&review.status),
                        Cell::id(&review.review_id),
                        Cell::plain(&review.created_at),
                        Cell::code(&review.snapshot_id),
                    ]
                })
                .collect(),
        );
        match self.reviews.first() {
            Some(latest) => view.next_action(
                format!("vee reviews show {}", latest.review_id),
                "get_review",
                serde_json::json!({"review_id": latest.review_id}),
            ),
            None => view,
        }
    }
}

impl ToView for VerificationList {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(format!("Verification runs ({})", self.runs.len()), None)
            .fields(vec![("Snapshot".into(), Cell::code(&self.snapshot_id))]);
        if self.runs.is_empty() {
            return view.paragraph(Cell::muted(
                "No verification runs recorded for this snapshot.",
            ));
        }
        let view = view.table(
            &["Status", "Profile", "Run", "Targets", "Logs"],
            self.runs
                .iter()
                .map(|run| {
                    let logs: Vec<&str> = [
                        ("stdout", run.has_stdout_artifact),
                        ("stderr", run.has_stderr_artifact),
                    ]
                    .into_iter()
                    .filter_map(|(name, present)| present.then_some(name))
                    .collect();
                    vec![
                        verification_status(run.status),
                        Cell::strong(&run.profile_id),
                        Cell::id(&run.run_id),
                        Cell::plain(run.targets.join(", ")),
                        if logs.is_empty() {
                            Cell::muted("none")
                        } else {
                            Cell::plain(logs.join(", "))
                        },
                    ]
                })
                .collect(),
        );
        match self.runs.first() {
            Some(run) => view.next_action(
                format!("vee verification diagnose {}", run.run_id),
                "diagnose_verification",
                serde_json::json!({"run_id": run.run_id}),
            ),
            None => view,
        }
    }
}

impl ToView for FindingFeedbackList {
    fn to_view(&self) -> View {
        let view = View::new().title(format!("Reviewed feedback ({})", self.feedback.len()), None);
        if self.feedback.is_empty() {
            return view.paragraph(Cell::muted("No reviewed feedback recorded."));
        }
        view.table(
            &["Label", "Finding", "Reviewer", "Recorded", "Reason"],
            self.feedback
                .iter()
                .map(|item| {
                    vec![
                        feedback_label(item.label),
                        Cell::id(&item.finding_id),
                        Cell::plain(&item.reviewer),
                        Cell::plain(&item.created_at),
                        Cell::plain(summary(&item.reason, 56)),
                    ]
                })
                .collect(),
        )
    }
}
