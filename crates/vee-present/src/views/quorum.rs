//! The view of measured agreement quorums.

use crate::view::{Cell, ToView, Tone, View};
use vee_application::quorum::QuorumCalibration;

impl ToView for QuorumCalibration {
    fn to_view(&self) -> View {
        let mut view = View::new().title("Agreement quorums", None);
        if self.reviewers.is_empty() {
            return view.note(
                Tone::Info,
                "No enabled reviewer samples more than once; set `effort` or `samples` on a reviewer first.",
            );
        }
        for reviewer in &self.reviewers {
            let recommendation = match reviewer.recommended_quorum {
                Some(quorum) if quorum == reviewer.configured_quorum => {
                    Cell::badge(Tone::Success, format!("keep {quorum}"))
                }
                Some(quorum) => Cell::badge(Tone::Warning, format!("use {quorum}")),
                None => Cell::muted("not enough labels"),
            };
            view = view
                .section(format!("Reviewer {}", reviewer.reviewer_id))
                .fields(vec![
                    ("Samples".into(), Cell::plain(reviewer.samples.to_string())),
                    (
                        "Configured quorum".into(),
                        Cell::plain(reviewer.configured_quorum.to_string()),
                    ),
                    (
                        "Labelled findings".into(),
                        Cell::plain(reviewer.labeled.to_string()),
                    ),
                    ("Recommendation".into(), recommendation),
                    ("Why".into(), Cell::plain(reviewer.reason.clone())),
                ])
                .table(
                    &[
                        "Quorum",
                        "Confirmed kept",
                        "Rejected kept",
                        "Confirmed only shown",
                        "Rejected only shown",
                    ],
                    reviewer
                        .outcomes
                        .iter()
                        .map(|outcome| {
                            vec![
                                Cell::plain(outcome.quorum.to_string()),
                                Cell::plain(outcome.kept_confirmed.to_string()),
                                Cell::plain(outcome.kept_rejected.to_string()),
                                Cell::plain(outcome.dropped_confirmed.to_string()),
                                Cell::plain(outcome.dropped_rejected.to_string()),
                            ]
                        })
                        .collect(),
                );
            if let Some(quorum) = reviewer
                .recommended_quorum
                .filter(|quorum| *quorum != reviewer.configured_quorum)
            {
                view = view.paragraph(Cell::code(format!(
                    "reviewers.{}.sample_quorum: {quorum}",
                    reviewer.reviewer_id
                )));
            }
        }
        view.paragraph(Cell::muted(format!(
            "Counts use each finding's latest label from `vee findings feedback`; at least {} are needed per reviewer.",
            self.min_labeled
        )))
    }
}
