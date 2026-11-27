//! The views of a steward run and of a review shared for CI.

use crate::view::{Cell, ToView, Tone, View};
use vee_application::shared_review::SharedReview;
use vee_application::steward::StewardReport;
use vee_core::GateStatus;

fn short(oid: &str) -> String {
    oid.chars().take(12).collect()
}

impl ToView for StewardReport {
    fn to_view(&self) -> View {
        let gate = match self.gate {
            GateStatus::Pass => Cell::badge(Tone::Success, "pass"),
            GateStatus::Block => Cell::badge(Tone::Danger, "block"),
            GateStatus::Incomplete => Cell::badge(Tone::Warning, "incomplete"),
        };
        let kept = self.kept();
        let view = View::new()
            .title(
                format!("Steward kept {kept} of {} fixes", self.steps.len()),
                Some(gate),
            )
            .fields(vec![
                ("Base".into(), Cell::code(short(&self.base))),
                (
                    "Head".into(),
                    Cell::code(if self.head == self.start_head {
                        format!("{} (unchanged)", short(&self.head))
                    } else {
                        format!("{} → {}", short(&self.start_head), short(&self.head))
                    }),
                ),
                ("Review".into(), Cell::id(&self.review_id)),
                (
                    "Pushed".into(),
                    Cell::plain(if self.pushed { "yes" } else { "no" }),
                ),
            ])
            .section(format!("Steps ({})", self.steps.len()));
        let view = if self.steps.is_empty() {
            view.paragraph(Cell::muted(
                "Nothing to fix: no conflict with the base, no failing required verification, and no blocking finding.",
            ))
        } else {
            view.table(
                &["Problem", "Kept", "What happened", "Undo"],
                self.steps
                    .iter()
                    .map(|step| {
                        vec![
                            Cell::plain(format!(
                                "{} {}",
                                step.kind.as_str().replace('_', " "),
                                step.subject
                            )),
                            if step.kept {
                                Cell::badge(Tone::Success, "kept")
                            } else {
                                Cell::badge(Tone::Neutral, "not kept")
                            },
                            Cell::plain(&step.summary),
                            step.undo.as_ref().map(Cell::code).unwrap_or_default(),
                        ]
                    })
                    .collect(),
            )
        };
        view.paragraph(Cell::muted(
            "Each kept fix is its own commit on the branch; nothing was pushed unless shown above.",
        ))
    }
}

impl ToView for SharedReview {
    fn to_view(&self) -> View {
        View::new()
            .title(
                format!("Shared review {}", self.review_id),
                Some(Cell::badge(Tone::Success, "signed")),
            )
            .fields(vec![
                ("Head".into(), Cell::code(&self.head_oid)),
                ("Base".into(), Cell::code(&self.base_oid)),
                ("Key".into(), Cell::id(&self.key_id)),
                ("Stored in".into(), Cell::code(&self.notes_ref)),
            ])
            .paragraph(Cell::plain(format!(
                "Push the note so CI can reuse this review: {}",
                self.push_command
            )))
    }
}
