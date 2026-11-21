use crate::tone;
use crate::view::{Cell, ToView, Tone, View};
use crate::views::review::reasons_view;
use vee_application::operations::{GateHistory, WaiverList};
use vee_application::GateCheckResult;

impl ToView for GateCheckResult {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Gate for review {}", self.review_id),
                Some(tone::gate(self.status)),
            )
            .fields(vec![
                (
                    "Reviewed snapshot".into(),
                    Cell::code(&self.reviewed_snapshot_id),
                ),
                (
                    "Current snapshot".into(),
                    Cell::code(&self.current_snapshot_id),
                ),
                ("Decision".into(), Cell::id(&self.decision_id)),
            ]);
        if self.reviewed_snapshot_id != self.current_snapshot_id {
            view = view.note(
                Tone::Warning,
                "The working tree changed since this review; the decision covers the reviewed snapshot.",
            );
        }
        view = view.extend(reasons_view(&self.reasons));
        if !self.blocking_findings.is_empty() {
            view = view
                .section(format!(
                    "Blocking findings ({})",
                    self.blocking_findings.len()
                ))
                .list(self.blocking_findings.iter().map(Cell::id).collect());
            if let Some(first) = self
                .blocking_findings
                .iter()
                .find(|id| !id.starts_with("analyzer:"))
            {
                view = view.next_action(
                    format!("vee findings show {first}"),
                    "get_finding",
                    serde_json::json!({"finding_id": first}),
                );
            }
        }
        view
    }
}

impl ToView for GateHistory {
    fn to_view(&self) -> View {
        let view = View::new().title(format!("Gate history ({})", self.decisions.len()), None);
        if self.decisions.is_empty() {
            return view.paragraph(Cell::muted("No gate decisions recorded."));
        }
        view.table(
            &["Status", "Blocking", "Snapshot", "Decision"],
            self.decisions
                .iter()
                .map(|decision| {
                    vec![
                        tone::gate(decision.status),
                        Cell::plain(decision.blocking_findings.len().to_string()),
                        Cell::code(&decision.snapshot_id),
                        Cell::id(&decision.decision_id),
                    ]
                })
                .collect(),
        )
    }
}

impl ToView for WaiverList {
    fn to_view(&self) -> View {
        let view = View::new().title(format!("Waivers ({})", self.waivers.len()), None);
        if self.waivers.is_empty() {
            return view.paragraph(Cell::muted("No waivers for this review's snapshot."));
        }
        view.table(
            &["Waiver", "Author", "Expires (unix)", "Reason"],
            self.waivers
                .iter()
                .map(|waiver| {
                    vec![
                        Cell::id(&waiver.id),
                        Cell::plain(&waiver.author),
                        Cell::plain(waiver.expires_at_unix.to_string()),
                        Cell::plain(crate::view::summary(&waiver.reason, 60)),
                    ]
                })
                .collect(),
        )
    }
}
