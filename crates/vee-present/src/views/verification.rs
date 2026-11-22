use crate::view::{Cell, ToView, Tone, View};
use vee_core::{VerificationRun, VerificationStatus};

pub(crate) fn verification_status(status: VerificationStatus) -> Cell {
    match status {
        VerificationStatus::Passed => Cell::badge(Tone::Success, "passed"),
        VerificationStatus::Failed => Cell::badge(Tone::Danger, "failed"),
        VerificationStatus::TimedOut => Cell::badge(Tone::Danger, "timed out"),
        VerificationStatus::Incomplete => Cell::badge(Tone::Warning, "incomplete"),
    }
}

impl ToView for VerificationRun {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Verification {}", self.profile_id),
                Some(verification_status(self.status)),
            )
            .fields(vec![
                ("Run".into(), Cell::id(&self.run_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Finding".into(),
                    self.finding_id.clone().map(Cell::code).unwrap_or_default(),
                ),
                (
                    "Exit code".into(),
                    self.exit_code
                        .map_or_else(Cell::default, |code| Cell::plain(code.to_string())),
                ),
            ]);
        if !self.targets.is_empty() {
            view = view
                .section("Targets")
                .list(self.targets.iter().map(Cell::code).collect());
        }
        let artifacts: Vec<Cell> = [
            ("stdout", &self.stdout_artifact),
            ("stderr", &self.stderr_artifact),
        ]
        .into_iter()
        .filter_map(|(name, artifact)| {
            artifact.as_ref().map(|artifact| {
                Cell::plain(name)
                    .then(crate::Span::new(&artifact.path, crate::Style::Code))
                    .then(crate::Span::new(&artifact.digest, crate::Style::Id))
            })
        })
        .collect();
        if !artifacts.is_empty() {
            view = view.section("Logs").list(artifacts);
        }
        view
    }
}
