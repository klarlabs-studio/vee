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
        run_view(self, verification_status(self.status))
    }
}

/// A SARIF analyzer exits non-zero when it reports results, so a finished run
/// is judged by its results on changed lines, as the gate does, not by its
/// exit code.
impl ToView for vee_application::operations::VerificationResult {
    fn to_view(&self) -> View {
        let run = &self.run;
        let Some(report) = self.analyzer.as_ref().filter(|_| {
            matches!(
                run.status,
                VerificationStatus::Passed | VerificationStatus::Failed
            )
        }) else {
            return run.to_view();
        };
        let badge = if !report.parsed {
            Cell::badge(Tone::Danger, "not evaluable")
        } else if report.findings.is_empty() {
            Cell::badge(Tone::Success, "clean on changed lines")
        } else {
            Cell::badge(
                Tone::Warning,
                format!("{} on changed lines", report.findings.len()),
            )
        };
        let mut view = run_view(run, badge).note(
            Tone::Info,
            Cell::plain(format!(
                "Analyzer: {} results, {} on changed lines, {} pre-existing (never blocking).",
                report.results_total,
                report.findings.len(),
                report.results_outside_changes
            )),
        );
        if run.exit_code.is_some_and(|code| code != 0) && report.parsed {
            view = view.note(
                Tone::Neutral,
                Cell::plain(
                    "A non-zero exit is how the analyzer reports results; the gate reads its SARIF on changed lines.",
                ),
            );
        }
        view.next_action(
            format!("vee verification findings {}", run.run_id),
            "get_analyzer_findings",
            serde_json::json!({ "run_id": run.run_id }),
        )
    }
}

fn run_view(run: &VerificationRun, badge: Cell) -> View {
    {
        let mut view = View::new()
            .title(format!("Verification {}", run.profile_id), Some(badge))
            .fields(vec![
                ("Run".into(), Cell::id(&run.run_id)),
                ("Snapshot".into(), Cell::code(&run.snapshot_id)),
                (
                    "Finding".into(),
                    run.finding_id.clone().map(Cell::code).unwrap_or_default(),
                ),
                (
                    "Exit code".into(),
                    run.exit_code
                        .map_or_else(Cell::default, |code| Cell::plain(code.to_string())),
                ),
            ]);
        if !run.targets.is_empty() {
            view = view
                .section("Targets")
                .list(run.targets.iter().map(Cell::code).collect());
        }
        let artifacts: Vec<Cell> = [
            ("stdout", &run.stdout_artifact),
            ("stderr", &run.stderr_artifact),
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
