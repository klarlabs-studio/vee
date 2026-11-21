use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::serde_name;
use vee_application::{ReviewResult, ReviewerOutcome};
use vee_core::Finding;

const SUMMARY_WIDTH: usize = 72;

impl ToView for ReviewResult {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Review {}", self.review_id),
                Some(tone::gate(self.gate.status)),
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Status".into(), tone::status_text(&self.status)),
                (
                    "Changed files".into(),
                    Cell::plain(self.change_set.files.len().to_string()),
                ),
                (
                    "Reviewers".into(),
                    Cell::plain(self.selected_reviewers.join(", ")),
                ),
                (
                    "Policy".into(),
                    self.policy_profile
                        .clone()
                        .map(Cell::plain)
                        .unwrap_or_default(),
                ),
            ]);
        if !self.analysis_complete {
            view = view.note(
                Tone::Warning,
                "Analysis did not complete; findings may be missing.",
            );
        }
        view = view.extend(reasons_view(&self.gate.reasons));
        if !self.unreviewed_paths.is_empty() {
            view = view
                .section("Not reviewed")
                .paragraph(Cell::muted(
                    "No reviewer received these changed files. Add or widen a reviewer, or set policy.on_unreviewed: allow.",
                ))
                .list(self.unreviewed_paths.iter().map(Cell::code).collect());
        }
        view = view.extend(outcomes_view(&self.reviewer_outcomes));
        view = view.section(format!("Findings ({})", self.findings.len()));
        if self.findings.is_empty() {
            view = view.paragraph(if self.analysis_complete {
                Cell::muted("No findings were reported.")
            } else {
                Cell::muted("No findings; analysis did not complete.")
            });
        } else {
            view = view.extend(findings_table(&self.findings, &self.gate.blocking_findings));
        }
        if !self.reviewer_arbitration.is_empty() {
            view = view.section("Reviewer disagreement").list(
                self.reviewer_arbitration
                    .iter()
                    .filter(|item| {
                        item.severity_disagreement
                            || item.confidence_disagreement
                            || item.rationale_disagreement
                    })
                    .map(|item| {
                        let mut dimensions = Vec::new();
                        if item.severity_disagreement {
                            dimensions.push("severity");
                        }
                        if item.confidence_disagreement {
                            dimensions.push("confidence");
                        }
                        if item.rationale_disagreement {
                            dimensions.push("rationale");
                        }
                        Cell::code(&item.finding_id).then(Span::new(
                            format!(
                                "{} reports disagree on {}",
                                item.reports.len(),
                                dimensions.join(", ")
                            ),
                            Style::Plain,
                        ))
                    })
                    .collect(),
            );
        }
        if let Some(first) = self.findings.first() {
            view = view.next_step(format!("vee findings show {}", first.id));
        }
        view
    }
}

pub(crate) fn reasons_view(reasons: &[String]) -> View {
    if reasons.is_empty() {
        return View::new();
    }
    View::new()
        .section("Gate reasons")
        .list(reasons.iter().map(Cell::plain).collect())
}

fn outcomes_view(outcomes: &[ReviewerOutcome]) -> View {
    if outcomes.is_empty() {
        return View::new()
            .section("Reviewers")
            .paragraph(Cell::muted("No reviewers ran."));
    }
    View::new().section("Reviewers").table(
        &["Reviewer", "Status", "Provider", "Time", "Tokens in/out"],
        outcomes
            .iter()
            .map(|outcome| {
                let provider = match &outcome.model {
                    Some(model) => format!("{} · {model}", serde_name(&outcome.provider_kind)),
                    None => serde_name(&outcome.provider_kind),
                };
                let tokens = outcome.usage.as_ref().map_or_else(
                    || Cell::muted("–"),
                    |usage| {
                        let count = |value: Option<u64>| {
                            value.map_or_else(|| "?".to_owned(), |value| value.to_string())
                        };
                        Cell::plain(format!(
                            "{}/{}",
                            count(usage.input_tokens),
                            count(usage.output_tokens)
                        ))
                    },
                );
                vec![
                    Cell::strong(&outcome.reviewer_id),
                    tone::status_text(&outcome.status),
                    Cell::plain(provider),
                    outcome
                        .duration_ms
                        .map_or_else(|| Cell::muted("–"), |ms| Cell::plain(duration(ms))),
                    tokens,
                ]
            })
            .collect(),
    )
}

/// The findings table shared by the review and findings views.
pub(crate) fn findings_table(findings: &[Finding], blocking: &[String]) -> View {
    View::new().table(
        &["Severity", "Location", "Category", "Finding", "ID"],
        findings
            .iter()
            .map(|finding| {
                let mut severity = tone::severity(finding.severity);
                if blocking.contains(&finding.id) {
                    severity = severity.then(Span::new("blocks", Style::Strong));
                } else if finding.advisory {
                    severity = severity.then(Span::new("advisory", Style::Muted));
                }
                vec![
                    severity,
                    tone::location(finding.path.as_deref(), finding.line),
                    Cell::plain(&finding.category),
                    Cell::plain(summary(&finding.rationale, SUMMARY_WIDTH)),
                    Cell::muted(&finding.id),
                ]
            })
            .collect(),
    )
}

fn duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    match seconds {
        0 => format!("{milliseconds} ms"),
        1..=59 => format!("{seconds} s"),
        _ => format!("{}m {:02}s", seconds / 60, seconds % 60),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn durations_read_naturally() {
        assert_eq!(super::duration(250), "250 ms");
        assert_eq!(super::duration(12_400), "12 s");
        assert_eq!(super::duration(1_840_942), "30m 40s");
    }
}
