//! The view of team analytics across repositories.

use crate::view::{Cell, ToView, Tone, View};
use vee_application::analytics::FeedbackRate;
use vee_application::team_analytics::TeamAnalytics;

fn percent(rate: Option<f64>) -> String {
    rate.map_or_else(|| "n/a".to_owned(), |rate| format!("{:.0}%", rate * 100.0))
}

fn of(numerator: usize, denominator: usize, rate: Option<f64>) -> Cell {
    Cell::plain(format!("{} ({numerator} of {denominator})", percent(rate)))
}

fn feedback(rate: &FeedbackRate) -> Cell {
    let cell = of(
        rate.positive_occurrences,
        rate.denominator,
        rate.observed_rate,
    );
    if rate.disputed_occurrences > 0 {
        cell.then(crate::view::Span::new(
            format!("{} disputed, left out", rate.disputed_occurrences),
            crate::view::Style::Muted,
        ))
    } else {
        cell
    }
}

impl ToView for TeamAnalytics {
    fn to_view(&self) -> View {
        let count = |key: &str| self.gate_decisions.get(key).copied().unwrap_or(0);
        let decided = count("pass") + count("block") + count("incomplete");
        let pass_rate = (decided > 0).then(|| count("pass") as f64 / decided as f64);
        let mut view = View::new()
            .title(
                format!("Team analytics over {} document(s)", self.sources.len()),
                None,
            )
            .section("Gate outcomes")
            .fields(vec![
                ("Reviews".into(), Cell::plain(self.reviews.to_string())),
                ("Passed".into(), of(count("pass"), decided, pass_rate)),
                ("Blocked".into(), Cell::plain(count("block").to_string())),
                (
                    "Incomplete".into(),
                    Cell::plain(count("incomplete").to_string()),
                ),
                (
                    "Without a gate decision".into(),
                    Cell::plain(self.reviews_without_gate_decision.to_string()),
                ),
            ])
            .section("Findings")
            .fields(
                self.findings_by_severity
                    .iter()
                    .map(|(severity, count)| (severity.clone(), Cell::plain(count.to_string())))
                    .chain([
                        (
                            "Accurate, as labelled".into(),
                            feedback(&self.finding_accuracy),
                        ),
                        (
                            "Actionable, as labelled".into(),
                            feedback(&self.actionability),
                        ),
                    ])
                    .collect(),
            )
            .section("Approval without a person")
            .fields(vec![
                (
                    "Repositories".into(),
                    Cell::plain(self.approvals.repositories.to_string()),
                ),
                (
                    "Pull requests read".into(),
                    Cell::plain(self.approvals.pull_requests_read.to_string()),
                ),
                (
                    "Agreement".into(),
                    of(
                        self.approvals
                            .outcomes
                            .get("merged_as_eligible")
                            .copied()
                            .unwrap_or(0),
                        self.approvals.eligible,
                        self.approvals.agreement_rate,
                    ),
                ),
                (
                    "Override".into(),
                    of(
                        self.approvals.eligible.saturating_sub(
                            self.approvals
                                .outcomes
                                .get("merged_as_eligible")
                                .copied()
                                .unwrap_or(0),
                        ),
                        self.approvals.eligible,
                        self.approvals.override_rate,
                    ),
                ),
            ])
            .section("Cost")
            .fields(vec![
                (
                    "Estimated".into(),
                    Cell::plain(
                        self.cost
                            .estimated_cost_usd
                            .map_or_else(|| "n/a".to_owned(), |cost| format!("${cost:.2}")),
                    )
                    .then(crate::view::Span::new(
                        format!(
                            "over {} priced of {} runs",
                            self.cost.priced_runs,
                            self.cost.priced_runs + self.cost.unpriced_runs
                        ),
                        crate::view::Style::Muted,
                    )),
                ),
                (
                    "Tokens".into(),
                    Cell::plain(format!(
                        "{} in, {} out",
                        self.cost.input_tokens, self.cost.output_tokens
                    )),
                ),
            ])
            .section("Rule effectiveness")
            .fields(vec![
                (
                    "Approved rules".into(),
                    Cell::plain(self.rules.rule_approvals.to_string()),
                ),
                (
                    "False positives before".into(),
                    of(
                        self.rules.baseline.false_positive_count,
                        self.rules.baseline.accuracy_denominator,
                        self.rules.baseline.false_positive_rate,
                    ),
                ),
                (
                    "False positives after".into(),
                    of(
                        self.rules.after_activation.false_positive_count,
                        self.rules.after_activation.accuracy_denominator,
                        self.rules.after_activation.false_positive_rate,
                    ),
                ),
            ]);
        if !self.verification_runs.is_empty() {
            view = view.section("Verification").table(
                &["Profile", "Results"],
                self.verification_runs
                    .iter()
                    .map(|(profile, results)| {
                        vec![
                            Cell::code(profile),
                            Cell::plain(
                                results
                                    .iter()
                                    .map(|(result, count)| format!("{result} {count}"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ),
                        ]
                    })
                    .collect(),
            );
        }
        view = view
            .section(format!("Sources ({})", self.sources.len()))
            .table(
                &["Source", "Kind", "Reviews", "Eligible", "Agreement"],
                self.sources
                    .iter()
                    .map(|source| {
                        vec![
                            Cell::plain(&source.label),
                            Cell::plain(source.kind.as_str()),
                            source
                                .reviews
                                .map(|reviews| Cell::plain(reviews.to_string()))
                                .unwrap_or_default(),
                            source
                                .eligible
                                .map(|eligible| Cell::plain(eligible.to_string()))
                                .unwrap_or_default(),
                            source
                                .eligible
                                .map(|_| Cell::plain(percent(source.agreement_rate)))
                                .unwrap_or_default(),
                        ]
                    })
                    .collect(),
            );
        for skipped in &self.skipped {
            view = view.note(
                Tone::Warning,
                Cell::plain(format!("Skipped {}: {}", skipped.path, skipped.reason)),
            );
        }
        view.section("Limitations").list(
            self.limitations
                .iter()
                .map(Cell::muted)
                .collect(),
        )
    }
}
