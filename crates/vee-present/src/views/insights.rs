//! Views for insight documents: local quality analytics and model-drafted
//! pull request descriptions.

use crate::tone;
use crate::view::{Cell, Span, Style, ToView, Tone, View};
use crate::views::governance::rate;
use crate::views::serde_name;
use std::collections::BTreeMap;
use vee_application::analytics::{FeedbackRate, QualityAnalytics};
use vee_application::ProviderTaskResult;
use vee_core::{FindingStatus, GateStatus, Severity};

const GATE_ORDER: &[&str] = &["block", "incomplete", "pass"];
const LIFECYCLE_ORDER: &[&str] = &["open", "verified", "refuted", "resolved", "waived"];
const SEVERITY_ORDER: &[&str] = &["critical", "high", "medium", "low", "info"];
const VERIFICATION_OUTCOMES: &[&str] = &["passed", "failed", "timed_out", "incomplete"];

/// `counts` in `order` first, then any other keys alphabetically.
fn ordered<'a>(counts: &'a BTreeMap<String, usize>, order: &[&str]) -> Vec<(&'a str, usize)> {
    let mut rows: Vec<(&str, usize)> = order
        .iter()
        .filter_map(|name| {
            counts
                .get_key_value(*name)
                .map(|(key, count)| (key.as_str(), *count))
        })
        .collect();
    rows.extend(
        counts
            .iter()
            .filter(|(key, _)| !order.contains(&key.as_str()))
            .map(|(key, count)| (key.as_str(), *count)),
    );
    rows
}

/// A two-column count table, or a muted empty-state line.
fn count_table(
    header: &str,
    counts: &BTreeMap<String, usize>,
    order: &[&str],
    label: impl Fn(&str) -> Cell,
    empty: &str,
) -> View {
    if counts.is_empty() {
        return View::new().paragraph(Cell::muted(empty));
    }
    View::new().table(
        &[header, "Count"],
        ordered(counts, order)
            .into_iter()
            .map(|(name, count)| vec![label(name), Cell::plain(count.to_string())])
            .collect(),
    )
}

/// The badge for a serialized enum value, or the raw value when it is unknown.
fn parsed<T: serde::de::DeserializeOwned>(name: &str, badge: impl Fn(T) -> Cell) -> Cell {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_or_else(|_| Cell::plain(name), badge)
}

fn feedback_rate(metric: &FeedbackRate) -> Cell {
    match metric.observed_rate {
        Some(observed) => Cell::plain(format!(
            "{} ({}/{} labeled occurrences; {} disputed)",
            rate(Some(observed)),
            metric.positive_occurrences,
            metric.denominator,
            metric.disputed_occurrences
        )),
        None => Cell::muted(format!(
            "unavailable (no unambiguous labels; {} disputed)",
            metric.disputed_occurrences
        )),
    }
}

fn optional_ms(value: Option<u64>) -> Cell {
    value.map_or_else(|| Cell::muted("n/a"), |ms| Cell::plain(format!("{ms}ms")))
}

impl ToView for QualityAnalytics {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Local quality analytics ({} reviews)", self.review_count),
                None,
            )
            .fields(vec![
                (
                    "Without gate decision".into(),
                    Cell::plain(self.reviews_without_gate_decision.to_string()),
                ),
                (
                    "Finding accuracy".into(),
                    feedback_rate(&self.reviewed_feedback_metrics.finding_accuracy),
                ),
                (
                    "Actionability".into(),
                    feedback_rate(&self.reviewed_feedback_metrics.actionability),
                ),
            ])
            .section("Latest gate decisions")
            .extend(count_table(
                "Decision",
                &self.latest_gate_decisions,
                GATE_ORDER,
                |name| parsed::<GateStatus>(name, tone::gate),
                "No gate decisions recorded.",
            ))
            .section("Findings by lifecycle")
            .extend(count_table(
                "Status",
                &self.findings_by_status,
                LIFECYCLE_ORDER,
                |name| parsed::<FindingStatus>(name, tone::finding_status),
                "No findings recorded.",
            ))
            .section("Findings by severity")
            .extend(count_table(
                "Severity",
                &self.findings_by_severity,
                SEVERITY_ORDER,
                |name| parsed::<Severity>(name, tone::severity),
                "No findings recorded.",
            ))
            .section("Verification profile outcomes");
        if self.verification_runs_by_profile.is_empty() {
            view = view.paragraph(Cell::muted("No verification runs recorded."));
        } else {
            view = view.table(
                &["Profile", "Passed", "Failed", "Timed out", "Incomplete"],
                self.verification_runs_by_profile
                    .iter()
                    .map(|(profile, outcomes)| {
                        let mut row = vec![Cell::plain(profile)];
                        row.extend(VERIFICATION_OUTCOMES.iter().map(|outcome| {
                            Cell::plain(outcomes.get(*outcome).copied().unwrap_or(0).to_string())
                        }));
                        row
                    })
                    .collect(),
            );
        }
        view = view.section("Recognized test log events");
        if self
            .test_diagnostics_by_profile
            .values()
            .all(BTreeMap::is_empty)
        {
            view = view.paragraph(Cell::muted("No recognized test log events."));
        } else {
            view = view
                .table(
                    &["Profile", "Event", "Count"],
                    self.test_diagnostics_by_profile
                        .iter()
                        .flat_map(|(profile, events)| {
                            events.iter().map(move |(event, count)| {
                                vec![
                                    Cell::plain(profile),
                                    Cell::plain(event),
                                    Cell::plain(count.to_string()),
                                ]
                            })
                        })
                        .collect(),
                )
                .paragraph(Cell::muted(
                    "Observed event counts, not complete CI test-run denominators.",
                ));
        }
        for limitation in &self.test_diagnostics_limitations {
            view = view.note(Tone::Warning, limitation.as_str());
        }
        view = view.section("Reviewed feedback labels").extend(count_table(
            "Label",
            &self.reviewed_feedback_by_label,
            &[
                "confirmed",
                "false_positive",
                "actionable",
                "not_actionable",
            ],
            |name| Cell::plain(name),
            "No reviewed feedback recorded.",
        ));
        view = view.section("Provider latency (latest saved reviews)");
        if self.provider_latency.is_empty() {
            view = view.paragraph(Cell::muted("No provider runs recorded."));
        } else {
            view = view.table(
                &["Provider", "Samples", "p50", "p95", "Unmeasured", "Failed"],
                self.provider_latency
                    .iter()
                    .map(|(provider, metric)| {
                        vec![
                            Cell::plain(provider),
                            Cell::plain(metric.measured_runs.to_string()),
                            optional_ms(metric.median_duration_ms),
                            optional_ms(metric.p95_duration_ms),
                            Cell::plain(metric.unmeasured_runs.to_string()),
                            Cell::plain(metric.failed_runs.to_string()),
                        ]
                    })
                    .collect(),
            );
        }
        if !self.provider_latency_history_complete {
            view = view.note(
                Tone::Warning,
                "Latency covers a bounded window of the latest reviews, not the full history.",
            );
        }
        view = view
            .paragraph(Cell::muted(&self.provider_latency_note))
            .section("Provider usage");
        if self.provider_usage.is_empty() {
            view = view.paragraph(Cell::muted("No provider usage recorded."));
        } else {
            view = view.table(
                &[
                    "Provider",
                    "Runs reported/unreported",
                    "Tokens in/out/total",
                    "Estimated cost",
                    "Runs priced/unpriced",
                ],
                self.provider_usage
                    .iter()
                    .map(|(provider, usage)| {
                        vec![
                            Cell::plain(provider),
                            Cell::plain(format!(
                                "{}/{}",
                                usage.reported_runs, usage.unreported_runs
                            )),
                            Cell::plain(format!(
                                "{}/{}/{}",
                                usage.input_tokens, usage.output_tokens, usage.total_tokens
                            )),
                            usage.estimated_cost_usd.map_or_else(
                                || Cell::muted("n/a"),
                                |cost| Cell::plain(format!("{cost:.6} USD")),
                            ),
                            Cell::plain(format!("{}/{}", usage.priced_runs, usage.unpriced_runs)),
                        ]
                    })
                    .collect(),
            );
        }
        view.paragraph(Cell::muted(&self.provider_usage_note))
    }
}

/// Model-authored Markdown, split into paragraphs and lists. Backends escape
/// every span, so the text is shown as written and cannot add structure.
fn authored_text(body: &str) -> View {
    let mut view = View::new();
    for block in body.split("\n\n") {
        let lines: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if lines.is_empty() {
            continue;
        }
        let mut prose: Vec<&str> = Vec::new();
        let mut items: Vec<Cell> = Vec::new();
        let flush_prose = |view: View, prose: &mut Vec<&str>| {
            if prose.is_empty() {
                return view;
            }
            let text = prose.join(" ");
            prose.clear();
            view.paragraph(Cell::plain(text))
        };
        for line in lines {
            if let Some(heading) = heading(line) {
                view = flush_prose(view, &mut prose).list(std::mem::take(&mut items));
                view = view.paragraph(Cell::strong(heading));
            } else if let Some(item) = list_item(line) {
                view = flush_prose(view, &mut prose);
                items.push(Cell::plain(item));
            } else {
                view = view.list(std::mem::take(&mut items));
                prose.push(line);
            }
        }
        view = flush_prose(view, &mut prose).list(items);
    }
    view
}

fn heading(line: &str) -> Option<&str> {
    let text = line.trim_start_matches('#');
    (text.len() < line.len() && text.starts_with(' ')).then(|| text.trim())
}

fn list_item(line: &str) -> Option<&str> {
    ["- ", "* ", "+ "]
        .iter()
        .find_map(|marker| line.strip_prefix(marker))
        .map(str::trim)
}

impl ToView for ProviderTaskResult {
    fn to_view(&self) -> View {
        let title = self.output.get("title").and_then(|value| value.as_str());
        let body = self.output.get("body").and_then(|value| value.as_str());
        let is_draft = title.is_some() || body.is_some();
        let mut view = View::new()
            .title(
                if is_draft {
                    "Pull request draft"
                } else {
                    "Provider task output"
                },
                Some(Cell::badge(Tone::Neutral, "draft")),
            )
            .fields(vec![
                ("Reviewer".into(), Cell::plain(&self.reviewer_id)),
                (
                    "Provider".into(),
                    Cell::plain(&self.provider_id).then(Span::new(
                        match &self.model {
                            Some(model) => {
                                format!("· {} · {model}", serde_name(&self.provider_kind))
                            }
                            None => format!("· {}", serde_name(&self.provider_kind)),
                        },
                        Style::Muted,
                    )),
                ),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Output digest".into(), Cell::id(&self.output_digest)),
            ]);
        if !is_draft {
            return view
                .section("Output")
                .paragraph(Cell::code(self.output.to_string()))
                .note(
                    Tone::Info,
                    "Generated content only; it is not review evidence or a gate decision.",
                );
        }
        view = view.section("Title").paragraph(match title {
            Some(title) if !title.trim().is_empty() => Cell::strong(title),
            _ => Cell::muted("The draft has no title."),
        });
        view = view.section("Body");
        let body_view = authored_text(body.unwrap_or(""));
        view = if body_view.blocks.is_empty() {
            view.paragraph(Cell::muted("The draft has no body."))
        } else {
            view.extend(body_view)
        };
        view.note(
            Tone::Info,
            "Draft only; it was not published or used in a gate.",
        )
    }
}
