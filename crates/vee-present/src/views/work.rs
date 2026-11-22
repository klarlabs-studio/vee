//! Views for work documents: agent investigation tasks, work packages, and
//! recorded human feedback.

use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::serde_name;
use vee_application::finding_task::{FindingTask, FindingWorkPackage, SourceContext};
use vee_core::{FindingFeedback, FindingFeedbackLabel};

const SUMMARY_WIDTH: usize = 56;

const STALE_SNAPSHOT: &str =
    "The source changed since this review; investigate against the reviewed snapshot.";

impl ToView for FindingTask {
    fn to_view(&self) -> View {
        let record = &self.finding;
        let finding = &record.finding;
        let mut view = View::new()
            .title(
                format!("Task for finding {}", finding.id),
                Some(
                    tone::severity(finding.severity)
                        .then(Span::new(format!("· {}", finding.category), Style::Plain)),
                ),
            )
            .fields(vec![
                ("Status".into(), tone::finding_status(record.status)),
                (
                    "Location".into(),
                    tone::location(finding.path.as_deref(), finding.line),
                ),
                ("Review".into(), Cell::id(&self.review_id)),
                (
                    "Snapshot".into(),
                    snapshot(&self.snapshot_id, self.snapshot_current),
                ),
                ("Owners".into(), owners(self)),
                ("Task".into(), Cell::id(&self.task_id)),
            ]);
        if !self.snapshot_current {
            view = view.note(Tone::Warning, STALE_SNAPSHOT);
        }
        view = view.section("Rationale");
        for paragraph in finding
            .rationale
            .split("\n\n")
            .filter(|text| !text.trim().is_empty())
        {
            view = view.paragraph(Cell::plain(paragraph.trim()));
        }
        view = view.section("Source");
        view = match &self.source_context {
            Some(source) => view.extend(source_view(source)),
            None => view.paragraph(Cell::muted("No source context available.")),
        };
        if let Some(note) = &self.context_note {
            view = view.note(Tone::Info, Cell::plain(note));
        }
        view.extend(impact_view(self))
            .extend(evidence_view(self))
            .extend(standards_view(self))
            .section("Instructions")
            .paragraph(Cell::plain(self.instructions))
            .next_action(
                format!("vee verify {} --profile <profile>", finding.id),
                "verify_finding",
                serde_json::json!({"finding_id": finding.id, "profile_id": "<profile>"}),
            )
    }
}

fn snapshot(snapshot_id: &str, current: bool) -> Cell {
    Cell::code(snapshot_id).then(if current {
        Span::new("current", Style::Badge(Tone::Success))
    } else {
        Span::new("changed since review", Style::Badge(Tone::Warning))
    })
}

fn owners(task: &FindingTask) -> Cell {
    match (&task.ownership, &task.ownership_note) {
        (Some(ownership), _) if !ownership.owners.is_empty() => {
            Cell::plain(ownership.owners.join(", ")).then(Span::new("(advisory)", Style::Muted))
        }
        (Some(ownership), _) => tone::status_text(&ownership.status),
        (None, Some(note)) => Cell::muted(note),
        (None, None) => Cell::default(),
    }
}

/// The excerpt as numbered lines; the document stores each as `  12 | text`.
fn source_view(source: &SourceContext) -> View {
    let rows = source
        .content
        .lines()
        .map(|line| match line.split_once(" | ") {
            Some((number, text)) => vec![Cell::muted(number.trim()), Cell::code(text)],
            None => vec![Cell::default(), Cell::code(line)],
        })
        .collect();
    View::new()
        .paragraph(Cell::code(format!(
            "{}:{}-{}",
            source.path, source.start_line, source.end_line
        )))
        .table(&["Line", "Source"], rows)
}

fn impact_view(task: &FindingTask) -> View {
    let view = View::new().section(format!("Impact paths ({})", task.impact_paths.len()));
    let view = if task.impact_paths.is_empty() {
        view.paragraph(Cell::muted("No impact paths recorded."))
    } else {
        view.table(
            &["Affected", "Via", "Relationship", "Certainty"],
            task.impact_paths
                .iter()
                .map(|edge| {
                    vec![
                        Cell::code(format!("{}:{}", edge.affected_path, edge.evidence_line)),
                        Cell::code(&edge.symbol),
                        Cell::plain(&edge.relationship),
                        Cell::plain(&edge.certainty),
                    ]
                })
                .collect(),
        )
    };
    if task.impact_coverage_complete == Some(false) {
        view.note(
            Tone::Warning,
            "Impact analysis is incomplete; callers and tests may be missing.",
        )
    } else {
        view
    }
}

fn evidence_view(task: &FindingTask) -> View {
    let view = View::new().section(format!("Evidence ({})", task.evidence.len()));
    if task.evidence.is_empty() {
        return view.paragraph(Cell::muted("No evidence recorded."));
    }
    view.list(
        task.evidence
            .iter()
            .map(|item| {
                let lines = match (item.start_line, item.end_line) {
                    (Some(start), Some(end)) if end != start => format!(":{start}-{end}"),
                    (Some(start), _) => format!(":{start}"),
                    _ => String::new(),
                };
                Cell::code(format!("{}{lines}", item.source_path))
                    .then(Span::new(serde_name(&item.kind), Style::Plain))
                    .then(Span::new(&item.id, Style::Id))
            })
            .collect(),
    )
}

fn standards_view(task: &FindingTask) -> View {
    let view = View::new().section(format!(
        "Applicable standards ({})",
        task.applicable_standards.len()
    ));
    let view = if task.applicable_standards.is_empty() {
        view.paragraph(Cell::muted("No applicable standards recorded."))
    } else {
        view.table(
            &["Standard", "Kind", "Scope", "Integrity"],
            task.applicable_standards
                .iter()
                .map(|standard| {
                    let mut integrity = Cell::plain(&standard.integrity);
                    if standard.truncated {
                        integrity = integrity.then(Span::new("truncated", Style::Muted));
                    }
                    vec![
                        Cell::code(&standard.path),
                        Cell::plain(&standard.kind),
                        Cell::plain(&standard.scope),
                        integrity,
                    ]
                })
                .collect(),
        )
    };
    match &task.standards_note {
        Some(note) => view.note(Tone::Info, Cell::plain(note)),
        None => view,
    }
}

impl ToView for FindingWorkPackage {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Work package ({} findings)", self.findings.len()),
                None,
            )
            .fields(vec![
                ("Review".into(), Cell::id(&self.review_id)),
                (
                    "Snapshot".into(),
                    snapshot(&self.snapshot_id, self.snapshot_current),
                ),
                ("Package".into(), Cell::id(&self.package_id)),
            ]);
        if !self.snapshot_current {
            view = view.note(Tone::Warning, STALE_SNAPSHOT);
        }
        view = view.section("Findings");
        if self.findings.is_empty() {
            view = view.paragraph(Cell::muted("No findings in this package."));
        } else {
            view = view.table(
                &[
                    "Severity", "Status", "Location", "Category", "Finding", "ID",
                ],
                self.findings
                    .iter()
                    .map(|task| {
                        let finding = &task.finding.finding;
                        vec![
                            tone::severity(finding.severity),
                            tone::finding_status(task.finding.status),
                            tone::location(finding.path.as_deref(), finding.line),
                            Cell::plain(&finding.category),
                            Cell::plain(summary(&finding.rationale, SUMMARY_WIDTH)),
                            Cell::id(&finding.id),
                        ]
                    })
                    .collect(),
            );
        }
        view = view
            .section("Instructions")
            .paragraph(Cell::plain(self.instructions));
        if let Some(first) = self.findings.first() {
            let id = &first.finding.finding.id;
            view = view.next_action(
                format!("vee findings task {id}"),
                "get_finding_task",
                serde_json::json!({"finding_id": id}),
            );
        }
        view
    }
}

fn feedback_label(label: FindingFeedbackLabel) -> Cell {
    let tone = match label {
        FindingFeedbackLabel::Confirmed | FindingFeedbackLabel::Actionable => Tone::Success,
        FindingFeedbackLabel::FalsePositive | FindingFeedbackLabel::NotActionable => Tone::Warning,
    };
    Cell::badge(tone, label.as_str())
}

impl ToView for FindingFeedback {
    fn to_view(&self) -> View {
        View::new()
            .title(
                format!("Feedback recorded for finding {}", self.finding_id),
                Some(feedback_label(self.label)),
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Reason".into(), Cell::plain(&self.reason)),
                ("Reviewer".into(), Cell::plain(&self.reviewer)),
                ("Recorded".into(), Cell::plain(&self.created_at)),
                ("Feedback".into(), Cell::id(&self.feedback_id)),
            ])
            .next_step(format!(
                "vee findings feedback list --finding {}",
                self.finding_id
            ))
    }
}
