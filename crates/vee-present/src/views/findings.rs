use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::verification::verification_status;
use vee_application::operations::{FindingDetail, FindingStatusUpdate, FindingsPage};

const SUMMARY_WIDTH: usize = 72;

impl ToView for FindingsPage {
    fn to_view(&self) -> View {
        let mut view = View::new().title(format!("Findings ({})", self.total), None);
        if self.findings.is_empty() {
            return view.paragraph(Cell::muted(if self.total == 0 {
                "No findings."
            } else {
                "No findings on this page."
            }));
        }
        view = view.table(
            &["Severity", "Status", "Location", "Finding", "ID"],
            self.findings
                .iter()
                .map(|record| {
                    vec![
                        tone::severity(record.finding.severity),
                        tone::finding_status(record.status),
                        tone::location(record.finding.path.as_deref(), record.finding.line),
                        Cell::plain(summary(&record.finding.rationale, SUMMARY_WIDTH)),
                        Cell::id(&record.finding.id),
                    ]
                })
                .collect(),
        );
        let shown_end = self.offset + self.findings.len();
        if shown_end < self.total {
            view = view
                .paragraph(Cell::muted(format!(
                    "Showing {}–{} of {}.",
                    self.offset + 1,
                    shown_end,
                    self.total
                )))
                .next_action(
                    format!("vee findings list --offset {shown_end}"),
                    "list_findings",
                    serde_json::json!({"offset": shown_end}),
                );
        } else if let Some(first) = self.findings.first() {
            view = view.next_action(
                format!("vee findings show {}", first.finding.id),
                "get_finding",
                serde_json::json!({"finding_id": first.finding.id}),
            );
        }
        view
    }
}

impl ToView for FindingDetail {
    fn to_view(&self) -> View {
        let record = &self.finding;
        let finding = &record.finding;
        let mut view = View::new()
            .title(
                format!("Finding {}", finding.id),
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
                ("Confidence".into(), tone::confidence(finding.confidence)),
                (
                    "Reviewers".into(),
                    Cell::plain(finding.reviewer_ids.join(", ")),
                ),
                ("Provenance".into(), Cell::muted(&finding.provenance)),
                (
                    "Seen".into(),
                    Cell::plain(format!(
                        "{} time(s), {} → {}",
                        record.occurrence_count, record.first_seen, record.last_seen
                    )),
                ),
                (
                    "Status reason".into(),
                    record
                        .status_reason
                        .clone()
                        .map(Cell::plain)
                        .unwrap_or_default(),
                ),
            ])
            .section("Rationale");
        for paragraph in finding
            .rationale
            .split("\n\n")
            .filter(|text| !text.trim().is_empty())
        {
            view = view.paragraph(Cell::plain(paragraph.trim()));
        }
        if finding.advisory {
            view = view.note(
                Tone::Info,
                "Advisory: shown for review, never blocks the gate.",
            );
        }
        if !self.evidence.is_empty() {
            view = view.section("Evidence").list(
                self.evidence
                    .iter()
                    .map(|item| {
                        let lines = match (item.start_line, item.end_line) {
                            (Some(start), Some(end)) if end != start => format!(":{start}-{end}"),
                            (Some(start), _) => format!(":{start}"),
                            _ => String::new(),
                        };
                        Cell::code(format!("{}{lines}", item.source_path))
                            .then(Span::new(
                                crate::views::serde_name(&item.kind),
                                Style::Plain,
                            ))
                            .then(Span::new(&item.id, Style::Id))
                    })
                    .collect(),
            );
        }
        view = view.section("Verification");
        if self.verification_runs.is_empty() {
            view = view
                .paragraph(Cell::muted("No finding-specific verification recorded."))
                .next_action(
                    format!("vee verify {} --profile <profile>", finding.id),
                    "verify_finding",
                    serde_json::json!({"finding_id": finding.id, "profile_id": "<profile>"}),
                );
        } else {
            view = view.table(
                &["Run", "Profile", "Status", "Snapshot"],
                self.verification_runs
                    .iter()
                    .map(|run| {
                        vec![
                            Cell::id(&run.run_id),
                            Cell::plain(&run.profile_id),
                            verification_status(run.status),
                            Cell::code(&run.snapshot_id),
                        ]
                    })
                    .collect(),
            );
        }
        view
    }
}

impl ToView for FindingStatusUpdate {
    fn to_view(&self) -> View {
        View::new()
            .title(
                format!("Finding {}", self.finding_id),
                Some(tone::finding_status(self.status)),
            )
            .fields(vec![
                ("Reason".into(), Cell::plain(&self.reason)),
                ("Note".into(), Cell::muted(&self.note)),
            ])
    }
}
