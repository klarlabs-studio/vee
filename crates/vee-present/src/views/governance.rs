//! Views for governance documents: standards, rule guidance, ownership,
//! policy packs and acceptance traceability.

use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::serde_name;
use crate::views::verification::verification_status;
use vee_application::acceptance::AcceptanceReport;
use vee_application::ownership::OwnershipReport;
use vee_application::packs::PackList;
use vee_application::rule_candidates::{
    CandidateReport, EffectivenessWindow, RuleEffectivenessReport,
};
use vee_application::standards::StandardsReport;

const SUMMARY_WIDTH: usize = 56;

/// A "Limitations" section listing each limitation, or nothing when there are none.
pub(crate) fn limitations_view(limitations: &[String]) -> View {
    if limitations.is_empty() {
        return View::new();
    }
    View::new()
        .section("Limitations")
        .list(limitations.iter().map(Cell::plain).collect())
}

/// An observed rate as a percentage, or `n/a` when no eligible labels exist.
pub(crate) fn rate(rate: Option<f64>) -> String {
    rate.map_or_else(|| "n/a".to_owned(), |rate| format!("{:.1}%", rate * 100.0))
}

impl ToView for StandardsReport {
    fn to_view(&self) -> View {
        let title = match &self.target_path {
            Some(path) => format!("Applicable standards for {path}"),
            None => "Applicable standards".to_owned(),
        };
        let mut view = View::new()
            .title(title, None)
            .section(format!("Sources ({})", self.sources.len()));
        if self.sources.is_empty() {
            view = view.paragraph(Cell::muted("No standards found."));
        } else {
            view = view.table(
                &[
                    "Source",
                    "Kind",
                    "Precedence",
                    "Scope",
                    "Content",
                    "Integrity",
                ],
                self.sources
                    .iter()
                    .map(|source| {
                        vec![
                            Cell::code(&source.path),
                            Cell::plain(&source.kind),
                            Cell::plain(source.precedence.to_string()),
                            Cell::plain(&source.scope),
                            if source.truncated {
                                Cell::badge(Tone::Warning, "truncated")
                            } else {
                                Cell::plain("complete")
                            },
                            Cell::plain(&source.integrity),
                        ]
                    })
                    .collect(),
            );
        }
        for conflict in &self.potential_conflicts {
            view = view.note(Tone::Warning, format!("Potential conflict: {conflict}"));
        }
        view.extend(limitations_view(&self.limitations))
    }
}

impl ToView for CandidateReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(format!("Rule candidates ({})", self.candidates.len()), None)
            .fields(vec![
                (
                    "Disputed findings excluded".into(),
                    Cell::plain(self.disputed_findings_excluded.to_string()),
                ),
                (
                    "Disputed comments excluded".into(),
                    Cell::plain(self.disputed_external_comments_excluded.to_string()),
                ),
                (
                    "Feedback without saved finding".into(),
                    Cell::plain(self.feedback_without_saved_finding.to_string()),
                ),
            ]);
        if self.truncated {
            view = view.note(
                Tone::Warning,
                "The feedback history was truncated; candidates may be missing.",
            );
        }
        if self.candidates.is_empty() {
            view = view.paragraph(Cell::muted(
                "No repeated feedback patterns qualify as rule candidates.",
            ));
        } else {
            view = view
                .table(
                    &[
                        "Candidate",
                        "Sources",
                        "Category",
                        "Label",
                        "Source kind",
                        "Approval",
                        "Suggestion",
                    ],
                    self.candidates
                        .iter()
                        .map(|candidate| {
                            vec![
                                Cell::id(&candidate.candidate_id),
                                Cell::plain(format!(
                                    "{} distinct ({} events)",
                                    candidate.feedback_count, candidate.feedback_event_count
                                )),
                                Cell::plain(&candidate.category),
                                Cell::plain(serde_name(&candidate.feedback_label)),
                                Cell::plain(&candidate.source_kind),
                                tone::status_text(candidate.approval_status),
                                Cell::plain(summary(&candidate.suggestion, SUMMARY_WIDTH)),
                            ]
                        })
                        .collect(),
                )
                .section("Suggestions");
            for candidate in &self.candidates {
                view = view
                    .paragraph(
                        Cell::id(&candidate.candidate_id)
                            .then(Span::new(&candidate.suggestion, Style::Plain)),
                    )
                    .paragraph(
                        Cell::muted("evidence digest")
                            .then(Span::new(&candidate.evidence_digest, Style::Id)),
                    );
            }
        }
        view = view.extend(limitations_view(&self.limitations)).note(
            Tone::Info,
            "Suggestions require human review and are not active policy.",
        );
        if let Some(first) = self.candidates.first() {
            view = view.next_action(
                format!(
                    "vee rules approve {} --evidence-digest {} --scope <path> --instruction <guidance> --approver <name> --reason <why>",
                    first.candidate_id, first.evidence_digest
                ),
                "approve_rule_candidate",
                serde_json::json!({
                    "candidate_id": first.candidate_id,
                    "evidence_digest": first.evidence_digest,
                    "scope": "<path>",
                    "instruction": "<guidance>",
                    "approver": "<name>",
                    "reason": "<why>",
                }),
            );
        }
        view
    }
}

fn approval_status(status: &str) -> Cell {
    let tone = match status {
        "active" => Tone::Success,
        "expired" => Tone::Warning,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, status)
}

fn before_after(
    baseline: &EffectivenessWindow,
    later: &EffectivenessWindow,
    value: impl Fn(&EffectivenessWindow) -> String,
) -> Cell {
    Cell::plain(format!("{} → {}", value(baseline), value(later)))
}

impl ToView for RuleEffectivenessReport {
    fn to_view(&self) -> View {
        let mut view = View::new().title(
            format!("Rule effectiveness ({})", self.approvals.len()),
            None,
        );
        if self.approvals.is_empty() {
            return view
                .paragraph(Cell::muted("No rule approvals to evaluate."))
                .extend(limitations_view(&self.limitations))
                .next_action(
                    "vee rules candidates",
                    "list_rule_candidates",
                    serde_json::json!({}),
                );
        }
        view = view
            .table(
                &[
                    "Approval",
                    "Version",
                    "Status",
                    "Accuracy labels",
                    "False-positive rate",
                    "Actionability labels",
                    "Not-actionable rate",
                ],
                self.approvals
                    .iter()
                    .map(|item| {
                        let (before, after) = (&item.baseline, &item.after_activation);
                        vec![
                            Cell::id(&item.approval_id),
                            Cell::plain(format!("v{}", item.version)),
                            approval_status(&item.status),
                            before_after(before, after, |window| {
                                window.accuracy_denominator.to_string()
                            }),
                            before_after(before, after, |window| rate(window.false_positive_rate)),
                            before_after(before, after, |window| {
                                window.actionability_denominator.to_string()
                            }),
                            before_after(before, after, |window| rate(window.not_actionable_rate)),
                        ]
                    })
                    .collect(),
            )
            .paragraph(Cell::muted(
                "Each column reads baseline → after activation.",
            ));
        let disputed: Vec<Cell> = self
            .approvals
            .iter()
            .filter(|item| {
                item.baseline.disputed_occurrences + item.after_activation.disputed_occurrences > 0
            })
            .map(|item| {
                Cell::id(&item.approval_id).then(Span::new(
                    format!(
                        "{} → {} disputed occurrences excluded",
                        item.baseline.disputed_occurrences,
                        item.after_activation.disputed_occurrences
                    ),
                    Style::Plain,
                ))
            })
            .collect();
        if !disputed.is_empty() {
            view = view.section("Disputed feedback").list(disputed);
        }
        view.extend(limitations_view(&self.limitations)).note(
            Tone::Info,
            "Observational comparison only; it does not establish that guidance caused an outcome.",
        )
    }
}

impl ToView for OwnershipReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Owners ({} paths)", self.results.len()),
                Some(if self.coverage_complete {
                    Cell::badge(Tone::Success, "complete")
                } else {
                    Cell::badge(Tone::Warning, "incomplete")
                }),
            )
            .fields(vec![
                (
                    "Ownership rules".into(),
                    match &self.codeowners_path {
                        Some(path) => Cell::code(path).then(Span::new(
                            self.codeowners_digest.as_deref().unwrap_or("no digest"),
                            Style::Id,
                        )),
                        None => Cell::muted("none found"),
                    },
                ),
                ("Repository".into(), Cell::code(&self.repository_root)),
                ("Report digest".into(), Cell::id(&self.digest)),
            ]);
        if self.advisory_only {
            view = view.note(
                Tone::Info,
                "Advisory only: ownership is routing context, not authorization or gate approval.",
            );
        }
        if self.results.is_empty() {
            view = view.paragraph(Cell::muted("No paths resolved."));
        } else {
            view = view.table(
                &["Path", "Status", "Owners", "Rule"],
                self.results
                    .iter()
                    .map(|result| {
                        let rule = match (&result.matching_pattern, result.matching_rule_line) {
                            (Some(pattern), Some(line)) => Cell::code(pattern)
                                .then(Span::new(format!("line {line}"), Style::Muted)),
                            (Some(pattern), None) => Cell::code(pattern),
                            (None, _) => Cell::muted("no matching rule"),
                        };
                        vec![
                            Cell::code(&result.path),
                            tone::status_text(&result.status),
                            if result.owners.is_empty() {
                                Cell::muted("none")
                            } else {
                                Cell::plain(result.owners.join(", "))
                            },
                            rule,
                        ]
                    })
                    .collect(),
            );
        }
        view.extend(limitations_view(&self.limitations))
    }
}

fn pack_status(status: &str) -> Cell {
    let tone = match status {
        "ok" => Tone::Success,
        "changed" => Tone::Warning,
        "invalid" => Tone::Danger,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, status)
}

impl ToView for PackList {
    fn to_view(&self) -> View {
        let mismatched = self.packs.iter().filter(|pack| pack.status != "ok").count();
        let badge = match (self.packs.is_empty(), mismatched) {
            (true, _) => None,
            (false, 0) => Some(Cell::badge(Tone::Success, "all match their pins")),
            (false, count) => Some(Cell::badge(
                Tone::Danger,
                format!("{count} differ from their pins"),
            )),
        };
        let mut view = View::new().title(format!("Pinned packs ({})", self.packs.len()), badge);
        if self.packs.is_empty() {
            return view.paragraph(Cell::muted("No packs are pinned in .vee.yaml."));
        }
        view = view.table(
            &["Status", "Pack", "Path", "Provider", "Pinned digest"],
            self.packs
                .iter()
                .map(|pack| {
                    let name = match &pack.name {
                        Some(name) => Cell::strong(name),
                        None => Cell::muted("unknown"),
                    };
                    vec![
                        pack_status(&pack.status),
                        name.then(match &pack.version {
                            Some(version) => Span::new(version, Style::Plain),
                            None => Span::new("?", Style::Muted),
                        }),
                        Cell::code(&pack.path),
                        Cell::plain(&pack.provider),
                        Cell::id(&pack.pinned_digest),
                    ]
                })
                .collect(),
        );
        for pack in &self.packs {
            if let Some(problem) = &pack.problem {
                let tone = if pack.status == "invalid" {
                    Tone::Danger
                } else {
                    Tone::Warning
                };
                view = view.note(
                    tone,
                    Cell::code(&pack.path).then(Span::new(problem, Style::Plain)),
                );
            }
        }
        if mismatched > 0 {
            view = view
                .paragraph(Cell::muted(
                    "Configuration loading fails until a human re-pins each changed or invalid pack.",
                ))
                .next_step("vee packs add <pack-directory> --replace");
        }
        view
    }
}

impl ToView for AcceptanceReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Acceptance traceability for review {}", self.review_id),
                None,
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Work item".into(),
                    match &self.work_item {
                        Some(item) => {
                            Cell::code(&item.url).then(Span::new(&item.content_digest, Style::Id))
                        }
                        None => Cell::muted("none"),
                    },
                ),
                (
                    "Changed paths".into(),
                    Cell::plain(self.changed_paths.len().to_string()),
                ),
                (
                    "Impact snapshot".into(),
                    self.impact_snapshot_id
                        .clone()
                        .map(Cell::code)
                        .unwrap_or_default(),
                ),
                (
                    "Impact coverage".into(),
                    match self.impact_coverage_complete {
                        Some(true) => Cell::badge(Tone::Success, "complete"),
                        Some(false) => Cell::badge(Tone::Warning, "incomplete"),
                        None => Cell::default(),
                    },
                ),
            ])
            .section(format!("Criteria ({})", self.criteria.len()));
        if self.criteria.is_empty() {
            view = view.paragraph(Cell::muted(
                "No supported acceptance criteria were extracted.",
            ));
        } else {
            view = view.table(
                &["Criterion", "Line", "Status", "Paths", "Tests", "Text"],
                self.criteria
                    .iter()
                    .map(|criterion| {
                        vec![
                            Cell::id(&criterion.id),
                            Cell::plain(criterion.source_line.to_string()),
                            tone::status_text(criterion.status),
                            Cell::plain(criterion.candidate_changed_paths.len().to_string()),
                            Cell::plain(criterion.candidate_test_references.len().to_string()),
                            Cell::plain(summary(&criterion.text, SUMMARY_WIDTH)),
                        ]
                    })
                    .collect(),
            );
            for criterion in &self.criteria {
                view = view
                    .section(format!("Criterion {}", criterion.id))
                    .paragraph(Cell::plain(&criterion.text));
                let mut evidence: Vec<Cell> = criterion
                    .candidate_changed_paths
                    .iter()
                    .map(|path| Cell::muted("changed").then(Span::new(path, Style::Code)))
                    .collect();
                evidence.extend(criterion.candidate_test_references.iter().map(|reference| {
                    Cell::muted("likely test")
                        .then(Span::new(
                            format!("{}:{}", reference.test_path, reference.evidence_line),
                            Style::Code,
                        ))
                        .then(Span::new(
                            format!(
                                "{} for {} ({})",
                                reference.symbol, reference.changed_path, reference.certainty
                            ),
                            Style::Plain,
                        ))
                }));
                view = if evidence.is_empty() {
                    view.paragraph(Cell::muted("No candidate changed paths."))
                } else {
                    view.list(evidence)
                };
            }
        }
        view = view.section(format!(
            "Snapshot-bound verification runs ({})",
            self.verification_runs.len()
        ));
        if self.verification_runs.is_empty() {
            view = view.paragraph(Cell::muted(
                "No verification runs recorded for this snapshot.",
            ));
        } else {
            view = view.table(
                &["Run", "Profile", "Status", "Targets"],
                self.verification_runs
                    .iter()
                    .map(|run| {
                        vec![
                            Cell::id(&run.run_id),
                            Cell::plain(&run.profile_id),
                            verification_status(run.status),
                            if run.targets.is_empty() {
                                Cell::muted("none")
                            } else {
                                Cell::code(run.targets.join(", "))
                            },
                        ]
                    })
                    .collect(),
            );
        }
        if !self.impact_analyzers.is_empty() {
            view = view.section("Impact analyzers").table(
                &["Analyzer", "Version", "Status"],
                self.impact_analyzers
                    .iter()
                    .map(|analyzer| {
                        vec![
                            Cell::plain(&analyzer.id),
                            analyzer
                                .version
                                .clone()
                                .map_or_else(|| Cell::muted("unknown"), Cell::plain),
                            tone::status_text(&analyzer.status),
                        ]
                    })
                    .collect(),
            );
        }
        view = view.extend(limitations_view(&self.limitations));
        if !self.criteria.is_empty() {
            view = view.next_step(format!(
                "vee acceptance validate --review {} --mapping <mapping-file>",
                self.review_id
            ));
        }
        view
    }
}
