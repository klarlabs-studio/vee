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

impl ToView for vee_core::Waiver {
    fn to_view(&self) -> View {
        View::new()
            .title(
                format!("Waiver {}", self.id),
                Some(Cell::badge(Tone::Warning, "waived")),
            )
            .fields(vec![
                ("Finding".into(), Cell::id(&self.finding_fingerprint)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Author".into(), Cell::plain(&self.author)),
                ("Reason".into(), Cell::plain(&self.reason)),
                (
                    "Created (unix)".into(),
                    Cell::plain(self.created_at_unix.to_string()),
                ),
                (
                    "Expires (unix)".into(),
                    Cell::plain(self.expires_at_unix.to_string()),
                ),
                ("Provenance".into(), Cell::muted(&self.provenance)),
            ])
            .note(
                Tone::Info,
                "The waiver covers only this finding in this snapshot, until it expires.",
            )
    }
}

impl ToView for vee_application::ApprovalEligibility {
    fn to_view(&self) -> View {
        let badge = if self.eligible {
            Cell::badge(Tone::Success, "eligible")
        } else {
            Cell::badge(Tone::Warning, "needs a human")
        };
        View::new()
            .title("Approval", Some(badge))
            .fields(vec![
                ("Review".into(), Cell::id(&self.review_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
            ])
            .section("Stages")
            .table(
                &["Stage", "Result", "Reason"],
                self.stages
                    .iter()
                    .map(|stage| {
                        vec![
                            Cell::plain(&stage.id),
                            if stage.passed {
                                Cell::badge(Tone::Success, "passed")
                            } else {
                                Cell::badge(Tone::Danger, "failed")
                            },
                            Cell::plain(&stage.detail),
                        ]
                    })
                    .collect(),
            )
    }
}

impl ToView for vee_application::ReviewSession {
    fn to_view(&self) -> View {
        let verdict = match self.verdict.as_str() {
            "pass" => Cell::badge(Tone::Success, "pass"),
            "block" => Cell::badge(Tone::Danger, "block"),
            _ => Cell::badge(Tone::Warning, "incomplete"),
        };
        let gate = |status: &str| match status {
            "pass" => Cell::badge(Tone::Success, "pass"),
            "block" => Cell::badge(Tone::Danger, "block"),
            _ => Cell::badge(Tone::Warning, "incomplete"),
        };
        let mut view = View::new()
            .title(
                format!("Review session ({} changes)", self.reviews.len()),
                Some(verdict),
            )
            .fields(vec![
                (
                    "Open findings".into(),
                    Cell::plain(self.open_findings.to_string()),
                ),
                (
                    "Approval eligible".into(),
                    Cell::plain(format!(
                        "{} of {}",
                        self.approval_eligible,
                        self.reviews.len()
                    )),
                ),
            ])
            .section("Changes")
            .table(
                &[
                    "Review",
                    "Gate",
                    "Current",
                    "Risk",
                    "Open findings",
                    "Approval",
                ],
                self.reviews
                    .iter()
                    .map(|review| {
                        let findings = if review.open_findings.is_empty() {
                            Cell::muted("none")
                        } else {
                            Cell::plain(
                                review
                                    .open_findings
                                    .iter()
                                    .map(|(severity, count)| format!("{count} {severity}"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            )
                        };
                        vec![
                            Cell::id(&review.review_id),
                            gate(&review.gate),
                            Cell::plain(if review.snapshot_current {
                                "yes"
                            } else {
                                "moved"
                            }),
                            review.risk_tier.map_or_else(
                                || Cell::muted("unknown"),
                                |tier| Cell::plain(tier.as_str()),
                            ),
                            findings,
                            Cell::plain(if review.approval_eligible {
                                "eligible"
                            } else {
                                "needs a human"
                            }),
                        ]
                    })
                    .collect(),
            );
        let reasons: Vec<Cell> = self
            .reviews
            .iter()
            .flat_map(|review| {
                review
                    .reasons
                    .iter()
                    .map(move |reason| Cell::plain(format!("{}: {reason}", review.review_id)))
            })
            .collect();
        if !reasons.is_empty() {
            view = view.section("Reasons").list(reasons);
        }
        view
    }
}
