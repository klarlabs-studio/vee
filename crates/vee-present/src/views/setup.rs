use crate::view::{Cell, Span, Style, ToView, Tone, View};
use vee_application::setup::{DetectionReport, DoctorReport, InitReport};

impl ToView for DetectionReport {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(
                "AI backends on this machine",
                Some(match self.recommended {
                    Some(_) => Cell::badge(Tone::Success, "ready to configure"),
                    None => Cell::badge(Tone::Warning, "none configurable"),
                }),
            )
            .paragraph(Cell::muted(
                "Preference order: local model, agent CLIs, API keys.",
            ));
        view.extend(backends_table(self))
    }
}

fn backends_table(report: &DetectionReport) -> View {
    let mut view = View::new().table(
        &["", "Backend", "Kind", "Egress", "Detail"],
        report
            .candidates
            .iter()
            .map(|candidate| {
                let state =
                    if report.recommended.as_deref() == Some(candidate.candidate_id.as_str()) {
                        Cell::badge(Tone::Success, "recommended")
                    } else if candidate.available {
                        Cell::badge(Tone::Info, "available")
                    } else {
                        Cell::badge(Tone::Neutral, "unavailable")
                    };
                let detail = if candidate.available {
                    let mut parts: Vec<String> = candidate.detail.iter().cloned().collect();
                    if !candidate.models.is_empty() {
                        parts.push(format!("models: {}", candidate.models.join(", ")));
                    }
                    if candidate.requires_model {
                        parts.push("needs --model".into());
                    }
                    Cell::plain(parts.join("; "))
                } else {
                    Cell::muted(candidate.reason.clone().unwrap_or_default())
                };
                vec![
                    state,
                    Cell::strong(&candidate.candidate_id),
                    Cell::plain(&candidate.kind),
                    Cell::plain(&candidate.egress),
                    detail,
                ]
            })
            .collect(),
    );
    view = match &report.recommended {
        Some(recommended) => view.next_step(format!("vee init --provider {recommended}")),
        None => view.paragraph(Cell::muted("No backend can be configured automatically.")),
    };
    view
}

impl ToView for DoctorReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                "Vee setup",
                Some(if self.ready {
                    Cell::badge(Tone::Success, "ready to review")
                } else {
                    Cell::badge(Tone::Danger, "not ready")
                }),
            )
            .fields(vec![
                (
                    "Repository config".into(),
                    Cell::code(&self.repository_config).then(if self.config_valid {
                        Span::new("valid", Style::Badge(Tone::Success))
                    } else {
                        Span::new("invalid", Style::Badge(Tone::Danger))
                    }),
                ),
                (
                    "User config".into(),
                    match &self.user_config {
                        Some(path) if self.user_config_exists => Cell::code(path),
                        Some(path) => {
                            Cell::code(path).then(Span::new("not created yet", Style::Muted))
                        }
                        None => Cell::muted("location unknown (set VEE_CONFIG)"),
                    },
                ),
                (
                    "Offline mode".into(),
                    if self.offline {
                        Cell::plain("on: network providers are rejected")
                    } else {
                        Cell::muted("off")
                    },
                ),
            ]);
        if let Some(error) = &self.config_error {
            view = view.note(Tone::Danger, error.as_str());
        }
        view = view.section("Reviewers");
        if self.reviewers.is_empty() {
            view = view.paragraph(Cell::muted("No reviewers configured."));
        } else {
            view = view.table(
                &["", "Reviewer", "Role", "Provider", "Notes"],
                self.reviewers
                    .iter()
                    .map(|check| {
                        let notes: Vec<&str> = check
                            .problem
                            .iter()
                            .chain(check.detail.iter())
                            .map(String::as_str)
                            .collect();
                        vec![
                            if check.usable {
                                Cell::badge(Tone::Success, "ok")
                            } else if check.required {
                                Cell::badge(Tone::Danger, "fails")
                            } else {
                                Cell::badge(Tone::Warning, "fails")
                            },
                            Cell::strong(&check.reviewer_id),
                            if check.required {
                                Cell::plain("required")
                            } else {
                                Cell::muted("optional")
                            },
                            Cell::plain(format!(
                                "{} · {} · {} egress",
                                check.provider_id, check.kind, check.egress
                            )),
                            Cell::plain(notes.join("; ")),
                        ]
                    })
                    .collect(),
            );
        }
        view = view
            .section("AI backends")
            .extend(backends_table(&self.detection));
        for step in &self.next_steps {
            view = view.next_step(step.as_str());
        }
        view
    }
}

/// Where to read how to get the best reviews from Vee.
pub const BEST_RESULTS_GUIDE: &str =
    "https://github.com/klarlabs-studio/vee/blob/main/docs/guides/best-results.md";

impl ToView for InitReport {
    fn to_view(&self) -> View {
        let created = |written: bool, path: &str| {
            Cell::code(path).then(if written {
                Span::new("created", Style::Badge(Tone::Success))
            } else {
                Span::new("already present", Style::Muted)
            })
        };
        let provider = match (self.provider_status.as_str(), self.candidate_id.as_deref()) {
            ("written", Some(candidate)) => Cell::strong(&self.provider_id)
                .then(Span::new("configured", Style::Badge(Tone::Success)))
                .then(Span::new(format!("from {candidate}"), Style::Muted)),
            _ => {
                Cell::strong(&self.provider_id).then(Span::new("already configured", Style::Muted))
            }
        };
        View::new()
            .title("Vee initialized", Some(Cell::badge(Tone::Success, "ready")))
            .fields(vec![
                (
                    "Repository config".into(),
                    created(
                        self.repository_config_status == "written",
                        &self.repository_config,
                    ),
                ),
                (
                    "Reviewer guide".into(),
                    created(
                        self.reviewer_instructions_created,
                        &self.reviewer_instructions,
                    ),
                ),
                ("Provider".into(), provider),
                ("Egress".into(), Cell::plain(&self.egress)),
                (
                    "Review effort".into(),
                    match self.effort {
                        Some(effort) => Cell::plain(effort_label(effort)),
                        None => Cell::muted("set by each reviewer (one run unless configured)"),
                    },
                ),
                ("User config".into(), Cell::code(&self.user_config)),
            ])
            .paragraph(Cell::muted(format!(
                "How to get the best results: {BEST_RESULTS_GUIDE}"
            )))
            .next_action("vee doctor", "check_setup", serde_json::json!({}))
            .next_action(
                "vee review",
                "review_changes",
                serde_json::json!({"scope": "working_tree"}),
            )
    }
}

fn effort_label(effort: vee_core::ReviewEffort) -> String {
    let (name, runs) = match effort {
        vee_core::ReviewEffort::Low => ("low", "one run"),
        vee_core::ReviewEffort::Medium => ("medium", "three runs"),
        vee_core::ReviewEffort::High => ("high", "five runs"),
    };
    format!("{name} ({runs} per reviewer)")
}

impl ToView for vee_application::hooks::GitHook {
    fn to_view(&self) -> View {
        use vee_application::hooks::HookState;
        let badge = match self.state {
            HookState::Installed => Cell::badge(Tone::Success, "installed"),
            HookState::Missing => Cell::badge(Tone::Neutral, "not installed"),
            HookState::Other => Cell::badge(Tone::Warning, "another tool's hook"),
        };
        View::new()
            .title(format!("Git {} hook", self.hook), Some(badge))
            .fields(vec![
                ("Result".into(), Cell::plain(&self.message)),
                ("Path".into(), Cell::plain(self.path.display().to_string())),
            ])
    }
}
