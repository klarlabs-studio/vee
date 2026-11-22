//! Views for generated-test documents: impacted-test plans, test patch
//! proposals, their application and trusted runs, and mutation effectiveness.

use crate::tone;
use crate::view::{Block, Cell, Span, Style, ToView, Tone, View};
use crate::views::governance::limitations_view;
use crate::views::verification::verification_status;
use vee_application::test_effectiveness::{
    CorpusEffectivenessReport, CoverageRunProvenance, EffectivenessReport, MutantFileCoverage,
};
use vee_application::test_proposals::{
    PersistedAssessment, TestPatchProposal, TestProposalApplication, TestProposalVerification,
};
use vee_application::ImpactedTestPlan;
use vee_core::VerificationStatus;

/// One argument as a shell reader would type it: bare when it is safe, quoted otherwise.
fn shell_word(argument: &str) -> String {
    let safe = !argument.is_empty()
        && argument.chars().all(|character| {
            character.is_ascii_alphanumeric() || "-_./:=@+,%{}".contains(character)
        });
    if safe {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', r"'\''"))
    }
}

impl ToView for ImpactedTestPlan {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Impacted test plan for {}", self.profile_id),
                Some(Cell::badge(Tone::Info, "not run")),
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Profile".into(), Cell::plain(&self.profile_id)),
                ("Profile digest".into(), Cell::id(&self.profile_digest)),
                ("Executable".into(), Cell::code(&self.executable)),
                (
                    "Impact coverage".into(),
                    if self.impact_coverage_complete {
                        Cell::badge(Tone::Success, "complete")
                    } else {
                        Cell::badge(Tone::Warning, "incomplete")
                    },
                ),
            ])
            .section(format!("Commands ({})", self.invocations.len()));
        view = if self.invocations.is_empty() {
            view.paragraph(Cell::muted("No test command would run for this change."))
        } else {
            view.list(
                self.invocations
                    .iter()
                    .map(|arguments| {
                        let words = std::iter::once(self.executable.as_str())
                            .chain(arguments.iter().map(String::as_str))
                            .map(shell_word)
                            .collect::<Vec<_>>();
                        Cell::code(words.join(" "))
                    })
                    .collect(),
            )
        };
        view = view.section(format!("Targets ({})", self.targets.len()));
        view = if self.targets.is_empty() {
            view.paragraph(Cell::muted("No impacted test targets."))
        } else {
            view.list(self.targets.iter().map(Cell::code).collect())
        };
        view.extend(limitations_view(&self.limitations))
            .note(
                Tone::Info,
                "No commands were executed; this is a preview of the trusted profile.",
            )
            .next_step(format!(
                "vee verify --profile {} --impacted-tests",
                self.profile_id
            ))
    }
}

fn application_status(application: &str) -> Cell {
    match application {
        "applied" => Cell::badge(Tone::Success, "applied"),
        "not_applied" => Cell::badge(Tone::Info, "not applied"),
        other => tone::status_text(other),
    }
}

fn context_completeness(summary: &serde_json::Value) -> Cell {
    match summary["context_complete"].as_bool() {
        Some(true) => Cell::plain("complete"),
        Some(false) => Cell::badge(Tone::Warning, "partial"),
        None => Cell::default(),
    }
}

fn context_budget(summary: &serde_json::Value) -> Cell {
    let budget = &summary["context_budget"];
    match (
        budget["estimated_prompt_tokens"].as_u64(),
        budget["max_context_tokens"].as_u64(),
    ) {
        (Some(estimated), Some(max)) => {
            Cell::plain(format!("{estimated} of {max} estimated tokens"))
        }
        _ => Cell::default(),
    }
}

impl ToView for TestPatchProposal {
    fn to_view(&self) -> View {
        let title = if self.refinement.is_some() {
            "Refined test proposal"
        } else {
            "Test proposal"
        };
        let mut fields = vec![
            ("Proposal".into(), Cell::id(&self.proposal_id)),
            ("Patch digest".into(), Cell::id(&self.patch_digest)),
            ("Snapshot".into(), Cell::code(&self.snapshot_id)),
            ("Scope".into(), Cell::plain(&self.source_scope)),
            ("Reviewer".into(), Cell::plain(&self.reviewer_id)),
            (
                "Provider".into(),
                Cell::plain(match &self.model {
                    Some(model) => format!("{} ({model})", self.provider_id),
                    None => self.provider_id.clone(),
                }),
            ),
            (
                "Context".into(),
                context_completeness(&self.context_summary),
            ),
            (
                "Context budget".into(),
                context_budget(&self.context_summary),
            ),
            (
                "Sandbox".into(),
                if self.validated_in_isolated_sandbox {
                    Cell::badge(Tone::Success, "validated in isolated copy")
                } else {
                    Cell::badge(Tone::Danger, "not validated")
                },
            ),
            ("Saved at".into(), Cell::code(&self.patch_path)),
        ];
        if let Some(refinement) = &self.refinement {
            fields.push(("Refines".into(), Cell::id(&refinement.parent_proposal_id)));
            fields.push(("Failed run".into(), Cell::id(&refinement.failed_run_id)));
            fields.push((
                "Attempt".into(),
                Cell::plain(refinement.attempt.to_string()),
            ));
        }
        let mut view = View::new()
            .title(title, Some(application_status(&self.application)))
            .fields(fields);
        let executed = if self.tests_executed {
            "Tests have run against it."
        } else {
            "Tests were not run."
        };
        let applied = if self.application == "not_applied" {
            "Not applied: inspect the saved diff and approve it explicitly before running tests."
        } else {
            "Applied after explicit approval."
        };
        view = view.note(Tone::Info, format!("{applied} {executed}"));
        if matches!(self.source_scope.as_str(), "commit" | "commit_range") {
            view.note(
                Tone::Warning,
                "Commit-scope proposals are inspection-only and cannot be applied.",
            )
        } else if self.application == "not_applied" {
            view.next_step(format!(
                "vee tests apply {id} --approve {id}",
                id = self.proposal_id
            ))
        } else {
            view
        }
    }
}

impl ToView for TestProposalApplication {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(
                "Test proposal applied",
                Some(if self.concurrent_mutation_detected {
                    Cell::badge(Tone::Warning, "concurrent change")
                } else {
                    application_status(&self.application)
                }),
            )
            .fields(vec![
                ("Proposal".into(), Cell::id(&self.proposal_id)),
                ("Current snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Concurrent mutation".into(),
                    Cell::plain(if self.concurrent_mutation_detected {
                        "detected"
                    } else {
                        "none"
                    }),
                ),
            ]);
        if self.concurrent_mutation_detected {
            view.note(
                Tone::Warning,
                "Other files changed while the patch was applied; review the worktree. This proposal cannot be run; generate a new one.",
            )
            .next_step("vee tests generate")
        } else {
            view.next_step(format!(
                "vee tests run {} --profile <profile>",
                self.proposal_id
            ))
        }
    }
}

impl ToView for TestProposalVerification {
    fn to_view(&self) -> View {
        let run = &self.verification_run;
        let mut view = View::new().title(
            format!("Test proposal verification {}", run.profile_id),
            Some(verification_status(run.status)),
        );
        // The run's own view without its title, with the proposal leading its fields.
        let proposal = ("Proposal".to_owned(), Cell::id(&self.proposal_id));
        let mut blocks = run.to_view().blocks.into_iter().skip(1).peekable();
        match blocks.peek_mut() {
            Some(Block::Fields(fields)) => fields.insert(0, proposal),
            _ => view = view.fields(vec![proposal]),
        }
        view.blocks.extend(blocks);
        match run.status {
            VerificationStatus::Passed => view.next_step(format!(
                "vee tests effectiveness {} --profile {} --mutant-patch <patch>",
                self.proposal_id, run.profile_id
            )),
            VerificationStatus::Failed => view.next_step(format!(
                "vee tests refine {} --run {}",
                self.proposal_id, run.run_id
            )),
            VerificationStatus::TimedOut | VerificationStatus::Incomplete => {
                view.next_step(format!("vee verification diagnose {}", run.run_id))
            }
        }
    }
}

fn outcome(outcome: &str) -> Cell {
    match outcome {
        "killed" => Cell::badge(Tone::Success, "killed"),
        "survived" => Cell::badge(Tone::Danger, "survived"),
        "inconclusive" => Cell::badge(Tone::Warning, "inconclusive"),
        other => tone::status_text(other),
    }
}

fn coverage_run(run: Option<&CoverageRunProvenance>) -> Cell {
    match run {
        Some(run) => Cell::id(&run.run_id).then(Span::new(&run.stream, Style::Muted)),
        None => Cell::muted("unavailable"),
    }
}

fn changed_lines(file: &MutantFileCoverage) -> Cell {
    match (file.changed_covered_lines, file.changed_executable_lines) {
        (Some(covered), Some(executable)) => Cell::plain(match file.changed_percent {
            Some(percent) => format!("{covered}/{executable} ({percent:.1}%)"),
            None => format!("{covered}/{executable}"),
        }),
        _ => Cell::muted("–"),
    }
}

fn mutated_files_view(paths: &[String], coverage: &[MutantFileCoverage]) -> View {
    let view = View::new().section(format!("Mutated files ({})", paths.len()));
    if paths.is_empty() {
        return view.paragraph(Cell::muted("The mutant changed no production files."));
    }
    view.table(
        &["File", "Changed lines covered"],
        paths
            .iter()
            .map(|path| {
                vec![
                    Cell::code(path),
                    coverage
                        .iter()
                        .find(|file| &file.path == path)
                        .map_or_else(|| Cell::muted("–"), changed_lines),
                ]
            })
            .collect(),
    )
}

fn artifact_view<R>(assessment: &PersistedAssessment<R>) -> View {
    View::new().section("Saved report").fields(vec![
        ("Path".into(), Cell::code(&assessment.artifact_path)),
        ("Digest".into(), Cell::id(&assessment.artifact_digest)),
    ])
}

impl ToView for EffectivenessReport {
    fn to_view(&self) -> View {
        View::new()
            .title("Mutation effectiveness", Some(outcome(&self.outcome)))
            .fields(vec![
                ("Proposal".into(), Cell::id(&self.proposal_id)),
                ("Profile".into(), Cell::plain(&self.profile_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Baseline".into(),
                    tone::status_text(&self.baseline_status)
                        .then(Span::new(&self.baseline_verification_run_id, Style::Id)),
                ),
                ("Mutant".into(), Cell::plain(&self.mutated_status)),
                (
                    "Failure signal".into(),
                    self.mutant_failure_signal
                        .clone()
                        .map(Cell::plain)
                        .unwrap_or_default(),
                ),
                ("Mutant patch".into(), Cell::id(&self.mutant_patch_digest)),
                (
                    "Mutant snapshot".into(),
                    Cell::code(&self.mutant_snapshot_id),
                ),
                (
                    "Coverage run".into(),
                    coverage_run(self.coverage_run.as_ref()),
                ),
            ])
            .extend(mutated_files_view(
                &self.mutant_paths,
                &self.changed_line_coverage,
            ))
            .extend(limitations_view(&self.limitations))
    }
}

impl ToView for PersistedAssessment<EffectivenessReport> {
    fn to_view(&self) -> View {
        self.report.to_view().extend(artifact_view(self))
    }
}

fn corpus_badge(report: &CorpusEffectivenessReport) -> Cell {
    let label = format!("{}/{} killed", report.killed, report.sample_size);
    let tone = if report.sample_size == 0 || report.inconclusive == report.sample_size {
        Tone::Warning
    } else if report.survived > 0 {
        Tone::Danger
    } else if report.inconclusive > 0 {
        Tone::Warning
    } else {
        Tone::Success
    };
    Cell::badge(tone, label)
}

impl ToView for CorpusEffectivenessReport {
    fn to_view(&self) -> View {
        let provenance = &self.provenance;
        let view = View::new()
            .title(
                format!("Mutant corpus {}", self.corpus_id),
                Some(corpus_badge(self)),
            )
            .fields(vec![
                (
                    "Outcomes".into(),
                    Cell::plain(format!(
                        "{} killed, {} survived, {} inconclusive of {}",
                        self.killed, self.survived, self.inconclusive, self.sample_size
                    )),
                ),
                ("Proposal".into(), Cell::id(&self.proposal_id)),
                ("Profile".into(), Cell::plain(&self.profile_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                (
                    "Baseline run".into(),
                    Cell::id(&self.baseline_verification_run_id),
                ),
                ("Corpus digest".into(), Cell::id(&self.corpus_digest)),
                ("Dataset".into(), Cell::plain(&provenance.dataset_kind)),
                (
                    "Source".into(),
                    match (&provenance.source, &provenance.source_revision) {
                        (Some(source), Some(revision)) => {
                            Cell::plain(source).then(Span::new(revision, Style::Code))
                        }
                        (Some(source), None) => Cell::plain(source),
                        (None, _) => Cell::default(),
                    },
                ),
                (
                    "License".into(),
                    provenance
                        .license
                        .clone()
                        .map(Cell::plain)
                        .unwrap_or_default(),
                ),
                (
                    "Coverage run".into(),
                    coverage_run(self.coverage_run.as_ref()),
                ),
            ])
            .section(format!("Mutants ({})", self.results.len()));
        let view = if self.results.is_empty() {
            view.paragraph(Cell::muted("The corpus has no mutants."))
        } else {
            view.table(
                &[
                    "Outcome", "Mutant", "Baseline", "Mutated", "Files", "Signal",
                ],
                self.results
                    .iter()
                    .map(|result| {
                        vec![
                            outcome(&result.outcome),
                            Cell::code(&result.id),
                            Cell::plain(&result.baseline_status),
                            Cell::plain(&result.mutated_status),
                            Cell::plain(if result.mutant_paths.is_empty() {
                                "–".to_owned()
                            } else {
                                result.mutant_paths.join(", ")
                            }),
                            result
                                .mutant_failure_signal
                                .clone()
                                .map_or_else(|| Cell::muted("–"), Cell::plain),
                        ]
                    })
                    .collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
    }
}

impl ToView for PersistedAssessment<CorpusEffectivenessReport> {
    fn to_view(&self) -> View {
        self.report.to_view().extend(artifact_view(self))
    }
}
