//! Views for review records: evidence bundles, attestations, signing keys,
//! imported review archives, coverage and acceptance validation.

use crate::tone;
use crate::view::{summary, Cell, Span, Style, ToView, Tone, View};
use crate::views::governance::limitations_view;
use crate::views::verification::verification_status;
use vee_application::acceptance::{AcceptanceValidation, ValidatedCriterion};
use vee_application::attestation::AttestationVerification;
use vee_application::coverage::{CoverageReport, FileCoverage};
use vee_application::evidence_bundle::{BundleBindings, BundleVerification, SignedBundle};
use vee_application::imported_history::{
    ImportedArchiveEntry, ImportedArchiveList, ImportedReview,
};
use vee_application::signing::SigningKeyPair;

const SUMMARY_WIDTH: usize = 56;
const UNTRUSTED_NOTE: &str =
    "Imported history is untrusted external context; it is excluded from gate evaluation.";

/// `path` as one shell word, quoted only when it needs to be.
fn shell_word(path: &str) -> String {
    let safe = !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@%+=,".contains(c));
    if safe {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', r"'\''"))
    }
}

fn yes_no(value: bool) -> Cell {
    Cell::plain(if value { "yes" } else { "no" })
}

/// A JSON value from a signed statement: its text, or a placeholder when absent.
fn statement_text(value: &serde_json::Value) -> Cell {
    match value.as_str() {
        Some(text) => Cell::plain(text),
        None if value.is_null() => Cell::muted("not stated"),
        None => Cell::plain(value.to_string()),
    }
}

impl ToView for AttestationVerification {
    fn to_view(&self) -> View {
        let Some(verified) = self.verified.as_ref().filter(|_| self.valid) else {
            return View::new()
                .title(
                    "Attestation verification",
                    Some(Cell::badge(Tone::Danger, "rejected")),
                )
                .note(Tone::Danger, self.message.as_str());
        };
        let gate = match verified.gate_status.as_str() {
            Some(status) => tone::status_text(status),
            None => statement_text(&verified.gate_status),
        };
        let mut view = View::new()
            .title(
                "Attestation verification",
                Some(Cell::badge(Tone::Success, "verified")),
            )
            .fields(vec![
                ("Gate".into(), gate),
                (
                    "Decision".into(),
                    match verified.decision_id.as_str() {
                        Some(id) => Cell::id(id),
                        None => statement_text(&verified.decision_id),
                    },
                ),
                ("Signed by".into(), Cell::code(&verified.key_id)),
            ]);
        let subjects: Vec<Cell> = verified
            .subjects
            .as_array()
            .into_iter()
            .flatten()
            .map(|subject| {
                let name = subject["name"].as_str().unwrap_or("unnamed subject");
                let digests = subject["digest"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(algorithm, value)| {
                        format!("{algorithm}:{}", value.as_str().unwrap_or_default())
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let cell = Cell::code(name);
                if digests.is_empty() {
                    cell
                } else {
                    cell.then(Span::new(digests, Style::Id))
                }
            })
            .collect();
        view = view.section(format!("Subjects ({})", subjects.len()));
        view = if subjects.is_empty() {
            view.paragraph(Cell::muted("The statement names no subjects."))
        } else {
            view.list(subjects)
        };
        view.note(Tone::Info, self.message.as_str())
    }
}

fn replay_cell(bindings: &BundleBindings) -> Cell {
    match bindings.replay_matches {
        Some(true) => Cell::badge(Tone::Success, "matches"),
        Some(false) => Cell::badge(Tone::Danger, "differs"),
        None => Cell::badge(Tone::Warning, &bindings.replay_status),
    }
}

impl ToView for BundleVerification {
    fn to_view(&self) -> View {
        let badge = if !self.valid {
            Cell::badge(Tone::Danger, "invalid")
        } else if self.passed() {
            Cell::badge(Tone::Success, "valid")
        } else {
            Cell::badge(Tone::Danger, "replay mismatch")
        };
        let view = View::new().title("Evidence bundle verification", Some(badge));
        let Some(bindings) = self.bindings.as_ref().filter(|_| self.valid) else {
            return view.note(Tone::Danger, self.message.as_str());
        };
        let mut view = view
            .fields(vec![
                ("Review".into(), Cell::id(&bindings.review_id)),
                ("Snapshot".into(), Cell::code(&bindings.snapshot_id)),
                ("Gate".into(), tone::status_text(&bindings.gate_status)),
                ("Manifest".into(), Cell::id(&bindings.manifest_digest)),
                (
                    "Signature".into(),
                    if bindings.signature_valid {
                        Cell::badge(Tone::Success, "verified")
                    } else {
                        Cell::badge(Tone::Warning, "unsigned")
                    },
                ),
                ("Gate replay".into(), replay_cell(bindings)),
            ])
            .note(
                if bindings.signature_valid {
                    Tone::Info
                } else {
                    Tone::Warning
                },
                self.message.as_str(),
            )
            .note(
                match bindings.replay_matches {
                    Some(true) => Tone::Info,
                    Some(false) => Tone::Danger,
                    None => Tone::Warning,
                },
                bindings.replay_message.as_str(),
            );
        if self.passed() && !bindings.signature_valid {
            view = view.next_step(
                "vee reviews sign-bundle <bundle> --private-key <private-key> --key-id <key-id>",
            );
        }
        view
    }
}

impl ToView for SignedBundle {
    fn to_view(&self) -> View {
        View::new()
            .title(
                "Evidence bundle signed",
                Some(Cell::badge(Tone::Success, "signed")),
            )
            .fields(vec![
                ("Bundle".into(), Cell::code(&self.path)),
                ("Key ID".into(), Cell::code(&self.key_id)),
                ("Algorithm".into(), Cell::plain(&self.algorithm)),
                ("Manifest".into(), Cell::id(&self.manifest_digest)),
            ])
            .paragraph(Cell::plain(format!(
                "Signed evidence bundle with Ed25519 key {}.",
                self.key_id
            )))
            .next_step(format!(
                "vee reviews verify-bundle {} --public-key <public-key>",
                shell_word(&self.path)
            ))
    }
}

impl ToView for SigningKeyPair {
    fn to_view(&self) -> View {
        View::new()
            .title("Signing key pair generated", None)
            .fields(vec![
                ("Algorithm".into(), Cell::plain(&self.algorithm)),
                ("Private key".into(), Cell::code(&self.private_key)),
                ("Public key".into(), Cell::code(&self.public_key)),
            ])
            .note(
                Tone::Warning,
                format!(
                    "Keep {} private and distribute {} to verifiers.",
                    self.private_key, self.public_key
                ),
            )
            .next_step(format!(
                "vee reviews sign-bundle <bundle> --private-key {} --key-id <key-id>",
                shell_word(&self.private_key)
            ))
    }
}

impl ToView for ImportedReview {
    fn to_view(&self) -> View {
        View::new()
            .title(
                format!("Imported review {}", self.review_id),
                Some(Cell::badge(Tone::Warning, &self.trust)),
            )
            .fields(vec![
                ("Archive".into(), Cell::id(&self.archive_digest)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Status".into(), tone::status_text(&self.status)),
                ("Gate eligible".into(), yes_no(self.gate_eligible)),
            ])
            .note(Tone::Info, UNTRUSTED_NOTE)
            .next_step(format!("vee reviews imported show {}", self.archive_digest))
            .next_action(
                "vee reviews imported search <query>",
                "search_imported_review_history",
                serde_json::json!({ "query": "<query>" }),
            )
    }
}

fn archive_row(entry: &ImportedArchiveEntry) -> Vec<Cell> {
    match entry {
        ImportedArchiveEntry::Review {
            archive_digest,
            review_id,
            status,
            trust,
            ..
        } => vec![
            Cell::id(archive_digest),
            Cell::plain("review"),
            Cell::id(review_id),
            tone::status_text(status),
            Cell::plain(trust),
        ],
        ImportedArchiveEntry::ProviderDiscussions {
            archive_digest,
            provider,
            pull_request,
            complete,
            issue_count,
            trust,
            ..
        } => vec![
            Cell::id(archive_digest),
            Cell::plain(format!("{provider} discussion")),
            Cell::plain(format!(
                "{} #{}",
                pull_request.repository.full_name, pull_request.number
            )),
            Cell::plain(format!("{issue_count} issues")).then(if *complete {
                Span::new("complete", Style::Muted)
            } else {
                Span::new("partial", Style::Badge(Tone::Warning))
            }),
            Cell::plain(trust),
        ],
    }
}

impl ToView for ImportedArchiveList {
    fn to_view(&self) -> View {
        let view = View::new().title(
            format!("Imported review archives ({})", self.reviews.len()),
            None,
        );
        if self.reviews.is_empty() {
            return view
                .paragraph(Cell::muted("No imported review archives."))
                .next_step("vee reviews import <path>");
        }
        let mut view = view
            .table(
                &["Archive", "Type", "Source", "Contents", "Trust"],
                self.reviews.iter().map(archive_row).collect(),
            )
            .note(Tone::Info, UNTRUSTED_NOTE);
        if let Some(first) = self.reviews.first() {
            view = view.next_step(format!(
                "vee reviews imported show {}",
                first.archive_digest()
            ));
        }
        view
    }
}

fn percent(value: Option<f64>, covered: Option<u64>, total: Option<u64>) -> Cell {
    match (value, covered, total) {
        (Some(value), Some(covered), Some(total)) => {
            Cell::plain(format!("{value:.1}% ({covered}/{total})"))
        }
        (Some(value), _, _) => Cell::plain(format!("{value:.1}%")),
        (None, _, Some(0)) => Cell::muted("no executable lines"),
        (None, _, _) => Cell::muted("not measured"),
    }
}

fn coverage_row(file: &FileCoverage) -> Vec<Cell> {
    vec![
        Cell::code(&file.path),
        percent(
            file.percent,
            Some(file.covered_lines),
            Some(file.executable_lines),
        ),
        percent(
            file.changed_percent,
            file.changed_covered_lines,
            file.changed_executable_lines,
        ),
        file.changed_line_count.map_or_else(
            || Cell::muted("unknown"),
            |count| Cell::plain(count.to_string()),
        ),
    ]
}

impl ToView for CoverageReport {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Coverage for changed files ({})", self.files.len()),
                None,
            )
            .fields(vec![
                ("Run".into(), Cell::id(&self.run_id)),
                ("Profile".into(), Cell::plain(&self.profile_id)),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Stream".into(), Cell::plain(&self.stream)),
            ]);
        view = if self.files.is_empty() {
            view.paragraph(Cell::muted(
                "No changed files appear in the coverage report.",
            ))
        } else {
            view.table(
                &[
                    "File",
                    "File coverage",
                    "Changed-line coverage",
                    "Changed lines",
                ],
                self.files.iter().map(coverage_row).collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
    }
}

fn acceptance_result(result: &str) -> Cell {
    let (tone, label) = match result {
        "all_attested_met" => (Tone::Success, "all attested met"),
        "attention_required" => (Tone::Danger, "attention required"),
        "evidence_incomplete" => (Tone::Warning, "evidence incomplete"),
        "incomplete" => (Tone::Warning, "incomplete"),
        other => (Tone::Neutral, other),
    };
    Cell::badge(tone, label)
}

fn assessment(criterion: &ValidatedCriterion) -> Cell {
    match criterion.assessment.as_deref() {
        Some("met") => Cell::badge(Tone::Success, "met"),
        Some("not_met") => Cell::badge(Tone::Danger, "not met"),
        Some("uncertain") => Cell::badge(Tone::Warning, "uncertain"),
        Some(other) => Cell::badge(Tone::Neutral, other),
        None => Cell::badge(Tone::Warning, "unassessed"),
    }
}

fn criterion_details(view: View, criterion: &ValidatedCriterion) -> View {
    let mut view = view
        .section(format!("Criterion {}", criterion.id))
        .paragraph(Cell::plain(&criterion.text))
        .fields(vec![
            ("Assessment".into(), assessment(criterion)),
            (
                "Rationale".into(),
                criterion
                    .rationale
                    .clone()
                    .map(Cell::plain)
                    .unwrap_or_default(),
            ),
            (
                "Source".into(),
                criterion
                    .source_id
                    .clone()
                    .map(Cell::code)
                    .unwrap_or_default(),
            ),
        ]);
    let mut evidence: Vec<Cell> = criterion
        .changed_paths
        .iter()
        .map(|path| Cell::muted("path").then(Span::new(path, Style::Code)))
        .collect();
    evidence.extend(criterion.verification_runs.iter().map(|run| {
        verification_status(run.status).spans.into_iter().fold(
            Cell::muted("verification")
                .then(Span::new(&run.run_id, Style::Id))
                .then(Span::new(&run.profile_id, Style::Plain)),
            Cell::then,
        )
    }));
    view = view.list(evidence);
    if !criterion.evidence_satisfied {
        for reason in &criterion.evidence_reasons {
            view = view.note(Tone::Warning, format!("Evidence required: {reason}"));
        }
    }
    view
}

impl ToView for AcceptanceValidation {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!("Acceptance assessment for review {}", self.review_id),
                Some(acceptance_result(&self.result)),
            )
            .fields(vec![
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Gate".into(), tone::status_text(&self.gate_status)),
                ("Policy".into(), Cell::id(&self.policy_digest)),
                ("Work item".into(), Cell::id(&self.work_item_digest)),
                ("Author".into(), Cell::plain(&self.author)),
                ("Recorded at".into(), Cell::plain(&self.recorded_at)),
                (
                    "Assessment complete".into(),
                    yes_no(self.assessment_complete),
                ),
            ])
            .note(
                Tone::Info,
                "The result is a human attestation of traceability, not behavioral proof.",
            )
            .section(format!("Criteria ({})", self.criteria.len()));
        if self.criteria.is_empty() {
            view = view.paragraph(Cell::muted("The work item has no acceptance criteria."));
        } else {
            view = view.table(
                &["Criterion", "Assessment", "Evidence", "Text"],
                self.criteria
                    .iter()
                    .map(|criterion| {
                        vec![
                            Cell::id(&criterion.id),
                            assessment(criterion),
                            if criterion.evidence_satisfied {
                                Cell::badge(Tone::Success, "satisfied")
                            } else {
                                Cell::badge(Tone::Warning, "required")
                            },
                            Cell::plain(summary(&criterion.text, SUMMARY_WIDTH)),
                        ]
                    })
                    .collect(),
            );
            for criterion in &self.criteria {
                view = criterion_details(view, criterion);
            }
        }
        view.extend(limitations_view(&self.limitations))
    }
}
