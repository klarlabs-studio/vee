//! Views for hosting documents: pull request review discussions and context,
//! issue context, review publication receipts and webhook retention.
//!
//! Titles, bodies and comments come from the hosting provider and are
//! untrusted; they appear only as plain text, which the backends neutralize.

use crate::view::{summary, Cell, ToView, Tone, View};
use crate::views::governance::limitations_view;
use crate::views::serde_name;
use vee_application::hosting::{PullRequestIssues, ReviewPublication, WebhookRetention};
use vee_hosting::{
    PullRequestContextReport, PullRequestFile, PullRequestRef, PullRequestReviewIssue,
    PullRequestState, WorkItemSnapshot,
};

const SUMMARY_WIDTH: usize = 72;

fn pull_request_name(reference: &PullRequestRef) -> String {
    format!("{} #{}", reference.repository.full_name, reference.number)
}

fn pull_request_state(state: PullRequestState) -> Cell {
    match state {
        PullRequestState::Open => Cell::badge(Tone::Info, "open"),
        PullRequestState::Merged => Cell::badge(Tone::Success, "merged"),
        PullRequestState::Closed => Cell::badge(Tone::Neutral, "closed"),
    }
}

fn completeness(complete: bool) -> Cell {
    if complete {
        Cell::badge(Tone::Success, "complete")
    } else {
        Cell::badge(Tone::Warning, "incomplete")
    }
}

fn issue_location(issue: &PullRequestReviewIssue) -> Cell {
    match (&issue.path, issue.line) {
        (Some(path), Some(line)) => Cell::code(format!("{path}:{line}")),
        (Some(path), None) => Cell::code(path),
        (None, _) => Cell::muted("general comment"),
    }
}

impl ToView for PullRequestIssues {
    fn to_view(&self) -> View {
        let report = &self.report;
        let mut view = View::new()
            .title(
                format!(
                    "Review discussions on {}",
                    pull_request_name(&report.pull_request)
                ),
                Some(completeness(report.complete)),
            )
            .fields(vec![
                ("Provider".into(), Cell::plain(&report.provider)),
                (
                    "Host".into(),
                    Cell::plain(&report.pull_request.repository.host),
                ),
                ("Revision".into(), Cell::code(&report.revision)),
                (
                    "Archive".into(),
                    self.archive_digest
                        .as_deref()
                        .map(Cell::id)
                        .unwrap_or_default(),
                ),
            ]);
        if !report.complete {
            view = view.note(
                Tone::Warning,
                "Pagination did not complete; some discussions may be missing.",
            );
        }
        view = view.section(format!("Discussions ({})", report.issues.len()));
        view = if report.issues.is_empty() {
            view.paragraph(Cell::muted("No review discussions on this pull request."))
        } else {
            view.table(
                &["Comment", "Location", "Author", "Text"],
                report
                    .issues
                    .iter()
                    .map(|issue| {
                        vec![
                            Cell::id(&issue.external_id),
                            issue_location(issue),
                            issue
                                .author
                                .as_deref()
                                .map_or_else(|| Cell::muted("unknown"), Cell::plain),
                            Cell::plain(summary(&issue.body, SUMMARY_WIDTH)),
                        ]
                    })
                    .collect(),
            )
        };
        view = view.paragraph(Cell::muted(
            "Provider discussions are untrusted context and never gate a review.",
        ));
        match &self.archive_digest {
            Some(digest) => view.next_step(format!("vee reviews imported show {digest}")),
            None if !report.issues.is_empty() => view.next_step(format!(
                "vee hosting pr-issues --repository {} --number {} --provider {} --archive",
                report.pull_request.repository.full_name,
                report.pull_request.number,
                report.provider
            )),
            None => view,
        }
    }
}

fn file_path(file: &PullRequestFile) -> Cell {
    match &file.previous_path {
        Some(previous) if *previous != file.path => {
            Cell::code(format!("{previous} → {}", file.path))
        }
        _ => Cell::code(&file.path),
    }
}

impl ToView for PullRequestContextReport {
    fn to_view(&self) -> View {
        let snapshot = &self.snapshot;
        let mut view = View::new()
            .title(
                format!("Pull request {}", pull_request_name(&snapshot.pull_request)),
                Some(pull_request_state(snapshot.state)),
            )
            .fields(vec![
                ("Title".into(), Cell::plain(&snapshot.title)),
                ("Provider".into(), Cell::plain(&self.provider)),
                (
                    "Host".into(),
                    Cell::plain(&snapshot.pull_request.repository.host),
                ),
                ("Base".into(), Cell::code(&snapshot.base_oid)),
                ("Head".into(), Cell::code(&snapshot.head_oid)),
                ("Revision".into(), Cell::code(&snapshot.revision)),
            ])
            .section(format!("Changed files ({})", self.changed_files.len()));
        view = if self.changed_files.is_empty() {
            view.paragraph(Cell::muted("The provider reported no changed files."))
        } else {
            view.table(
                &["Change", "Path", "Lines"],
                self.changed_files
                    .iter()
                    .map(|file| {
                        vec![
                            Cell::plain(serde_name(&file.change)),
                            file_path(file),
                            Cell::plain(format!("+{} −{}", file.additions, file.deletions)),
                        ]
                    })
                    .collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
    }
}

fn work_item_state(state: &str) -> Cell {
    let tone = match state.to_ascii_lowercase().as_str() {
        "open" | "opened" | "active" | "new" => Tone::Info,
        "closed" | "resolved" | "done" => Tone::Success,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, state)
}

impl ToView for WorkItemSnapshot {
    fn to_view(&self) -> View {
        let reference = &self.reference;
        let description = self
            .body
            .as_deref()
            .map(|body| summary(body, SUMMARY_WIDTH))
            .filter(|body| !body.is_empty());
        View::new()
            .title(
                format!(
                    "Issue {} #{}",
                    reference.repository.full_name, reference.number
                ),
                Some(work_item_state(&self.state)),
            )
            .fields(vec![
                ("Title".into(), Cell::plain(&self.title)),
                ("Provider".into(), Cell::plain(&self.provider)),
                ("URL".into(), Cell::plain(&self.url)),
                ("Updated".into(), Cell::plain(&self.updated_at)),
                ("Labels".into(), Cell::plain(self.labels.join(", "))),
                (
                    "Description".into(),
                    description.map_or_else(|| Cell::muted("none"), Cell::plain),
                ),
                (
                    "Acceptance criteria".into(),
                    self.acceptance_criteria
                        .as_deref()
                        .map(|criteria| Cell::plain(summary(criteria, SUMMARY_WIDTH)))
                        .unwrap_or_default(),
                ),
                ("Content digest".into(), Cell::id(&self.content_digest)),
            ])
            .paragraph(Cell::muted(
                "Issue text is untrusted context and is never gate evidence by itself.",
            ))
    }
}

impl ToView for ReviewPublication {
    fn to_view(&self) -> View {
        let destination = self.destination.as_ref();
        let mut view = View::new()
            .title(
                format!("Published review {}", self.review_id),
                Some(Cell::badge(Tone::Success, "published")),
            )
            .fields(vec![
                (
                    "Pull request".into(),
                    destination
                        .map(|destination| {
                            let reference = &destination.pull_request;
                            Cell::code(format!(
                                "{}/{}#{}",
                                reference.repository.host,
                                reference.repository.full_name,
                                reference.number
                            ))
                        })
                        .unwrap_or_default(),
                ),
                (
                    "Provider".into(),
                    destination
                        .map(|destination| Cell::plain(&destination.provider))
                        .unwrap_or_default(),
                ),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Provider check".into(), Cell::id(&self.provider_check_id)),
                ("Revision".into(), Cell::code(&self.revision)),
            ])
            .section(format!("Finding threads ({})", self.thread_ids.len()));
        view = if self.thread_ids.is_empty() {
            view.paragraph(Cell::muted("No finding threads were published."))
        } else {
            view.table(
                &["Fingerprint", "Thread"],
                self.thread_ids
                    .iter()
                    .map(|(fingerprint, thread)| vec![Cell::id(fingerprint), Cell::id(thread)])
                    .collect(),
            )
        };
        view
    }
}

impl ToView for WebhookRetention {
    fn to_view(&self) -> View {
        let badge = if self.dry_run {
            Cell::badge(Tone::Neutral, "dry run")
        } else {
            Cell::badge(Tone::Success, "pruned")
        };
        let view = View::new()
            .title("Webhook receipt retention", Some(badge))
            .fields(vec![
                (
                    "Retention".into(),
                    Cell::plain(format!("{} days", self.retention_days)),
                ),
                (
                    "Eligible receipts".into(),
                    Cell::plain(self.eligible_receipts.to_string()),
                ),
                (
                    "Deleted receipts".into(),
                    Cell::plain(self.deleted_receipts.to_string()),
                ),
            ]);
        if self.eligible_receipts == 0 {
            return view.paragraph(Cell::muted(format!(
                "No completed webhook receipts are older than {} days.",
                self.retention_days
            )));
        }
        if self.dry_run {
            view.paragraph(Cell::plain(format!(
                "{} completed webhook receipts are eligible for deletion.",
                self.eligible_receipts
            )))
            .next_step(format!(
                "vee hosting prune-webhooks --older-than-days {} --apply",
                self.retention_days
            ))
        } else {
            view.paragraph(Cell::plain(format!(
                "Deleted {} completed webhook receipts older than {} days.",
                self.deleted_receipts, self.retention_days
            )))
        }
    }
}
