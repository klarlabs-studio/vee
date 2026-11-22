//! Views for cross-repository documents: the local dependency map, change
//! packages and cross-repository impact.

use crate::tone;
use crate::view::{Cell, ToView, Tone, View};
use crate::views::governance::limitations_view;
use vee_application::repository_map::{
    ChangePackage, ChangePackageRepository, CrossRepositoryImpact, RepositoryMap,
};

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

impl ToView for RepositoryMap {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                format!(
                    "Repository map ({}, {})",
                    plural(self.repositories.len(), "repository", "repositories"),
                    plural(self.dependencies.len(), "direct edge", "direct edges")
                ),
                None,
            )
            .fields(vec![("Digest".into(), Cell::id(&self.digest))])
            .section("Repositories");
        view = if self.repositories.is_empty() {
            view.paragraph(Cell::muted("No repositories were mapped."))
        } else {
            view.table(
                &["Repository", "Ecosystem", "Manifest", "Root"],
                self.repositories
                    .iter()
                    .map(|repository| {
                        vec![
                            Cell::strong(&repository.id),
                            Cell::plain(&repository.ecosystem),
                            Cell::code(&repository.manifest),
                            Cell::code(&repository.root),
                        ]
                    })
                    .collect(),
            )
        };
        view = view.section(format!("Dependencies ({})", self.dependencies.len()));
        view = if self.dependencies.is_empty() {
            view.paragraph(Cell::muted(
                "No direct dependencies between these repositories.",
            ))
        } else {
            view.table(
                &["From", "To", "Package", "Kind", "Version", "Evidence"],
                self.dependencies
                    .iter()
                    .map(|edge| {
                        vec![
                            Cell::strong(&edge.from),
                            Cell::strong(&edge.to),
                            Cell::code(&edge.package),
                            Cell::plain(&edge.kind),
                            version_compatibility(&edge.version_compatibility),
                            Cell::id(&edge.evidence_digest),
                        ]
                    })
                    .collect(),
            )
        };
        view.extend(limitations_view(&self.limitations))
    }
}

fn version_compatibility(value: &str) -> Cell {
    let tone = match value {
        "satisfied" => Tone::Success,
        "mismatch" | "invalid_requirement" | "invalid_package_version" => Tone::Danger,
        "unknown" => Tone::Warning,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, value)
}

fn readiness(value: &str) -> Cell {
    let tone = match value {
        "ready" => Tone::Success,
        "blocked" => Tone::Danger,
        _ => Tone::Warning,
    };
    Cell::badge(tone, value)
}

fn pull_request_state(state: &str) -> Cell {
    let tone = match state {
        "open" => Tone::Info,
        "merged" => Tone::Success,
        _ => Tone::Neutral,
    };
    Cell::badge(tone, state)
}

fn pull_request_rows(repository: &ChangePackageRepository) -> Vec<Vec<Cell>> {
    repository
        .pull_requests
        .iter()
        .map(|reference| {
            let name = Cell::code(format!(
                "{}/{}#{}",
                reference.repository.host, reference.repository.full_name, reference.number
            ));
            let remote = repository
                .remote_pull_requests
                .iter()
                .find(|remote| remote.pull_request == *reference);
            let (state, revision, head) = match remote {
                Some(remote) => (
                    pull_request_state(&remote.state),
                    Cell::code(&remote.revision),
                    if remote.local_head_matches {
                        Cell::badge(Tone::Success, "matches")
                    } else {
                        Cell::badge(Tone::Warning, "differs")
                    },
                ),
                None => (
                    Cell::muted("not refreshed"),
                    Cell::muted("—"),
                    Cell::muted("—"),
                ),
            };
            let source = if repository.discovered_pull_requests.contains(reference) {
                Cell::plain("discovered")
            } else {
                Cell::plain("linked")
            };
            vec![
                Cell::strong(&repository.repository_id),
                name,
                source,
                state,
                revision,
                head,
            ]
        })
        .collect()
}

impl ToView for ChangePackage {
    fn to_view(&self) -> View {
        let lifecycle = &self.pull_request_lifecycle;
        let mut view = View::new()
            .title(
                format!("Change package {}", self.package_id),
                Some(readiness(&self.readiness)),
            )
            .fields(vec![
                (
                    "Repositories".into(),
                    Cell::plain(self.repositories.len().to_string()),
                ),
                (
                    "Priority order".into(),
                    Cell::plain(self.priority_order.join(" → ")),
                ),
                (
                    "Local dependency edges".into(),
                    Cell::plain(self.dependency_edges.len().to_string()),
                ),
                (
                    "Pull requests".into(),
                    Cell::plain(format!(
                        "{} ({} linked, {} refreshed)",
                        lifecycle.status.replace('_', " "),
                        lifecycle.linked_count,
                        lifecycle.refreshed_count
                    )),
                ),
                (
                    "Dependency map".into(),
                    Cell::id(&self.dependency_map_digest),
                ),
            ])
            .section("Repositories");
        view = if self.repositories.is_empty() {
            view.paragraph(Cell::muted("No repositories in this package."))
        } else {
            view.table(
                &[
                    "Repository",
                    "Branch",
                    "Root",
                    "Changed files",
                    "Gate",
                    "Validity",
                ],
                self.repositories
                    .iter()
                    .map(|repository| {
                        vec![
                            Cell::strong(&repository.repository_id),
                            repository
                                .branch
                                .as_deref()
                                .map_or_else(|| Cell::muted("detached"), Cell::plain),
                            Cell::code(&repository.root),
                            Cell::plain(repository.changed_files.len().to_string()),
                            tone::status_text(&repository.saved_gate_status),
                            Cell::plain(repository.gate_validity.replace('_', " ")),
                        ]
                    })
                    .collect(),
            )
        };
        let changes: Vec<Vec<Cell>> = self
            .repositories
            .iter()
            .flat_map(|repository| {
                repository.changed_files.iter().map(|file| {
                    vec![
                        Cell::strong(&repository.repository_id),
                        tone::status_text(&file.status),
                        Cell::code(&file.path),
                    ]
                })
            })
            .collect();
        view = view.section(format!("Changed files ({})", changes.len()));
        view = if changes.is_empty() {
            view.paragraph(Cell::muted("No changed files in these repositories."))
        } else {
            view.table(&["Repository", "Status", "Path"], changes)
        };
        let pull_requests: Vec<Vec<Cell>> = self
            .repositories
            .iter()
            .flat_map(pull_request_rows)
            .collect();
        if !pull_requests.is_empty() {
            view = view
                .section(format!("Pull requests ({})", pull_requests.len()))
                .table(
                    &[
                        "Repository",
                        "Pull request",
                        "Source",
                        "State",
                        "Revision",
                        "Local head",
                    ],
                    pull_requests,
                );
        }
        view.extend(limitations_view(&self.limitations))
    }
}

impl ToView for CrossRepositoryImpact {
    fn to_view(&self) -> View {
        let coverage = if self.coverage_complete {
            Cell::badge(Tone::Success, "complete")
        } else {
            Cell::badge(Tone::Warning, "incomplete")
        };
        let mut view = View::new()
            .title("Cross-repository impact", Some(coverage))
            .fields(vec![
                (
                    "Producer snapshot".into(),
                    Cell::code(&self.producer_snapshot_id),
                ),
                (
                    "Changed symbols".into(),
                    if self.changed_symbols.is_empty() {
                        Cell::muted("none")
                    } else {
                        Cell::code(self.changed_symbols.join(", "))
                    },
                ),
                ("Digest".into(), Cell::id(&self.digest)),
            ]);
        if !self.coverage_complete {
            view = view.note(
                Tone::Warning,
                "Coverage is incomplete; consumers may reference changes this analysis missed.",
            );
        }
        view = view.section(format!("References ({})", self.references.len()));
        view = if self.references.is_empty() {
            view.paragraph(Cell::muted(
                "No consumer references to the changed symbols.",
            ))
        } else {
            view.table(
                &["Location", "Symbol", "Certainty", "Dependency"],
                self.references
                    .iter()
                    .map(|reference| {
                        vec![
                            Cell::code(format!(
                                "{}:{}:{}",
                                reference.consumer_repository, reference.path, reference.line
                            )),
                            Cell::code(&reference.symbol),
                            Cell::plain(reference.certainty.replace('_', " ")),
                            tone::status_text(&reference.dependency_status),
                        ]
                    })
                    .collect(),
            )
        };
        if !self.dependency_paths.is_empty() {
            view = view
                .section(format!(
                    "Dependency paths ({})",
                    self.dependency_paths.len()
                ))
                .table(
                    &["Packages", "Manifest digests"],
                    self.dependency_paths
                        .iter()
                        .map(|path| {
                            vec![
                                Cell::code(path.packages.join(" → ")),
                                Cell::id(path.manifest_digests.join(", ")),
                            ]
                        })
                        .collect(),
                );
        }
        if !self.api_contract_changes.is_empty() {
            view = view
                .section(format!(
                    "API contract changes ({})",
                    self.api_contract_changes.len()
                ))
                .table(
                    &["Operation", "Operation ID", "Contract"],
                    self.api_contract_changes
                        .iter()
                        .map(|change| {
                            vec![
                                Cell::code(format!("{} {}", change.method, change.route)),
                                Cell::code(&change.operation_id),
                                Cell::code(&change.producer_path),
                            ]
                        })
                        .collect(),
                );
        }
        if !self.api_contract_compatibility.is_empty() {
            view = view
                .section(format!(
                    "API compatibility issues ({})",
                    self.api_contract_compatibility.len()
                ))
                .table(
                    &["Issue", "Operation", "Contract"],
                    self.api_contract_compatibility
                        .iter()
                        .map(|issue| {
                            vec![
                                Cell::badge(Tone::Danger, issue.issue.replace('_', " ")),
                                Cell::code(format!("{} {}", issue.method, issue.route)),
                                Cell::code(&issue.producer_path),
                            ]
                        })
                        .collect(),
                );
        }
        if !self.api_contract_coverage.is_empty() {
            view = view
                .section(format!(
                    "API contract coverage ({})",
                    self.api_contract_coverage.len()
                ))
                .table(
                    &["Operation", "Status", "Not analyzed"],
                    self.api_contract_coverage
                        .iter()
                        .map(|coverage| {
                            vec![
                                Cell::code(format!("{} {}", coverage.method, coverage.route)),
                                tone::status_text(&coverage.status),
                                Cell::plain(coverage.not_analyzed.join(", ")),
                            ]
                        })
                        .collect(),
                );
        }
        view.extend(limitations_view(&self.limitations))
    }
}
