//! Read-only reviewer tools over the review snapshot (ADR 0017).
//!
//! A reviewer may list, read and search files of the snapshot it reviews,
//! nothing else: reads go through the snapshot readers (captured bytes for
//! changed files, Git objects for unchanged ones), never the working tree.
//! Every result counts against per-request budgets, and every call is logged
//! so the review record can show what the reviewer read.

use crate::review::{glob_matches, review_path_is_included};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use vee_core::{ChangeSet, ReviewConfig, EXPLORATION_DENIED_PATHS};

/// Version of the tool contract; part of the review cache key.
const TOOL_CONTRACT_VERSION: u32 = 1;
const DEFAULT_LIST_LIMIT: usize = 200;
const MAX_LIST_LIMIT: usize = 1000;
const DEFAULT_SEARCH_LIMIT: usize = 50;
const MAX_SEARCH_LIMIT: usize = 200;
const SEARCH_MATCHES_PER_FILE: usize = 20;
const MAX_MATCH_LINE_CHARS: usize = 300;
/// A file may be read in line ranges up to this multiple of the per-file
/// context limit; larger files are searched instead.
const MAX_READ_FILE_FACTOR: usize = 8;

/// Everything the snapshot tool server needs, written by the review for the
/// server process it starts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplorationSpec {
    pub root: PathBuf,
    pub change_set: ChangeSet,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub deny: Vec<String>,
    /// The reviewer's own `include` and `exclude`, applied on top of the
    /// repository filter, so exploration reads no more than the reviewer may.
    #[serde(default)]
    pub reviewer_include: Vec<String>,
    #[serde(default)]
    pub reviewer_exclude: Vec<String>,
    pub max_tool_calls: usize,
    pub max_read_bytes: usize,
    pub max_file_bytes: usize,
}

impl ExplorationSpec {
    pub fn new(root: &Path, change_set: &ChangeSet, review: &ReviewConfig) -> Self {
        let mut deny = EXPLORATION_DENIED_PATHS
            .iter()
            .map(|pattern| pattern.to_string())
            .collect::<Vec<_>>();
        deny.extend(review.exploration.deny.iter().cloned());
        Self {
            root: root.to_path_buf(),
            change_set: change_set.clone(),
            include: review.include.clone(),
            exclude: review.exclude.clone(),
            deny,
            reviewer_include: Vec::new(),
            reviewer_exclude: Vec::new(),
            max_tool_calls: review.exploration.max_tool_calls,
            max_read_bytes: review.exploration.max_read_bytes,
            max_file_bytes: review.max_context_file_bytes,
        }
    }

    /// This spec narrowed to what `reviewer` may read.
    pub fn for_reviewer(mut self, reviewer: &vee_core::ReviewerConfig) -> Self {
        self.reviewer_include = reviewer.include.clone();
        self.reviewer_exclude = reviewer.exclude.clone();
        self
    }

    /// The contract and limits, without per-run paths or the snapshot (the
    /// request already carries the snapshot), for the review cache key.
    pub fn descriptor(&self) -> String {
        serde_json::json!({
            "tool_contract_version": TOOL_CONTRACT_VERSION,
            "include": self.include,
            "exclude": self.exclude,
            "deny": self.deny,
            "reviewer_include": self.reviewer_include,
            "reviewer_exclude": self.reviewer_exclude,
            "max_tool_calls": self.max_tool_calls,
            "max_read_bytes": self.max_read_bytes,
            "max_file_bytes": self.max_file_bytes,
        })
        .to_string()
    }

    fn is_readable(&self, path: &str) -> bool {
        let review = ReviewConfig {
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            ..ReviewConfig::default()
        };
        let reviewer_allows = !self
            .reviewer_exclude
            .iter()
            .any(|pattern| glob_matches(pattern, path))
            && (self.reviewer_include.is_empty()
                || self
                    .reviewer_include
                    .iter()
                    .any(|pattern| glob_matches(pattern, path)));
        review_path_is_included(path, &review) && reviewer_allows && !self.is_denied(path)
    }

    fn is_denied(&self, path: &str) -> bool {
        self.deny.iter().any(|pattern| {
            glob_matches(pattern, path)
                || (!pattern.contains('/') && glob_matches(&format!("**/{pattern}"), path))
        })
    }
}

/// One tool call, as recorded in the review.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExplorationCall {
    pub tool: String,
    pub arguments: serde_json::Value,
    /// Files whose text the result contained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Bytes of the result counted against the read budget.
    pub bytes: usize,
    /// `ok`, `denied`, `not_found`, `binary`, `invalid` or `budget_exhausted`.
    pub outcome: String,
}

/// A tool result: text for the model plus its log entry.
struct Outcome {
    text: String,
    paths: Vec<String>,
    outcome: &'static str,
}

impl Outcome {
    fn ok(text: String, paths: Vec<String>) -> Self {
        Self {
            text,
            paths,
            outcome: "ok",
        }
    }

    fn refused(outcome: &'static str, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            paths: Vec::new(),
            outcome,
        }
    }
}

pub struct SnapshotExplorer {
    spec: ExplorationSpec,
    paths: Option<Vec<String>>,
    read_bytes: usize,
    calls: Vec<ExplorationCall>,
}

impl SnapshotExplorer {
    pub fn new(spec: ExplorationSpec) -> Self {
        Self {
            spec,
            paths: None,
            read_bytes: 0,
            calls: Vec::new(),
        }
    }

    pub fn calls(&self) -> &[ExplorationCall] {
        &self.calls
    }

    /// Tracked snapshot paths matching `glob` (all when absent).
    pub fn list_files(&mut self, glob: Option<&str>, limit: Option<usize>) -> String {
        let arguments = serde_json::json!({ "glob": glob, "limit": limit });
        self.call("list_files", arguments, |explorer| {
            let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT);
            let all = explorer.snapshot_paths()?.to_vec();
            let matching = all
                .iter()
                .filter(|path| explorer.spec.is_readable(path))
                .filter(|path| glob.is_none_or(|glob| glob_matches(glob, path)))
                .cloned()
                .collect::<Vec<_>>();
            let shown = matching.len().min(limit);
            let mut text = format!("{shown} of {} matching snapshot paths\n", matching.len());
            for path in &matching[..shown] {
                text.push_str(path);
                text.push('\n');
            }
            Ok(Outcome::ok(text, Vec::new()))
        })
    }

    /// Lines `start_line..=end_line` (1-based, whole file when absent) of one
    /// snapshot file, numbered.
    pub fn read_file(
        &mut self,
        path: &str,
        start_line: Option<u64>,
        end_line: Option<u64>,
    ) -> String {
        let arguments =
            serde_json::json!({ "path": path, "start_line": start_line, "end_line": end_line });
        self.call("read_file", arguments, |explorer| {
            let path = match explorer.readable_path(path)? {
                Ok(path) => path,
                Err(refusal) => return Ok(refusal),
            };
            let Some(bytes) = vee_git::read_snapshot_file(
                &explorer.spec.root,
                &explorer.spec.change_set,
                Path::new(path.as_str()),
            )?
            else {
                return Ok(Outcome::refused("not_found", format!("{path} is not in the snapshot")));
            };
            if bytes.len() > MAX_READ_FILE_FACTOR * explorer.spec.max_file_bytes {
                return Ok(Outcome::refused(
                    "invalid",
                    format!("{path} is too large to read; search it for the lines you need"),
                ));
            }
            let Some(text) = source_text(bytes) else {
                return Ok(Outcome::refused("binary", format!("{path} is binary or not UTF-8")));
            };
            let start = start_line.unwrap_or(1).max(1);
            let end = end_line.unwrap_or(u64::MAX).max(start);
            let limit = explorer.spec.max_file_bytes.min(explorer.remaining_bytes());
            let mut body = String::new();
            let mut last_line = 0;
            let mut truncated = false;
            for (number, line) in (1u64..).zip(text.lines()) {
                if number < start {
                    continue;
                }
                if number > end {
                    break;
                }
                let numbered = format!("{number:>6}| {line}\n");
                if body.len() + numbered.len() > limit {
                    truncated = true;
                    break;
                }
                body.push_str(&numbered);
                last_line = number;
            }
            let mut result = format!("{path}\n{body}");
            if truncated {
                result.push_str(&format!(
                    "[truncated after line {last_line}; call read_file with start_line {} to continue]\n",
                    last_line + 1
                ));
            }
            Ok(Outcome::ok(result, vec![path]))
        })
    }

    /// Lines containing `pattern` (a fixed string) in snapshot files matching
    /// `glob` (all when absent).
    pub fn search(
        &mut self,
        pattern: &str,
        glob: Option<&str>,
        ignore_case: bool,
        limit: Option<usize>,
    ) -> String {
        let arguments = serde_json::json!({
            "pattern": pattern, "glob": glob, "ignore_case": ignore_case, "limit": limit,
        });
        self.call("search", arguments, |explorer| {
            if pattern.is_empty() || pattern.contains(['\n', '\0']) {
                return Ok(Outcome::refused(
                    "invalid",
                    "pattern must be one non-empty line",
                ));
            }
            let limit = limit
                .unwrap_or(DEFAULT_SEARCH_LIMIT)
                .clamp(1, MAX_SEARCH_LIMIT);
            let selected = |path: &str| {
                explorer.spec.is_readable(path) && glob.is_none_or(|glob| glob_matches(glob, path))
            };
            let change_set = &explorer.spec.change_set;
            let changed = |path: &str| change_set.files.iter().any(|file| file.path == path);
            let mut matches = Vec::new();
            // Unchanged files from the captured head tree, through `git grep`.
            if let Some(head) = change_set.head_oid.as_deref() {
                for found in vee_git::grep_tree(
                    &explorer.spec.root,
                    head,
                    pattern,
                    ignore_case,
                    SEARCH_MATCHES_PER_FILE,
                )? {
                    if !changed(&found.path) && selected(&found.path) {
                        matches.push((found.path, found.line, found.text));
                    }
                }
            }
            // Changed files from their captured, digest-checked bytes.
            let needle = if ignore_case {
                pattern.to_lowercase()
            } else {
                pattern.to_string()
            };
            for file in change_set
                .files
                .iter()
                .filter(|file| file.status != "deleted")
            {
                if !selected(&file.path) {
                    continue;
                }
                let Some(text) = vee_git::read_snapshot_file(
                    &explorer.spec.root,
                    change_set,
                    Path::new(file.path.as_str()),
                )?
                .and_then(source_text) else {
                    continue;
                };
                let found = (1u64..)
                    .zip(text.lines())
                    .filter(|(_, line)| {
                        if ignore_case {
                            line.to_lowercase().contains(&needle)
                        } else {
                            line.contains(&needle)
                        }
                    })
                    .take(SEARCH_MATCHES_PER_FILE);
                for (number, line) in found {
                    matches.push((file.path.clone(), number, line.to_string()));
                }
            }
            matches.sort();
            let total = matches.len();
            let budget = explorer.remaining_bytes();
            let mut text = String::new();
            let mut paths = Vec::new();
            let mut shown = 0;
            for (path, line, content) in matches.into_iter().take(limit) {
                let content: String = content
                    .trim_end()
                    .chars()
                    .take(MAX_MATCH_LINE_CHARS)
                    .collect();
                let entry = format!("{path}:{line}: {content}\n");
                if text.len() + entry.len() > budget {
                    break;
                }
                text.push_str(&entry);
                if paths.last() != Some(&path) {
                    paths.push(path);
                }
                shown += 1;
            }
            paths.dedup();
            Ok(Outcome::ok(
                format!("{shown} of {total} matching lines\n{text}"),
                paths,
            ))
        })
    }

    /// Run one tool call within the budgets and log it.
    fn call(
        &mut self,
        tool: &str,
        arguments: serde_json::Value,
        run: impl FnOnce(&mut Self) -> Result<Outcome, String>,
    ) -> String {
        let outcome = if self.calls.len() >= self.spec.max_tool_calls || self.remaining_bytes() == 0
        {
            Outcome::refused(
                "budget_exhausted",
                "Exploration budget exhausted. Finish the review with the context you already have.",
            )
        } else {
            run(self).unwrap_or_else(|error| Outcome::refused("invalid", error))
        };
        let bytes = if outcome.outcome == "ok" {
            outcome.text.len()
        } else {
            0
        };
        self.read_bytes = self.read_bytes.saturating_add(bytes);
        self.calls.push(ExplorationCall {
            tool: tool.to_string(),
            arguments,
            paths: outcome.paths,
            bytes,
            outcome: outcome.outcome.to_string(),
        });
        outcome.text
    }

    fn remaining_bytes(&self) -> usize {
        self.spec.max_read_bytes.saturating_sub(self.read_bytes)
    }

    fn snapshot_paths(&mut self) -> Result<&[String], String> {
        if self.paths.is_none() {
            self.paths = Some(vee_git::snapshot_paths(
                &self.spec.root,
                &self.spec.change_set,
            )?);
        }
        Ok(self.paths.as_deref().unwrap_or_default())
    }

    /// The normalized path when the reviewer may read it, or the refusal.
    fn readable_path(&mut self, raw: &str) -> Result<Result<String, Outcome>, String> {
        let Some(path) = normalize_path(raw) else {
            return Ok(Err(Outcome::refused(
                "invalid",
                format!("{raw} is not a relative path inside the repository"),
            )));
        };
        if !self.spec.is_readable(&path) {
            return Ok(Err(Outcome::refused(
                "denied",
                format!("{path} may not be read by reviewers"),
            )));
        }
        if self.snapshot_paths()?.binary_search(&path).is_err() {
            return Ok(Err(Outcome::refused(
                "not_found",
                format!("{path} is not in the snapshot"),
            )));
        }
        Ok(Ok(path))
    }
}

/// What one reviewer read through the snapshot tools, as recorded in the
/// review's reviewer context manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerExploration {
    /// `used`, `unused`, `cached` (the reviewer's result came from the
    /// cache, so nothing was read this time) or `unsupported` (the provider
    /// cannot use the tools).
    pub status: String,
    pub tool_calls: usize,
    pub read_bytes: usize,
    pub budget_exhausted: bool,
    /// Files whose text reached the reviewer through the tools, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

impl ReviewerExploration {
    pub(crate) fn status_only(status: &str) -> Self {
        Self {
            status: status.into(),
            tool_calls: 0,
            read_bytes: 0,
            budget_exhausted: false,
            files: Vec::new(),
        }
    }
}

/// Exploration resources of one review: the spec the snapshot servers read
/// and a call log per reviewer, in a private directory removed with it.
pub(crate) struct ReviewExploration {
    directory: tempfile::TempDir,
    spec: ExplorationSpec,
    program: PathBuf,
}

impl ReviewExploration {
    /// `None` when exploration is off.
    pub(crate) fn prepare(
        root: &Path,
        change_set: &ChangeSet,
        review: &ReviewConfig,
    ) -> Result<Option<Self>, String> {
        if !review.exploration.enabled {
            return Ok(None);
        }
        let program = std::env::current_exe()
            .map_err(|error| format!("locating the vee executable for snapshot tools: {error}"))?;
        let directory = tempfile::Builder::new()
            .prefix("vee-exploration-")
            .tempdir()
            .map_err(|error| format!("creating the exploration directory: {error}"))?;
        Ok(Some(Self {
            spec: ExplorationSpec::new(root, change_set, review),
            directory,
            program,
        }))
    }

    /// Providers that can start the snapshot server.
    pub(crate) fn supports(kind: vee_core::ProviderKind) -> bool {
        kind == vee_core::ProviderKind::ClaudeCli
    }

    /// How reviewer `index` starts the snapshot server; `None` when its
    /// provider cannot use it.
    pub(crate) fn launch(
        &self,
        index: usize,
        kind: vee_core::ProviderKind,
        reviewer: &vee_core::ReviewerConfig,
    ) -> Result<Option<vee_core::ExplorationLaunch>, String> {
        if !Self::supports(kind) {
            return Ok(None);
        }
        // One spec per reviewer, carrying the reviewer's own path filters.
        let spec = self.spec.clone().for_reviewer(reviewer);
        let spec_path = self.directory.path().join(format!("spec-{index}.json"));
        std::fs::write(
            &spec_path,
            serde_json::to_vec(&spec).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("writing the exploration spec: {error}"))?;
        let path = |path: &Path| {
            path.to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("exploration path is not UTF-8: {}", path.display()))
        };
        Ok(Some(vee_core::ExplorationLaunch {
            program: path(&self.program)?,
            args: vec![
                "mcp".into(),
                "snapshot".into(),
                "--spec".into(),
                path(&spec_path)?,
                "--log".into(),
                path(&self.log_path(index))?,
            ],
            descriptor: spec.descriptor(),
        }))
    }

    /// What reviewer `index` read, across all of its samples.
    pub(crate) fn summary(&self, index: usize) -> Result<ReviewerExploration, String> {
        let log = match std::fs::read_to_string(self.log_path(index)) {
            Ok(log) => log,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("reading the exploration log: {error}")),
        };
        let mut summary = ReviewerExploration::status_only("unused");
        let mut files = std::collections::BTreeSet::new();
        for line in log.lines().filter(|line| !line.trim().is_empty()) {
            let call: ExplorationCall = serde_json::from_str(line)
                .map_err(|error| format!("parsing the exploration log: {error}"))?;
            summary.tool_calls += 1;
            summary.read_bytes += call.bytes;
            summary.budget_exhausted |= call.outcome == "budget_exhausted";
            files.extend(call.paths);
        }
        if summary.tool_calls > 0 {
            summary.status = "used".into();
        }
        summary.files = files.into_iter().collect();
        Ok(summary)
    }

    fn log_path(&self, index: usize) -> PathBuf {
        self.directory
            .path()
            .join(format!("reviewer-{index}.jsonl"))
    }
}

/// `dir/./a/../b` → `dir/b`; `None` for absolute paths, paths that climb
/// above the root, and the root itself.
fn normalize_path(raw: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in Path::new(raw.trim()).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn source_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
#[path = "tests/exploration.rs"]
mod snapshot_tests;

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn paths_resolve_inside_the_repository_only() {
        assert_eq!(
            normalize_path("src/./a/../b.rs").as_deref(),
            Some("src/b.rs")
        );
        assert_eq!(normalize_path("/etc/passwd"), None);
        assert_eq!(normalize_path("../outside.rs"), None);
        assert_eq!(normalize_path("src/../../outside.rs"), None);
        assert_eq!(normalize_path("."), None);
    }
}
