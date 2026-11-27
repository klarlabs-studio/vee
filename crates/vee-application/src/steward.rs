//! The steward (ADR 0042): fix what keeps a change from passing its gate, one
//! problem at a time, and keep a fix only when a new review accepts it.
//!
//! Problems come from the review of the change's head: a merge conflict with
//! the base, required verification profiles that fail, and Vee's blocking
//! findings. On a pull request, review comments from people with write access
//! are added (`@vee steward`). The configured reviewer's model, an agent CLI
//! or a local model, proposes each fix; Vee commits it and reviews the new
//! head. A fix that leaves the review incomplete, adds a blocking finding,
//! breaks a verification that passed, or does not solve its problem is
//! undone. Whoever starts the steward approves its commits: a person running
//! `vee steward`, a person commenting `@vee steward`, or a coding agent the
//! repository's `steward.agents` permits.

use crate::operations::Workspace;
use crate::pr_fix::FixTask;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use vee_core::{GateStatus, VerificationStatus};

pub const STEWARD_SCHEMA_VERSION: u32 = 1;
/// The most conflicted files the steward resolves in one merge.
const MAX_CONFLICTED_FILES: usize = 5;
/// The most diagnostic lines of a failing verification sent to the model.
const MAX_DIAGNOSTIC_LINES: usize = 40;

/// What a step of the steward worked on.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StewardTaskKind {
    MergeConflict,
    FailingVerification,
    Finding,
    ReviewComment,
}

impl StewardTaskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MergeConflict => "merge_conflict",
            Self::FailingVerification => "failing_verification",
            Self::Finding => "finding",
            Self::ReviewComment => "review_comment",
        }
    }
}

/// One problem the steward took on, and what came of it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StewardStep {
    pub kind: StewardTaskKind,
    /// The base commit, verification profile, finding ID or comment ID.
    pub subject: String,
    /// Whether the fix was kept.
    pub kept: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The reviewer and model that proposed the fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// What the fix changed, or why nothing was kept.
    pub summary: String,
    /// How to undo a kept step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo: Option<String>,
}

/// `steward-run-v1`: what one run of the steward did.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StewardReport {
    pub schema_version: u32,
    /// The base the change is reviewed and merged against.
    pub base: String,
    /// The head before the steward ran.
    pub start_head: String,
    /// The head after the steward ran: the last kept fix, or the start.
    pub head: String,
    pub steps: Vec<StewardStep>,
    /// The review of `head`.
    pub review_id: String,
    /// The gate on `head`.
    pub gate: GateStatus,
    /// Whether the kept fixes were pushed to the pull request.
    pub pushed: bool,
}

impl StewardReport {
    pub fn kept(&self) -> usize {
        self.steps.iter().filter(|step| step.kept).count()
    }
}

/// A review of a head: the CI review on a pull request, or a local one.
pub(crate) trait HeadReview {
    fn result(&self) -> &crate::ReviewResult;
}

impl HeadReview for crate::ReviewResult {
    fn result(&self) -> &crate::ReviewResult {
        self
    }
}

/// A review comment a person left, for `@vee steward` to address.
#[derive(Clone, Debug)]
pub(crate) struct CommentTask {
    pub(crate) comment_id: String,
    pub(crate) fix: FixTask,
}

/// What the engine needs from its caller.
pub(crate) struct Steward<'a, R> {
    pub(crate) workspace: &'a Workspace,
    /// The base to merge and review against, as a commit.
    pub(crate) base: String,
    /// Who commits; `None` uses the repository's Git identity.
    pub(crate) identity: Option<(String, String)>,
    /// Named in each commit message as who asked for the fix.
    pub(crate) requested_by: String,
    pub(crate) max_fixes: usize,
    /// Review the checked-out head, running the policy's required
    /// verifications first.
    pub(crate) review: &'a dyn Fn() -> Result<R>,
}

enum Task {
    Verification { profile_id: String, fix: FixTask },
    Finding { fingerprint: String, fix: FixTask },
    Comment(CommentTask),
}

impl Task {
    fn kind(&self) -> StewardTaskKind {
        match self {
            Self::Verification { .. } => StewardTaskKind::FailingVerification,
            Self::Finding { .. } => StewardTaskKind::Finding,
            Self::Comment(_) => StewardTaskKind::ReviewComment,
        }
    }

    fn subject(&self) -> String {
        match self {
            Self::Verification { profile_id, .. } => profile_id.clone(),
            Self::Finding { fix, .. } => fix.id.clone(),
            Self::Comment(comment) => comment.comment_id.clone(),
        }
    }

    fn fix(&self) -> &FixTask {
        match self {
            Self::Verification { fix, .. } | Self::Finding { fix, .. } => fix,
            Self::Comment(comment) => &comment.fix,
        }
    }

    /// Whether `review` shows the problem gone already.
    fn solved_in(&self, review: &crate::ReviewResult) -> bool {
        match self {
            Self::Verification { profile_id, .. } => {
                verification_statuses(review).get(profile_id) == Some(&VerificationStatus::Passed)
            }
            Self::Finding { fingerprint, .. } => !review
                .findings
                .iter()
                .any(|finding| &finding.fingerprint == fingerprint),
            Self::Comment(_) => false,
        }
    }
}

pub(crate) fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("running git {}", args.first().unwrap_or(&"")))?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed: {}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(12)]
}

/// The latest status of each verification profile run for the review.
fn verification_statuses(review: &crate::ReviewResult) -> BTreeMap<String, VerificationStatus> {
    review
        .verification_runs
        .iter()
        .map(|run| (run.profile_id.clone(), run.status))
        .collect()
}

/// Whether a fix may be kept: the review of its head is complete, nothing
/// blocks that did not before, every verification that passed still passes,
/// and the problem it was for is solved.
fn verdict(
    kind: StewardTaskKind,
    task: Option<&Task>,
    before: &crate::ReviewResult,
    after: &crate::ReviewResult,
) -> Result<(), String> {
    if after.gate.status == GateStatus::Incomplete {
        return Err("the review of the fix is incomplete".into());
    }
    let earlier: BTreeSet<&str> = before
        .findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect();
    let new_blockers: Vec<&str> = after
        .gate
        .blocking_findings
        .iter()
        .filter_map(|id| after.findings.iter().find(|finding| &finding.id == id))
        .filter(|finding| !earlier.contains(finding.fingerprint.as_str()))
        .map(|finding| finding.id.as_str())
        .collect();
    if !new_blockers.is_empty() {
        return Err(format!(
            "the review of the fix found new blocking findings ({})",
            new_blockers.join(", ")
        ));
    }
    let after_runs = verification_statuses(after);
    let broken: Vec<String> = verification_statuses(before)
        .into_iter()
        .filter(|(profile, status)| {
            *status == VerificationStatus::Passed
                && after_runs.get(profile) != Some(&VerificationStatus::Passed)
        })
        .map(|(profile, _)| profile)
        .collect();
    if !broken.is_empty() {
        return Err(format!(
            "verification no longer passes after the fix ({})",
            broken.join(", ")
        ));
    }
    match (kind, task) {
        (StewardTaskKind::MergeConflict, _) => {
            if after_runs.is_empty() {
                return Err("no required verification checks the merged result, so a person resolves the conflict".into());
            }
            if after_runs
                .values()
                .any(|status| *status != VerificationStatus::Passed)
            {
                return Err("verification does not pass on the merged result".into());
            }
        }
        (_, Some(task)) if !matches!(task, Task::Comment(_)) && !task.solved_in(after) => {
            return Err(match task {
                Task::Verification { .. } => "the verification still fails".into(),
                _ => "the review still reports the finding".into(),
            });
        }
        _ => {}
    }
    Ok(())
}

/// The problems in `review` the steward can take on, and those it leaves
/// for a person, with why.
fn tasks(workspace: &Workspace, review: &crate::ReviewResult) -> (Vec<Task>, Vec<StewardStep>) {
    let mut tasks = Vec::new();
    let mut left = Vec::new();
    let required: BTreeSet<String> = workspace
        .effective_config(None)
        .map(|config| config.policy.required_verifications.into_iter().collect())
        .unwrap_or_default();
    let store = workspace.store().ok();
    for run in &review.verification_runs {
        if run.status == VerificationStatus::Passed || !required.contains(&run.profile_id) {
            continue;
        }
        let diagnosis = store.as_ref().and_then(|store| {
            crate::verification_diagnosis::diagnose(workspace.root(), &**store, run).ok()
        });
        let path = diagnosis.as_ref().and_then(|diagnosis| {
            diagnosis
                .diagnostics
                .iter()
                .find_map(|diagnostic| diagnostic.referenced_changed_paths.first().cloned())
        });
        let Some(path) = path else {
            left.push(StewardStep {
                kind: StewardTaskKind::FailingVerification,
                subject: run.profile_id.clone(),
                kept: false,
                commit: None,
                by: None,
                summary: "its output names no changed file, so a person investigates".into(),
                undo: None,
            });
            continue;
        };
        let lines = diagnosis
            .map(|diagnosis| {
                diagnosis
                    .diagnostics
                    .iter()
                    .take(MAX_DIAGNOSTIC_LINES)
                    .map(|diagnostic| diagnostic.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        tasks.push(Task::Verification {
            profile_id: run.profile_id.clone(),
            fix: FixTask {
                classification: "untrusted_check_output",
                id: run.profile_id.clone(),
                path,
                line: None,
                text: format!(
                    "The verification profile `{}` fails on this change. Its diagnostics:\n{lines}",
                    run.profile_id
                ),
            },
        });
    }
    for id in &review.gate.blocking_findings {
        let Some(finding) = review.findings.iter().find(|finding| &finding.id == id) else {
            continue;
        };
        let Some(path) = finding.path.clone() else {
            left.push(StewardStep {
                kind: StewardTaskKind::Finding,
                subject: finding.id.clone(),
                kept: false,
                commit: None,
                by: None,
                summary: "the finding names no file, so a person fixes it".into(),
                undo: None,
            });
            continue;
        };
        tasks.push(Task::Finding {
            fingerprint: finding.fingerprint.clone(),
            fix: FixTask {
                classification: "untrusted_review_finding",
                id: finding.id.clone(),
                path,
                line: finding.line.map(u64::from),
                text: format!(
                    "{} ({:?}): {}",
                    finding.category, finding.severity, finding.rationale
                ),
            },
        });
    }
    (tasks, left)
}

/// Whether merging `base` into `head` conflicts. A base already in the
/// head needs no merge.
fn merge_conflicts(root: &Path, head: &str, base: &str) -> Result<bool> {
    if git(root, &["merge-base", "--is-ancestor", base, head]).is_ok() {
        return Ok(false);
    }
    let output = std::process::Command::new("git")
        .args([
            "merge-tree",
            "--write-tree",
            "--name-only",
            "--no-messages",
            head,
            base,
        ])
        .current_dir(root)
        .output()
        .context("running git merge-tree")?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => anyhow::bail!(
            "git merge-tree could not check for conflicts (Git 2.38 or later is needed): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

impl<R: HeadReview> Steward<'_, R> {
    fn commit(&self, message: &str) -> Result<String> {
        let root = self.workspace.root();
        let mut args: Vec<String> = Vec::new();
        if let Some((name, email)) = &self.identity {
            args.extend([
                "-c".into(),
                format!("user.name={name}"),
                "-c".into(),
                format!("user.email={email}"),
            ]);
        }
        args.extend(
            ["commit", "--quiet", "--no-verify", "-m", message]
                .iter()
                .map(|arg| (*arg).to_owned()),
        );
        git(root, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
        git(root, &["rev-parse", "HEAD"])
    }

    /// Put the checkout back at `tip`, dropping a merge in progress.
    fn undo(&self, tip: &str) -> Result<()> {
        git(self.workspace.root(), &["reset", "--quiet", "--hard", tip]).map(|_| ())
    }

    /// Merge the base into `tip`, have the model resolve each conflicted
    /// file, and review the merged head.
    fn resolve_merge(&self, tip: &str, before: &R) -> Result<(StewardStep, R), String> {
        let root = self.workspace.root();
        let failed = |why: String| -> Result<(StewardStep, R), String> {
            self.undo(tip).map_err(|error| format!("{error:#}"))?;
            Err(why)
        };
        // The merge stops at the conflicts; its error is expected.
        let _ = git(
            root,
            &["merge", "--no-ff", "--no-commit", "--quiet", &self.base],
        );
        let conflicted: Vec<String> = match git(root, &["diff", "--name-only", "--diff-filter=U"]) {
            Ok(list) => list.lines().map(str::to_owned).collect(),
            Err(error) => return failed(format!("{error:#}")),
        };
        if conflicted.is_empty() {
            return failed("Git reported conflicts but left no conflicted file".into());
        }
        if conflicted.len() > MAX_CONFLICTED_FILES {
            return failed(format!(
                "{} files conflict, more than the {MAX_CONFLICTED_FILES} Vee resolves; a person resolves them",
                conflicted.len()
            ));
        }
        let mut by = None;
        let mut summaries = Vec::new();
        for path in &conflicted {
            match crate::pr_fix::resolve_conflicts(self.workspace, path, tip) {
                Ok(resolution) => {
                    by.get_or_insert_with(|| {
                        reviewer_label(&resolution.reviewer_id, resolution.model.as_deref())
                    });
                    summaries.push(format!("{path}: {}", neutral(&resolution.summary)));
                }
                Err(error) => return failed(neutral(&format!("{error:#}"))),
            }
        }
        let paths: Vec<&str> = conflicted.iter().map(String::as_str).collect();
        let mut add = vec!["add", "--"];
        add.extend(&paths);
        if let Err(error) = git(root, &add) {
            return failed(format!("{error:#}"));
        }
        let message = format!(
            "Merge {} into the change\n\nVee's steward resolved the conflicts in {} at the request of {}, and Vee reviewed the result before keeping it. Revert this merge with `git revert -m 1` to undo it.\n\n{}\n\nVee-Steward: merge_conflict {}",
            short(&self.base),
            conflicted.join(", "),
            self.requested_by,
            summaries.join("\n"),
            self.base
        );
        let commit = match self.commit(&message) {
            Ok(commit) => commit,
            Err(error) => return failed(format!("{error:#}")),
        };
        let after = match (self.review)() {
            Ok(after) => after,
            Err(error) => {
                return failed(format!(
                    "Vee could not review the merge: {}",
                    neutral(&format!("{error:#}"))
                ))
            }
        };
        if let Err(why) = verdict(
            StewardTaskKind::MergeConflict,
            None,
            before.result(),
            after.result(),
        ) {
            return failed(why);
        }
        Ok((
            StewardStep {
                kind: StewardTaskKind::MergeConflict,
                subject: self.base.clone(),
                kept: true,
                commit: Some(commit.clone()),
                by,
                summary: format!(
                    "Resolved the conflicts with the base in {}.",
                    conflicted.join(", ")
                ),
                undo: Some(format!("git revert -m 1 {commit}")),
            },
            after,
        ))
    }

    /// Have the model fix `task` on `tip`, commit it and review the result.
    fn attempt(&self, task: &Task, tip: &str, before: &R) -> Result<(StewardStep, R), String> {
        let root = self.workspace.root();
        let failed = |why: String| -> Result<(StewardStep, R), String> {
            self.undo(tip).map_err(|error| format!("{error:#}"))?;
            Err(why)
        };
        let fix = task.fix();
        let proposed = match crate::pr_fix::propose_and_apply_task(self.workspace, fix, tip) {
            Ok(proposed) => proposed,
            Err(error) => {
                return failed(format!(
                    "Vee could not fix it: {}",
                    neutral(&format!("{error:#}"))
                ))
            }
        };
        let by = reviewer_label(&proposed.reviewer_id, proposed.model.as_deref());
        let summary = neutral(&proposed.summary);
        if proposed.content.is_none() {
            return failed(format!("{by} proposed no change: {summary}"));
        }
        let message = format!(
            "fix: address {} {}\n\n{}\n\nProposed by {by} for Vee's steward at the request of {}, and reviewed by Vee before it was kept. Revert this commit to undo it.\n\nVee-Steward: {} {}",
            task.kind().as_str().replace('_', " "),
            fix.id,
            proposed.summary.trim(),
            self.requested_by,
            task.kind().as_str(),
            fix.id
        );
        if let Err(error) = git(root, &["add", "--", &proposed.path]) {
            return failed(format!("{error:#}"));
        }
        let commit = match self.commit(&message) {
            Ok(commit) => commit,
            Err(error) => return failed(format!("Vee could not commit the fix: {error:#}")),
        };
        let after = match (self.review)() {
            Ok(after) => after,
            Err(error) => {
                return failed(format!(
                    "Vee could not review the fix: {}",
                    neutral(&format!("{error:#}"))
                ))
            }
        };
        if let Err(why) = verdict(task.kind(), Some(task), before.result(), after.result()) {
            return failed(format!(
                "{by} proposed a fix, but Vee did not keep it: {why}. The fix: {summary}"
            ));
        }
        Ok((
            StewardStep {
                kind: task.kind(),
                subject: task.subject(),
                kept: true,
                commit: Some(commit.clone()),
                by: Some(by),
                summary,
                undo: Some(format!("git revert {commit}")),
            },
            after,
        ))
    }

    /// Run the steward from the checked-out head. Returns what it did and the
    /// review of the final head.
    pub(crate) fn run(&self, comments: Vec<CommentTask>) -> Result<(StewardReport, R)> {
        let root = self.workspace.root();
        let start = git(root, &["rev-parse", "HEAD"])?;
        let mut tip = start.clone();
        let mut current = (self.review)().context("reviewing the head before the steward runs")?;
        let mut steps = Vec::new();
        let mut attempts = 0;
        let not_kept = |kind, subject: String, summary: String| StewardStep {
            kind,
            subject,
            kept: false,
            commit: None,
            by: None,
            summary,
            undo: None,
        };
        match merge_conflicts(root, &tip, &self.base) {
            Ok(false) => {}
            Ok(true) => {
                attempts += 1;
                match self.resolve_merge(&tip, &current) {
                    Ok((step, after)) => {
                        tip = step.commit.clone().unwrap_or(tip);
                        current = after;
                        steps.push(step);
                    }
                    Err(why) => steps.push(not_kept(
                        StewardTaskKind::MergeConflict,
                        self.base.clone(),
                        why,
                    )),
                }
            }
            Err(error) => steps.push(not_kept(
                StewardTaskKind::MergeConflict,
                self.base.clone(),
                format!("{error:#}"),
            )),
        }
        let (found, left) = tasks(self.workspace, current.result());
        steps.extend(left);
        let all = found
            .into_iter()
            .chain(comments.into_iter().map(Task::Comment));
        for task in all {
            if task.solved_in(current.result()) {
                continue;
            }
            if attempts >= self.max_fixes {
                steps.push(not_kept(
                    task.kind(),
                    task.subject(),
                    format!(
                        "not attempted: this run reached steward.max_fixes ({})",
                        self.max_fixes
                    ),
                ));
                continue;
            }
            attempts += 1;
            match self.attempt(&task, &tip, &current) {
                Ok((step, after)) => {
                    tip = step.commit.clone().unwrap_or(tip);
                    current = after;
                    steps.push(step);
                }
                Err(why) => steps.push(not_kept(task.kind(), task.subject(), why)),
            }
        }
        let review = current.result();
        Ok((
            StewardReport {
                schema_version: STEWARD_SCHEMA_VERSION,
                base: self.base.clone(),
                start_head: start,
                head: tip,
                steps,
                review_id: review.review_id.clone(),
                gate: review.gate.status,
                pushed: false,
            },
            current,
        ))
    }
}

/// `vee steward`: run the steward on the checked-out branch, against `base`.
pub struct StewardRequest<'a> {
    /// The branch or commit the change is reviewed and merged against.
    pub base: &'a str,
    /// Overrides `steward.max_fixes` for this run.
    pub max_fixes: Option<u32>,
    /// Whether a coding agent started the run (through MCP), which needs
    /// `steward.agents`.
    pub by_agent: bool,
}

/// Run the steward on the checked-out branch. Fixes are committed to the
/// branch and never pushed; each commit says how to undo it.
pub fn run_local(workspace: &Workspace, request: StewardRequest<'_>) -> Result<StewardReport> {
    let root = workspace.root();
    let config = workspace.effective_config(None)?;
    if request.by_agent && !config.steward.agents {
        return Err(crate::failure::configuration_failure(
            "coding agents may run the steward only when the repository sets `steward.agents: true` in .vee.yaml",
        ));
    }
    if git(root, &["symbolic-ref", "--quiet", "HEAD"]).is_err() {
        return Err(crate::failure::usage_failure(
            "check out a branch first: the steward commits its fixes to the current branch",
        ));
    }
    if !git(root, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        return Err(crate::failure::usage_failure(
            "commit or stash your changes first: the steward undoes a fix it does not keep by resetting the branch",
        ));
    }
    let base = git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{}^{{commit}}", request.base),
        ],
    )
    .map_err(|_| crate::failure::usage_failure(format!("`{}` is not a commit", request.base)))?;
    let max_fixes = request
        .max_fixes
        .unwrap_or_else(|| config.steward.max_fixes())
        .clamp(1, vee_core::MAX_STEWARD_FIXES) as usize;
    crate::ci::exclude_vee_runtime_files(root)?;
    let review = || -> Result<crate::ReviewResult> {
        crate::ci::run_required_verifications(workspace, &base, None)?;
        crate::operations::review(
            workspace,
            crate::operations::ReviewRequest {
                scope: crate::operations::ScopeRequest::BaseAndWorktree {
                    base: Some(base.clone()),
                },
                reviewer_ids: None,
                policy_profile: None,
                effort: None,
                work_item: None,
                hosting: Default::default(),
                progress: None,
                carried: None,
            },
            None,
        )
    };
    let steward = Steward {
        workspace,
        base: base.clone(),
        identity: None,
        requested_by: if request.by_agent {
            "a coding agent, as `steward.agents` permits".to_owned()
        } else {
            "the person who ran `vee steward`".to_owned()
        },
        max_fixes,
        review: &review,
    };
    steward.run(Vec::new()).map(|(report, _)| report)
}

fn reviewer_label(reviewer_id: &str, model: Option<&str>) -> String {
    format!(
        "the `{reviewer_id}` reviewer{}",
        model.map(|model| format!(" ({model})")).unwrap_or_default()
    )
}

/// Model and tool text, flattened to one line for a report or a comment.
fn neutral(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review(
        findings: &[(&str, &str)],
        blocking: &[&str],
        runs: &[(&str, VerificationStatus)],
        status: GateStatus,
    ) -> crate::ReviewResult {
        let mut value = serde_json::json!({
            "schema_version": 2,
            "review_id": "review",
            "snapshot_id": "sha256:s",
            "status": "pass",
            "findings": findings.iter().map(|(id, fingerprint)| serde_json::json!({
                "id": id, "fingerprint": fingerprint, "category": "bug", "severity": "high",
                "rationale": "r", "path": "src/lib.rs", "line": 1, "provenance": "reviewer"
            })).collect::<Vec<_>>(),
            "evidence": [],
            "verification_runs": runs.iter().map(|(profile, status)| serde_json::json!({
                "schema_version": 1, "run_id": format!("run-{profile}"), "snapshot_id": "sha256:s",
                "profile_id": profile, "targets": [], "command_digest": "sha256:c",
                "status": status, "exit_code": 0, "stdout_digest": "sha256:o", "stderr_digest": "sha256:e"
            })).collect::<Vec<_>>(),
            "reviewer_outcomes": [],
            "analysis_complete": true,
            "reasons": [],
            "gate": {
                "schema_version": 1, "decision_id": "d", "snapshot_id": "sha256:s",
                "effective_config_digest": "sha256:c", "policy_digest": "sha256:p",
                "status": status, "blocking_findings": blocking, "verification_run_ids": [],
                "evidence_digest": "sha256:e", "reasons": []
            },
            "change_set": {"schema_version": 1, "base_oid": null, "head_oid": null, "scope": "working_tree", "files": [], "warnings": [], "digest": "sha256:s"},
            "effective_config_digest": "sha256:c",
            "selected_reviewers": [],
            "policy_profile": null,
            "work_item": null
        });
        value["status"] = serde_json::json!(status);
        serde_json::from_value(value).unwrap()
    }

    fn finding_task(id: &str, fingerprint: &str) -> Task {
        Task::Finding {
            fingerprint: fingerprint.into(),
            fix: FixTask {
                classification: "untrusted_review_finding",
                id: id.into(),
                path: "src/lib.rs".into(),
                line: Some(1),
                text: "t".into(),
            },
        }
    }

    #[test]
    fn a_fix_is_kept_only_when_its_finding_is_gone_and_nothing_new_blocks() {
        let before = review(
            &[("find_a", "fa"), ("find_b", "fb")],
            &["find_a", "find_b"],
            &[],
            GateStatus::Block,
        );
        let task = finding_task("find_a", "fa");
        let fixed = review(&[("find_b", "fb")], &["find_b"], &[], GateStatus::Block);
        assert_eq!(
            verdict(StewardTaskKind::Finding, Some(&task), &before, &fixed),
            Ok(())
        );

        let still = review(&[("find_a", "fa")], &["find_a"], &[], GateStatus::Block);
        assert!(
            verdict(StewardTaskKind::Finding, Some(&task), &before, &still)
                .unwrap_err()
                .contains("still reports")
        );

        let new = review(&[("find_c", "fc")], &["find_c"], &[], GateStatus::Block);
        assert!(
            verdict(StewardTaskKind::Finding, Some(&task), &before, &new)
                .unwrap_err()
                .contains("new blocking")
        );

        let incomplete = review(&[], &[], &[], GateStatus::Incomplete);
        assert!(
            verdict(StewardTaskKind::Finding, Some(&task), &before, &incomplete)
                .unwrap_err()
                .contains("incomplete")
        );
    }

    #[test]
    fn a_fix_that_breaks_a_passing_verification_is_undone() {
        let before = review(
            &[("find_a", "fa")],
            &["find_a"],
            &[("tests", VerificationStatus::Passed)],
            GateStatus::Block,
        );
        let after = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Failed)],
            GateStatus::Block,
        );
        let task = finding_task("find_a", "fa");
        assert!(
            verdict(StewardTaskKind::Finding, Some(&task), &before, &after)
                .unwrap_err()
                .contains("no longer passes after the fix (tests)")
        );
    }

    #[test]
    fn a_verification_fix_must_make_it_pass() {
        let before = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Failed)],
            GateStatus::Block,
        );
        let task = Task::Verification {
            profile_id: "tests".into(),
            fix: FixTask {
                classification: "untrusted_check_output",
                id: "tests".into(),
                path: "src/lib.rs".into(),
                line: None,
                text: String::new(),
            },
        };
        let still = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Failed)],
            GateStatus::Block,
        );
        assert!(verdict(
            StewardTaskKind::FailingVerification,
            Some(&task),
            &before,
            &still
        )
        .unwrap_err()
        .contains("still fails"));
        let passing = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Passed)],
            GateStatus::Pass,
        );
        assert_eq!(
            verdict(
                StewardTaskKind::FailingVerification,
                Some(&task),
                &before,
                &passing
            ),
            Ok(())
        );
    }

    #[test]
    fn a_merge_is_kept_only_when_verification_checks_it() {
        let before = review(&[], &[], &[], GateStatus::Pass);
        let unverified = review(&[], &[], &[], GateStatus::Pass);
        assert!(
            verdict(StewardTaskKind::MergeConflict, None, &before, &unverified)
                .unwrap_err()
                .contains("a person resolves")
        );
        let failing = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Failed)],
            GateStatus::Block,
        );
        assert!(verdict(StewardTaskKind::MergeConflict, None, &before, &failing).is_err());
        let verified = review(
            &[],
            &[],
            &[("tests", VerificationStatus::Passed)],
            GateStatus::Pass,
        );
        assert_eq!(
            verdict(StewardTaskKind::MergeConflict, None, &before, &verified),
            Ok(())
        );
    }
}
