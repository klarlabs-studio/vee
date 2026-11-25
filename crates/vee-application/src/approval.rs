//! Approval eligibility: whether a reviewed change may be approved without a
//! human, decided by layered, deterministic guards.
//!
//! Automated approval in production is layered with the cheapest
//! deterministic checks first, and any failing or missing stage keeps a human
//! in the loop. An approval is bound to the exact snapshot and withdrawn when
//! the change moves (`docs/research/review-literature.md`, section 5). Every
//! stage is evaluated and reported, so a reader sees all the reasons at once.

use super::*;

/// Version of the approval eligibility document (`approval-eligibility-v1`).
pub const APPROVAL_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalStage {
    /// `snapshot`, `paths`, `authors`, `risk`, or `gate`, in evaluation order.
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalEligibility {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    /// True only when every stage passed.
    pub eligible: bool,
    pub stages: Vec<ApprovalStage>,
}

fn stage(id: &str, passed: bool, detail: impl Into<String>) -> ApprovalStage {
    ApprovalStage {
        id: id.into(),
        passed,
        detail: detail.into(),
    }
}

/// Evaluate approval for a saved review. `current` says whether the checkout
/// still matches the reviewed snapshot; `risk` is its change risk when it does.
pub fn evaluate_approval(
    root: &Path,
    guards: &vee_core::ApprovalConfig,
    review: &ReviewResult,
    current: bool,
    risk: Option<&ChangeRisk>,
) -> ApprovalEligibility {
    let mut stages = Vec::new();
    stages.push(if current {
        stage(
            "snapshot",
            true,
            "The checkout matches the reviewed snapshot.",
        )
    } else {
        stage(
            "snapshot",
            false,
            "The change moved after the review; approval is withdrawn until it is reviewed again.",
        )
    });

    let protected: Vec<String> = review
        .change_set
        .files
        .iter()
        .filter_map(|file| {
            guards
                .never_paths
                .iter()
                .find(|pattern| crate::review::glob_matches(pattern, &file.path))
                .map(|pattern| format!("{} (matches {pattern})", file.path))
        })
        .collect();
    stages.push(if protected.is_empty() {
        stage(
            "paths",
            true,
            if guards.never_paths.is_empty() {
                "No protected paths are configured."
            } else {
                "No changed path is protected."
            },
        )
    } else {
        stage(
            "paths",
            false,
            format!("Protected paths changed: {}.", protected.join(", ")),
        )
    });

    stages.push(authors_stage(root, guards, &review.change_set));

    let allowed = guards.max_risk();
    stages.push(match risk {
        None => stage(
            "risk",
            false,
            "Change risk is unavailable, so eligibility cannot be shown.",
        ),
        Some(risk) => {
            let limit = if allowed == "elevated" {
                RiskTier::Elevated
            } else {
                RiskTier::Low
            };
            let flagged: Vec<&str> = risk
                .factors
                .iter()
                .filter(|factor| factor.flagged)
                .map(|factor| factor.label.as_str())
                .collect();
            let detail = if flagged.is_empty() {
                format!("Risk is {} (allowed up to {allowed}).", risk.tier.as_str())
            } else {
                format!(
                    "Risk is {} (allowed up to {allowed}); flagged: {}.",
                    risk.tier.as_str(),
                    flagged.join(", ")
                )
            };
            stage("risk", risk.tier <= limit, detail)
        }
    });

    let gate = &review.gate;
    stages.push(match gate.status {
        vee_core::GateStatus::Pass => stage("gate", true, "The gate passed."),
        vee_core::GateStatus::Block => stage(
            "gate",
            false,
            format!("The gate blocked: {}", gate.reasons.join("; ")),
        ),
        vee_core::GateStatus::Incomplete => stage(
            "gate",
            false,
            format!("The gate is incomplete: {}", gate.reasons.join("; ")),
        ),
    });

    ApprovalEligibility {
        schema_version: APPROVAL_SCHEMA_VERSION,
        review_id: review.review_id.clone(),
        snapshot_id: review.snapshot_id.clone(),
        eligible: stages.iter().all(|stage| stage.passed),
        stages,
    }
}

/// Author guards apply to the commits in the change. Only the matching
/// pattern is reported, never the author's name or email.
fn authors_stage(
    root: &Path,
    guards: &vee_core::ApprovalConfig,
    change_set: &ChangeSet,
) -> ApprovalStage {
    if guards.never_authors.is_empty() {
        return stage("authors", true, "No author guards are configured.");
    }
    let (Some(base), Some(head)) = (
        change_set.base_oid.as_deref(),
        change_set.head_oid.as_deref(),
    ) else {
        return stage(
            "authors",
            false,
            "The change has no commit range, so its authors cannot be checked.",
        );
    };
    let authors = match vee_git::commit_authors(root, base, head) {
        Ok(authors) => authors,
        Err(error) => {
            return stage(
                "authors",
                false,
                format!("Commit authors could not be read: {error}"),
            )
        }
    };
    let matched: std::collections::BTreeSet<&str> = guards
        .never_authors
        .iter()
        .filter(|pattern| {
            authors.iter().any(|(name, email)| {
                crate::review::glob_matches(pattern, name)
                    || crate::review::glob_matches(pattern, email)
            })
        })
        .map(String::as_str)
        .collect();
    if matched.is_empty() {
        stage(
            "authors",
            true,
            format!(
                "No commit author matches a guarded pattern ({} commit(s)).",
                authors.len()
            ),
        )
    } else {
        stage(
            "authors",
            false,
            format!(
                "A commit author matches: {}.",
                matched.into_iter().collect::<Vec<_>>().join(", ")
            ),
        )
    }
}
