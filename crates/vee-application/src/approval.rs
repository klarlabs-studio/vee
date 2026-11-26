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
    policy: &vee_core::PolicyConfig,
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
    stages.push(owners_stage(root, guards, &review.change_set));
    stages.extend(owner_approvals_pending(guards));
    stages.push(if policy.allows_automatic_approval() {
        stage("policy", true, "The policy allows approval without a person.")
    } else {
        stage(
            "policy",
            false,
            match review.policy_profile.as_deref() {
                Some(profile) => format!(
                    "Policy profile {profile} sets automatic_approval: false; a person must approve."
                ),
                None => "The policy sets automatic_approval: false; a person must approve.".to_owned(),
            },
        )
    });

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
/// Changed files owned, per `CODEOWNERS` on the base, by an owner whose
/// changes always need a human. The base's file, not the change's, so a
/// change cannot edit its own guard away.
fn owners_stage(
    root: &Path,
    guards: &vee_core::ApprovalConfig,
    change_set: &ChangeSet,
) -> ApprovalStage {
    if guards.never_owners.is_empty() {
        return stage("owners", true, "No owner guards are configured.");
    }
    let codeowners = match base_codeowners(root, change_set) {
        Ok(codeowners) => codeowners,
        Err(error) => return stage("owners", false, error),
    };
    let Some(codeowners) = codeowners else {
        return stage(
            "owners",
            true,
            "The base has no CODEOWNERS, so no changed file has a guarded owner.",
        );
    };
    let mut guarded = Vec::new();
    for file in &change_set.files {
        let owners = match crate::ownership::owners_in(&codeowners, &file.path) {
            Ok(owners) => owners,
            Err(error) => {
                return stage(
                    "owners",
                    false,
                    format!("CODEOWNERS on the base could not be read: {error}"),
                )
            }
        };
        if let Some(owner) = owners.iter().find(|owner| {
            guards
                .never_owners
                .iter()
                .any(|guard| guard.eq_ignore_ascii_case(owner))
        }) {
            guarded.push(format!("{} ({owner})", file.path));
        }
    }
    if guarded.is_empty() {
        stage(
            "owners",
            true,
            "No changed file is owned by a guarded owner.",
        )
    } else {
        stage(
            "owners",
            false,
            format!(
                "Changed files with a guarded owner: {}.",
                guarded.join(", ")
            ),
        )
    }
}

/// `CODEOWNERS` as it is on the change's base, or `None` when the base has
/// none. The base's file, so a change cannot edit its own owners away.
fn base_codeowners(root: &Path, change_set: &ChangeSet) -> Result<Option<String>, String> {
    let Some(base) = change_set.base_oid.as_deref() else {
        return Err("The change has no base, so CODEOWNERS cannot be read.".into());
    };
    for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] {
        match vee_git::read_tree_file(root, base, Path::new(path)) {
            Ok(Some(bytes)) => {
                return String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| format!("{path} on the base is not UTF-8."));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("CODEOWNERS on the base could not be read: {error}")),
        }
    }
    Ok(None)
}

pub const OWNER_APPROVALS_STAGE: &str = "owner_approvals";

/// People whose latest approving or blocking review, oldest first in
/// `reviews`, approves `head_oid`. Bots and Vee's own account do not count.
pub fn standing_approvers(
    reviews: &[vee_hosting::PullRequestReview],
    head_oid: &str,
    actor_login: &str,
) -> Vec<String> {
    let mut latest: std::collections::BTreeMap<String, &vee_hosting::PullRequestReview> =
        std::collections::BTreeMap::new();
    for review in reviews {
        if review.author_is_bot
            || review.author.eq_ignore_ascii_case(actor_login)
            || !matches!(
                review.state.as_str(),
                "APPROVED" | "CHANGES_REQUESTED" | "DISMISSED"
            )
        {
            continue;
        }
        latest.insert(review.author.to_ascii_lowercase(), review);
    }
    latest
        .into_values()
        .filter(|review| review.state == "APPROVED" && review.commit_id == head_oid)
        .map(|review| review.author.clone())
        .collect()
}

/// Until the host says who approved, owner approval cannot pass; `vee ci
/// run` replaces this stage with [`owner_approvals_stage`].
fn owner_approvals_pending(guards: &vee_core::ApprovalConfig) -> Option<ApprovalStage> {
    guards.require_owner_approval.then(|| {
        stage(
            OWNER_APPROVALS_STAGE,
            false,
            "approval.require_owner_approval is set; owners' approvals are read from the pull request by `vee ci run`.",
        )
    })
}

/// Whether, for every changed file `CODEOWNERS` on the base assigns, one of
/// its owners is among `approvers`: people whose approval of the current
/// head stands. `@user` owners match a login, `@org/team` owners match a
/// member as `is_member` reports, and email owners cannot be matched.
pub fn owner_approvals_stage(
    root: &Path,
    change_set: &ChangeSet,
    approvers: &[String],
    is_member: &dyn Fn(&str, &str) -> bool,
) -> ApprovalStage {
    let codeowners = match base_codeowners(root, change_set) {
        Ok(Some(codeowners)) => codeowners,
        Ok(None) => {
            return stage(
                OWNER_APPROVALS_STAGE,
                false,
                "approval.require_owner_approval is set, but the base has no CODEOWNERS.",
            )
        }
        Err(error) => return stage(OWNER_APPROVALS_STAGE, false, error),
    };
    let approved_by = |owner: &str| {
        let Some(name) = owner.strip_prefix('@') else {
            return false;
        };
        match name.split_once('/') {
            Some(_) => approvers.iter().any(|login| is_member(name, login)),
            None => approvers
                .iter()
                .any(|login| login.eq_ignore_ascii_case(name)),
        }
    };
    let mut waiting = Vec::new();
    let mut owned = 0;
    for file in &change_set.files {
        let owners = match crate::ownership::owners_in(&codeowners, &file.path) {
            Ok(owners) => owners,
            Err(error) => {
                return stage(
                    OWNER_APPROVALS_STAGE,
                    false,
                    format!("CODEOWNERS on the base could not be read: {error}"),
                )
            }
        };
        if owners.is_empty() {
            continue;
        }
        owned += 1;
        if !owners.iter().any(|owner| approved_by(owner)) {
            waiting.push(format!("{} ({})", file.path, owners.join(" ")));
        }
    }
    match (owned, waiting.is_empty()) {
        (0, _) => stage(
            OWNER_APPROVALS_STAGE,
            true,
            "No changed file has an owner in CODEOWNERS.",
        ),
        (_, true) => stage(
            OWNER_APPROVALS_STAGE,
            true,
            "An owner approved every changed file that has one.",
        ),
        (_, false) => stage(
            OWNER_APPROVALS_STAGE,
            false,
            format!(
                "Waiting for an owner's approval of: {}.",
                waiting.join(", ")
            ),
        ),
    }
}

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
