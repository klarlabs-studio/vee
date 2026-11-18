use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_REPOSITORIES: usize = 128;
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_IMPACT_FILES: usize = 10_000;
const MAX_IMPACT_BYTES: usize = 32 * 1024 * 1024;
const MAX_IMPACT_FILE_BYTES: u64 = 512 * 1024;
const MAX_DEPENDENCY_PATHS: usize = 10_000;
const MAX_DEPENDENCY_PATH_STATES: usize = 50_000;
const MAX_GO_SEMANTIC_REFERENCES: usize = 32;
const MAX_RUST_SEMANTIC_REFERENCES: usize = 32;
const MAX_TYPESCRIPT_SEMANTIC_REFERENCES: usize = 32;
static GO_CROSS_REPO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static RUST_CROSS_REPO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TYPESCRIPT_CROSS_REPO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const CONSUMER_SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "go", "ts", "tsx", "js", "jsx", "mts", "cts", "py", "java",
];

#[derive(Debug, Serialize)]
pub struct RepositoryMap {
    pub schema_version: u32,
    pub repositories: Vec<RepositoryEntry>,
    pub dependencies: Vec<DependencyEdge>,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePackage {
    pub schema_version: u32,
    pub package_id: String,
    pub dependency_map_digest: String,
    pub readiness: String,
    pub priority_order: Vec<String>,
    pub remote_state_refreshed: bool,
    pub pull_request_lifecycle: PullRequestLifecycleSummary,
    pub repositories: Vec<ChangePackageRepository>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PullRequestLifecycleSummary {
    pub status: String,
    pub linked_count: usize,
    pub refreshed_count: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub merged_count: usize,
    pub local_head_mismatch_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ChangePackageRepository {
    pub repository_id: String,
    pub pull_requests: Vec<vero_hosting::PullRequestRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_pull_requests: Vec<vero_hosting::PullRequestRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_pull_requests: Vec<RemotePullRequestState>,
    pub root: String,
    pub head_oid: String,
    pub base_oid: Option<String>,
    pub branch: Option<String>,
    pub snapshot_id: String,
    pub review_id: Option<String>,
    /// Latest saved status for this exact snapshot; config digests show its policy basis.
    pub saved_gate_status: String,
    /// Whether the saved outcome still matches the current snapshot, policy, and retained inputs.
    pub gate_validity: String,
    pub downstream_repository_count: usize,
    pub priority_factors: Vec<String>,
    pub gate_decision_id: Option<String>,
    pub effective_config_digest: Option<String>,
    pub policy_digest: Option<String>,
    pub changed_files: Vec<vero_core::SnapshotFile>,
    pub source_digest: String,
    pub has_changes: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RemotePullRequestState {
    pub pull_request: vero_hosting::PullRequestRef,
    pub provider: String,
    pub state: String,
    pub base_oid: String,
    pub head_oid: String,
    pub revision: String,
    pub local_head_matches: bool,
}

/// Capture a deterministic local change package across related checkouts.
/// It groups working-tree state and manifest relationships; it does not assert
/// that any repository has passed review or verification.
pub fn change_package_with_pull_requests(
    roots: &[PathBuf],
    base_ref: Option<&str>,
    pull_requests: &BTreeMap<String, Vec<vero_hosting::PullRequestRef>>,
    discovered_links: &BTreeMap<String, Vec<vero_hosting::PullRequestRef>>,
    remote_states: &BTreeMap<String, Vec<RemotePullRequestState>>,
    stores: &dyn vero_core::ports::RepositoryStores,
) -> Result<ChangePackage, String> {
    if roots.is_empty() || roots.len() > MAX_REPOSITORIES {
        return Err(format!(
            "provide between 1 and {MAX_REPOSITORIES} repositories"
        ));
    }
    let map = build(roots)?;
    let repository_ids = map
        .repositories
        .iter()
        .map(|repository| repository.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for (repository_id, references) in pull_requests {
        if !repository_ids.contains(repository_id.as_str()) {
            return Err(format!(
                "pull request link refers to repository ID `{repository_id}` outside this package"
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for reference in references {
            reference.validate()?;
            if !unique.insert(reference) {
                return Err(format!(
                    "pull request link for `{repository_id}` is repeated"
                ));
            }
        }
    }
    for (repository_id, references) in discovered_links {
        if !repository_ids.contains(repository_id.as_str()) {
            return Err(format!(
                "discovered pull request refers to repository ID `{repository_id}` outside this package"
            ));
        }
        for reference in references {
            reference.validate()?;
            if !pull_requests
                .get(repository_id)
                .is_some_and(|all| all.contains(reference))
            {
                return Err(format!(
                    "discovered pull request for `{repository_id}` is not linked in this package"
                ));
            }
        }
    }
    for (repository_id, states) in remote_states {
        let Some(references) = pull_requests.get(repository_id) else {
            return Err(format!(
                "remote pull request state has no linked PRs for `{repository_id}`"
            ));
        };
        for state in states {
            state.pull_request.validate()?;
            if !references.contains(&state.pull_request) || state.revision.trim().is_empty() {
                return Err(format!(
                    "remote pull request state does not match a linked PR for `{repository_id}`"
                ));
            }
        }
    }
    let mut repositories = Vec::new();
    let mut captured_git_state = BTreeMap::new();
    for entry in &map.repositories {
        let root = PathBuf::from(&entry.root);
        let head_oid = git_output(&root, &["rev-parse", "HEAD"])?;
        let branch_output = git_output(&root, &["branch", "--show-current"])?;
        let branch = (!branch_output.is_empty()).then_some(branch_output);
        let base_oid = base_ref
            .map(|base| vero_git::merge_base(&root, base))
            .transpose()?;
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
            .output()
            .map_err(|error| error.to_string())?;
        if !status.status.success() {
            return Err(format!("git status failed in {}", root.display()));
        }
        captured_git_state.insert(root.clone(), (head_oid.clone(), status.stdout.clone()));
        let snapshot = vero_git::capture(
            &root,
            vero_git::ChangeScope::BaseAndWorktree {
                base_oid: base_oid.clone(),
            },
        )?;
        let changed_files = snapshot.files.clone();
        let gate = exact_snapshot_gate(&root, &snapshot.digest, stores)?;
        let mut remote_pull_requests = remote_states.get(&entry.id).cloned().unwrap_or_default();
        for remote in &mut remote_pull_requests {
            remote.local_head_matches = remote.head_oid == head_oid;
        }
        let payload = serde_json::to_vec(&(
            snapshot.digest.as_str(),
            pull_requests.get(&entry.id),
            discovered_links.get(&entry.id),
            &remote_pull_requests,
            head_oid.as_str(),
            base_oid.as_deref(),
            branch.as_deref(),
            &changed_files,
            gate.review_id.as_deref(),
            gate.saved_gate_status.as_str(),
            gate.gate_validity.as_str(),
            gate.gate_decision_id.as_deref(),
            gate.effective_config_digest.as_deref(),
            gate.policy_digest.as_deref(),
        ))
        .map_err(|error| error.to_string())?;
        let downstream_repository_count = map
            .dependencies
            .iter()
            .filter(|edge| edge.to == entry.id)
            .map(|edge| edge.from.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let mut priority_factors = Vec::new();
        if gate.saved_gate_status == "block" && gate.gate_validity == "current" {
            priority_factors.push("current_blocking_gate".into());
        }
        if gate.gate_validity != "current" {
            priority_factors.push("gate_not_currently_validated".into());
        }
        if downstream_repository_count > 0 {
            priority_factors.push(format!(
                "directly_required_by_{downstream_repository_count}_selected_repositories"
            ));
        }
        if !changed_files.is_empty() {
            priority_factors.push(format!("{} changed files", changed_files.len()));
        }
        repositories.push(ChangePackageRepository {
            repository_id: entry.id.clone(),
            pull_requests: pull_requests.get(&entry.id).cloned().unwrap_or_default(),
            discovered_pull_requests: discovered_links.get(&entry.id).cloned().unwrap_or_default(),
            remote_pull_requests,
            root: entry.root.clone(),
            head_oid,
            base_oid,
            branch,
            snapshot_id: snapshot.digest,
            review_id: gate.review_id,
            saved_gate_status: gate.saved_gate_status,
            gate_validity: gate.gate_validity,
            downstream_repository_count,
            priority_factors,
            gate_decision_id: gate.gate_decision_id,
            effective_config_digest: gate.effective_config_digest,
            policy_digest: gate.policy_digest,
            has_changes: !changed_files.is_empty(),
            changed_files,
            source_digest: format!("sha256:{}", hex(&Sha256::digest(payload))),
        });
    }
    for (root, (captured_head, captured_status)) in &captured_git_state {
        let current_head = git_output(root, &["rev-parse", "HEAD"])?;
        let current_status = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
            .output()
            .map_err(|error| error.to_string())?;
        if !current_status.status.success()
            || &current_head != captured_head
            || &current_status.stdout != captured_status
        {
            return Err(format!(
                "repository changed while capturing package: {}",
                root.display()
            ));
        }
    }
    let current_map = build(roots)?;
    if current_map.digest != map.digest {
        return Err("repository manifests changed while capturing package".into());
    }
    let readiness = if repositories.iter().any(|repository| {
        repository.saved_gate_status == "block" && repository.gate_validity == "current"
    }) {
        "blocked"
    } else if repositories.iter().all(|repository| {
        repository.saved_gate_status == "pass" && repository.gate_validity == "current"
    }) {
        "ready"
    } else {
        "incomplete"
    };
    let mut priority_order = repositories.iter().collect::<Vec<_>>();
    priority_order.sort_by(|left, right| {
        let rank = |repository: &ChangePackageRepository| {
            if repository.saved_gate_status == "block" && repository.gate_validity == "current" {
                0
            } else if repository.gate_validity != "current"
                || repository.saved_gate_status == "incomplete"
            {
                1
            } else {
                2
            }
        };
        rank(left)
            .cmp(&rank(right))
            .then_with(|| {
                right
                    .downstream_repository_count
                    .cmp(&left.downstream_repository_count)
            })
            .then_with(|| right.changed_files.len().cmp(&left.changed_files.len()))
            .then_with(|| left.repository_id.cmp(&right.repository_id))
    });
    let priority_order = priority_order
        .into_iter()
        .map(|repository| repository.repository_id.clone())
        .collect::<Vec<_>>();
    let remote_state_refreshed = repositories
        .iter()
        .any(|repository| !repository.remote_pull_requests.is_empty());
    let linked_count = repositories
        .iter()
        .map(|repository| repository.pull_requests.len())
        .sum();
    let refreshed = repositories
        .iter()
        .flat_map(|repository| repository.remote_pull_requests.iter().cloned())
        .collect::<Vec<_>>();
    let pull_request_lifecycle = summarize_pull_request_lifecycle(linked_count, &refreshed);
    let package_payload = serde_json::to_vec(&(
        map.digest.as_str(),
        readiness,
        &priority_order,
        &repositories,
        &pull_request_lifecycle,
        &map.dependencies,
    ))
    .map_err(|error| error.to_string())?;
    let mut limitations = vec![
        if base_ref.is_some() {
            "Base is resolved independently in each checkout using its merge-base with the requested ref.".into()
        } else {
            "Without --base, only staged, unstaged, and untracked working-tree changes are captured; committed changes relative to a target branch are not included.".into()
        },
        "Saved gate outcomes are marked current only when the exact snapshot, effective configuration, protected policy, and deterministic replay all match; historical outcomes remain distinguishable.".into(),
        "Local manifest mapping is direct-only and does not resolve remote, transitive, or version-constraint relationships.".into(),
    ];
    if !remote_states.is_empty() {
        limitations.push("Linked pull request state is a point-in-time provider observation; it is informational context and never gate evidence.".into());
    }
    if !discovered_links.is_empty() {
        limitations.push("Discovered pull requests come from local provider refs whose object ID matched checkout HEAD; refs may be stale, so refresh explicitly before relying on remote state.".into());
    }
    Ok(ChangePackage {
        schema_version: 2,
        package_id: format!("sha256:{}", hex(&Sha256::digest(package_payload))),
        dependency_map_digest: map.digest,
        readiness: readiness.into(),
        priority_order,
        remote_state_refreshed,
        pull_request_lifecycle,
        repositories,
        dependency_edges: map.dependencies,
        limitations,
    })
}

fn summarize_pull_request_lifecycle(
    linked_count: usize,
    refreshed: &[RemotePullRequestState],
) -> PullRequestLifecycleSummary {
    let open_count = refreshed
        .iter()
        .filter(|state| state.state == "open")
        .count();
    let closed_count = refreshed
        .iter()
        .filter(|state| state.state == "closed")
        .count();
    let merged_count = refreshed
        .iter()
        .filter(|state| state.state == "merged")
        .count();
    let local_head_mismatch_count = refreshed
        .iter()
        .filter(|state| !state.local_head_matches)
        .count();
    let distinct_states = [open_count > 0, closed_count > 0, merged_count > 0]
        .into_iter()
        .filter(|present| *present)
        .count();
    let status = if linked_count == 0 {
        "no_linked_pull_requests"
    } else if refreshed.is_empty() {
        "unrefreshed"
    } else if refreshed.len() < linked_count {
        "partially_refreshed"
    } else if distinct_states > 1 {
        "mixed"
    } else if local_head_mismatch_count > 0 {
        "local_head_mismatch"
    } else if open_count == linked_count {
        "all_open"
    } else if closed_count == linked_count {
        "all_closed"
    } else if merged_count == linked_count {
        "all_merged"
    } else {
        "partially_refreshed"
    };
    PullRequestLifecycleSummary {
        status: status.into(),
        linked_count,
        refreshed_count: refreshed.len(),
        open_count,
        closed_count,
        merged_count,
        local_head_mismatch_count,
    }
}

struct ExactSnapshotGate {
    review_id: Option<String>,
    saved_gate_status: String,
    gate_validity: String,
    gate_decision_id: Option<String>,
    effective_config_digest: Option<String>,
    policy_digest: Option<String>,
}

fn exact_snapshot_gate(
    root: &Path,
    snapshot_id: &str,
    stores: &dyn vero_core::ports::RepositoryStores,
) -> Result<ExactSnapshotGate, String> {
    let Some(store) = stores.open_existing(root)? else {
        return Ok(ExactSnapshotGate {
            review_id: None,
            saved_gate_status: "not_reviewed".into(),
            gate_validity: "not_available".into(),
            gate_decision_id: None,
            effective_config_digest: None,
            policy_digest: None,
        });
    };
    let store: &dyn vero_core::ports::Repositories = store.as_ref();
    let mut matching_review_without_gate = None;
    for review in store.list_reviews()? {
        if review.snapshot_id != snapshot_id {
            continue;
        }
        let Some(decision) = store
            .gate_decisions_for_review(&review.review_id)?
            .last()
            .cloned()
        else {
            matching_review_without_gate.get_or_insert(review.review_id);
            continue;
        };
        let payload = store
            .get(&review.review_id)?
            .ok_or_else(|| format!("saved review {} has no payload", review.review_id))?;
        let gate_validity = match crate::deserialize_review_result(&payload) {
            Ok(saved) => current_gate_validity(root, snapshot_id, &saved, store)?,
            Err(_) => "replay_unavailable".into(),
        };
        let status = match decision.status {
            vero_core::GateStatus::Pass => "pass",
            vero_core::GateStatus::Block => "block",
            vero_core::GateStatus::Incomplete => "incomplete",
        };
        return Ok(ExactSnapshotGate {
            review_id: Some(review.review_id),
            saved_gate_status: status.into(),
            gate_validity,
            gate_decision_id: Some(decision.decision_id),
            effective_config_digest: Some(decision.effective_config_digest),
            policy_digest: Some(decision.policy_digest),
        });
    }
    if let Some(review_id) = matching_review_without_gate {
        return Ok(ExactSnapshotGate {
            review_id: Some(review_id),
            saved_gate_status: "not_gated".into(),
            gate_validity: "not_available".into(),
            gate_decision_id: None,
            effective_config_digest: None,
            policy_digest: None,
        });
    }
    Ok(ExactSnapshotGate {
        review_id: None,
        saved_gate_status: "not_reviewed".into(),
        gate_validity: "not_available".into(),
        gate_decision_id: None,
        effective_config_digest: None,
        policy_digest: None,
    })
}

fn current_gate_validity(
    root: &Path,
    snapshot_id: &str,
    saved: &crate::ReviewResult,
    store: &dyn vero_core::ports::Repositories,
) -> Result<String, String> {
    if saved.snapshot_id != snapshot_id {
        return Ok("stale_snapshot".into());
    }
    let current = crate::capture_current_change_set(root, &saved.change_set)
        .map(|snapshot| snapshot.digest == snapshot_id)
        .unwrap_or(false);
    if !current {
        return Ok("stale_snapshot".into());
    }
    let mut config = crate::load_repository_config(root)?;
    config.select_policy_profile(saved.policy_profile.as_deref())?;
    crate::apply_protected_policy(root, &mut config)?;
    let digest = crate::effective_review_config_digest_with_work_item(
        &config,
        root,
        &saved.selected_reviewers,
        &crate::active_rule_approvals(store)?,
        saved.work_item.as_ref(),
    )?;
    if digest != saved.effective_config_digest {
        return Ok("stale_configuration".into());
    }
    // Package capture is local and must not make an implicit network request. A review
    // bound to a live work item needs the regular gate check to re-fetch that source.
    if saved.work_item.is_some() {
        return Ok("external_context_unverified".into());
    }
    let replay_inputs = match saved.gate.replay_inputs.as_ref() {
        Some(inputs) if inputs.schema_version == 1 => inputs,
        _ => return Ok("replay_unavailable".into()),
    };
    let findings = saved.policy_findings.as_deref().unwrap_or(&saved.findings);
    let current_verification_runs = store.verifications_for_snapshot(snapshot_id)?;
    let current_waivers = store.waivers_for_snapshot(snapshot_id)?;
    let evaluation_time_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64;
    let mut replayed = vero_core::evaluate_gate_with_waivers_and_reviewer_policies(
        &saved.snapshot_id,
        vero_core::GateDigests {
            effective_config_digest: &saved.effective_config_digest,
            policy_digest: &saved.gate.policy_digest,
        },
        findings,
        &replay_inputs.policy,
        replay_inputs.complete,
        vero_core::GateEvidence {
            verification_runs: &current_verification_runs,
            source_evidence: &replay_inputs.evidence,
            analyzer_reports: &replay_inputs.analyzer_reports,
        },
        vero_core::GateEvaluationOptions {
            waiver_evaluation: vero_core::WaiverEvaluation {
                records: &current_waivers,
                evaluation_time_unix,
            },
            reviewer_policies: &replay_inputs.reviewer_policies,
        },
    );
    replayed.blocking_findings =
        crate::visible_blocking_findings(&replayed.blocking_findings, findings, &saved.findings);
    if replayed.verification_run_ids != saved.gate.verification_run_ids
        || replayed.evidence_digest != saved.gate.evidence_digest
    {
        return Ok("stale_verification".into());
    }
    if replayed.decision_id != saved.gate.decision_id
        || replayed.status != saved.gate.status
        || replayed.blocking_findings != saved.gate.blocking_findings
        || replayed.reasons != saved.gate.reasons
    {
        return Ok("replay_mismatch".into());
    }
    Ok("current".into())
}

fn git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}",
            args.join(" "),
            root.display()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| error.to_string())
}

pub fn repository_head_oid(root: &Path) -> Result<String, String> {
    git_output(root, &["rev-parse", "HEAD"])
}

/// Discover pull requests solely from already-fetched local refs. A ref is
/// accepted only when its object ID is exactly the current checkout HEAD.
pub fn discover_linked_pull_requests(
    roots: &[PathBuf],
) -> Result<BTreeMap<String, Vec<vero_hosting::PullRequestRef>>, String> {
    let map = build(roots)?;
    let mut result = BTreeMap::new();
    for repository in map.repositories {
        let root = Path::new(&repository.root);
        let Ok(remote) = git_output(root, &["config", "--get", "remote.origin.url"]) else {
            continue;
        };
        let Some((host, full_name)) = parse_remote_repository(&remote) else {
            continue;
        };
        let provider = match host.as_str() {
            "github.com" => "github",
            "gitlab.com" => "gitlab",
            "bitbucket.org" => "bitbucket",
            "dev.azure.com" | "ssh.dev.azure.com" => "azure-devops",
            _ => continue,
        };
        let (prefix, suffix) = match provider {
            "github" => ("refs/pull/", "/head"),
            "gitlab" => ("refs/merge-requests/", "/head"),
            "bitbucket" => ("refs/pull-requests/", "/from"),
            // Azure's usual pull/<n>/merge ref is a synthetic merge commit,
            // so it cannot safely be treated as the source branch head.
            _ => continue,
        };
        let head = git_output(root, &["rev-parse", "HEAD"])?;
        let refs = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "for-each-ref",
                "--format=%(refname)%00%(objectname)",
                prefix,
            ])
            .output()
            .map_err(|error| error.to_string())?;
        if !refs.status.success() {
            return Err(format!(
                "could not inspect local pull request refs in {}",
                root.display()
            ));
        }
        let mut found = Vec::new();
        for line in String::from_utf8_lossy(&refs.stdout).lines() {
            let Some((name, oid)) = line.split_once('\0') else {
                continue;
            };
            if oid != head || !name.starts_with(prefix) || !name.ends_with(suffix) {
                continue;
            }
            let number = &name[prefix.len()..name.len() - suffix.len()];
            let Ok(number) = number.parse::<u64>() else {
                continue;
            };
            let reference = vero_hosting::PullRequestRef {
                repository: vero_hosting::RepositoryRef {
                    host: host.clone(),
                    full_name: full_name.clone(),
                },
                number,
            };
            if reference.validate().is_ok() && !found.contains(&reference) {
                found.push(reference);
            }
        }
        if !found.is_empty() {
            result.insert(repository.id, found);
        }
    }
    Ok(result)
}

fn parse_remote_repository(remote: &str) -> Option<(String, String)> {
    let remote = remote.trim();
    let (host, path) = if let Some(rest) = remote
        .strip_prefix("https://")
        .or_else(|| remote.strip_prefix("http://"))
    {
        let (host, path) = rest.split_once('/')?;
        (host.rsplit('@').next()?.split(':').next()?, path)
    } else if let Some(rest) = remote.strip_prefix("ssh://") {
        let rest = rest.rsplit('@').next()?;
        let (host, path) = rest.split_once('/')?;
        (host.split(':').next()?, path)
    } else if let Some((left, path)) = remote.split_once(':') {
        (left.rsplit('@').next()?, path)
    } else {
        return None;
    };
    let host = host.to_ascii_lowercase();
    let mut parts = path
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .split('/');
    let owner = parts.next()?;
    let repository = parts.next()?;
    if owner.is_empty() || repository.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((host, format!("{owner}/{repository}")))
}

#[derive(Debug, Serialize)]
pub struct RepositoryEntry {
    pub id: String,
    pub root: String,
    pub ecosystem: String,
    pub manifest: String,
    pub manifest_digest: String,
}

#[derive(Debug, Serialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub package: String,
    pub declared_alias: Option<String>,
    pub kind: String,
    pub declared_requirement: Option<String>,
    pub version_compatibility: String,
    pub declared_path: Option<String>,
    pub match_basis: String,
    pub evidence_path: String,
    pub evidence_digest: String,
    pub constraint_source_path: Option<String>,
    pub constraint_source_digest: Option<String>,
}

/// Parse `REPOSITORY_ID=HOST/OWNER/REPOSITORY#NUMBER` without accepting a URL,
/// credentials, query, or fragment syntax beyond the single numeric PR marker.
pub fn parse_pull_request_link(
    value: &str,
) -> Result<(String, vero_hosting::PullRequestRef), String> {
    let (repository_id, reference) = value.split_once('=').ok_or_else(|| {
        "pull request link must be REPOSITORY_ID=HOST/OWNER/REPO#NUMBER".to_owned()
    })?;
    if repository_id.is_empty()
        || !repository_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("pull request link has an invalid repository ID".into());
    }
    let (path, number) = reference
        .rsplit_once('#')
        .ok_or_else(|| "pull request link must end with #NUMBER".to_owned())?;
    let number = number
        .parse::<u64>()
        .map_err(|_| "pull request number must be a positive integer".to_owned())?;
    let (host, full_name) = path
        .split_once('/')
        .ok_or_else(|| "pull request link must include HOST/OWNER/REPO".to_owned())?;
    let pull_request = vero_hosting::PullRequestRef {
        repository: vero_hosting::RepositoryRef {
            host: host.to_owned(),
            full_name: full_name.to_owned(),
        },
        number,
    };
    pull_request.validate()?;
    Ok((repository_id.to_owned(), pull_request))
}

#[derive(Debug, Serialize)]
pub struct CrossRepositoryImpact {
    pub schema_version: u32,
    pub producer_snapshot_id: String,
    pub changed_symbols: Vec<String>,
    pub api_contract_changes: Vec<ApiContractChange>,
    pub api_contract_compatibility: Vec<ApiContractCompatibilityIssue>,
    pub api_contract_coverage: Vec<ApiContractCoverage>,
    pub dependency_paths: Vec<CrossRepositoryDependencyPath>,
    pub references: Vec<ConsumerSymbolReference>,
    pub coverage_complete: bool,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiContractCompatibilityIssue {
    pub producer_path: String,
    pub issue: String,
    pub component_path: Option<String>,
    pub method: String,
    pub route: String,
    pub previous_operation_id: Option<String>,
    pub current_operation_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiContractCoverage {
    pub producer_path: String,
    pub method: String,
    pub route: String,
    pub analyzed: Vec<String>,
    pub not_analyzed: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiContractChange {
    pub producer_path: String,
    pub producer_digest: String,
    pub method: String,
    pub route: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CrossRepositoryDependencyPath {
    pub producer_package: String,
    pub consumer_package: String,
    pub packages: Vec<String>,
    pub manifest_digests: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsumerSymbolReference {
    pub consumer_repository: String,
    pub path: String,
    pub line: u32,
    pub symbol: String,
    #[serde(skip)]
    column: Option<u32>,
    pub certainty: String,
    pub match_context: String,
    pub source_digest: String,
    pub consumer_package_id: Option<String>,
    pub dependency_status: String,
    pub dependency_paths: Vec<CrossRepositoryDependencyPath>,
}

fn collect_changed_openapi_operations(
    producer_root: &Path,
    changed_paths: &[String],
) -> (Vec<ApiContractChange>, Vec<String>, Vec<(PathBuf, String)>) {
    let Ok(root) = producer_root.canonicalize() else {
        return (
            Vec::new(),
            vec!["Producer root could not be resolved for OpenAPI contract analysis.".into()],
            Vec::new(),
        );
    };
    let mut operations = Vec::new();
    let mut limitations = Vec::new();
    let mut scanned_contracts = Vec::new();
    for relative in changed_paths {
        let extension = Path::new(relative)
            .extension()
            .and_then(|extension| extension.to_str());
        if !matches!(extension, Some("yaml" | "yml" | "json")) {
            continue;
        }
        let path = root.join(relative);
        let Ok(canonical) = path.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(&root) {
            limitations.push(format!(
                "Changed contract path `{relative}` resolves outside the producer repository and was omitted."
            ));
            continue;
        }
        let Ok(metadata) = std::fs::metadata(&canonical) else {
            continue;
        };
        if metadata.len() > MAX_IMPACT_FILE_BYTES {
            limitations.push(format!(
                "OpenAPI contract `{relative}` exceeds the {MAX_IMPACT_FILE_BYTES} byte analysis limit."
            ));
            continue;
        }
        let Ok(bytes) = std::fs::read(&canonical) else {
            limitations.push(format!("OpenAPI contract `{relative}` could not be read."));
            continue;
        };
        scanned_contracts.push((
            canonical.clone(),
            format!("sha256:{}", hex(&Sha256::digest(&bytes))),
        ));
        let looks_like_openapi = Path::new(relative)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.to_ascii_lowercase().contains("openapi"));
        let looks_like_asyncapi = Path::new(relative)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.to_ascii_lowercase().contains("asyncapi"));
        let document: serde_yaml::Value = match serde_yaml::from_slice(&bytes) {
            Ok(document) => document,
            Err(_) => {
                if looks_like_openapi {
                    limitations.push(format!(
                        "OpenAPI contract `{relative}` could not be parsed as JSON or YAML."
                    ));
                }
                if looks_like_asyncapi {
                    limitations.push(format!(
                        "AsyncAPI contract `{relative}` could not be parsed as JSON or YAML."
                    ));
                }
                continue;
            }
        };
        let producer_digest = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
        if let Some(asyncapi_version) = yaml_string_field(&document, "asyncapi") {
            if !asyncapi_version.starts_with("2.") && !asyncapi_version.starts_with("3.") {
                limitations.push(format!(
                    "AsyncAPI contract `{relative}` uses unsupported version `{asyncapi_version}`; operation impact is unknown."
                ));
                continue;
            }
            if asyncapi_version.starts_with("3.") {
                let Some(channels) =
                    yaml_field(&document, "channels").and_then(serde_yaml::Value::as_mapping)
                else {
                    limitations.push(format!(
                        "AsyncAPI 3.x contract `{relative}` has no parseable channels mapping."
                    ));
                    continue;
                };
                let Some(async_operations) =
                    yaml_field(&document, "operations").and_then(serde_yaml::Value::as_mapping)
                else {
                    limitations.push(format!(
                        "AsyncAPI 3.x contract `{relative}` has no parseable operations mapping."
                    ));
                    continue;
                };
                let mut seen = std::collections::BTreeSet::new();
                let mut operation_without_id = false;
                let mut analyzed_operation_count = 0usize;
                for (operation_key, operation) in async_operations {
                    let Some(operation_key) = operation_key.as_str() else {
                        limitations.push(format!(
                            "AsyncAPI 3.x contract `{relative}` contains a non-string operation identifier."
                        ));
                        continue;
                    };
                    let Some(action) = yaml_string_field(operation, "action") else {
                        operation_without_id = true;
                        continue;
                    };
                    if !matches!(action, "send" | "receive") {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` has unsupported action `{action}`."
                        ));
                        continue;
                    }
                    let Some(channel_ref_obj) = yaml_field(operation, "channel") else {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` has no local channel reference."
                        ));
                        continue;
                    };
                    let Some(channel_reference) = yaml_string_field(channel_ref_obj, "$ref") else {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` has no local channel reference."
                        ));
                        continue;
                    };
                    let Some(channel_key) = channel_reference
                        .strip_prefix("#/channels/")
                        .filter(|key| !key.is_empty() && !key.contains('/'))
                        .map(|key| key.replace("~1", "/").replace("~0", "~"))
                    else {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` uses an external or unsupported channel reference."
                        ));
                        continue;
                    };
                    let Some(channel) =
                        channels.get(serde_yaml::Value::String(channel_key.clone()))
                    else {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` references a missing channel."
                        ));
                        continue;
                    };
                    if resolve_local_schema_pointer(&document, channel_reference).is_none() {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation `{operation_key}` in `{relative}` has an unresolved channel reference."
                        ));
                        continue;
                    }
                    let route = yaml_string_field(channel, "address")
                        .unwrap_or_else(|| {
                            limitations.push(format!(
                                "AsyncAPI 3.x channel `{channel_key}` in `{relative}` has no address; its channel identifier is shown instead."
                            ));
                            &channel_key
                        })
                        .to_owned();
                    let operation_id = yaml_string_field(operation, "operationId")
                        .unwrap_or(operation_key)
                        .to_owned();
                    let key = (action.to_ascii_uppercase(), channel_key.clone());
                    if !seen.insert(key.clone()) {
                        limitations.push(format!(
                            "AsyncAPI 3.x contract `{relative}` has multiple `{action}` operations on channel `{channel_key}`; operation-level compatibility is unknown."
                        ));
                        continue;
                    }
                    if operation_id.is_empty()
                        || !operation_id
                            .chars()
                            .all(|character| character == '_' || character.is_alphanumeric())
                    {
                        limitations.push(format!(
                            "AsyncAPI 3.x operation identifier `{operation_id}` in `{relative}` cannot be matched as a source identifier."
                        ));
                        continue;
                    }
                    operations.push(ApiContractChange {
                        producer_path: relative.clone(),
                        producer_digest: producer_digest.clone(),
                        method: action.to_ascii_uppercase(),
                        route,
                        operation_id,
                    });
                    analyzed_operation_count += 1;
                }
                if operation_without_id {
                    limitations.push(format!(
                        "AsyncAPI 3.x contract `{relative}` contains operations without a supported action; those operations cannot be matched to consumers."
                    ));
                }
                if async_operations.len() > analyzed_operation_count {
                    limitations.push(format!(
                        "AsyncAPI 3.x contract `{relative}` has operations with unsupported or unresolved shapes; impact coverage is incomplete."
                    ));
                }
                limitations.push(format!(
                    "AsyncAPI 3.x contract `{relative}` uses local operation/channel references; message impact is limited to single local payload schemas, while bindings, replies, traits, and multi-message operations are not fully evaluated."
                ));
                continue;
            }
            let Some(channels) =
                yaml_field(&document, "channels").and_then(serde_yaml::Value::as_mapping)
            else {
                limitations.push(format!(
                    "AsyncAPI 2.x contract `{relative}` has no parseable channels mapping."
                ));
                continue;
            };
            let mut operation_without_id = false;
            for (channel, channel_item) in channels {
                let Some(channel) = channel.as_str() else {
                    limitations.push(format!(
                        "AsyncAPI contract `{relative}` contains a non-string channel name; that channel was omitted."
                    ));
                    continue;
                };
                for action in ["publish", "subscribe"] {
                    let Some(operation) = yaml_field(channel_item, action) else {
                        continue;
                    };
                    let Some(operation_id) = yaml_string_field(operation, "operationId") else {
                        operation_without_id = true;
                        continue;
                    };
                    if operation_id.is_empty()
                        || !operation_id
                            .chars()
                            .all(|character| character == '_' || character.is_alphanumeric())
                    {
                        limitations.push(format!(
                            "AsyncAPI operation in `{relative}` has an operationId that cannot be matched as a source identifier."
                        ));
                        continue;
                    }
                    operations.push(ApiContractChange {
                        producer_path: relative.clone(),
                        producer_digest: producer_digest.clone(),
                        method: action.to_ascii_uppercase(),
                        route: channel.to_owned(),
                        operation_id: operation_id.to_owned(),
                    });
                }
            }
            if operation_without_id {
                limitations.push(format!(
                    "AsyncAPI 2.x contract `{relative}` contains operations without operationId values; those operations cannot be matched to consumer source."
                ));
            }
            limitations.push(format!(
                "AsyncAPI 2.x compatibility for `{relative}` is limited to channel/action/operationId; message schemas and protocol bindings are not analyzed."
            ));
            continue;
        }
        let Some(openapi_version) = yaml_string_field(&document, "openapi") else {
            continue;
        };
        if openapi_version.trim().is_empty() {
            limitations.push(format!(
                "OpenAPI contract `{relative}` has an empty OpenAPI version."
            ));
            continue;
        }
        let Some(paths) = yaml_field(&document, "paths").and_then(serde_yaml::Value::as_mapping)
        else {
            limitations.push(format!(
                "OpenAPI contract `{relative}` has no parseable paths mapping."
            ));
            continue;
        };
        let mut operation_without_id = false;
        for (route, path_item) in paths {
            let Some(route) = route.as_str() else {
                continue;
            };
            let Some(methods) = path_item.as_mapping() else {
                continue;
            };
            for (method, operation) in methods {
                let Some(method) = method.as_str().map(str::to_ascii_lowercase) else {
                    continue;
                };
                if !matches!(
                    method.as_str(),
                    "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace"
                ) {
                    continue;
                }
                let Some(operation_id) = yaml_string_field(operation, "operationId") else {
                    operation_without_id = true;
                    continue;
                };
                if operation_id.is_empty()
                    || !operation_id
                        .chars()
                        .all(|character| character == '_' || character.is_alphanumeric())
                {
                    limitations.push(format!(
                        "OpenAPI operation in `{relative}` has an operationId that cannot be matched as a source identifier."
                    ));
                    continue;
                }
                operations.push(ApiContractChange {
                    producer_path: relative.clone(),
                    producer_digest: producer_digest.clone(),
                    method: method.to_ascii_uppercase(),
                    route: route.to_owned(),
                    operation_id: operation_id.to_owned(),
                });
            }
        }
        if operation_without_id {
            limitations.push(format!(
                "OpenAPI contract `{relative}` contains operations without operationId values; those operations cannot be matched to consumer source."
            ));
        }
    }
    operations.sort_by(|left, right| {
        (
            &left.producer_path,
            &left.route,
            &left.method,
            &left.operation_id,
        )
            .cmp(&(
                &right.producer_path,
                &right.route,
                &right.method,
                &right.operation_id,
            ))
    });
    operations.dedup_by(|left, right| {
        left.producer_path == right.producer_path
            && left.route == right.route
            && left.method == right.method
            && left.operation_id == right.operation_id
    });
    limitations.sort();
    limitations.dedup();
    (operations, limitations, scanned_contracts)
}

fn yaml_field<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    value
        .as_mapping()?
        .get(serde_yaml::Value::String(key.to_owned()))
}

fn yaml_string_field<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a str> {
    yaml_field(value, key)?.as_str()
}

#[derive(Clone)]
struct OpenApiOperation {
    operation_id: String,
    path_parameters: Vec<serde_yaml::Value>,
    operation: serde_yaml::Value,
    document: Arc<serde_yaml::Value>,
}

type OpenApiOperationMap = BTreeMap<(String, String), OpenApiOperation>;

fn openapi_parameters(
    operation: &OpenApiOperation,
) -> BTreeMap<(String, String), serde_yaml::Value> {
    let mut parameters = BTreeMap::new();
    let operation_parameters = yaml_field(&operation.operation, "parameters")
        .and_then(serde_yaml::Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    for parameter in operation
        .path_parameters
        .iter()
        .chain(operation_parameters.iter())
    {
        let (Some(location), Some(name)) = (
            yaml_string_field(parameter, "in"),
            yaml_string_field(parameter, "name"),
        ) else {
            continue;
        };
        parameters.insert((location.to_owned(), name.to_owned()), parameter.clone());
    }
    parameters
}

fn openapi_parameter_required(parameter: Option<&serde_yaml::Value>) -> bool {
    parameter
        .and_then(|parameter| yaml_field(parameter, "required"))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
}

fn parameter_uses_content(parameter: &serde_yaml::Value) -> bool {
    yaml_field(parameter, "content").is_some()
}

fn parameter_content_schema(
    parameter: &serde_yaml::Value,
) -> Result<Option<(String, &serde_yaml::Value)>, ()> {
    let Some(content) = yaml_field(parameter, "content") else {
        return Ok(None);
    };
    let Some(content) = content.as_mapping() else {
        return Err(());
    };
    if content.len() != 1 {
        return Err(());
    }
    let (media_type, media) = content.iter().next().ok_or(())?;
    let Some(media_type) = media_type.as_str() else {
        return Err(());
    };
    let Some(schema) = yaml_field(media, "schema") else {
        return Ok(None);
    };
    Ok(Some((media_type.to_owned(), schema)))
}

fn parameter_content_media_type(parameter: &serde_yaml::Value) -> Result<Option<String>, ()> {
    let Some(content) = yaml_field(parameter, "content") else {
        return Ok(None);
    };
    let Some(content) = content.as_mapping() else {
        return Err(());
    };
    if content.len() != 1 {
        return Err(());
    }
    let (media_type, _) = content.iter().next().ok_or(())?;
    media_type
        .as_str()
        .map(|value| Some(value.to_owned()))
        .ok_or(())
}

fn parameter_schema_pair<'a>(
    baseline: &'a serde_yaml::Value,
    current: &'a serde_yaml::Value,
    component_path: &str,
) -> Result<Option<(&'a serde_yaml::Value, &'a serde_yaml::Value, String)>, ()> {
    let baseline_content = parameter_uses_content(baseline);
    let current_content = parameter_uses_content(current);
    if baseline_content || current_content {
        if !baseline_content
            || !current_content
            || yaml_field(baseline, "schema").is_some()
            || yaml_field(current, "schema").is_some()
        {
            return Err(());
        }
        let (Some((baseline_media, baseline_schema)), Some((current_media, current_schema))) = (
            parameter_content_schema(baseline)?,
            parameter_content_schema(current)?,
        ) else {
            return Err(());
        };
        if !baseline_media.eq_ignore_ascii_case(&current_media) {
            return Err(());
        }
        return Ok(Some((
            baseline_schema,
            current_schema,
            format!("{component_path}.content.{baseline_media}.schema"),
        )));
    }
    match (
        yaml_field(baseline, "schema"),
        yaml_field(current, "schema"),
    ) {
        (Some(baseline_schema), Some(current_schema)) => Ok(Some((
            baseline_schema,
            current_schema,
            format!("{component_path}.schema"),
        ))),
        (None, None) => Ok(None),
        _ => Err(()),
    }
}

fn parameter_serialization_changes(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    component_path: &str,
) -> Vec<(String, String)> {
    // Compare only explicitly supplied values. OpenAPI defaults vary by parameter
    // location and style, so treating an omitted value as a concrete default here
    // could report a false compatibility break.
    ["style", "explode", "allowReserved", "allowEmptyValue"]
        .into_iter()
        .filter_map(|field| {
            let previous = yaml_field(baseline, field)?;
            let next = yaml_field(current, field)?;
            (previous != next).then(|| {
                (
                    "parameter_serialization_changed".into(),
                    format!("{component_path}.{field}"),
                )
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
struct NumericBound {
    value: f64,
    exclusive: bool,
}

fn numeric_schema_bound(schema: &serde_yaml::Value, lower: bool) -> Option<NumericBound> {
    let (inclusive_key, exclusive_key) = if lower {
        ("minimum", "exclusiveMinimum")
    } else {
        ("maximum", "exclusiveMaximum")
    };
    let inclusive = yaml_field(schema, inclusive_key)
        .and_then(serde_yaml::Value::as_f64)
        .map(|value| NumericBound {
            value,
            exclusive: yaml_field(schema, exclusive_key)
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false),
        });
    let exclusive = yaml_field(schema, exclusive_key)
        .and_then(serde_yaml::Value::as_f64)
        .map(|value| NumericBound {
            value,
            exclusive: true,
        });
    match (inclusive, exclusive) {
        (Some(inclusive), Some(exclusive)) if lower => {
            if exclusive.value > inclusive.value
                || (exclusive.value == inclusive.value && exclusive.exclusive)
            {
                Some(exclusive)
            } else {
                Some(inclusive)
            }
        }
        (Some(inclusive), Some(exclusive)) => {
            if exclusive.value < inclusive.value
                || (exclusive.value == inclusive.value && exclusive.exclusive)
            {
                Some(exclusive)
            } else {
                Some(inclusive)
            }
        }
        (Some(bound), None) | (None, Some(bound)) => Some(bound),
        (None, None) => None,
    }
}

fn schema_types(schema: &serde_yaml::Value) -> Option<std::collections::BTreeSet<String>> {
    let type_value = yaml_field(schema, "type")?;
    let values = if let Some(value) = type_value.as_str() {
        vec![value]
    } else {
        type_value
            .as_sequence()?
            .iter()
            .map(serde_yaml::Value::as_str)
            .collect::<Option<Vec<_>>>()?
    };
    if values.is_empty()
        || values.iter().any(|value| {
            ![
                "null", "boolean", "object", "array", "number", "integer", "string",
            ]
            .contains(value)
        })
    {
        return None;
    }
    Some(values.into_iter().map(str::to_owned).collect())
}

fn schema_type_set_is_subset(
    subset: &std::collections::BTreeSet<String>,
    superset: &std::collections::BTreeSet<String>,
) -> bool {
    subset.iter().all(|value| {
        superset.contains(value) || (value == "integer" && superset.contains("number"))
    })
}

fn schema_type_change_is_breaking(
    previous: &serde_yaml::Value,
    current: &serde_yaml::Value,
    direction: &str,
) -> bool {
    let (Some(previous), Some(current)) = (schema_types(previous), schema_types(current)) else {
        return false;
    };
    if direction == "request" {
        !schema_type_set_is_subset(&previous, &current)
    } else {
        !schema_type_set_is_subset(&current, &previous)
    }
}

fn bound_is_stricter(
    previous: Option<NumericBound>,
    current: Option<NumericBound>,
    lower: bool,
) -> bool {
    match (previous, current) {
        (None, Some(_)) => true,
        (Some(previous), Some(current)) if current.value == previous.value => {
            current.exclusive && !previous.exclusive
        }
        (Some(previous), Some(current)) if lower => current.value > previous.value,
        (Some(previous), Some(current)) => current.value < previous.value,
        _ => false,
    }
}

fn bound_is_looser(
    previous: Option<NumericBound>,
    current: Option<NumericBound>,
    lower: bool,
) -> bool {
    match (previous, current) {
        (Some(_), None) => true,
        (Some(previous), Some(current)) if current.value == previous.value => {
            previous.exclusive && !current.exclusive
        }
        (Some(previous), Some(current)) if lower => current.value < previous.value,
        (Some(previous), Some(current)) => current.value > previous.value,
        _ => false,
    }
}

fn scalar_bound_is_stricter(previous: Option<f64>, current: Option<f64>, lower: bool) -> bool {
    match (previous, current) {
        (None, Some(_)) => true,
        (Some(previous), Some(current)) if lower => current > previous,
        (Some(previous), Some(current)) => current < previous,
        _ => false,
    }
}

fn scalar_bound_is_looser(previous: Option<f64>, current: Option<f64>, lower: bool) -> bool {
    match (previous, current) {
        (Some(_), None) => true,
        (Some(previous), Some(current)) if lower => current < previous,
        (Some(previous), Some(current)) => current > previous,
        _ => false,
    }
}

fn openapi_30_nullable_enabled(document: &serde_yaml::Value) -> bool {
    yaml_string_field(document, "openapi").is_some_and(|version| version.starts_with("3.0."))
}

fn schema_declares_nullable(schema: &serde_yaml::Value) -> bool {
    yaml_field(schema, "nullable")
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
        && schema_types(schema).is_some()
}

fn parameter_schema_changes(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    baseline_document: &serde_yaml::Value,
    current_document: &serde_yaml::Value,
    component_path: &str,
) -> (Vec<(String, String)>, bool) {
    if parameter_uses_content(baseline) && parameter_uses_content(current) {
        match (
            parameter_content_media_type(baseline),
            parameter_content_media_type(current),
        ) {
            (Ok(Some(previous)), Ok(Some(next))) if !previous.eq_ignore_ascii_case(&next) => {
                return (
                    vec![(
                        "parameter_content_media_type_changed".into(),
                        format!("{component_path}.content"),
                    )],
                    false,
                );
            }
            (Err(()), _) | (_, Err(())) => return (Vec::new(), true),
            _ => {}
        }
    }
    let (previous_schema, current_schema, schema_path) =
        match parameter_schema_pair(baseline, current, component_path) {
            Ok(Some(pair)) => pair,
            Ok(None) => return (Vec::new(), false),
            Err(()) => return (Vec::new(), true),
        };
    let (Ok(previous_schema), Ok(current_schema)) = (
        resolve_openapi_schema(baseline_document, previous_schema),
        resolve_openapi_schema(current_document, current_schema),
    ) else {
        return (Vec::new(), true);
    };
    let mut changes = Vec::new();
    if openapi_30_nullable_enabled(baseline_document)
        && openapi_30_nullable_enabled(current_document)
        && schema_declares_nullable(&previous_schema)
        && !schema_declares_nullable(&current_schema)
    {
        changes.push((
            "parameter_nullable_removed".into(),
            format!("{schema_path}.nullable"),
        ));
    }
    if schema_types(&previous_schema).is_some()
        && schema_types(&current_schema).is_some()
        && schema_type_change_is_breaking(&previous_schema, &current_schema, "request")
    {
        changes.push((
            "parameter_type_changed".into(),
            format!("{schema_path}.type"),
        ));
    }
    let previous_format = yaml_string_field(&previous_schema, "format");
    let current_format = yaml_string_field(&current_schema, "format");
    if previous_format.is_some() && current_format.is_some() && previous_format != current_format {
        changes.push((
            "parameter_format_changed".into(),
            format!("{schema_path}.format"),
        ));
    }
    if let (Some(previous_enum), Some(current_enum)) = (
        yaml_field(&previous_schema, "enum").and_then(serde_yaml::Value::as_sequence),
        yaml_field(&current_schema, "enum").and_then(serde_yaml::Value::as_sequence),
    ) {
        if previous_enum
            .iter()
            .any(|value| !current_enum.contains(value))
        {
            changes.push((
                "parameter_enum_narrowed".into(),
                format!("{schema_path}.enum"),
            ));
        }
    }
    let previous_pattern =
        yaml_field(&previous_schema, "pattern").and_then(serde_yaml::Value::as_str);
    let current_pattern =
        yaml_field(&current_schema, "pattern").and_then(serde_yaml::Value::as_str);
    if previous_pattern != current_pattern
        && (previous_pattern.is_some() || current_pattern.is_some())
    {
        changes.push((
            "parameter_pattern_changed".into(),
            format!("{schema_path}.pattern"),
        ));
    }
    if bound_is_stricter(
        numeric_schema_bound(&previous_schema, true),
        numeric_schema_bound(&current_schema, true),
        true,
    ) || bound_is_stricter(
        numeric_schema_bound(&previous_schema, false),
        numeric_schema_bound(&current_schema, false),
        false,
    ) {
        changes.push(("parameter_range_narrowed".into(), schema_path.clone()));
    }
    for (minimum, maximum) in [
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
        ("minProperties", "maxProperties"),
    ] {
        let previous_minimum = yaml_field(&previous_schema, minimum).and_then(|v| v.as_f64());
        let current_minimum = yaml_field(&current_schema, minimum).and_then(|v| v.as_f64());
        let previous_maximum = yaml_field(&previous_schema, maximum).and_then(|v| v.as_f64());
        let current_maximum = yaml_field(&current_schema, maximum).and_then(|v| v.as_f64());
        if scalar_bound_is_stricter(previous_minimum, current_minimum, true)
            || scalar_bound_is_stricter(previous_maximum, current_maximum, false)
        {
            let field = if scalar_bound_is_stricter(previous_minimum, current_minimum, true) {
                minimum
            } else {
                maximum
            };
            changes.push((
                "parameter_size_range_narrowed".into(),
                format!("{schema_path}.{field}"),
            ));
        }
    }
    (changes, false)
}

fn resolve_openapi_schema(
    document: &serde_yaml::Value,
    schema: &serde_yaml::Value,
) -> Result<serde_yaml::Value, ()> {
    fn validate_merged_bounds(mapping: &serde_yaml::Mapping) -> Result<(), ()> {
        let value = serde_yaml::Value::Mapping(mapping.clone());
        if let (Some(minimum), Some(maximum)) = (
            numeric_schema_bound(&value, true),
            numeric_schema_bound(&value, false),
        ) {
            if minimum.value > maximum.value
                || (minimum.value == maximum.value && (minimum.exclusive || maximum.exclusive))
            {
                return Err(());
            }
        }
        for (minimum, maximum) in [
            ("minLength", "maxLength"),
            ("minItems", "maxItems"),
            ("minProperties", "maxProperties"),
        ] {
            let (Some(minimum), Some(maximum)) = (
                mapping
                    .get(serde_yaml::Value::String(minimum.into()))
                    .and_then(serde_yaml::Value::as_f64),
                mapping
                    .get(serde_yaml::Value::String(maximum.into()))
                    .and_then(serde_yaml::Value::as_f64),
            ) else {
                continue;
            };
            if minimum > maximum {
                return Err(());
            }
        }
        if let (Some(constant), Some(values)) = (
            mapping.get(serde_yaml::Value::String("const".into())),
            mapping
                .get(serde_yaml::Value::String("enum".into()))
                .and_then(serde_yaml::Value::as_sequence),
        ) {
            if !values.contains(constant) {
                return Err(());
            }
        }
        Ok(())
    }

    fn merge_constraint(
        key: &str,
        left: &serde_yaml::Value,
        right: &serde_yaml::Value,
    ) -> Result<serde_yaml::Value, ()> {
        if left == right {
            return Ok(left.clone());
        }
        if key == "enum" {
            let (Some(left), Some(right)) = (left.as_sequence(), right.as_sequence()) else {
                return Err(());
            };
            let intersection = left
                .iter()
                .filter(|value| right.contains(value))
                .cloned()
                .collect::<Vec<_>>();
            if intersection.is_empty() {
                return Err(());
            }
            return Ok(serde_yaml::Value::Sequence(intersection));
        }
        if key == "type"
            && ((left.as_str() == Some("integer") && right.as_str() == Some("number"))
                || (left.as_str() == Some("number") && right.as_str() == Some("integer")))
        {
            return Ok(serde_yaml::Value::String("integer".into()));
        }
        let lower = [
            "minimum",
            "exclusiveMinimum",
            "minLength",
            "minItems",
            "minProperties",
        ]
        .contains(&key);
        let upper = [
            "maximum",
            "exclusiveMaximum",
            "maxLength",
            "maxItems",
            "maxProperties",
        ]
        .contains(&key);
        if lower || upper {
            let (Some(left_number), Some(right_number)) = (left.as_f64(), right.as_f64()) else {
                return Err(());
            };
            return Ok(
                if (lower && left_number >= right_number) || (upper && left_number <= right_number)
                {
                    left.clone()
                } else {
                    right.clone()
                },
            );
        }
        Err(())
    }

    fn merge_schema_constraints(
        left: &serde_yaml::Value,
        right: &serde_yaml::Value,
    ) -> Result<serde_yaml::Value, ()> {
        let (Some(left), Some(right)) = (left.as_mapping(), right.as_mapping()) else {
            return Err(());
        };
        let mut merged = left.clone();
        for (key, value) in right {
            let Some(key_name) = key.as_str() else {
                return Err(());
            };
            if key_name == "required" {
                let (Some(left), Some(right)) = (
                    merged.get(key).and_then(serde_yaml::Value::as_sequence),
                    value.as_sequence(),
                ) else {
                    return Err(());
                };
                let mut names = std::collections::BTreeSet::new();
                for name in left.iter().chain(right) {
                    names.insert(name.as_str().ok_or(())?.to_owned());
                }
                merged.insert(
                    key.clone(),
                    serde_yaml::Value::Sequence(
                        names.into_iter().map(serde_yaml::Value::String).collect(),
                    ),
                );
            } else if key_name == "properties" {
                let (Some(left_properties), Some(right_properties)) = (
                    merged.get(key).and_then(serde_yaml::Value::as_mapping),
                    value.as_mapping(),
                ) else {
                    return Err(());
                };
                let mut properties = left_properties.clone();
                for (name, property) in right_properties {
                    match properties.get(name) {
                        Some(previous) => {
                            properties.insert(
                                name.clone(),
                                merge_schema_constraints(previous, property)?,
                            );
                        }
                        None => {
                            properties.insert(name.clone(), property.clone());
                        }
                    }
                }
                merged.insert(key.clone(), serde_yaml::Value::Mapping(properties));
            } else if let Some(previous) = merged.get(key) {
                merged.insert(key.clone(), merge_constraint(key_name, previous, value)?);
            } else {
                merged.insert(key.clone(), value.clone());
            }
        }
        validate_merged_bounds(&merged)?;
        Ok(serde_yaml::Value::Mapping(merged))
    }

    fn merge_all_of(
        target: &mut serde_yaml::Mapping,
        source: serde_yaml::Mapping,
    ) -> Result<(), ()> {
        for (key, value) in source {
            if key.as_str() == Some("allOf") {
                continue;
            }
            match key.as_str() {
                Some("required") => {
                    let Some(values) = value.as_sequence() else {
                        return Err(());
                    };
                    let key = serde_yaml::Value::String("required".into());
                    let existing = target
                        .get(&key)
                        .and_then(serde_yaml::Value::as_sequence)
                        .cloned()
                        .unwrap_or_default();
                    let mut merged = std::collections::BTreeSet::new();
                    for name in existing.iter().chain(values) {
                        let Some(name) = name.as_str() else {
                            return Err(());
                        };
                        merged.insert(name.to_owned());
                    }
                    target.insert(
                        key,
                        serde_yaml::Value::Sequence(
                            merged.into_iter().map(serde_yaml::Value::String).collect(),
                        ),
                    );
                }
                Some("properties") => {
                    let Some(properties) = value.as_mapping() else {
                        return Err(());
                    };
                    let key = serde_yaml::Value::String("properties".into());
                    let existing = target
                        .entry(key)
                        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()))
                        .as_mapping_mut()
                        .ok_or(())?;
                    for (name, property) in properties {
                        if name.as_str().is_none() {
                            return Err(());
                        }
                        match existing.get(name) {
                            Some(previous) if previous != property => {
                                existing.insert(
                                    name.clone(),
                                    merge_schema_constraints(previous, property)?,
                                );
                            }
                            Some(_) => {}
                            None => {
                                existing.insert(name.clone(), property.clone());
                            }
                        }
                    }
                }
                _ => match target.get(&key) {
                    Some(previous) if previous != &value => {
                        target.insert(
                            key.clone(),
                            merge_constraint(key.as_str().ok_or(())?, previous, &value)?,
                        );
                    }
                    Some(_) => {}
                    None => {
                        target.insert(key, value);
                    }
                },
            }
        }
        validate_merged_bounds(target)?;
        Ok(())
    }

    fn expand(
        document: &serde_yaml::Value,
        schema: &serde_yaml::Value,
        active_refs: &mut std::collections::BTreeSet<String>,
        visited: &mut usize,
        depth: usize,
    ) -> Result<serde_yaml::Value, ()> {
        *visited += 1;
        if *visited > 4096 || depth >= 128 {
            return Err(());
        }
        let Some(mapping) = schema.as_mapping() else {
            return Err(());
        };
        if ["oneOf", "anyOf", "not"]
            .iter()
            .any(|key| yaml_field(schema, key).is_some())
        {
            return Err(());
        }
        if let Some(reference) = yaml_string_field(schema, "$ref") {
            if mapping.len() != 1 || !active_refs.insert(reference.to_owned()) {
                return Err(());
            }
            let target = resolve_local_schema_pointer(document, reference).ok_or(())?;
            let expanded = expand(document, target, active_refs, visited, depth + 1);
            active_refs.remove(reference);
            return expanded;
        }

        if let Some(all_of) = yaml_field(schema, "allOf") {
            let Some(branches) = all_of.as_sequence() else {
                return Err(());
            };
            let mut merged = schema.as_mapping().cloned().ok_or(())?;
            merged.remove(serde_yaml::Value::String("allOf".into()));
            for branch in branches {
                let branch = expand(document, branch, active_refs, visited, depth + 1)?;
                merge_all_of(&mut merged, branch.as_mapping().cloned().ok_or(())?)?;
            }
            let merged = serde_yaml::Value::Mapping(merged);
            return expand(document, &merged, active_refs, visited, depth + 1);
        }

        let mut expanded = schema.clone();
        let expanded_mapping = expanded.as_mapping_mut().ok_or(())?;
        if let Some(properties) =
            yaml_field(schema, "properties").and_then(serde_yaml::Value::as_mapping)
        {
            let mut resolved_properties = serde_yaml::Mapping::new();
            for (name, property_schema) in properties {
                resolved_properties.insert(
                    name.clone(),
                    expand(document, property_schema, active_refs, visited, depth + 1)?,
                );
            }
            expanded_mapping.insert(
                serde_yaml::Value::String("properties".into()),
                serde_yaml::Value::Mapping(resolved_properties),
            );
        }
        if let Some(items) = yaml_field(schema, "items") {
            expanded_mapping.insert(
                serde_yaml::Value::String("items".into()),
                expand(document, items, active_refs, visited, depth + 1)?,
            );
        }
        if let Some(additional_properties) = yaml_field(schema, "additionalProperties") {
            if additional_properties.is_mapping() {
                expanded_mapping.insert(
                    serde_yaml::Value::String("additionalProperties".into()),
                    expand(
                        document,
                        additional_properties,
                        active_refs,
                        visited,
                        depth + 1,
                    )?,
                );
            }
        }
        validate_merged_bounds(expanded_mapping)?;
        Ok(expanded)
    }

    expand(
        document,
        schema,
        &mut std::collections::BTreeSet::new(),
        &mut 0,
        0,
    )
}

fn resolve_local_schema_pointer<'a>(
    document: &'a serde_yaml::Value,
    reference: &str,
) -> Option<&'a serde_yaml::Value> {
    let pointer = reference.strip_prefix("#/")?;
    if pointer.contains('%') {
        return None;
    }
    pointer.split('/').try_fold(document, |value, part| {
        let mut decoded = String::with_capacity(part.len());
        let mut chars = part.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                match chars.next()? {
                    '0' => decoded.push('~'),
                    '1' => decoded.push('/'),
                    _ => return None,
                }
            } else {
                decoded.push(ch);
            }
        }
        value.as_mapping()?.get(serde_yaml::Value::String(decoded))
    })
}

fn expand_openapi_schema_refs(
    document: &serde_yaml::Value,
    schema: &serde_yaml::Value,
) -> Result<serde_yaml::Value, ()> {
    fn expand(
        document: &serde_yaml::Value,
        schema: &serde_yaml::Value,
        active: &mut std::collections::BTreeSet<String>,
        visited: &mut usize,
        depth: usize,
    ) -> Result<serde_yaml::Value, ()> {
        *visited += 1;
        if *visited > 4096 || depth >= 128 {
            return Err(());
        }
        let Some(mapping) = schema.as_mapping() else {
            return Err(());
        };
        if let Some(reference) = yaml_string_field(schema, "$ref") {
            if mapping.len() != 1 || !active.insert(reference.to_owned()) {
                return Err(());
            }
            let result = resolve_local_schema_pointer(document, reference)
                .ok_or(())
                .and_then(|target| expand(document, target, active, visited, depth + 1));
            active.remove(reference);
            return result;
        }

        let mut result = schema.clone();
        let result_map = result.as_mapping_mut().ok_or(())?;
        if let Some(properties) =
            yaml_field(schema, "properties").and_then(serde_yaml::Value::as_mapping)
        {
            let mut expanded = serde_yaml::Mapping::new();
            for (name, property) in properties {
                expanded.insert(
                    name.clone(),
                    expand(document, property, active, visited, depth + 1)?,
                );
            }
            result_map.insert(
                serde_yaml::Value::String("properties".into()),
                serde_yaml::Value::Mapping(expanded),
            );
        }
        for field in ["items", "additionalProperties", "not"] {
            if let Some(child) = yaml_field(schema, field).filter(|value| value.is_mapping()) {
                result_map.insert(
                    serde_yaml::Value::String(field.into()),
                    expand(document, child, active, visited, depth + 1)?,
                );
            }
        }
        for field in ["allOf", "oneOf", "anyOf"] {
            if let Some(branches) = yaml_field(schema, field) {
                let Some(branches) = branches.as_sequence() else {
                    return Err(());
                };
                let expanded = branches
                    .iter()
                    .map(|branch| expand(document, branch, active, visited, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                result_map.insert(
                    serde_yaml::Value::String(field.into()),
                    serde_yaml::Value::Sequence(expanded),
                );
            }
        }
        Ok(result)
    }

    expand(
        document,
        schema,
        &mut std::collections::BTreeSet::new(),
        &mut 0,
        0,
    )
}

fn unsupported_inline_schema(schema: &serde_yaml::Value) -> bool {
    let mut pending = vec![(schema, 0usize)];
    let mut visited = 0usize;
    while let Some((schema, depth)) = pending.pop() {
        visited += 1;
        if visited > 4096
            || depth >= 128
            || ["$ref", "allOf", "oneOf", "anyOf", "not"]
                .iter()
                .any(|key| yaml_field(schema, key).is_some())
        {
            return true;
        }
        if let Some(properties) =
            yaml_field(schema, "properties").and_then(serde_yaml::Value::as_mapping)
        {
            pending.extend(properties.values().map(|property| (property, depth + 1)));
        }
        if let Some(items) = yaml_field(schema, "items") {
            pending.push((items, depth + 1));
        }
        if let Some(additional_properties) = yaml_field(schema, "additionalProperties") {
            if additional_properties.is_mapping() {
                pending.push((additional_properties, depth + 1));
            }
        }
    }
    false
}

fn content_schemas<'a>(
    operation: &'a OpenApiOperation,
    field: &str,
) -> BTreeMap<String, &'a serde_yaml::Value> {
    let Some(content) = yaml_field(&operation.operation, field)
        .and_then(|body| yaml_field(body, "content"))
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return BTreeMap::new();
    };
    content
        .iter()
        .filter_map(|(media, value)| {
            let media = media.as_str()?;
            let schema = yaml_field(value, "schema")?;
            Some((media.to_owned(), schema))
        })
        .collect()
}

fn response_schemas(
    operation: &OpenApiOperation,
) -> BTreeMap<(String, String), &serde_yaml::Value> {
    let Some(responses) =
        yaml_field(&operation.operation, "responses").and_then(serde_yaml::Value::as_mapping)
    else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    for (status, response) in responses {
        let Some(status) = status.as_str() else {
            continue;
        };
        let Some(content) = yaml_field(response, "content").and_then(serde_yaml::Value::as_mapping)
        else {
            continue;
        };
        for (media, value) in content {
            let (Some(media), Some(schema)) = (media.as_str(), yaml_field(value, "schema")) else {
                continue;
            };
            result.insert((status.to_owned(), media.to_owned()), schema);
        }
    }
    result
}

fn has_unresolved_inline_schemas(operation: &OpenApiOperation) -> bool {
    content_schemas(operation, "requestBody")
        .values()
        .chain(response_schemas(operation).values())
        .any(|schema| resolve_openapi_schema(&operation.document, schema).is_err())
        || operation
            .path_parameters
            .iter()
            .chain(
                yaml_field(&operation.operation, "parameters")
                    .and_then(serde_yaml::Value::as_sequence)
                    .into_iter()
                    .flatten(),
            )
            .any(|parameter| {
                yaml_field(parameter, "$ref").is_some()
                    || (parameter_uses_content(parameter)
                        && parameter_content_schema(parameter)
                            .ok()
                            .flatten()
                            .is_none_or(|(_, schema)| {
                                resolve_openapi_schema(&operation.document, schema).is_err()
                            }))
                    || yaml_field(parameter, "schema").is_some_and(|schema| {
                        resolve_openapi_schema(&operation.document, schema).is_err()
                    })
            })
}

fn schema_change_issues(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    baseline_document: &serde_yaml::Value,
    current_document: &serde_yaml::Value,
    direction: &str,
    media_type: &str,
) -> Vec<(String, String)> {
    let (Ok(baseline), Ok(current)) = (
        resolve_openapi_schema(baseline_document, baseline),
        resolve_openapi_schema(current_document, current),
    ) else {
        return Vec::new();
    };
    let baseline = &baseline;
    let current = &current;
    if unsupported_inline_schema(baseline) || unsupported_inline_schema(current) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let component_prefix = if direction == "request" {
        "requestBody"
    } else {
        "content"
    };
    if schema_types(baseline).is_some()
        && schema_types(current).is_some()
        && schema_type_change_is_breaking(baseline, current, direction)
    {
        issues.push((
            format!("{direction}_schema_type_changed"),
            format!("{component_prefix}.content.{media_type}.schema.type"),
        ));
    }
    let previous_properties =
        yaml_field(baseline, "properties").and_then(serde_yaml::Value::as_mapping);
    let current_properties =
        yaml_field(current, "properties").and_then(serde_yaml::Value::as_mapping);
    let previous_required = yaml_field(baseline, "required")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let current_required = yaml_field(current, "required")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(current_properties) = current_properties {
        for (name, current_property) in current_properties {
            let Some(name) = name.as_str() else { continue };
            if direction == "request"
                && current_required.contains(name)
                && !previous_required.contains(name)
            {
                issues.push((
                    "request_required_property_added".into(),
                    format!("requestBody.content.{media_type}.schema.required.{name}"),
                ));
            }
            if let Some(previous_property) = previous_properties
                .and_then(|properties| properties.get(serde_yaml::Value::String(name.to_owned())))
            {
                if schema_types(previous_property).is_some()
                    && schema_types(current_property).is_some()
                    && schema_type_change_is_breaking(
                        previous_property,
                        current_property,
                        direction,
                    )
                {
                    issues.push((
                        format!("{direction}_property_type_changed"),
                        format!(
                            "{component_prefix}.content.{media_type}.schema.properties.{name}.type"
                        ),
                    ));
                }
            }
        }
    }
    if direction == "request" {
        if let Some(previous_properties) = previous_properties {
            for name in previous_properties
                .keys()
                .filter_map(serde_yaml::Value::as_str)
            {
                if !current_properties.is_some_and(|properties| {
                    properties.contains_key(serde_yaml::Value::String(name.to_owned()))
                }) {
                    issues.push((
                        "request_property_removed".into(),
                        format!("requestBody.content.{media_type}.schema.properties.{name}"),
                    ));
                }
            }
        }
    }
    if direction == "response" {
        for name in previous_required {
            if !current_required.contains(name) {
                issues.push((
                    "response_required_property_removed".into(),
                    format!("required.{name}"),
                ));
            }
        }
        if let Some(previous_properties) = previous_properties {
            for name in previous_properties
                .keys()
                .filter_map(serde_yaml::Value::as_str)
            {
                if !current_properties.is_some_and(|properties| {
                    properties.contains_key(serde_yaml::Value::String(name.to_owned()))
                }) {
                    issues.push((
                        "response_property_removed".into(),
                        format!("content.{media_type}.schema.properties.{name}"),
                    ));
                }
            }
        }
    }
    collect_nested_schema_issues_with_nullable(
        baseline,
        current,
        direction,
        &format!("{component_prefix}.content.{media_type}.schema"),
        0,
        openapi_30_nullable_enabled(baseline_document)
            && openapi_30_nullable_enabled(current_document),
        &mut issues,
    );
    issues
}

fn schema_composition_changes(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    path: &str,
) -> Result<Vec<String>, ()> {
    fn canonical_schema(value: &serde_yaml::Value, depth: usize) -> Result<serde_json::Value, ()> {
        if depth >= 128 {
            return Err(());
        }
        match value {
            serde_yaml::Value::Sequence(values) => Ok(serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| canonical_schema(value, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            serde_yaml::Value::Mapping(mapping) => {
                let mut result = serde_json::Map::new();
                for (key, child) in mapping {
                    let Some(key) = key.as_str() else {
                        return Err(());
                    };
                    let mut canonical = canonical_schema(child, depth + 1)?;
                    if matches!(key, "allOf" | "oneOf" | "anyOf") {
                        let Some(branches) = canonical.as_array_mut() else {
                            return Err(());
                        };
                        branches.sort_by_key(serde_json::Value::to_string);
                    }
                    result.insert(key.to_owned(), canonical);
                }
                Ok(serde_json::Value::Object(result))
            }
            _ => serde_json::to_value(value).map_err(|_| ()),
        }
    }

    fn collect(
        schema: &serde_yaml::Value,
        path: &str,
        found: &mut BTreeMap<String, String>,
        visited: &mut usize,
        depth: usize,
    ) -> Result<(), ()> {
        *visited += 1;
        if *visited > 4096 || depth >= 128 {
            return Err(());
        }
        for operator in ["allOf", "oneOf", "anyOf", "not"] {
            if let Some(value) = yaml_field(schema, operator) {
                let mut canonical_branches = value.as_sequence().cloned();
                if let Some(branches) = canonical_branches.as_mut() {
                    let mut keyed = branches
                        .iter()
                        .map(|branch| {
                            canonical_schema(branch, 0)
                                .map(|value| (value.to_string(), branch.clone()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
                    *branches = keyed.into_iter().map(|(_, branch)| branch).collect();
                }
                let canonical_value = canonical_branches
                    .as_ref()
                    .map(|branches| {
                        branches
                            .iter()
                            .map(|branch| canonical_schema(branch, 0))
                            .collect::<Result<Vec<_>, _>>()
                            .map(|value| serde_json::Value::Array(value).to_string())
                    })
                    .transpose()?
                    .unwrap_or(serde_json::to_value(value).map_err(|_| ())?.to_string());
                if found
                    .insert(format!("{path}.{operator}"), canonical_value)
                    .is_some()
                {
                    return Err(());
                }
                if let Some(branches) = canonical_branches.as_ref() {
                    for (index, branch) in branches.iter().enumerate() {
                        let branch_path = format!("{path}.{operator}[{index}]");
                        found.insert(
                            branch_path.clone(),
                            canonical_schema(branch, 0)?.to_string(),
                        );
                        collect(branch, &branch_path, found, visited, depth + 1)?;
                    }
                } else if operator != "not" {
                    return Err(());
                } else {
                    collect(
                        value,
                        &format!("{path}.{operator}"),
                        found,
                        visited,
                        depth + 1,
                    )?;
                }
            }
        }
        if let Some(properties) =
            yaml_field(schema, "properties").and_then(serde_yaml::Value::as_mapping)
        {
            for (name, child) in properties {
                let Some(name) = name.as_str() else {
                    return Err(());
                };
                collect(
                    child,
                    &format!("{path}.properties.{name}"),
                    found,
                    visited,
                    depth + 1,
                )?;
            }
        }
        if let Some(items) = yaml_field(schema, "items") {
            collect(items, &format!("{path}.items"), found, visited, depth + 1)?;
        }
        Ok(())
    }

    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    collect(baseline, path, &mut before, &mut 0, 0)?;
    collect(current, path, &mut after, &mut 0, 0)?;
    let paths = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    Ok(paths
        .into_iter()
        .filter(|path| before.get(path) != after.get(path))
        .collect())
}

fn directional_composition_issues(
    baseline_document: &serde_yaml::Value,
    baseline: &serde_yaml::Value,
    current_document: &serde_yaml::Value,
    current: &serde_yaml::Value,
    direction: &str,
    path: &str,
) -> Vec<(String, String)> {
    let (Ok(resolved_baseline), Ok(resolved_current)) = (
        expand_openapi_schema_refs(baseline_document, baseline),
        expand_openapi_schema_refs(current_document, current),
    ) else {
        return Vec::new();
    };
    fn stable_branch_type(branch: &serde_yaml::Value) -> Option<Vec<String>> {
        schema_types(branch).map(|types| types.into_iter().collect())
    }

    fn pair_branches(
        old: &[serde_yaml::Value],
        new: &[serde_yaml::Value],
    ) -> (Vec<bool>, Vec<bool>, Vec<(usize, usize)>) {
        let mut old_matched = vec![false; old.len()];
        let mut new_matched = vec![false; new.len()];
        let mut pairs = Vec::new();
        for (old_index, old_branch) in old.iter().enumerate() {
            if let Ok(old_json) = serde_json::to_value(old_branch) {
                if let Some(new_index) = new.iter().enumerate().find_map(|(index, candidate)| {
                    (!new_matched[index]
                        && serde_json::to_value(candidate).ok().as_ref() == Some(&old_json))
                    .then_some(index)
                }) {
                    old_matched[old_index] = true;
                    new_matched[new_index] = true;
                    pairs.push((old_index, new_index));
                }
            }
        }
        for old_index in 0..old.len() {
            if old_matched[old_index] {
                continue;
            }
            let Some(key) = stable_branch_type(&old[old_index]) else {
                continue;
            };
            let old_candidates = (0..old.len())
                .filter(|index| {
                    !old_matched[*index] && stable_branch_type(&old[*index]).as_ref() == Some(&key)
                })
                .collect::<Vec<_>>();
            let new_candidates = (0..new.len())
                .filter(|index| {
                    !new_matched[*index] && stable_branch_type(&new[*index]).as_ref() == Some(&key)
                })
                .collect::<Vec<_>>();
            if old_candidates.len() == 1 && new_candidates.len() == 1 {
                let new_index = new_candidates[0];
                old_matched[old_index] = true;
                new_matched[new_index] = true;
                pairs.push((old_index, new_index));
            }
        }
        (old_matched, new_matched, pairs)
    }

    let nullable_semantics_enabled = openapi_30_nullable_enabled(baseline_document)
        && openapi_30_nullable_enabled(current_document);
    struct WalkState {
        visited: usize,
        nullable_semantics_enabled: bool,
    }

    fn walk(
        baseline: &serde_yaml::Value,
        current: &serde_yaml::Value,
        direction: &str,
        path: &str,
        depth: usize,
        state: &mut WalkState,
        issues: &mut Vec<(String, String)>,
    ) {
        state.visited += 1;
        if state.visited > 4096 || depth >= 128 {
            return;
        }
        for operator in ["oneOf", "anyOf"] {
            let old = yaml_field(baseline, operator)
                .and_then(serde_yaml::Value::as_sequence)
                .cloned()
                .unwrap_or_default();
            let new = yaml_field(current, operator)
                .and_then(serde_yaml::Value::as_sequence)
                .cloned()
                .unwrap_or_default();
            // Exact branches match as a multiset; residual branches match only when
            // their declared type sets are unique on both sides.
            let (old_matched, new_matched, pairs) = pair_branches(&old, &new);

            for (old_index, new_index) in pairs {
                collect_nested_schema_issues_with_nullable(
                    &old[old_index],
                    &new[new_index],
                    direction,
                    &format!("{path}.{operator}.branch[{new_index}]"),
                    1,
                    state.nullable_semantics_enabled,
                    issues,
                );
            }

            if direction == "request" {
                for (index, matched) in old_matched.iter().enumerate() {
                    if !matched {
                        issues.push((
                            "request_composition_branch_removed".into(),
                            format!("{path}.{operator}.branch[{index}]"),
                        ));
                    }
                }
            } else {
                for (index, matched) in new_matched.iter().enumerate() {
                    if !matched {
                        issues.push((
                            "response_composition_branch_added".into(),
                            format!("{path}.{operator}.branch[{index}]"),
                        ));
                    }
                }
            }
        }

        if let (Some(old), Some(new)) = (
            yaml_field(baseline, "properties").and_then(serde_yaml::Value::as_mapping),
            yaml_field(current, "properties").and_then(serde_yaml::Value::as_mapping),
        ) {
            for (name, old_schema) in old {
                let Some(name) = name.as_str() else { continue };
                if let Some(new_schema) = new.get(serde_yaml::Value::String(name.to_owned())) {
                    walk(
                        old_schema,
                        new_schema,
                        direction,
                        &format!("{path}.properties.{name}"),
                        depth + 1,
                        state,
                        issues,
                    );
                }
            }
        }
        for (field, suffix) in [
            ("items", "items"),
            ("additionalProperties", "additionalProperties"),
            ("not", "not"),
        ] {
            if let (Some(old), Some(new)) =
                (yaml_field(baseline, field), yaml_field(current, field))
            {
                if old.is_mapping() && new.is_mapping() {
                    walk(
                        old,
                        new,
                        direction,
                        &format!("{path}.{suffix}"),
                        depth + 1,
                        state,
                        issues,
                    );
                }
            }
        }
        if let (Some(old), Some(new)) = (
            yaml_field(baseline, "allOf").and_then(serde_yaml::Value::as_sequence),
            yaml_field(current, "allOf").and_then(serde_yaml::Value::as_sequence),
        ) {
            let (_, _, pairs) = pair_branches(old, new);
            for (old_index, new_index) in pairs {
                walk(
                    &old[old_index],
                    &new[new_index],
                    direction,
                    &format!("{path}.allOf.branch[{new_index}]"),
                    depth + 1,
                    state,
                    issues,
                );
            }
        }
    }

    let mut issues = Vec::new();
    let mut state = WalkState {
        visited: 0,
        nullable_semantics_enabled,
    };
    walk(
        &resolved_baseline,
        &resolved_current,
        direction,
        path,
        0,
        &mut state,
        &mut issues,
    );
    issues
}

fn schema_finite_values(schema: &serde_yaml::Value) -> Option<Vec<serde_yaml::Value>> {
    let enum_values = yaml_field(schema, "enum")
        .and_then(serde_yaml::Value::as_sequence)
        .cloned();
    let constant = yaml_field(schema, "const").cloned();
    match (enum_values, constant) {
        (Some(values), Some(constant)) => Some(
            values
                .into_iter()
                .filter(|value| value == &constant)
                .collect(),
        ),
        (Some(values), None) => Some(values),
        (None, Some(value)) => Some(vec![value]),
        (None, None) => None,
    }
}

#[cfg(test)]
fn collect_nested_schema_issues(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    direction: &str,
    schema_path: &str,
    depth: usize,
    issues: &mut Vec<(String, String)>,
) {
    collect_nested_schema_issues_with_nullable(
        baseline,
        current,
        direction,
        schema_path,
        depth,
        false,
        issues,
    );
}

fn collect_nested_schema_issues_with_nullable(
    baseline: &serde_yaml::Value,
    current: &serde_yaml::Value,
    direction: &str,
    schema_path: &str,
    depth: usize,
    nullable_semantics_enabled: bool,
    issues: &mut Vec<(String, String)>,
) {
    if depth >= 128 {
        return;
    }
    if nullable_semantics_enabled
        && schema_types(baseline).is_some()
        && schema_types(current).is_some()
    {
        let previous_nullable = schema_declares_nullable(baseline);
        let current_nullable = schema_declares_nullable(current);
        let breaking = match direction {
            "request" => previous_nullable && !current_nullable,
            "response" => !previous_nullable && current_nullable,
            _ => false,
        };
        if breaking {
            issues.push((
                format!(
                    "{direction}_nullable_{}",
                    if direction == "request" {
                        "removed"
                    } else {
                        "added"
                    }
                ),
                format!("{schema_path}.nullable"),
            ));
        }
    }
    let previous_properties =
        yaml_field(baseline, "properties").and_then(serde_yaml::Value::as_mapping);
    let current_properties =
        yaml_field(current, "properties").and_then(serde_yaml::Value::as_mapping);
    let previous_required = yaml_field(baseline, "required")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let current_required = yaml_field(current, "required")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();

    let previous_values = schema_finite_values(baseline);
    let current_values = schema_finite_values(current);
    let enum_narrowed = match (&previous_values, &current_values) {
        (Some(previous), Some(current)) => previous.iter().any(|value| !current.contains(value)),
        (None, Some(_)) => true,
        _ => false,
    };
    let enum_broadened = match (&previous_values, &current_values) {
        (Some(previous), Some(current)) => current.iter().any(|value| !previous.contains(value)),
        (Some(_), None) => true,
        _ => false,
    };
    if (direction == "request" && enum_narrowed) || (direction == "response" && enum_broadened) {
        issues.push((
            format!(
                "{direction}_enum_{}",
                if direction == "request" {
                    "narrowed"
                } else {
                    "broadened"
                }
            ),
            format!(
                "{schema_path}.{}",
                if yaml_field(current, "enum").is_some()
                    || (yaml_field(current, "const").is_none()
                        && yaml_field(baseline, "enum").is_some())
                {
                    "enum"
                } else {
                    "const"
                }
            ),
        ));
    }

    let previous_pattern = yaml_field(baseline, "pattern").and_then(serde_yaml::Value::as_str);
    let current_pattern = yaml_field(current, "pattern").and_then(serde_yaml::Value::as_str);
    if previous_pattern != current_pattern
        && (previous_pattern.is_some() || current_pattern.is_some())
    {
        issues.push((
            format!("{direction}_schema_pattern_changed"),
            format!("{schema_path}.pattern"),
        ));
    }

    let lower_narrowed = bound_is_stricter(
        numeric_schema_bound(baseline, true),
        numeric_schema_bound(current, true),
        true,
    );
    let upper_narrowed = bound_is_stricter(
        numeric_schema_bound(baseline, false),
        numeric_schema_bound(current, false),
        false,
    );
    let lower_broadened = bound_is_looser(
        numeric_schema_bound(baseline, true),
        numeric_schema_bound(current, true),
        true,
    );
    let upper_broadened = bound_is_looser(
        numeric_schema_bound(baseline, false),
        numeric_schema_bound(current, false),
        false,
    );
    if (direction == "request" && (lower_narrowed || upper_narrowed))
        || (direction == "response" && (lower_broadened || upper_broadened))
    {
        issues.push((
            format!(
                "{direction}_numeric_range_{}",
                if direction == "request" {
                    "narrowed"
                } else {
                    "broadened"
                }
            ),
            schema_path.to_owned(),
        ));
    }

    for (minimum, maximum) in [
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
        ("minProperties", "maxProperties"),
    ] {
        let narrowed = scalar_bound_is_stricter(
            yaml_field(baseline, minimum).and_then(serde_yaml::Value::as_f64),
            yaml_field(current, minimum).and_then(serde_yaml::Value::as_f64),
            true,
        ) || scalar_bound_is_stricter(
            yaml_field(baseline, maximum).and_then(serde_yaml::Value::as_f64),
            yaml_field(current, maximum).and_then(serde_yaml::Value::as_f64),
            false,
        );
        let broadened = scalar_bound_is_looser(
            yaml_field(baseline, minimum).and_then(serde_yaml::Value::as_f64),
            yaml_field(current, minimum).and_then(serde_yaml::Value::as_f64),
            true,
        ) || scalar_bound_is_looser(
            yaml_field(baseline, maximum).and_then(serde_yaml::Value::as_f64),
            yaml_field(current, maximum).and_then(serde_yaml::Value::as_f64),
            false,
        );
        if (direction == "request" && narrowed) || (direction == "response" && broadened) {
            issues.push((
                if direction == "request" {
                    "request_schema_size_range_narrowed".into()
                } else {
                    "response_schema_size_range_broadened".into()
                },
                format!(
                    "{schema_path}.{}",
                    if (direction == "request"
                        && scalar_bound_is_stricter(
                            yaml_field(baseline, minimum).and_then(serde_yaml::Value::as_f64),
                            yaml_field(current, minimum).and_then(serde_yaml::Value::as_f64),
                            true,
                        ))
                        || (direction == "response"
                            && scalar_bound_is_looser(
                                yaml_field(baseline, minimum).and_then(serde_yaml::Value::as_f64),
                                yaml_field(current, minimum).and_then(serde_yaml::Value::as_f64),
                                true,
                            ))
                    {
                        minimum
                    } else {
                        maximum
                    }
                ),
            ));
        }
    }

    if let Some(current_properties) = current_properties {
        for (name, current_property) in current_properties {
            let Some(name) = name.as_str() else { continue };
            let property_path = format!("{schema_path}.properties.{name}");
            if depth > 0
                && direction == "request"
                && current_required.contains(name)
                && !previous_required.contains(name)
            {
                issues.push((
                    "request_required_property_added".into(),
                    format!("{schema_path}.required.{name}"),
                ));
            }
            if let Some(previous_property) = previous_properties
                .and_then(|properties| properties.get(serde_yaml::Value::String(name.to_owned())))
            {
                if depth > 0
                    && schema_types(previous_property).is_some()
                    && schema_types(current_property).is_some()
                    && schema_type_change_is_breaking(
                        previous_property,
                        current_property,
                        direction,
                    )
                {
                    issues.push((
                        format!("{direction}_property_type_changed"),
                        format!("{property_path}.type"),
                    ));
                }
                collect_nested_schema_issues_with_nullable(
                    previous_property,
                    current_property,
                    direction,
                    &property_path,
                    depth + 1,
                    nullable_semantics_enabled,
                    issues,
                );
            }
        }
    }

    if depth > 0 && direction == "request" {
        if let Some(previous_properties) = previous_properties {
            for name in previous_properties
                .keys()
                .filter_map(serde_yaml::Value::as_str)
            {
                if !current_properties.is_some_and(|properties| {
                    properties.contains_key(serde_yaml::Value::String(name.to_owned()))
                }) {
                    issues.push((
                        "request_property_removed".into(),
                        format!("{schema_path}.properties.{name}"),
                    ));
                }
            }
        }
    } else if depth > 0 {
        for name in previous_required {
            if !current_required.contains(name) {
                issues.push((
                    "response_required_property_removed".into(),
                    format!("{schema_path}.required.{name}"),
                ));
            }
        }
        if let Some(previous_properties) = previous_properties {
            for name in previous_properties
                .keys()
                .filter_map(serde_yaml::Value::as_str)
            {
                if !current_properties.is_some_and(|properties| {
                    properties.contains_key(serde_yaml::Value::String(name.to_owned()))
                }) {
                    issues.push((
                        "response_property_removed".into(),
                        format!("{schema_path}.properties.{name}"),
                    ));
                }
            }
        }
    }

    if let (Some(previous_items), Some(current_items)) =
        (yaml_field(baseline, "items"), yaml_field(current, "items"))
    {
        if schema_types(previous_items).is_some()
            && schema_types(current_items).is_some()
            && schema_type_change_is_breaking(previous_items, current_items, direction)
        {
            issues.push((
                format!("{direction}_schema_type_changed"),
                format!("{schema_path}.items.type"),
            ));
        }
        collect_nested_schema_issues_with_nullable(
            previous_items,
            current_items,
            direction,
            &format!("{schema_path}.items"),
            depth + 1,
            nullable_semantics_enabled,
            issues,
        );
    }

    if let (Some(previous_values), Some(current_values)) = (
        yaml_field(baseline, "additionalProperties"),
        yaml_field(current, "additionalProperties"),
    ) {
        if previous_values.is_mapping() && current_values.is_mapping() {
            let values_path = format!("{schema_path}.additionalProperties");
            if schema_types(previous_values).is_some()
                && schema_types(current_values).is_some()
                && schema_type_change_is_breaking(previous_values, current_values, direction)
            {
                issues.push((
                    format!("{direction}_schema_type_changed"),
                    format!("{values_path}.type"),
                ));
            }
            collect_nested_schema_issues_with_nullable(
                previous_values,
                current_values,
                direction,
                &values_path,
                depth + 1,
                nullable_semantics_enabled,
                issues,
            );
        }
    }
}

fn openapi_operations(bytes: &[u8]) -> Result<Option<OpenApiOperationMap>, String> {
    let document: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|error| error.to_string())?;
    if yaml_string_field(&document, "openapi").is_none() {
        return Ok(None);
    }
    let shared_document = Arc::new(document.clone());
    let paths = yaml_field(&document, "paths")
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| "OpenAPI document is missing its paths mapping".to_owned())?;
    let mut operations = BTreeMap::new();
    for (route, path_item) in paths {
        let Some(route) = route.as_str() else {
            continue;
        };
        let Some(methods) = path_item.as_mapping() else {
            continue;
        };
        for (method, operation) in methods {
            let Some(method) = method.as_str().map(str::to_ascii_uppercase) else {
                continue;
            };
            if !matches!(
                method.as_str(),
                "GET" | "PUT" | "POST" | "DELETE" | "OPTIONS" | "HEAD" | "PATCH" | "TRACE"
            ) {
                continue;
            }
            let operation_id = yaml_string_field(operation, "operationId")
                .unwrap_or_default()
                .to_owned();
            let path_parameters = yaml_field(path_item, "parameters")
                .and_then(serde_yaml::Value::as_sequence)
                .cloned()
                .unwrap_or_default();
            operations.insert(
                (method, route.to_owned()),
                OpenApiOperation {
                    operation_id,
                    path_parameters,
                    operation: operation.clone(),
                    document: shared_document.clone(),
                },
            );
        }
    }
    Ok(Some(operations))
}

type OpenApiSecurityRequirements =
    std::collections::BTreeSet<BTreeMap<String, std::collections::BTreeSet<String>>>;

fn openapi_security_requirements(
    operation: &OpenApiOperation,
) -> Result<OpenApiSecurityRequirements, ()> {
    let security = yaml_field(&operation.operation, "security")
        .or_else(|| yaml_field(&operation.document, "security"));
    let Some(security) = security else {
        return Ok(std::collections::BTreeSet::new());
    };
    let Some(requirements) = security.as_sequence() else {
        return Err(());
    };
    let mut normalized = std::collections::BTreeSet::new();
    for requirement in requirements {
        let Some(schemes) = requirement.as_mapping() else {
            return Err(());
        };
        let mut normalized_schemes = BTreeMap::new();
        for (scheme, scopes) in schemes {
            let Some(scheme) = scheme.as_str() else {
                return Err(());
            };
            let Some(scopes) = scopes.as_sequence() else {
                return Err(());
            };
            let mut normalized_scopes = std::collections::BTreeSet::new();
            for scope in scopes {
                let Some(scope) = scope.as_str() else {
                    return Err(());
                };
                normalized_scopes.insert(scope.to_owned());
            }
            normalized_schemes.insert(scheme.to_owned(), normalized_scopes);
        }
        normalized.insert(normalized_schemes);
    }
    Ok(normalized)
}

fn openapi_security_scheme_definition<'a>(
    document: &'a serde_yaml::Value,
    name: &str,
) -> Result<Option<&'a serde_yaml::Value>, ()> {
    let Some(schemes) = yaml_field(document, "components")
        .and_then(|components| yaml_field(components, "securitySchemes"))
    else {
        return Ok(None);
    };
    let Some(schemes) = schemes.as_mapping() else {
        return Err(());
    };
    let Some(definition) = schemes.get(serde_yaml::Value::String(name.to_owned())) else {
        return Ok(None);
    };
    if definition.as_mapping().is_none() || yaml_string_field(definition, "type").is_none() {
        return Err(());
    }
    Ok(Some(definition))
}

fn openapi_security_scheme_names(
    requirements: &OpenApiSecurityRequirements,
) -> std::collections::BTreeSet<String> {
    requirements
        .iter()
        .flat_map(|alternative| alternative.keys().cloned())
        .collect()
}

#[derive(Clone)]
struct AsyncApiOperation {
    operation_id: String,
    payload: Option<serde_yaml::Value>,
    document: serde_yaml::Value,
    route: String,
    component_path: String,
}

type AsyncApiOperationMap = BTreeMap<(String, String), AsyncApiOperation>;

fn asyncapi_message_payload<'a>(
    document: &'a serde_yaml::Value,
    mut message: &'a serde_yaml::Value,
) -> Option<serde_yaml::Value> {
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..32 {
        if yaml_field(message, "oneOf").is_some() || yaml_field(message, "anyOf").is_some() {
            return None;
        }
        let Some(reference) = yaml_string_field(message, "$ref") else {
            return yaml_field(message, "payload").cloned();
        };
        if !visited.insert(reference.to_owned()) {
            return None;
        }
        message = resolve_local_schema_pointer(document, reference)?;
    }
    None
}

fn asyncapi_operations(bytes: &[u8]) -> Result<Option<AsyncApiOperationMap>, String> {
    let document: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|error| format!("contract could not be parsed: {error}"))?;
    let Some(version) = yaml_string_field(&document, "asyncapi") else {
        return Ok(None);
    };
    if !version.starts_with("2.") && !version.starts_with("3.") {
        return Err(format!("unsupported AsyncAPI version `{version}`"));
    }
    let channels = yaml_field(&document, "channels")
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| "AsyncAPI document is missing its channels mapping".to_owned())?;
    let mut operations = BTreeMap::new();
    if version.starts_with("3.") {
        let async_operations = yaml_field(&document, "operations")
            .and_then(serde_yaml::Value::as_mapping)
            .ok_or_else(|| "AsyncAPI 3.x document is missing its operations mapping".to_owned())?;
        for (operation_key, operation) in async_operations {
            let Some(operation_key) = operation_key.as_str() else {
                return Err("AsyncAPI 3.x operation identifier is not a string".into());
            };
            let action = yaml_string_field(operation, "action")
                .ok_or_else(|| format!("AsyncAPI 3.x operation `{operation_key}` has no action"))?;
            if !matches!(action, "send" | "receive") {
                return Err(format!(
                    "AsyncAPI 3.x operation `{operation_key}` has unsupported action `{action}`"
                ));
            }
            let reference = yaml_string_field(
                yaml_field(operation, "channel").ok_or_else(|| {
                    format!("AsyncAPI 3.x operation `{operation_key}` has no channel")
                })?,
                "$ref",
            )
            .ok_or_else(|| {
                format!("AsyncAPI 3.x operation `{operation_key}` has no local channel reference")
            })?;
            let channel_key = reference
                .strip_prefix("#/channels/")
                .filter(|key| !key.is_empty() && !key.contains('/'))
                .map(|key| key.replace("~1", "/").replace("~0", "~"))
                .ok_or_else(|| {
                    format!("AsyncAPI 3.x operation `{operation_key}` has an unsupported channel reference")
                })?;
            let channel = channels
                .get(serde_yaml::Value::String(channel_key.clone()))
                .ok_or_else(|| {
                    format!("AsyncAPI 3.x operation `{operation_key}` references a missing channel")
                })?;
            if resolve_local_schema_pointer(&document, reference).is_none() {
                return Err(format!(
                    "AsyncAPI 3.x operation `{operation_key}` has an unresolved channel reference"
                ));
            }
            let route = yaml_string_field(channel, "address")
                .unwrap_or(&channel_key)
                .to_owned();
            let messages =
                yaml_field(operation, "messages").and_then(serde_yaml::Value::as_sequence);
            let payload = messages
                .filter(|messages| messages.len() == 1)
                .and_then(|messages| messages.first())
                .and_then(|message_reference| yaml_string_field(message_reference, "$ref"))
                .and_then(|message_reference| {
                    resolve_local_schema_pointer(&document, message_reference)
                })
                .and_then(|message| asyncapi_message_payload(&document, message));
            let key = (action.to_ascii_uppercase(), channel_key.clone());
            if operations
                .insert(
                    key,
                    AsyncApiOperation {
                        operation_id: yaml_string_field(operation, "operationId")
                            .unwrap_or(operation_key)
                            .to_owned(),
                        payload,
                        document: document.clone(),
                        route,
                        component_path: format!("operations.{operation_key}"),
                    },
                )
                .is_some()
            {
                return Err(format!(
                    "AsyncAPI 3.x has multiple `{action}` operations on channel `{channel_key}`; comparison is ambiguous"
                ));
            }
        }
        return Ok(Some(operations));
    }
    for (channel, channel_item) in channels {
        let Some(channel) = channel.as_str() else {
            continue;
        };
        for action in ["publish", "subscribe"] {
            if let Some(operation) = yaml_field(channel_item, action) {
                operations.insert(
                    (action.to_ascii_uppercase(), channel.to_owned()),
                    AsyncApiOperation {
                        operation_id: yaml_string_field(operation, "operationId")
                            .unwrap_or_default()
                            .to_owned(),
                        payload: yaml_field(operation, "message")
                            .and_then(|message| asyncapi_message_payload(&document, message)),
                        document: document.clone(),
                        route: channel.to_owned(),
                        component_path: format!("channels.{channel}.{action}"),
                    },
                );
            }
        }
    }
    Ok(Some(operations))
}

fn compare_openapi_contracts(
    producer_root: &Path,
    baselines: &BTreeMap<String, Vec<u8>>,
) -> (
    Vec<ApiContractCompatibilityIssue>,
    Vec<ApiContractCoverage>,
    Vec<String>,
) {
    let mut issues = Vec::new();
    let mut coverage = Vec::new();
    let mut limitations = Vec::new();
    for (path, baseline_bytes) in baselines {
        match asyncapi_operations(baseline_bytes) {
            Ok(Some(baseline)) => {
                let current_path = producer_root.join(path);
                let current_path = match current_path.canonicalize() {
                    Ok(current_path) if current_path.starts_with(producer_root) => {
                        Some(current_path)
                    }
                    Ok(_) => {
                        limitations.push(format!(
                            "Current AsyncAPI contract `{path}` resolves outside the producer repository; compatibility is unknown."
                        ));
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        limitations.push(format!(
                            "Current AsyncAPI contract `{path}` could not be read ({error}); compatibility is unknown."
                        ));
                        continue;
                    }
                };
                let current_bytes = match current_path {
                    Some(current_file) => match std::fs::read(current_file) {
                        Ok(bytes) => Some(bytes),
                        Err(error) => {
                            limitations.push(format!(
                                "Current AsyncAPI contract `{path}` could not be read ({error}); compatibility is unknown."
                            ));
                            continue;
                        }
                    },
                    None => None,
                };
                let current = match current_bytes.as_deref() {
                    Some(bytes) => match asyncapi_operations(bytes) {
                        Ok(Some(operations)) => operations,
                        Ok(None) => {
                            limitations.push(format!(
                                "Current contract `{path}` is no longer recognized as AsyncAPI; compatibility is unknown."
                            ));
                            continue;
                        }
                        Err(error) => {
                            limitations.push(format!(
                                "Current AsyncAPI contract `{path}` could not be analyzed ({error}); compatibility is unknown."
                            ));
                            continue;
                        }
                    },
                    None => BTreeMap::new(),
                };
                for ((action, channel), previous) in &baseline {
                    coverage.push(ApiContractCoverage {
                        producer_path: path.clone(),
                        method: action.clone(),
                        route: previous.route.clone(),
                        analyzed: vec![
                            "asyncapi_channel".into(),
                            "asyncapi_operation_id".into(),
                            "asyncapi_inline_message_schema".into(),
                            "asyncapi_single_local_message_references".into(),
                            "schema_enum_constraints".into(),
                            "schema_const_constraints".into(),
                            "schema_numeric_range_constraints".into(),
                            "schema_pattern_constraints".into(),
                            "schema_size_range_constraints".into(),
                            "schema_type_constraints".into(),
                        ],
                        not_analyzed: vec![
                            "asyncapi_message_variants_and_external_references".into(),
                            "asyncapi_bindings".into(),
                            "schema_composition_semantics".into(),
                            "schema_pattern_language_inclusion".into(),
                        ],
                        status: "incomplete".into(),
                    });
                    let version =
                        yaml_string_field(&previous.document, "asyncapi").unwrap_or("2.x");
                    limitations.push(format!(
                        "AsyncAPI {version} compatibility for `{path}` checks channel/action/operationId and selected constraints in inline payload schemas or bounded single local message references; changed regular expressions are review signals without proving language inclusion. Multi-variant or external message references, protocol bindings, full schema composition semantics, and regular-expression language inclusion are not evaluated."
                    ));
                    let current_operation_id = current.get(&(action.clone(), channel.clone()));
                    let issue = match current_operation_id {
                        None => Some("operation_removed"),
                        Some(current) if current.operation_id.is_empty() => {
                            Some("operation_id_removed")
                        }
                        Some(current) if current.operation_id != previous.operation_id => {
                            Some("operation_id_changed")
                        }
                        _ => None,
                    };
                    if current_operation_id.is_some_and(|current| current.route != previous.route) {
                        issues.push(ApiContractCompatibilityIssue {
                            producer_path: path.clone(),
                            issue: "channel_address_changed".into(),
                            component_path: Some(format!(
                                "{}.channel.address",
                                previous.component_path
                            )),
                            method: action.clone(),
                            route: previous.route.clone(),
                            previous_operation_id: (!previous.operation_id.is_empty())
                                .then_some(previous.operation_id.clone()),
                            current_operation_id: current_operation_id
                                .map(|operation| operation.operation_id.clone())
                                .filter(|id| !id.is_empty()),
                        });
                    }
                    if let Some(issue) = issue {
                        issues.push(ApiContractCompatibilityIssue {
                            producer_path: path.clone(),
                            issue: issue.into(),
                            component_path: Some(previous.component_path.clone()),
                            method: action.clone(),
                            route: previous.route.clone(),
                            previous_operation_id: (!previous.operation_id.is_empty())
                                .then_some(previous.operation_id.clone()),
                            current_operation_id: current_operation_id
                                .map(|operation| operation.operation_id.clone())
                                .filter(|id| !id.is_empty()),
                        });
                    }
                    if let Some(current) = current_operation_id {
                        match (&previous.payload, &current.payload) {
                            (Some(previous_payload), Some(current_payload)) => {
                                let payload_path = if previous.component_path.starts_with("operations.") {
                                    format!("{}.messages[0].payload", previous.component_path)
                                } else {
                                    format!("{}.message.payload", previous.component_path)
                                };
                                if let Ok(paths) = schema_composition_changes(
                                    previous_payload,
                                    current_payload,
                                    &payload_path,
                                ) {
                                    for component_path in paths {
                                        issues.push(ApiContractCompatibilityIssue {
                                            producer_path: path.clone(),
                                            issue: "schema_composition_changed".into(),
                                            component_path: Some(component_path),
                                            method: action.clone(),
                                            route: previous.route.clone(),
                                            previous_operation_id: (!previous.operation_id.is_empty())
                                                .then_some(previous.operation_id.clone()),
                                            current_operation_id: (!current.operation_id.is_empty())
                                                .then_some(current.operation_id.clone()),
                                        });
                                    }
                                }
                                for (issue, component_path) in schema_change_issues(
                                    previous_payload,
                                    current_payload,
                                    &previous.document,
                                    &current.document,
                                    if matches!(action.as_str(), "SUBSCRIBE" | "RECEIVE") {
                                        "request"
                                    } else {
                                        "response"
                                    },
                                    "application/json",
                                ) {
                                    let suffix = component_path
                                        .split_once(".schema")
                                        .map(|(_, suffix)| suffix.trim_start_matches('.'))
                                        .unwrap_or(component_path.as_str());
                                    issues.push(ApiContractCompatibilityIssue {
                                        producer_path: path.clone(),
                                        issue,
                                        component_path: Some(if suffix.is_empty() {
                                            payload_path.clone()
                                        } else {
                                            format!("{payload_path}.{suffix}")
                                        }),
                                        method: action.clone(),
                                        route: previous.route.clone(),
                                        previous_operation_id: (!previous.operation_id.is_empty())
                                            .then_some(previous.operation_id.clone()),
                                        current_operation_id: (!current.operation_id.is_empty())
                                            .then_some(current.operation_id.clone()),
                                    });
                                }
                            }
                            _ => limitations.push(format!(
                                "AsyncAPI message payload compatibility for `{path}` channel `{channel}` action `{action}` is unknown because one side lacks a supported single payload schema or local message reference."
                            )),
                        }
                    }
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                if serde_yaml::from_slice::<serde_yaml::Value>(baseline_bytes)
                    .ok()
                    .is_some_and(|document| yaml_field(&document, "asyncapi").is_some())
                {
                    limitations.push(format!(
                        "Base AsyncAPI contract `{path}` could not be analyzed ({error}); compatibility is unknown."
                    ));
                    continue;
                }
            }
        }
        let baseline = match openapi_operations(baseline_bytes) {
            Ok(Some(operations)) => operations,
            Ok(None) => continue,
            Err(error) => {
                limitations.push(format!(
                    "Base OpenAPI contract `{path}` could not be analyzed ({error}); compatibility is unknown."
                ));
                continue;
            }
        };
        for (method, route) in baseline.keys() {
            coverage.push(ApiContractCoverage {
                producer_path: path.clone(),
                method: method.clone(),
                route: route.clone(),
                analyzed: vec![
                    "route".into(),
                    "operation_id".into(),
                    "local_schema_references".into(),
                    "requiredness".into(),
                    "parameter_type".into(),
                    "parameter_format".into(),
                    "parameter_enum".into(),
                    "parameter_numeric_range".into(),
                    "parameter_pattern".into(),
                    "parameter_serialization".into(),
                    "parameter_size_range".into(),
                    "parameter_composition_branch_changes".into(),
                    "single_media_parameter_content_schemas".into(),
                    "parameter_content_media_type".into(),
                    "response_status".into(),
                    "inline_request_schema".into(),
                    "inline_response_schema".into(),
                    "schema_enum_constraints".into(),
                    "schema_const_constraints".into(),
                    "schema_numeric_range_constraints".into(),
                    "schema_pattern_constraints".into(),
                    "schema_size_range_constraints".into(),
                    "schema_type_constraints".into(),
                    "schema_nullable_constraints".into(),
                    "security_requirements".into(),
                    "security_scheme_definitions".into(),
                    "schema_composition_shape".into(),
                    "all_of_object_constraints".into(),
                    "request_media_type".into(),
                    "response_media_type".into(),
                ],
                not_analyzed: vec![
                    "parameter_schema_constraints".into(),
                    "request_schema_constraints".into(),
                    "response_schema_constraints".into(),
                    "schema_composition_semantics".into(),
                    "schema_pattern_language_inclusion".into(),
                    "security_scheme_runtime_semantics".into(),
                    "unresolved_schema_reference".into(),
                ],
                status: "incomplete".into(),
            });
        }
        limitations.push(format!(
            "OpenAPI compatibility for `{path}` compares route/operationId changes, requiredness, removed request/response media types, parameter types/formats/enums/numeric ranges, pattern changes, size bounds, and conservative oneOf/anyOf branch additions/removals. Parameter content media-type changes are reported; content schemas are compared when both revisions use the same single media type and provide a schema. It also compares selected nested property/type/enum/numeric-range constraints and pattern changes, OpenAPI 3.0 nullable changes when both sides use 3.0, local schema references, effective security requirement scheme/scope sets, and structural definitions for referenced security schemes; pattern changes are review signals without proving regular-expression language inclusion. Other request/parameter/response schema constraints, full schema composition semantics, unresolved references, and runtime security protocol behavior are not fully evaluated."
        ));
        let current_path = producer_root.join(path);
        let current_path = match current_path.canonicalize() {
            Ok(current_path) if current_path.starts_with(producer_root) => Some(current_path),
            Ok(_) => {
                limitations.push(format!(
                    "Current OpenAPI contract `{path}` resolves outside the producer repository; compatibility is unknown."
                ));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                limitations.push(format!(
                    "Current OpenAPI contract `{path}` could not be read ({error}); compatibility is unknown."
                ));
                continue;
            }
        };
        let current_bytes = match current_path {
            Some(path) => match std::fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    limitations.push(format!(
                        "Current OpenAPI contract `{}` could not be read ({error}); compatibility is unknown.",
                        path.display()
                    ));
                    continue;
                }
            },
            None => None,
        };
        let current_operations = match current_bytes.as_deref() {
            Some(bytes) => match openapi_operations(bytes) {
                Ok(Some(operations)) => operations,
                Ok(None) => BTreeMap::new(),
                Err(error) => {
                    limitations.push(format!(
                        "Current OpenAPI contract `{path}` could not be analyzed ({error}); compatibility is unknown."
                    ));
                    continue;
                }
            },
            None => BTreeMap::new(),
        };
        for ((method, route), previous_operation) in baseline {
            let current_operation = current_operations.get(&(method.clone(), route.clone()));
            if let Some(current_operation) = current_operation {
                let previous_nullable = openapi_30_nullable_enabled(&previous_operation.document);
                let current_nullable = openapi_30_nullable_enabled(&current_operation.document);
                if previous_nullable != current_nullable {
                    limitations.push(format!(
                        "OpenAPI nullable semantics for `{method} {route}` in `{path}` are unknown because one revision uses OpenAPI 3.0 and the other does not."
                    ));
                }
            }
            let issue = match current_operation {
                None => Some("operation_removed"),
                Some(current) if current.operation_id.is_empty() => Some("operation_id_removed"),
                Some(current) if current.operation_id != previous_operation.operation_id => {
                    Some("operation_id_changed")
                }
                _ => None,
            };
            if let Some(issue) = issue {
                issues.push(ApiContractCompatibilityIssue {
                    producer_path: path.clone(),
                    issue: issue.into(),
                    component_path: None,
                    method: method.clone(),
                    route: route.clone(),
                    previous_operation_id: (!previous_operation.operation_id.is_empty())
                        .then_some(previous_operation.operation_id.clone()),
                    current_operation_id: current_operation
                        .map(|operation| operation.operation_id.clone())
                        .filter(|id| !id.is_empty()),
                });
            }
            if let Some(current_operation) = current_operation {
                match (
                    openapi_security_requirements(&previous_operation),
                    openapi_security_requirements(current_operation),
                ) {
                    (Ok(previous), Ok(current)) => {
                        if previous != current {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue: "security_requirements_changed".into(),
                                component_path: Some("security.requirements".into()),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                        let previous_schemes = openapi_security_scheme_names(&previous);
                        let current_schemes = openapi_security_scheme_names(&current);
                        let schemes = previous_schemes
                            .union(&current_schemes)
                            .cloned()
                            .collect::<std::collections::BTreeSet<_>>();
                        for scheme in schemes {
                            match (
                                openapi_security_scheme_definition(
                                    &previous_operation.document,
                                    &scheme,
                                ),
                                openapi_security_scheme_definition(
                                    &current_operation.document,
                                    &scheme,
                                ),
                            ) {
                                (Ok(Some(previous)), Ok(Some(current))) if previous != current => {
                                    issues.push(ApiContractCompatibilityIssue {
                                        producer_path: path.clone(),
                                        issue: "security_scheme_definition_changed".into(),
                                        component_path: Some(format!(
                                            "components.securitySchemes.{scheme}"
                                        )),
                                        method: method.clone(),
                                        route: route.clone(),
                                        previous_operation_id: (!previous_operation
                                            .operation_id
                                            .is_empty())
                                        .then_some(previous_operation.operation_id.clone()),
                                        current_operation_id: (!current_operation
                                            .operation_id
                                            .is_empty())
                                        .then_some(current_operation.operation_id.clone()),
                                    });
                                }
                                (Ok(Some(_)), Ok(None)) => {
                                    issues.push(ApiContractCompatibilityIssue {
                                        producer_path: path.clone(),
                                        issue: "security_scheme_definition_removed".into(),
                                        component_path: Some(format!(
                                            "components.securitySchemes.{scheme}"
                                        )),
                                        method: method.clone(),
                                        route: route.clone(),
                                        previous_operation_id: (!previous_operation
                                            .operation_id
                                            .is_empty())
                                        .then_some(previous_operation.operation_id.clone()),
                                        current_operation_id: (!current_operation
                                            .operation_id
                                            .is_empty())
                                        .then_some(current_operation.operation_id.clone()),
                                    });
                                }
                                (Ok(None), Ok(Some(_))) => limitations.push(format!(
                                    "OpenAPI security scheme `{scheme}` for `{method} {route}` in `{path}` is newly defined; compatibility with the baseline's unresolved scheme is unknown."
                                )),
                                (Ok(None), Ok(None)) => limitations.push(format!(
                                    "OpenAPI security scheme `{scheme}` for `{method} {route}` in `{path}` is undefined in both revisions; compatibility is unknown."
                                )),
                                (Err(()), _) | (_, Err(())) => limitations.push(format!(
                                    "OpenAPI security scheme `{scheme}` for `{method} {route}` in `{path}` could not be structurally compared; compatibility is unknown."
                                )),
                                _ => {}
                            }
                        }
                    }
                    (Err(()), _) | (_, Err(())) => limitations.push(format!(
                        "OpenAPI security requirements for `{method} {route}` in `{path}` could not be normalized; compatibility is unknown."
                    )),
                }
                let previous_parameters = openapi_parameters(&previous_operation);
                let current_parameters = openapi_parameters(current_operation);
                for (parameter_key, current_parameter) in &current_parameters {
                    if openapi_parameter_required(Some(current_parameter))
                        && !openapi_parameter_required(previous_parameters.get(parameter_key))
                    {
                        issues.push(ApiContractCompatibilityIssue {
                            producer_path: path.clone(),
                            issue: "required_parameter_added".into(),
                            component_path: Some(format!(
                                "parameters[{}:{}]",
                                parameter_key.0, parameter_key.1
                            )),
                            method: method.clone(),
                            route: route.clone(),
                            previous_operation_id: (!previous_operation.operation_id.is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                            current_operation_id: (!current_operation.operation_id.is_empty())
                                .then_some(current_operation.operation_id.clone()),
                        });
                    }
                    if let Some(previous_parameter) = previous_parameters.get(parameter_key) {
                        let component_path =
                            format!("parameters[{}:{}]", parameter_key.0, parameter_key.1);
                        for (issue, component_path) in parameter_serialization_changes(
                            previous_parameter,
                            current_parameter,
                            &component_path,
                        ) {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(component_path),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                        let (schema_changes, unresolved) = parameter_schema_changes(
                            previous_parameter,
                            current_parameter,
                            &previous_operation.document,
                            &current_operation.document,
                            &component_path,
                        );
                        for (issue, component_path) in schema_changes {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(component_path),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                        if let Ok(Some((previous_schema, current_schema, schema_path))) =
                            parameter_schema_pair(
                                previous_parameter,
                                current_parameter,
                                &component_path,
                            )
                        {
                            for (issue, component_path) in directional_composition_issues(
                                &previous_operation.document,
                                previous_schema,
                                &current_operation.document,
                                current_schema,
                                "request",
                                &schema_path,
                            ) {
                                issues.push(ApiContractCompatibilityIssue {
                                    producer_path: path.clone(),
                                    issue,
                                    component_path: Some(component_path),
                                    method: method.clone(),
                                    route: route.clone(),
                                    previous_operation_id: (!previous_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(previous_operation.operation_id.clone()),
                                    current_operation_id: (!current_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                                });
                            }
                        }
                        if unresolved {
                            if parameter_uses_content(previous_parameter)
                                || parameter_uses_content(current_parameter)
                            {
                                limitations.push(format!(
                                    "OpenAPI parameter `{method} {route} {}` in `{path}` uses content that lacks a matching single media type with a comparable schema, or changes between content and schema forms; compatibility is unknown.",
                                    component_path
                                ));
                            } else {
                                limitations.push(format!(
                                    "OpenAPI parameter `{method} {route} {}` in `{path}` contains an unresolved schema reference/composition or has a schema representation that could not be compared fully.",
                                    component_path
                                ));
                            }
                        }
                    }
                }
                let previous_request_body =
                    yaml_field(&previous_operation.operation, "requestBody");
                let current_request_body = yaml_field(&current_operation.operation, "requestBody");
                if current_request_body
                    .and_then(|body| yaml_field(body, "required"))
                    .and_then(serde_yaml::Value::as_bool)
                    .unwrap_or(false)
                    && !previous_request_body
                        .and_then(|body| yaml_field(body, "required"))
                        .and_then(serde_yaml::Value::as_bool)
                        .unwrap_or(false)
                {
                    issues.push(ApiContractCompatibilityIssue {
                        producer_path: path.clone(),
                        issue: "request_body_required".into(),
                        component_path: Some("requestBody.required".into()),
                        method: method.clone(),
                        route: route.clone(),
                        previous_operation_id: (!previous_operation.operation_id.is_empty())
                            .then_some(previous_operation.operation_id.clone()),
                        current_operation_id: (!current_operation.operation_id.is_empty())
                            .then_some(current_operation.operation_id.clone()),
                    });
                }
                let previous_request_schemas = content_schemas(&previous_operation, "requestBody");
                let current_request_schemas = content_schemas(current_operation, "requestBody");
                for media_type in previous_request_schemas.keys() {
                    if !current_request_schemas.contains_key(media_type) {
                        issues.push(ApiContractCompatibilityIssue {
                            producer_path: path.clone(),
                            issue: "request_media_type_removed".into(),
                            component_path: Some(format!("requestBody.content.{media_type}")),
                            method: method.clone(),
                            route: route.clone(),
                            previous_operation_id: (!previous_operation.operation_id.is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                            current_operation_id: (!current_operation.operation_id.is_empty())
                                .then_some(current_operation.operation_id.clone()),
                        });
                    }
                }
                for (media_type, current_schema) in &current_request_schemas {
                    if let Some(previous_schema) = previous_request_schemas.get(media_type) {
                        if let Ok(paths) = schema_composition_changes(
                            previous_schema,
                            current_schema,
                            &format!("requestBody.content.{media_type}.schema"),
                        ) {
                            for component_path in paths {
                                issues.push(ApiContractCompatibilityIssue {
                                    producer_path: path.clone(),
                                    issue: "schema_composition_changed".into(),
                                    component_path: Some(component_path),
                                    method: method.clone(),
                                    route: route.clone(),
                                    previous_operation_id: (!previous_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(previous_operation.operation_id.clone()),
                                    current_operation_id: (!current_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                                });
                            }
                        } else {
                            limitations.push(format!(
                                "OpenAPI schema composition for `{method} {route}` in `{path}` exceeded the comparison bounds or had an unsupported shape; compatibility is unknown."
                            ));
                        }
                        for (issue, component_path) in schema_change_issues(
                            previous_schema,
                            current_schema,
                            &previous_operation.document,
                            &current_operation.document,
                            "request",
                            media_type,
                        ) {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(component_path),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                        for (issue, component_path) in directional_composition_issues(
                            &previous_operation.document,
                            previous_schema,
                            &current_operation.document,
                            current_schema,
                            "request",
                            &format!("requestBody.content.{media_type}.schema"),
                        ) {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(component_path),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                    }
                }
                let previous_responses = yaml_field(&previous_operation.operation, "responses")
                    .and_then(serde_yaml::Value::as_mapping);
                let current_responses = yaml_field(&current_operation.operation, "responses")
                    .and_then(serde_yaml::Value::as_mapping);
                if let Some(previous_responses) = previous_responses {
                    for status in previous_responses
                        .keys()
                        .filter_map(serde_yaml::Value::as_str)
                    {
                        if status == "default" {
                            continue;
                        }
                        if !current_responses
                            .map(|responses| {
                                responses.contains_key(serde_yaml::Value::String(status.to_owned()))
                            })
                            .unwrap_or(false)
                        {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue: "response_status_removed".into(),
                                component_path: Some(format!("responses.{status}")),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                    }
                }
                let previous_response_schemas = response_schemas(&previous_operation);
                let current_response_schemas = response_schemas(current_operation);
                for (status, media_type) in previous_response_schemas.keys() {
                    if !current_response_schemas.contains_key(&(status.clone(), media_type.clone()))
                    {
                        issues.push(ApiContractCompatibilityIssue {
                            producer_path: path.clone(),
                            issue: "response_media_type_removed".into(),
                            component_path: Some(format!(
                                "responses.{status}.content.{media_type}"
                            )),
                            method: method.clone(),
                            route: route.clone(),
                            previous_operation_id: (!previous_operation.operation_id.is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                            current_operation_id: (!current_operation.operation_id.is_empty())
                                .then_some(current_operation.operation_id.clone()),
                        });
                    }
                }
                for (key, current_schema) in &current_response_schemas {
                    if let Some(previous_schema) = previous_response_schemas.get(key) {
                        if let Ok(paths) = schema_composition_changes(
                            previous_schema,
                            current_schema,
                            &format!("responses.{}.{}.schema", key.0, key.1),
                        ) {
                            for component_path in paths {
                                issues.push(ApiContractCompatibilityIssue {
                                    producer_path: path.clone(),
                                    issue: "schema_composition_changed".into(),
                                    component_path: Some(component_path),
                                    method: method.clone(),
                                    route: route.clone(),
                                    previous_operation_id: (!previous_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(previous_operation.operation_id.clone()),
                                    current_operation_id: (!current_operation
                                        .operation_id
                                        .is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                                });
                            }
                        } else {
                            limitations.push(format!(
                                "OpenAPI schema composition for `{method} {route}` in `{path}` exceeded the comparison bounds or had an unsupported shape; compatibility is unknown."
                            ));
                        }
                        for (issue, component_path) in schema_change_issues(
                            previous_schema,
                            current_schema,
                            &previous_operation.document,
                            &current_operation.document,
                            "response",
                            &key.1,
                        ) {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(format!(
                                    "responses.{}.{}",
                                    key.0, component_path
                                )),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                        for (issue, component_path) in directional_composition_issues(
                            &previous_operation.document,
                            previous_schema,
                            &current_operation.document,
                            current_schema,
                            "response",
                            &format!("responses.{}.{}.schema", key.0, key.1),
                        ) {
                            issues.push(ApiContractCompatibilityIssue {
                                producer_path: path.clone(),
                                issue,
                                component_path: Some(component_path),
                                method: method.clone(),
                                route: route.clone(),
                                previous_operation_id: (!previous_operation
                                    .operation_id
                                    .is_empty())
                                .then_some(previous_operation.operation_id.clone()),
                                current_operation_id: (!current_operation.operation_id.is_empty())
                                    .then_some(current_operation.operation_id.clone()),
                            });
                        }
                    }
                }
                if has_unresolved_inline_schemas(&previous_operation)
                    || has_unresolved_inline_schemas(current_operation)
                {
                    limitations.push(format!(
                        "OpenAPI schema compatibility for `{method} {route}` in `{path}` is incomplete because it contains a missing, external, cyclic, or unsupported reference, a parameter-object reference, or schema composition."
                    ));
                }
            }
        }
    }
    issues.sort_by(|left, right| {
        (&left.producer_path, &left.route, &left.method, &left.issue).cmp(&(
            &right.producer_path,
            &right.route,
            &right.method,
            &right.issue,
        ))
    });
    coverage.sort_by(|left, right| {
        (&left.producer_path, &left.route, &left.method).cmp(&(
            &right.producer_path,
            &right.route,
            &right.method,
        ))
    });
    limitations.sort();
    limitations.dedup();
    (issues, coverage, limitations)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn cross_impact(
    producer_impact: &crate::ImpactAssessment,
    dependency_map: &RepositoryMap,
    producer_root: &Path,
    consumer_roots: &[PathBuf],
) -> Result<CrossRepositoryImpact, String> {
    cross_impact_with_baselines(
        producer_impact,
        dependency_map,
        producer_root,
        consumer_roots,
        &BTreeMap::new(),
    )
}

fn cross_impact_with_baselines(
    producer_impact: &crate::ImpactAssessment,
    dependency_map: &RepositoryMap,
    producer_root: &Path,
    consumer_roots: &[PathBuf],
    baseline_contracts: &BTreeMap<String, Vec<u8>>,
) -> Result<CrossRepositoryImpact, String> {
    if consumer_roots.is_empty() {
        return Err("provide at least one consumer repository".into());
    }
    if consumer_roots.len() > MAX_REPOSITORIES {
        return Err(format!("repository limit is {MAX_REPOSITORIES}"));
    }
    if consumer_dependency_fingerprint(dependency_map, consumer_roots)?
        != consumer_dependency_fingerprint(&build(consumer_roots)?, consumer_roots)?
    {
        return Err(
            "consumer repository manifests changed before cross-repository impact analysis".into(),
        );
    }
    let (api_contract_changes, contract_limitations, scanned_contracts) =
        collect_changed_openapi_operations(producer_root, &producer_impact.changed_paths);
    let contract_analysis_complete = contract_limitations.is_empty();
    let (api_contract_compatibility, api_contract_coverage, compatibility_limitations) =
        compare_openapi_contracts(producer_root, baseline_contracts);
    let compatibility_analysis_complete = compatibility_limitations.is_empty();
    let mut symbols: std::collections::BTreeSet<_> =
        producer_impact.changed_symbols.iter().cloned().collect();
    symbols.extend(
        api_contract_changes
            .iter()
            .map(|operation| operation.operation_id.clone()),
    );
    let (dependency_paths, dependency_paths_complete) = trace_dependency_paths(
        producer_impact,
        dependency_map,
        producer_root,
        consumer_roots,
    )?;
    let mut references = Vec::new();
    let mut limitations = producer_impact.limitations.clone();
    limitations.extend(contract_limitations);
    limitations.extend(compatibility_limitations);
    let mut coverage_complete = producer_impact.coverage_complete
        && dependency_paths_complete
        && contract_analysis_complete
        && compatibility_analysis_complete;
    if !dependency_paths_complete {
        limitations.push(format!("Cross-repository dependency path traversal stopped at its deterministic bound ({MAX_DEPENDENCY_PATH_STATES} path states or {MAX_DEPENDENCY_PATHS} paths); additional dependency paths may be omitted."));
    }
    let mut scanned_files = 0usize;
    let mut scanned_bytes = 0usize;
    let mut scanned_sources = Vec::<(PathBuf, String)>::new();
    let mut go_references = Vec::new();
    let mut typescript_references = Vec::new();
    let mut python_sources = BTreeMap::<String, String>::new();
    let mut python_source_locations = BTreeMap::<String, (PathBuf, String, String)>::new();
    let mut source_inventory = BTreeMap::<PathBuf, Vec<PathBuf>>::new();
    let mut seen_roots = std::collections::BTreeSet::new();
    for supplied in consumer_roots {
        let root = supplied
            .canonicalize()
            .map_err(|e| format!("cannot resolve consumer {}: {e}", supplied.display()))?;
        if !root.is_dir() {
            return Err(format!("consumer {} is not a directory", root.display()));
        }
        if !seen_roots.insert(root.clone()) {
            return Err(format!("duplicate consumer repository: {}", root.display()));
        }
        let mut files = Vec::new();
        let mut file_limit_reached = false;
        collect_source_files(
            &root,
            &root,
            &mut files,
            &mut limitations,
            &mut file_limit_reached,
        )?;
        if file_limit_reached {
            coverage_complete = false;
            limitations.push(format!(
                "{}: source file discovery stopped at the {MAX_IMPACT_FILES} file limit",
                root.display()
            ));
        }
        files.sort();
        if !file_limit_reached {
            source_inventory.insert(root.clone(), files.clone());
        }
        for file in files {
            if scanned_files >= MAX_IMPACT_FILES {
                coverage_complete = false;
                limitations.push(format!(
                    "Consumer scanning stopped at the {MAX_IMPACT_FILES} file limit."
                ));
                break;
            }
            let metadata = std::fs::symlink_metadata(&file)
                .map_err(|e| format!("cannot inspect {}: {e}", file.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "consumer source changed type during cross-repository impact analysis: {}",
                    file.display()
                ));
            }
            if metadata.len() > MAX_IMPACT_FILE_BYTES
                || scanned_bytes.saturating_add(metadata.len() as usize) > MAX_IMPACT_BYTES
            {
                coverage_complete = false;
                limitations.push(format!(
                    "{}: source omitted by per-file or aggregate byte limit",
                    file.display()
                ));
                continue;
            }
            let bytes =
                std::fs::read(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            scanned_files += 1;
            scanned_bytes += bytes.len();
            let text = match std::str::from_utf8(&bytes) {
                Ok(text) => text,
                Err(_) => {
                    coverage_complete = false;
                    limitations.push(format!("{}: non-UTF-8 source omitted", file.display()));
                    continue;
                }
            };
            let relative_path = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/");
            let source_digest = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
            scanned_sources.push((file.clone(), source_digest.clone()));
            match file.extension().and_then(|ext| ext.to_str()) {
                Some("rs") => {
                    let syntax = match syn::parse_file(text) {
                        Ok(syntax) => syntax,
                        Err(_) => {
                            coverage_complete = false;
                            limitations.push(format!(
                                "{}: Rust syntax parse failed; potential references omitted",
                                file.display()
                            ));
                            continue;
                        }
                    };
                    let mut visitor = ConsumerSymbolVisitor {
                        symbols: &symbols,
                        file: relative_path,
                        root: root.clone(),
                        source_digest,
                        source: text,
                        found: Vec::new(),
                    };
                    syn::visit::Visit::visit_file(&mut visitor, &syntax);
                    references.extend(visitor.found);
                }
                Some("go") => {
                    let code = crate::go_code_without_comments_and_strings(text);
                    let first_reference = references.len();
                    collect_lexical_references(
                        &mut references,
                        &symbols,
                        &root,
                        &relative_path,
                        &source_digest,
                        &code,
                        "heuristic_lexical",
                    );
                    go_references.extend(first_reference..references.len());
                }
                Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts") => {
                    let code = crate::typescript_code_without_comments_and_strings(text);
                    let first_reference = references.len();
                    collect_lexical_references(
                        &mut references,
                        &symbols,
                        &root,
                        &relative_path,
                        &source_digest,
                        &code,
                        "heuristic_lexical",
                    );
                    typescript_references.extend(first_reference..references.len());
                }
                Some("py") => {
                    let key = format!("{}::{relative_path}", root.display());
                    python_sources.insert(key.clone(), text.to_owned());
                    python_source_locations
                        .insert(key, (root.clone(), relative_path, source_digest));
                }
                Some("java") => {
                    let code = crate::java_code_without_comments_and_strings(text);
                    collect_lexical_references(
                        &mut references,
                        &symbols,
                        &root,
                        &relative_path,
                        &source_digest,
                        &code,
                        "heuristic_lexical",
                    );
                }
                _ => unreachable!("only supported source extensions are collected"),
            }
        }
    }
    let mut python_ast_used = false;
    if !python_sources.is_empty() && !symbols.is_empty() {
        match crate::python_syntax_references(&python_sources, &symbols) {
            Ok(analysis) => {
                python_ast_used = true;
                for found in analysis.references {
                    if let Some((root, path, source_digest)) =
                        python_source_locations.get(&found.path)
                    {
                        references.push(ConsumerSymbolReference {
                            consumer_repository: root.display().to_string(),
                            path: path.clone(),
                            line: found.line,
                            symbol: found.symbol,
                            column: None,
                            certainty: "inferred_syntax".into(),
                            match_context: if found.test_context {
                                "likely_test_reference".into()
                            } else {
                                "python_ast_reference".into()
                            },
                            source_digest: source_digest.clone(),
                            consumer_package_id: None,
                            dependency_status: "package_unresolved".into(),
                            dependency_paths: Vec::new(),
                        });
                    }
                }
                for invalid_path in &analysis.parse_error_paths {
                    if let Some((root, path, source_digest)) =
                        python_source_locations.get(invalid_path)
                    {
                        let code = crate::python_code_without_comments_and_strings(
                            &python_sources[invalid_path],
                        );
                        let first = references.len();
                        collect_lexical_references(
                            &mut references,
                            &symbols,
                            root,
                            path,
                            source_digest,
                            &code,
                            "heuristic_lexical",
                        );
                        for reference in &mut references[first..] {
                            reference.certainty = "heuristic_lexical".into();
                        }
                    }
                }
                if !analysis.parse_error_paths.is_empty() || analysis.truncated {
                    coverage_complete = false;
                    limitations.push(format!(
                        "Python AST analysis using Python {} was partial ({} parse failures, truncated={}); parse failures retain lexical fallback.",
                        analysis.interpreter_version,
                        analysis.parse_error_paths.len(),
                        analysis.truncated
                    ));
                }
                limitations.push("Python cross-repository references are syntax-derived name matches, not import or type resolution; aliases, dynamic dispatch, and same-name unrelated symbols may be misclassified.".into());
            }
            Err(error) => {
                coverage_complete = false;
                limitations.push(format!(
                    "Python AST analysis unavailable ({error}); Python references use lexical fallback."
                ));
            }
        }
    }
    if !python_ast_used {
        for (key, source) in &python_sources {
            if let Some((root, path, source_digest)) = python_source_locations.get(key) {
                let code = crate::python_code_without_comments_and_strings(source);
                collect_lexical_references(
                    &mut references,
                    &symbols,
                    root,
                    path,
                    source_digest,
                    &code,
                    "heuristic_lexical",
                );
            }
        }
    }
    let (go_coverage_complete, go_limitations) = resolve_go_consumer_references(
        &mut references,
        &go_references,
        producer_root,
        consumer_roots,
    );
    coverage_complete &= go_coverage_complete;
    limitations.extend(go_limitations);
    // Semantic resolvers may discard false matches and shift vector indices.
    // Recompute candidates from the remaining references before each pass.
    let rust_references = references
        .iter()
        .enumerate()
        .filter(|(_, reference)| reference.path.ends_with(".rs"))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let (rust_coverage_complete, rust_limitations) = resolve_rust_consumer_references(
        &mut references,
        &rust_references,
        producer_impact,
        producer_root,
        consumer_roots,
    );
    coverage_complete &= rust_coverage_complete;
    limitations.extend(rust_limitations);
    let typescript_references = references
        .iter()
        .enumerate()
        .filter(|(_, reference)| {
            matches!(
                Path::new(&reference.path)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts")
            )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let (typescript_coverage_complete, typescript_limitations) =
        resolve_typescript_consumer_references(
            &mut references,
            &typescript_references,
            producer_impact,
            producer_root,
            consumer_roots,
        );
    coverage_complete &= typescript_coverage_complete;
    limitations.extend(typescript_limitations);
    verify_scanned_sources(&scanned_sources)?;
    verify_producer_contracts(&scanned_contracts)?;
    verify_source_inventory(&source_inventory)?;
    if consumer_dependency_fingerprint(dependency_map, consumer_roots)?
        != consumer_dependency_fingerprint(&build(consumer_roots)?, consumer_roots)?
    {
        return Err(
            "consumer repository manifests changed during cross-repository impact analysis".into(),
        );
    }
    references.sort_by(|a, b| {
        (&a.consumer_repository, &a.path, a.line, &a.symbol).cmp(&(
            &b.consumer_repository,
            &b.path,
            b.line,
            &b.symbol,
        ))
    });
    references.dedup_by(|a, b| {
        a.consumer_repository == b.consumer_repository
            && a.path == b.path
            && a.line == b.line
            && a.symbol == b.symbol
    });
    if symbols.is_empty() {
        limitations.push("The producer impact analyzer found no changed symbols; consumer scanning cannot establish symbol impact.".into());
    }
    for reference in &mut references {
        let source_path = Path::new(&reference.consumer_repository).join(&reference.path);
        let package = dependency_map
            .repositories
            .iter()
            .filter(|package| source_path.starts_with(&package.root))
            .max_by_key(|package| Path::new(&package.root).components().count());
        reference.consumer_package_id = package.map(|package| package.id.clone());
        reference.dependency_paths = package
            .map(|package| {
                dependency_paths
                    .iter()
                    .filter(|path| path.consumer_package == package.id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        reference.dependency_status = if package.is_none() {
            "package_unresolved".into()
        } else if reference.dependency_paths.is_empty() {
            "no_declared_path".into()
        } else {
            "declared_downstream".into()
        };
    }
    if references.iter().any(|reference| {
        reference.path.ends_with(".rs") && reference.certainty != "semantic_resolved"
    }) {
        limitations.push("Some Rust consumer call matches remain syntax-inferred because rust-analyzer was unavailable, unresolved, or bounded; aliases, trait methods, macros, and same-name targets may still be missed or misclassified.".into());
    }
    if references.iter().any(|reference| {
        matches!(
            Path::new(&reference.path)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts")
        ) && reference.certainty != "semantic_resolved"
    }) {
        limitations.push("Some TypeScript/JavaScript references remain lexical heuristics; declaration sites are filtered and call, qualified, and general identifier contexts are labeled, but unresolved or same-name symbols may still be misclassified.".into());
    }
    if !python_ast_used {
        limitations.push("Python matches are lexical heuristics when the local AST helper is unavailable; same-name symbols may be misclassified.".into());
    }
    limitations.push("Java matches are lexical heuristics. Declaration sites are filtered and call, qualified, and general identifier contexts are labeled, but language-specific syntax and same-name symbols may still be misclassified.".into());
    if go_references.is_empty() {
        limitations.push(
            "No candidate Go consumer references were found by the lexical prefilter.".into(),
        );
    } else if !references.iter().any(|reference| {
        reference.certainty == "semantic_resolved" && reference.path.ends_with(".go")
    }) {
        limitations.push("Go consumer references are lexical heuristics where gopls could not resolve a candidate to the selected producer checkout; same-name identifiers may be unrelated.".into());
    }
    limitations.push("Only the Rust, Go, TypeScript/JavaScript, Python, and Java source extensions listed by Vero are considered; generated code and runtime relationships may be absent.".into());
    limitations.extend(dependency_map.limitations.iter().cloned());
    limitations.push("Package dependency paths include only direct manifest edges among explicitly selected repositories; omitted repositories and transitive registry resolution are unknown.".into());
    if dependency_paths.is_empty() {
        limitations.push("No selected consumer package was connected to a producer package through declared manifest dependencies; this does not establish that no downstream dependency exists.".into());
    }
    limitations.sort();
    limitations.dedup();
    let mut result = CrossRepositoryImpact {
        schema_version: 16,
        producer_snapshot_id: producer_impact.snapshot_id.clone(),
        changed_symbols: symbols.into_iter().collect(),
        api_contract_changes,
        api_contract_compatibility,
        api_contract_coverage,
        dependency_paths,
        references,
        coverage_complete,
        limitations,
        digest: String::new(),
    };
    let bytes = serde_json::to_vec(&(
        &result.producer_snapshot_id,
        &result.changed_symbols,
        &result.api_contract_changes,
        &result.api_contract_compatibility,
        &result.api_contract_coverage,
        &result.dependency_paths,
        &result.references,
        result.coverage_complete,
        &result.limitations,
    ))
    .map_err(|e| e.to_string())?;
    result.digest = format!("sha256:{}", hex(&Sha256::digest(bytes)));
    Ok(result)
}

fn verify_scanned_sources(sources: &[(PathBuf, String)]) -> Result<(), String> {
    for (path, expected_digest) in sources {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!("cannot recheck consumer source {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "consumer source changed type during cross-repository impact analysis: {}",
                path.display()
            ));
        }
        let bytes = std::fs::read(path).map_err(|error| {
            format!("cannot recheck consumer source {}: {error}", path.display())
        })?;
        let actual_digest = format!("sha256:{}", hex(&Sha256::digest(bytes)));
        if &actual_digest != expected_digest {
            return Err(format!(
                "consumer source changed during cross-repository impact analysis: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_producer_contracts(sources: &[(PathBuf, String)]) -> Result<(), String> {
    for (path, expected_digest) in sources {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!(
                "cannot recheck producer contract {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "producer contract changed type during analysis: {}",
                path.display()
            ));
        }
        let bytes = std::fs::read(path).map_err(|error| {
            format!(
                "cannot re-read producer contract {}: {error}",
                path.display()
            )
        })?;
        let actual = format!("sha256:{}", hex(&Sha256::digest(bytes)));
        if &actual != expected_digest {
            return Err(format!(
                "producer contract changed during cross-repository impact analysis: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_source_inventory(inventory: &BTreeMap<PathBuf, Vec<PathBuf>>) -> Result<(), String> {
    for (root, expected) in inventory {
        let mut actual = Vec::new();
        let mut limitations = Vec::new();
        let mut limit_reached = false;
        collect_source_files(
            root,
            root,
            &mut actual,
            &mut limitations,
            &mut limit_reached,
        )?;
        actual.sort();
        if limit_reached || &actual != expected {
            return Err(format!(
                "consumer source inventory changed during cross-repository impact analysis: {}",
                root.display()
            ));
        }
    }
    Ok(())
}

fn consumer_dependency_fingerprint(
    map: &RepositoryMap,
    roots: &[PathBuf],
) -> Result<String, String> {
    let roots = roots
        .iter()
        .map(|root| root.canonicalize().map_err(|error| error.to_string()))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let repositories = map
        .repositories
        .iter()
        .filter(|repository| roots.contains(Path::new(&repository.root)))
        .collect::<Vec<_>>();
    let ids = repositories
        .iter()
        .map(|repository| repository.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let dependencies = map
        .dependencies
        .iter()
        .filter(|edge| ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str()))
        .collect::<Vec<_>>();
    let payload =
        serde_json::to_vec(&(repositories, dependencies)).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{}", hex(&Sha256::digest(payload))))
}

pub fn analyze_cross_impact(
    producer: &Path,
    base: &str,
    consumers: &[PathBuf],
) -> Result<CrossRepositoryImpact, String> {
    let producer = vero_git::repository_root(producer)?;
    let base_oid = vero_git::merge_base(&producer, base)?;
    let snapshot = crate::capture_change_set(
        &producer,
        vero_git::ChangeScope::BaseAndWorktree {
            base_oid: Some(base_oid.clone()),
        },
    )?;
    let impact = crate::analyze_impact(&producer, &snapshot)?;
    let mut baseline_contracts = BTreeMap::new();
    for relative in &impact.changed_paths {
        if !matches!(
            Path::new(relative)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("yaml" | "yml" | "json")
        ) {
            continue;
        }
        if let Some(bytes) = vero_git::read_tree_file(&producer, &base_oid, Path::new(relative))? {
            if bytes.len() as u64 > MAX_IMPACT_FILE_BYTES {
                return Err(format!(
                    "base API contract `{relative}` exceeds the {MAX_IMPACT_FILE_BYTES} byte compatibility-analysis limit"
                ));
            }
            baseline_contracts.insert(relative.clone(), bytes);
        }
    }
    let mut selected_repositories = vec![producer.clone()];
    selected_repositories.extend(consumers.iter().cloned());
    let dependency_map = build(&selected_repositories)?;
    cross_impact_with_baselines(
        &impact,
        &dependency_map,
        &producer,
        consumers,
        &baseline_contracts,
    )
}

fn trace_dependency_paths(
    impact: &crate::ImpactAssessment,
    dependency_map: &RepositoryMap,
    producer_root: &Path,
    consumer_roots: &[PathBuf],
) -> Result<(Vec<CrossRepositoryDependencyPath>, bool), String> {
    let producer_root = producer_root
        .canonicalize()
        .map_err(|e| format!("cannot resolve producer {}: {e}", producer_root.display()))?;
    let consumers: Vec<_> = consumer_roots
        .iter()
        .map(|root| {
            root.canonicalize()
                .map_err(|e| format!("cannot resolve consumer {}: {e}", root.display()))
        })
        .collect::<Result<_, _>>()?;
    let mut changed_packages = std::collections::BTreeSet::new();
    for repository in &dependency_map.repositories {
        let package_root = PathBuf::from(&repository.root);
        let Ok(relative_root) = package_root.strip_prefix(&producer_root) else {
            continue;
        };
        if impact.changed_paths.iter().any(|changed| {
            let changed = Path::new(changed);
            relative_root.as_os_str().is_empty() || changed.starts_with(relative_root)
        }) {
            changed_packages.insert((repository.ecosystem.clone(), repository.id.clone()));
        }
    }
    let is_consumer_package = |ecosystem: &str, id: &str| {
        dependency_map.repositories.iter().any(|repository| {
            repository.ecosystem == ecosystem
                && repository.id == id
                && consumers
                    .iter()
                    .any(|root| PathBuf::from(&repository.root).starts_with(root))
        })
    };
    let mut paths = Vec::new();
    let mut explored_states = 0usize;
    let mut complete = true;
    for (ecosystem, producer) in changed_packages {
        let producer_key = (ecosystem.clone(), producer.clone());
        let mut queue = std::collections::VecDeque::from([(
            producer_key.clone(),
            vec![producer.clone()],
            Vec::<String>::new(),
        )]);
        while let Some((current, package_path, manifest_digests)) = queue.pop_front() {
            explored_states += 1;
            if explored_states > MAX_DEPENDENCY_PATH_STATES || paths.len() >= MAX_DEPENDENCY_PATHS {
                complete = false;
                break;
            }
            for edge in dependency_map.dependencies.iter().filter(|edge| {
                edge.to == current.1
                    && dependency_map.repositories.iter().any(|repository| {
                        repository.id == edge.from
                            && repository.ecosystem == current.0
                            && Path::new(&edge.evidence_path).parent()
                                == Some(Path::new(&repository.root))
                    })
            }) {
                if package_path.contains(&edge.from) {
                    continue;
                }
                let next_key = (ecosystem.clone(), edge.from.clone());
                let mut next_packages = package_path.clone();
                next_packages.push(edge.from.clone());
                let mut next_digests = manifest_digests.clone();
                next_digests.push(edge.evidence_digest.clone());
                if is_consumer_package(&ecosystem, &edge.from) {
                    if paths.len() >= MAX_DEPENDENCY_PATHS {
                        complete = false;
                        break;
                    }
                    paths.push(CrossRepositoryDependencyPath {
                        producer_package: producer.clone(),
                        consumer_package: edge.from.clone(),
                        packages: next_packages.clone(),
                        manifest_digests: next_digests.clone(),
                    });
                }
                queue.push_back((next_key, next_packages, next_digests));
                if queue.len().saturating_add(explored_states) > MAX_DEPENDENCY_PATH_STATES {
                    complete = false;
                    break;
                }
            }
            if !complete {
                break;
            }
        }
        if !complete {
            break;
        }
    }
    paths.sort_by(|a, b| {
        (&a.producer_package, &a.consumer_package, &a.packages).cmp(&(
            &b.producer_package,
            &b.consumer_package,
            &b.packages,
        ))
    });
    paths.dedup_by(|a, b| {
        a.producer_package == b.producer_package
            && a.consumer_package == b.consumer_package
            && a.packages == b.packages
    });
    Ok((paths, complete))
}

fn collect_source_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
    limitations: &mut Vec<String>,
    limit_reached: &mut bool,
) -> Result<(), String> {
    if output.len() >= MAX_IMPACT_FILES {
        *limit_reached = true;
        return Ok(());
    }
    let entries = std::fs::read_dir(directory)
        .map_err(|e| format!("cannot read {}: {e}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some(".git" | ".vero" | "target" | "node_modules")
            ) {
                continue;
            }
            collect_source_files(root, &path, output, limitations, limit_reached)?;
        } else if metadata.is_file()
            && path
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|ext| CONSUMER_SOURCE_EXTENSIONS.contains(&ext))
        {
            if !path
                .canonicalize()
                .map_err(|e| e.to_string())?
                .starts_with(root)
            {
                limitations.push(format!(
                    "{}: path escaped consumer root and was skipped",
                    path.display()
                ));
                continue;
            }
            output.push(path);
        }
        if output.len() >= MAX_IMPACT_FILES {
            *limit_reached = true;
            return Ok(());
        }
    }
    Ok(())
}

fn collect_lexical_references(
    output: &mut Vec<ConsumerSymbolReference>,
    symbols: &std::collections::BTreeSet<String>,
    root: &Path,
    relative_path: &str,
    source_digest: &str,
    source: &str,
    certainty: &str,
) {
    for (line_index, line) in source.lines().enumerate() {
        let mut token = String::new();
        let mut token_start = 0;
        for (byte_index, character) in line
            .char_indices()
            .chain(std::iter::once((line.len(), ' ')))
        {
            if character == '_' || character.is_alphanumeric() {
                if token.is_empty() {
                    token_start = byte_index;
                }
                token.push(character);
            } else if !token.is_empty() {
                if symbols.contains(&token) {
                    let prefix = &line[..token_start];
                    let suffix = &line[byte_index..];
                    if is_lexical_declaration(prefix, suffix) {
                        token.clear();
                        continue;
                    }
                    let match_context = if suffix.trim_start().starts_with('(') {
                        "call"
                    } else if prefix.trim_end().ends_with('.') || prefix.trim_end().ends_with("::")
                    {
                        "qualified_reference"
                    } else {
                        "identifier_reference"
                    };
                    output.push(ConsumerSymbolReference {
                        consumer_repository: root.display().to_string(),
                        path: relative_path.to_owned(),
                        line: (line_index + 1) as u32,
                        symbol: std::mem::take(&mut token),
                        column: Some(line[..token_start].encode_utf16().count() as u32 + 1),
                        certainty: certainty.to_owned(),
                        match_context: match_context.to_owned(),
                        source_digest: source_digest.to_owned(),
                        consumer_package_id: None,
                        dependency_status: "package_unresolved".into(),
                        dependency_paths: Vec::new(),
                    });
                } else {
                    token.clear();
                }
            }
        }
    }
}

fn is_lexical_declaration(prefix: &str, suffix: &str) -> bool {
    let before = prefix.split_whitespace().last().unwrap_or("");
    if matches!(
        before,
        "function" | "class" | "interface" | "type" | "enum" | "def" | "var" | "let" | "const"
    ) {
        return true;
    }
    let after = suffix.trim_start();
    // A bare assignment target is commonly a variable declaration in these
    // languages. Do not filter equality, arrow, or comparison expressions.
    after.starts_with('=') && !after.starts_with("==") && !after.starts_with("=>")
}

fn resolve_rust_consumer_references(
    references: &mut Vec<ConsumerSymbolReference>,
    candidate_indices: &[usize],
    producer_impact: &crate::ImpactAssessment,
    producer_root: &Path,
    consumer_roots: &[PathBuf],
) -> (bool, Vec<String>) {
    if candidate_indices.is_empty() || producer_impact.changed_paths.is_empty() {
        return (true, Vec::new());
    }
    let _lock = RUST_CROSS_REPO_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(executable) = find_rust_analyzer_executable() else {
        return (
            true,
            vec![
                "rust-analyzer was not found on PATH; Rust consumer call matches remain syntax-inferred."
                    .into(),
            ],
        );
    };
    let producer_root = match producer_root.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            return (
                false,
                vec![format!(
                    "could not resolve producer root for rust-analyzer: {error}"
                )],
            );
        }
    };
    let mut changed_definitions = std::collections::BTreeSet::new();
    for changed in &producer_impact.changed_paths {
        let path = producer_root.join(changed);
        if let Ok(path) = path.canonicalize() {
            if path.starts_with(&producer_root)
                && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            {
                changed_definitions.insert(path);
            }
        }
    }
    if changed_definitions.is_empty() {
        return (
            true,
            vec!["Producer changes contain no resolvable Rust source file; Rust consumer call matches remain syntax-inferred.".into()],
        );
    }

    let roots: std::collections::BTreeSet<_> = consumer_roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect();
    let mut by_root = BTreeMap::<PathBuf, Vec<usize>>::new();
    for index in candidate_indices {
        if let Some(reference) = references.get(*index) {
            let root = PathBuf::from(&reference.consumer_repository);
            if roots.contains(&root) {
                by_root.entry(root).or_default().push(*index);
            }
        }
    }

    let mut complete = true;
    let mut limitations = Vec::new();
    let mut discard = std::collections::BTreeSet::new();
    let started = std::time::Instant::now();
    let checked = candidate_indices.len().min(MAX_RUST_SEMANTIC_REFERENCES);
    for (root, indices) in by_root {
        if started.elapsed() >= std::time::Duration::from_secs(45) {
            complete = false;
            limitations.push("Rust cross-repository resolution reached its 45 second total time limit; remaining matches are syntax-inferred.".into());
            break;
        }
        let remaining = std::time::Duration::from_secs(45).saturating_sub(started.elapsed());
        let mut session = match RustAnalyzerSession::start(&executable, &root, remaining) {
            Ok(session) => session,
            Err(error) => {
                complete = false;
                limitations.push(format!(
                    "rust-analyzer could not initialize for {} ({error}); syntax matches retained.",
                    root.display()
                ));
                continue;
            }
        };
        let total_deadline = started + std::time::Duration::from_secs(45);
        if let Err(error) = session.wait_until_quiescent(total_deadline) {
            complete = false;
            limitations.push(format!(
                "rust-analyzer stopped while indexing {} ({error}); syntax matches retained.",
                root.display()
            ));
            continue;
        }
        for index in indices {
            if index >= checked {
                complete = false;
                continue;
            }
            if started.elapsed() >= std::time::Duration::from_secs(45) {
                complete = false;
                limitations.push("Rust cross-repository resolution reached its 45 second total time limit; remaining matches are syntax-inferred.".into());
                break;
            }
            let Some(reference) = references.get_mut(index) else {
                continue;
            };
            let Some(column) = reference.column else {
                limitations.push(format!(
                    "Rust call candidate {}:{} has no source column; syntax match retained.",
                    reference.path, reference.line
                ));
                continue;
            };
            let source = root.join(&reference.path);
            let budget = std::time::Duration::from_secs(15)
                .min(std::time::Duration::from_secs(45).saturating_sub(started.elapsed()));
            match session.definition(&source, reference.line, column, budget) {
                Ok(Some(definitions)) => {
                    if definitions
                        .iter()
                        .any(|definition| changed_definitions.contains(definition))
                    {
                        reference.certainty = "semantic_resolved".into();
                    } else if !definitions.is_empty() {
                        discard.insert(index);
                    } else {
                        limitations.push(format!(
                            "rust-analyzer returned no definition for {}:{}; syntax match retained.",
                            reference.path, reference.line
                        ));
                    }
                }
                Ok(None) => limitations.push(format!(
                    "rust-analyzer could not resolve Rust candidate {}:{}; syntax match retained.",
                    reference.path, reference.line
                )),
                Err(error) => {
                    complete = false;
                    limitations.push(format!(
                        "rust-analyzer definition lookup failed for {}:{} ({error}); syntax match retained.",
                        reference.path, reference.line
                    ));
                }
            }
        }
    }
    if candidate_indices.len() > checked {
        complete = false;
        limitations.push(format!(
            "Rust cross-repository resolution stopped at {MAX_RUST_SEMANTIC_REFERENCES} candidate references; remaining matches are syntax-inferred."
        ));
    }
    if !discard.is_empty() {
        let mut index = 0usize;
        references.retain(|_| {
            let keep = !discard.contains(&index);
            index += 1;
            keep
        });
    }
    limitations.sort();
    limitations.dedup();
    (complete, limitations)
}

fn find_rust_analyzer_executable() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("VERO_RUST_ANALYZER") {
        let path = PathBuf::from(configured);
        return absolute_executable_path(&path);
    }
    let name = if cfg!(windows) {
        "rust-analyzer.exe"
    } else {
        "rust-analyzer"
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find_map(|candidate| absolute_executable_path(&candidate))
}

fn absolute_executable_path(path: &Path) -> Option<PathBuf> {
    if !path.is_file() {
        return None;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    if std::fs::symlink_metadata(&absolute)
        .ok()?
        .file_type()
        .is_symlink()
    {
        // Keep the requested command name: rustup dispatches components such as
        // rust-analyzer based on argv[0], but canonicalizing the shim turns it
        // into a plain `rustup` invocation.
        Some(absolute)
    } else {
        absolute.canonicalize().ok()
    }
}

struct RustAnalyzerSession {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    receiver: std::sync::mpsc::Receiver<Result<serde_json::Value, String>>,
    next_id: u64,
    opened: std::collections::BTreeSet<PathBuf>,
    /// Set once rust-analyzer reports `experimental/serverStatus` with
    /// `quiescent: true`: the workspace is loaded and indexed, so definition
    /// requests answer from a complete index.
    quiescent: bool,
    /// Whether the server has sent any `experimental/serverStatus`; servers that
    /// never do are not waited on.
    status_seen: bool,
}

impl RustAnalyzerSession {
    fn start(
        executable: &Path,
        root: &Path,
        time_budget: std::time::Duration,
    ) -> Result<Self, String> {
        use std::process::Stdio;
        let mut command = std::process::Command::new(executable);
        command
            .current_dir(root)
            .env_clear()
            .env("CARGO_NET_OFFLINE", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in ["PATH", "HOME", "USERPROFILE", "CARGO_HOME", "RUSTUP_HOME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("could not start rust-analyzer: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or("rust-analyzer stdin unavailable")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("rust-analyzer stdout unavailable")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Read};
            const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
            let mut reader = BufReader::new(stdout);
            loop {
                let mut length = None;
                let mut header_bytes = 0usize;
                loop {
                    let mut header = Vec::new();
                    match reader.by_ref().take(8193).read_until(b'\n', &mut header) {
                        Ok(0) => return,
                        Ok(_) => {}
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            return;
                        }
                    }
                    header_bytes = header_bytes.saturating_add(header.len());
                    if header_bytes > 8192 {
                        let _ =
                            sender.send(Err("rust-analyzer response header exceeded 8 KiB".into()));
                        return;
                    }
                    if header == b"\r\n" || header == b"\n" {
                        break;
                    }
                    if header
                        .get(..15)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Content-Length:"))
                    {
                        length = std::str::from_utf8(&header[15..])
                            .ok()
                            .and_then(|value| value.trim().parse::<usize>().ok());
                    }
                }
                let Some(length) = length else {
                    let _ =
                        sender.send(Err("rust-analyzer response omitted Content-Length".into()));
                    return;
                };
                if length > MAX_MESSAGE_BYTES {
                    let _ = sender.send(Err("rust-analyzer response exceeded 2 MiB".into()));
                    return;
                }
                let mut body = vec![0; length];
                if let Err(error) = reader.read_exact(&mut body) {
                    let _ = sender.send(Err(error.to_string()));
                    return;
                }
                let message = serde_json::from_slice(&body).map_err(|error| error.to_string());
                if sender.send(message).is_err() {
                    return;
                }
            }
        });
        let mut session = Self {
            child,
            stdin,
            receiver,
            next_id: 1,
            opened: std::collections::BTreeSet::new(),
            quiescent: false,
            status_seen: false,
        };
        let root_uri = reqwest::Url::from_directory_path(root)
            .map_err(|_| "could not encode consumer root as a file URI".to_owned())?;
        let initialize_id = session.next_id;
        session.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": initialize_id,
            "method": "initialize",
            "params": {
                "processId": std::process::id(),
                "rootUri": root_uri.as_str(),
                "workspaceFolders": [{"uri": root_uri.as_str(), "name": root.file_name().and_then(|n| n.to_str()).unwrap_or("consumer")}],
                "capabilities": {
                    "general": {"positionEncodings": ["utf-16"]},
                    "workspace": {"configuration": true, "workspaceFolders": true},
                    "textDocument": {"definition": {"dynamicRegistration": false, "linkSupport": true}},
                    "experimental": {"serverStatusNotification": true}
                },
                "initializationOptions": {
                    "cargo": {"buildScripts": {"enable": false}, "extraArgs": ["--offline"]},
                    "procMacro": {"enable": false},
                    "checkOnSave": {"enable": false}
                }
            }
        }))?;
        let deadline =
            std::time::Instant::now() + time_budget.min(std::time::Duration::from_secs(20));
        session.response(initialize_id, deadline)?;
        session.next_id = initialize_id + 1;
        session.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }))?;
        Ok(session)
    }

    fn definition(
        &mut self,
        source: &Path,
        line: u32,
        column: u32,
        time_budget: std::time::Duration,
    ) -> Result<Option<Vec<PathBuf>>, String> {
        let source = source
            .canonicalize()
            .map_err(|error| format!("could not resolve Rust source file: {error}"))?;
        let uri = reqwest::Url::from_file_path(&source)
            .map_err(|_| "could not encode Rust source path as a file URI".to_owned())?;
        if self.opened.insert(source.clone()) {
            let text = std::fs::read_to_string(&source)
                .map_err(|error| format!("could not read Rust source: {error}"))?;
            self.send(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {
                    "uri": uri.as_str(), "languageId": "rust", "version": 1, "text": text
                }}
            }))?;
        }
        let deadline =
            std::time::Instant::now() + time_budget.min(std::time::Duration::from_secs(15));
        let result = loop {
            let request_id = self.next_id;
            self.next_id += 1;
            self.send(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "textDocument/definition",
                "params": {
                    "textDocument": {"uri": uri.as_str()},
                    "position": {"line": line.saturating_sub(1), "character": column.saturating_sub(1)}
                }
            }))?;
            match self.response(request_id, deadline)? {
                serde_json::Value::Null if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                serde_json::Value::Array(ref locations)
                    if locations.is_empty() && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                result => break result,
            }
        };
        let locations = match result {
            serde_json::Value::Null => return Ok(None),
            serde_json::Value::Array(items) => items,
            item => vec![item],
        };
        let mut paths = std::collections::BTreeSet::new();
        for location in locations {
            let uri = location
                .get("uri")
                .or_else(|| location.get("targetUri"))
                .and_then(serde_json::Value::as_str);
            let Some(uri) = uri else {
                return Err("rust-analyzer returned a definition without a file URI".into());
            };
            let url = reqwest::Url::parse(uri)
                .map_err(|_| "rust-analyzer returned an invalid definition URI".to_owned())?;
            let path = url
                .to_file_path()
                .map_err(|_| "rust-analyzer returned a non-file definition URI".to_owned())?;
            let path = path
                .canonicalize()
                .map_err(|error| format!("could not resolve Rust definition path: {error}"))?;
            paths.insert(path);
        }
        Ok((!paths.is_empty()).then(|| paths.into_iter().collect()))
    }

    fn send(&mut self, value: &serde_json::Value) -> Result<(), String> {
        use std::io::Write;
        let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        if body.len() > 2 * 1024 * 1024 {
            return Err("rust-analyzer request exceeded 2 MiB".into());
        }
        write!(self.stdin, "Content-Length: {}\r\n\r\n", body.len())
            .and_then(|_| self.stdin.write_all(&body))
            .and_then(|_| self.stdin.flush())
            .map_err(|error| error.to_string())
    }

    /// Answer a request the server sent to the client (for example
    /// `workspace/configuration`). Returns whether `message` was such a request.
    fn answer_server_request(&mut self, message: &serde_json::Value) -> Result<bool, String> {
        if message.get("method").is_none() || message.get("id").is_none() {
            return Ok(false);
        }
        let id = message
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let result = if message.get("method").and_then(serde_json::Value::as_str)
            == Some("workspace/configuration")
        {
            serde_json::Value::Array(
                message
                    .pointer("/params/items")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| vec![serde_json::Value::Null; items.len()])
                    .unwrap_or_default(),
            )
        } else {
            serde_json::Value::Null
        };
        self.send(&serde_json::json!({"jsonrpc":"2.0", "id":id, "result":result}))?;
        Ok(true)
    }

    fn observe_status(&mut self, message: &serde_json::Value) {
        if message.get("method").and_then(serde_json::Value::as_str)
            == Some("experimental/serverStatus")
        {
            self.status_seen = true;
            if message.pointer("/params/quiescent") == Some(&serde_json::Value::Bool(true)) {
                self.quiescent = true;
            }
        }
    }

    /// Wait until rust-analyzer has loaded and indexed the workspace, or until
    /// `deadline`. A cold start (sysroot loading and indexing) can take longer
    /// than one definition request's budget; waiting here keeps that time out of
    /// the per-request cap. Returns whether the server became quiescent.
    fn wait_until_quiescent(&mut self, deadline: std::time::Instant) -> Result<bool, String> {
        // rust-analyzer announces its status right after `initialized`; a server
        // that has said nothing within the grace period does not report status.
        let status_grace = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !self.quiescent {
            let deadline = if self.status_seen {
                deadline
            } else {
                deadline.min(status_grace)
            };
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let message = match self.receiver.recv_timeout(remaining) {
                Ok(message) => message?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Ok(false),
                Err(error) => return Err(error.to_string()),
            };
            if !self.answer_server_request(&message)? {
                self.observe_status(&message);
            }
        }
        Ok(true)
    }

    fn response(
        &mut self,
        request_id: u64,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("rust-analyzer request timed out".into());
            }
            let message = self
                .receiver
                .recv_timeout(remaining)
                .map_err(|error| error.to_string())??;
            if self.answer_server_request(&message)? {
                continue;
            }
            self.observe_status(&message);
            if message.get("id").and_then(serde_json::Value::as_u64) != Some(request_id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                let detail = error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("server returned an error");
                return Err(format!(
                    "rust-analyzer: {}",
                    detail.chars().take(160).collect::<String>()
                ));
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| "rust-analyzer response omitted its result".into());
        }
    }
}

impl Drop for RustAnalyzerSession {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn resolve_go_consumer_references(
    references: &mut Vec<ConsumerSymbolReference>,
    candidate_indices: &[usize],
    producer_root: &Path,
    consumer_roots: &[PathBuf],
) -> (bool, Vec<String>) {
    let _gopls_lock = GO_CROSS_REPO_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(executable) = find_gopls_executable() else {
        return (
            true,
            vec![
                "gopls was not found on PATH; Go consumer references remain lexical heuristics."
                    .into(),
            ],
        );
    };
    let producer_root = match producer_root.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            return (
                false,
                vec![format!(
                    "could not resolve producer root for gopls: {error}"
                )],
            );
        }
    };
    let roots: std::collections::BTreeSet<_> = consumer_roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect();
    let mut complete = true;
    let mut limitations = Vec::new();
    let mut discard = std::collections::BTreeSet::new();
    let checked_count = candidate_indices.len().min(MAX_GO_SEMANTIC_REFERENCES);
    let analysis_started = std::time::Instant::now();
    for index in candidate_indices.iter().take(checked_count).copied() {
        if analysis_started.elapsed() >= std::time::Duration::from_secs(45) {
            complete = false;
            limitations.push(
                "gopls cross-repository resolution reached its 45 second total time limit; remaining Go matches are lexical heuristics.".into(),
            );
            break;
        }
        let Some(reference) = references.get_mut(index) else {
            continue;
        };
        let Some(column) = reference.column else {
            continue;
        };
        let repository = PathBuf::from(&reference.consumer_repository);
        if !roots.contains(&repository) {
            continue;
        }
        let source = repository.join(&reference.path);
        let position = format!("{}:{}:{column}", source.display(), reference.line);
        match run_gopls_definition(&executable, &repository, &position) {
            Ok(Some(definition)) => {
                let Ok(definition) = definition.canonicalize() else {
                    complete = false;
                    limitations.push(format!(
                        "gopls returned a definition that could not be resolved for {}:{}.",
                        reference.path, reference.line
                    ));
                    continue;
                };
                if definition.starts_with(&producer_root) {
                    reference.certainty = "semantic_resolved".into();
                } else {
                    discard.insert(index);
                }
            }
            Ok(None) => {
                limitations.push(format!(
                    "gopls could not resolve Go candidate {}:{}; lexical fallback retained.",
                    reference.path, reference.line
                ));
            }
            Err(error) => {
                complete = false;
                limitations.push(format!(
                    "gopls semantic resolution failed for {}:{} ({error}); lexical fallback retained.",
                    reference.path, reference.line
                ));
            }
        }
    }
    if candidate_indices.len() > checked_count {
        complete = false;
        limitations.push(format!(
            "gopls cross-repository resolution stopped at {MAX_GO_SEMANTIC_REFERENCES} candidate references; remaining Go matches are lexical heuristics."
        ));
    }
    if !discard.is_empty() {
        let mut index = 0usize;
        references.retain(|_| {
            let keep = !discard.contains(&index);
            index += 1;
            keep
        });
    }
    limitations.sort();
    limitations.dedup();
    (complete, limitations)
}

fn resolve_typescript_consumer_references(
    references: &mut Vec<ConsumerSymbolReference>,
    candidate_indices: &[usize],
    producer_impact: &crate::ImpactAssessment,
    producer_root: &Path,
    consumer_roots: &[PathBuf],
) -> (bool, Vec<String>) {
    let candidates = candidate_indices
        .iter()
        .filter(|index| {
            references.get(**index).is_some_and(|reference| {
                matches!(
                    Path::new(&reference.path)
                        .extension()
                        .and_then(|ext| ext.to_str()),
                    Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts")
                )
            })
        })
        .copied()
        .collect::<Vec<_>>();
    if candidates.is_empty() || producer_impact.changed_paths.is_empty() {
        return (true, Vec::new());
    }
    let _lock = TYPESCRIPT_CROSS_REPO_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(executable) = find_typescript_server() else {
        return (true, vec![
            "TypeScript server was not found (set VERO_TSSERVER or add tsserver to PATH); TypeScript/JavaScript consumer matches remain lexical heuristics.".into(),
        ]);
    };
    let producer_root = match producer_root.canonicalize() {
        Ok(root) => root,
        Err(error) => {
            return (
                false,
                vec![format!(
                    "could not resolve producer root for TypeScript: {error}"
                )],
            );
        }
    };
    let mut changed_definitions = std::collections::BTreeSet::new();
    for changed in &producer_impact.changed_paths {
        let path = producer_root.join(changed);
        if let Ok(path) = path.canonicalize() {
            if path.starts_with(&producer_root)
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts")
                )
            {
                changed_definitions.insert(path);
            }
        }
    }
    if changed_definitions.is_empty() {
        return (true, vec!["Producer changes contain no resolvable TypeScript/JavaScript files; consumer matches remain lexical heuristics.".into()]);
    }
    let roots: std::collections::BTreeSet<_> = consumer_roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect();
    let mut complete = true;
    let mut limitations = Vec::new();
    let mut discard = std::collections::BTreeSet::new();
    let start = std::time::Instant::now();
    let checked = candidates.len().min(MAX_TYPESCRIPT_SEMANTIC_REFERENCES);
    for index in candidates.iter().take(checked).copied() {
        let remaining = std::time::Duration::from_secs(45).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            complete = false;
            limitations.push("TypeScript cross-repository resolution reached its 45 second total time limit; remaining matches are lexical heuristics.".into());
            break;
        }
        let Some(reference) = references.get_mut(index) else {
            continue;
        };
        let repository = PathBuf::from(&reference.consumer_repository);
        let Some(column) = reference.column else {
            continue;
        };
        if !roots.contains(&repository) {
            continue;
        }
        let source = repository.join(&reference.path);
        match run_typescript_definition(
            &executable,
            &repository,
            &source,
            reference.line,
            column,
            remaining,
        ) {
            Ok(Some(definitions)) => {
                if definitions
                    .iter()
                    .any(|definition| changed_definitions.contains(definition))
                {
                    reference.certainty = "semantic_resolved".into();
                } else if !definitions.is_empty() {
                    discard.insert(index);
                } else {
                    limitations.push(format!("TypeScript server returned no definition for {}:{}; lexical fallback retained.", reference.path, reference.line));
                }
            }
            Ok(None) => limitations.push(format!(
                "TypeScript server could not resolve candidate {}:{}; lexical fallback retained.",
                reference.path, reference.line
            )),
            Err(error) => {
                complete = false;
                limitations.push(format!("TypeScript semantic resolution failed for {}:{} ({error}); lexical fallback retained.", reference.path, reference.line));
            }
        }
    }
    if candidates.len() > checked {
        complete = false;
        limitations.push(format!("TypeScript cross-repository resolution stopped at {MAX_TYPESCRIPT_SEMANTIC_REFERENCES} candidate references; remaining matches are lexical heuristics."));
    }
    if !discard.is_empty() {
        let mut index = 0usize;
        references.retain(|_| {
            let keep = !discard.contains(&index);
            index += 1;
            keep
        });
    }
    limitations.sort();
    limitations.dedup();
    (complete, limitations)
}

fn find_typescript_server() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("VERO_TSSERVER") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return path.canonicalize().ok();
        }
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| {
            directory.join(if cfg!(windows) {
                "tsserver.cmd"
            } else {
                "tsserver"
            })
        })
        .find_map(|candidate| {
            candidate
                .is_file()
                .then(|| candidate.canonicalize().ok())
                .flatten()
        })
}

fn nearest_typescript_project_config(
    working_directory: &Path,
    source: &Path,
) -> Result<Option<PathBuf>, String> {
    let root = working_directory
        .canonicalize()
        .map_err(|error| format!("could not resolve TypeScript project root: {error}"))?;
    let source = source
        .canonicalize()
        .map_err(|error| format!("could not resolve TypeScript source file: {error}"))?;
    if !source.starts_with(&root) {
        return Err("TypeScript source file is outside its project root".into());
    }
    let mut directory = source.parent();
    while let Some(current) = directory {
        for name in ["tsconfig.json", "jsconfig.json"] {
            let candidate = current.join(name);
            if candidate.is_file() {
                return Ok(Some(candidate));
            }
        }
        if current == root {
            break;
        }
        directory = current.parent();
    }
    Ok(None)
}

fn run_typescript_definition(
    executable: &Path,
    working_directory: &Path,
    source: &Path,
    line: u32,
    offset: u32,
    time_budget: std::time::Duration,
) -> Result<Option<Vec<PathBuf>>, String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::Stdio;
    use std::sync::mpsc;
    const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
    let mut command = if executable
        .extension()
        .is_some_and(|extension| extension == "js")
    {
        let node = find_executable("node").ok_or("node not found for configured tsserver")?;
        let mut command = std::process::Command::new(node);
        command.arg(executable);
        command
    } else {
        std::process::Command::new(executable)
    };
    command
        .arg("--disableAutomaticTypingAcquisition")
        .arg("--maxNodeModuleJsDepth")
        .arg("0")
        .current_dir(working_directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ["PATH", "HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start tsserver: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("tsserver stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("tsserver stdout unavailable")?;
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut length = None;
            loop {
                let mut header = Vec::new();
                match reader.read_until(b'\n', &mut header) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error) => {
                        let _ = tx.send(Err(error.to_string()));
                        return;
                    }
                }
                if header.len() > 8192 {
                    let _ = tx.send(Err("tsserver response header exceeded 8 KiB".into()));
                    return;
                }
                if header == b"\r\n" || header == b"\n" {
                    break;
                }
                if let Some(value) = header.strip_prefix(b"Content-Length:") {
                    length = std::str::from_utf8(value)
                        .ok()
                        .and_then(|v| v.trim().parse::<usize>().ok());
                }
            }
            let Some(length) = length else {
                let _ = tx.send(Err("tsserver response omitted Content-Length".into()));
                return;
            };
            if length > MAX_MESSAGE_BYTES {
                let _ = tx.send(Err("tsserver response exceeded 2 MiB".into()));
                return;
            }
            let mut body = vec![0; length];
            if let Err(error) = reader.read_exact(&mut body) {
                let _ = tx.send(Err(error.to_string()));
                return;
            }
            if tx.send(Ok(body)).is_err() {
                return;
            }
        }
    });
    let outcome = (|| {
        let discovered_config = nearest_typescript_project_config(working_directory, source)?;
        let mut seq = 0u64;
        let mut definitions = None;
        let call_deadline = std::time::Instant::now() + time_budget;
        for (name, args) in [
            ("open", serde_json::json!({"file": source})),
            (
                "definition",
                serde_json::json!({"file": source, "line": line, "offset": offset}),
            ),
            (
                "projectInfo",
                serde_json::json!({"file": source, "needFileNameList": false, "needDefaultConfiguredProjectInfo": true}),
            ),
        ] {
            seq += 1;
            let request =
                serde_json::json!({"seq": seq, "type":"request", "command":name, "arguments":args});
            serde_json::to_writer(&mut stdin, &request).map_err(|error| error.to_string())?;
            stdin
                .write_all(b"\n")
                .and_then(|_| stdin.flush())
                .map_err(|error| error.to_string())?;
            if name == "open" {
                continue;
            }
            let deadline =
                call_deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(5));
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err("tsserver request timed out".into());
                }
                let message = rx
                    .recv_timeout(remaining)
                    .map_err(|error| error.to_string())??;
                let message: serde_json::Value =
                    serde_json::from_slice(&message).map_err(|error| error.to_string())?;
                if message.get("type").and_then(serde_json::Value::as_str) == Some("event")
                    && message.get("event").and_then(serde_json::Value::as_str)
                        == Some("configFileDiag")
                {
                    let errors = message
                        .get("body")
                        .and_then(|body| body.get("diagnostics"))
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter(|diagnostic| {
                            diagnostic.get("category").is_some_and(|category| {
                                category.as_u64() == Some(1) || category.as_str() == Some("error")
                            })
                        })
                        .filter_map(|diagnostic| {
                            diagnostic
                                .get("text")
                                .and_then(serde_json::Value::as_str)
                                .map(|text| text.chars().take(160).collect::<String>())
                        })
                        .take(3)
                        .collect::<Vec<_>>();
                    if !errors.is_empty() {
                        return Err(format!(
                            "tsserver reported TypeScript project configuration errors: {}",
                            errors.join("; ")
                        ));
                    }
                }
                if message
                    .get("request_seq")
                    .and_then(serde_json::Value::as_u64)
                    != Some(seq)
                {
                    continue;
                }
                if message.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
                    if name == "definition" {
                        return Ok(None);
                    }
                    return Err(format!("tsserver {name} request failed"));
                }
                if name == "definition" {
                    let result = message
                        .get("body")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|definition| {
                            definition.get("file").and_then(serde_json::Value::as_str)
                        })
                        .filter_map(|file| PathBuf::from(file).canonicalize().ok())
                        .collect::<Vec<_>>();
                    definitions = Some(result);
                } else if name == "projectInfo" {
                    if let Some(config_path) = &discovered_config {
                        let loaded_config = message
                            .get("body")
                            .and_then(|body| body.get("configFileName"))
                            .and_then(serde_json::Value::as_str);
                        if loaded_config.is_none() {
                            return Err(format!(
                                "tsserver did not load discovered project configuration {}",
                                config_path.display()
                            ));
                        }
                    }
                    return Ok(definitions);
                }
                break;
            }
        }
        Ok(None)
    })();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait().map(|status| status.into_raw());
        }
    }
    #[cfg(not(unix))]
    {
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    outcome
}

fn find_gopls_executable() -> Option<PathBuf> {
    let name = if cfg!(windows) { "gopls.exe" } else { "gopls" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find_map(|candidate| {
            std::fs::metadata(&candidate)
                .ok()
                .filter(|metadata| metadata.is_file())
                .and_then(|_| candidate.canonicalize().ok())
        })
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let executable = if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(&executable))
        .find_map(|candidate| {
            candidate
                .is_file()
                .then(|| candidate.canonicalize().ok())
                .flatten()
        })
}

fn run_gopls_definition(
    executable: &Path,
    working_directory: &Path,
    position: &str,
) -> Result<Option<PathBuf>, String> {
    use std::{io::Read, process::Stdio, time::Duration};

    let mut child = std::process::Command::new(executable)
        .arg("definition")
        .arg(position)
        .current_dir(working_directory)
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("GOTOOLCHAIN", "local")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not start gopls: {error}"))?;
    let stdout = child.stdout.take().ok_or("gopls stdout unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut retained = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = match stdout.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            let available = (16 * 1024usize).saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..count.min(available)]);
        }
        retained
    });
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not wait for gopls: {error}"))?
        {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("gopls definition query exceeded 15 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = reader
        .join()
        .map_err(|_| "gopls output reader panicked".to_owned())?;
    if !status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output);
    let Some(location) = text
        .lines()
        .find(|line| line.contains(": defined here"))
        .and_then(|line| {
            line.split_once(": defined here")
                .map(|(location, _)| location)
        })
    else {
        return Ok(None);
    };
    let mut components = location.rsplitn(3, ':');
    let _column = components.next();
    let _line = components.next();
    let Some(path) = components.next() else {
        return Ok(None);
    };
    Ok(Some(PathBuf::from(path)))
}

struct ConsumerSymbolVisitor<'a> {
    symbols: &'a std::collections::BTreeSet<String>,
    file: String,
    root: PathBuf,
    source_digest: String,
    source: &'a str,
    found: Vec<ConsumerSymbolReference>,
}

impl<'ast> syn::visit::Visit<'ast> for ConsumerSymbolVisitor<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                self.record_call_symbol(&segment.ident, "function_call");
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.record_call_symbol(&call.method, "method_call");
        syn::visit::visit_expr_method_call(self, call);
    }

    /// Macro arguments are unparsed tokens to `syn`, so calls such as
    /// `assert!(api::changed())` or `format!("{}", value.changed())` would be
    /// missed. Scan the tokens for call shapes instead; the candidates stay
    /// syntax-inferred until semantic resolution confirms or discards them.
    /// `macro_rules!` bodies are templates, not calls, and are skipped.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !mac.path.is_ident("macro_rules") {
            self.record_token_calls(mac.tokens.clone());
        }
        syn::visit::visit_macro(self, mac);
    }
}

impl ConsumerSymbolVisitor<'_> {
    fn record_token_calls(&mut self, tokens: proc_macro2::TokenStream) {
        let tokens: Vec<proc_macro2::TokenTree> = tokens.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                proc_macro2::TokenTree::Ident(identifier) => {
                    let called = matches!(
                        tokens.get(index + 1),
                        Some(proc_macro2::TokenTree::Group(group))
                            if group.delimiter() == proc_macro2::Delimiter::Parenthesis
                    );
                    if called {
                        let after_dot = index > 0
                            && matches!(
                                &tokens[index - 1],
                                proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '.'
                            );
                        let context = if after_dot {
                            "method_call"
                        } else {
                            "function_call"
                        };
                        self.record_call_symbol(identifier, context);
                    }
                }
                proc_macro2::TokenTree::Group(group) => self.record_token_calls(group.stream()),
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }

    fn record_call_symbol(&mut self, identifier: &syn::Ident, context: &str) {
        let symbol = identifier.to_string();
        if self.symbols.contains(&symbol) {
            let start = identifier.span().start();
            let column = start
                .line
                .checked_sub(1)
                .and_then(|line| self.source.lines().nth(line))
                .map(|line| {
                    line.chars()
                        .take(start.column)
                        .map(char::len_utf16)
                        .sum::<usize>() as u32
                        + 1
                });
            self.found.push(ConsumerSymbolReference {
                consumer_repository: self.root.display().to_string(),
                path: self.file.clone(),
                line: start.line as u32,
                symbol,
                column,
                certainty: "inferred_syntax".into(),
                match_context: context.into(),
                source_digest: self.source_digest.clone(),
                consumer_package_id: None,
                dependency_status: "package_unresolved".into(),
                dependency_paths: Vec::new(),
            });
        }
    }
}

#[derive(Debug, Clone)]
struct PackageDependency {
    name: String,
    declared_alias: Option<String>,
    kind: String,
    requirement: Option<String>,
    path: Option<String>,
    inherited: bool,
    resolved_path: Option<PathBuf>,
    constraint_source: Option<(PathBuf, String)>,
    unresolved_go_replacement: bool,
}

#[derive(Debug, Clone)]
struct GoReplacement {
    old_module: String,
    old_version: Option<String>,
    local_path: Option<String>,
}

#[derive(Debug)]
struct Package {
    id: String,
    root: PathBuf,
    ecosystem: &'static str,
    manifest: &'static str,
    digest: String,
    name: String,
    version: Option<String>,
    dependencies: Vec<PackageDependency>,
}

pub fn build(roots: &[PathBuf]) -> Result<RepositoryMap, String> {
    if roots.is_empty() {
        return Err("provide at least one repository path".to_owned());
    }
    if roots.len() > MAX_REPOSITORIES {
        return Err(format!("repository limit is {MAX_REPOSITORIES}"));
    }
    let mut packages = Vec::new();
    let mut limitations = Vec::new();
    let mut canonical = std::collections::BTreeSet::new();
    for supplied in roots {
        let root = supplied
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", supplied.display()))?;
        if !root.is_dir() {
            return Err(format!("{} is not a directory", root.display()));
        }
        if !canonical.insert(root.clone()) {
            return Err(format!("duplicate repository path: {}", root.display()));
        }
        let mut found = Vec::new();
        if let Some(package) = read_package(&root)? {
            found.push(package);
        }
        let (members, member_limitations) = read_workspace_members(&root)?;
        found.extend(members);
        limitations.extend(member_limitations);
        if found.is_empty() {
            limitations.push(format!(
                "{}: no supported package manifest found",
                root.display()
            ));
            continue;
        }
        packages.extend(found);
        if packages.len() > MAX_REPOSITORIES {
            return Err(format!("package limit is {MAX_REPOSITORIES}"));
        }
    }
    packages.sort_by(|a, b| a.id.cmp(&b.id));
    let mut names: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for package in &packages {
        names
            .entry((package.ecosystem, package.name.as_str()))
            .or_default()
            .push(package.id.as_str());
    }
    let mut repositories = Vec::new();
    let mut dependencies = Vec::new();
    for package in &packages {
        repositories.push(RepositoryEntry {
            id: package.id.clone(),
            root: package.root.display().to_string(),
            ecosystem: package.ecosystem.to_owned(),
            manifest: package.manifest.to_owned(),
            manifest_digest: package.digest.clone(),
        });
        for dependency in &package.dependencies {
            if dependency.unresolved_go_replacement {
                limitations.push(format!(
                    "Go dependency `{}` from `{}` has a replacement that is not a selected local filesystem path; its edge was omitted.",
                    dependency.name, package.id
                ));
                continue;
            }
            let path_target = dependency.resolved_path.clone().or_else(|| {
                dependency
                    .path
                    .as_ref()
                    .and_then(|path| package.root.join(path).canonicalize().ok())
            });
            if dependency.path.is_some() && path_target.is_none() {
                limitations.push(format!(
                    "Dependency `{}` from `{}` declares an unavailable local path and was omitted.",
                    dependency.name, package.id
                ));
                continue;
            }
            let target_package = if let Some(path) = &path_target {
                packages.iter().find(|candidate| &candidate.root == path)
            } else {
                match names.get(&(package.ecosystem, dependency.name.as_str())) {
                    Some(targets) if targets.len() == 1 => {
                        packages.iter().find(|candidate| candidate.id == targets[0])
                    }
                    Some(_) => {
                        limitations.push(format!("Dependency `{}` from `{}` matches multiple supplied repositories and was omitted as ambiguous.", dependency.name, package.id));
                        continue;
                    }
                    None => None,
                }
            };
            if let Some(target_package) = target_package {
                if target_package.id == package.id {
                    continue;
                }
                let version_compatibility = if package.ecosystem == "cargo" {
                    cargo_version_compatibility(
                        dependency.requirement.as_deref(),
                        target_package.version.as_deref(),
                    )
                } else if package.ecosystem == "npm" {
                    npm_version_compatibility(
                        dependency.requirement.as_deref(),
                        target_package.version.as_deref(),
                    )
                } else if package.ecosystem == "go" {
                    go_version_compatibility(dependency.requirement.as_deref(), &dependency.name)
                } else {
                    "not_evaluated".to_owned()
                };
                if version_compatibility == "mismatch" {
                    if package.ecosystem == "go" {
                        limitations.push(format!(
                            "Go dependency `{}` from `{}` requires `{}` but selected local module path `{}` has an incompatible major version.",
                            dependency.name,
                            package.id,
                            dependency.requirement.as_deref().unwrap_or("unspecified"),
                            target_package.name
                        ));
                    } else {
                        limitations.push(format!(
                            "{} dependency `{}` from `{}` requires `{}` but selected local package version is `{}`.",
                            package.ecosystem,
                            dependency.name,
                            package.id,
                            dependency.requirement.as_deref().unwrap_or("unspecified"),
                            target_package.version.as_deref().unwrap_or("unknown")
                        ));
                    }
                }
                dependencies.push(DependencyEdge {
                    from: package.id.clone(),
                    to: target_package.id.clone(),
                    package: dependency.name.clone(),
                    declared_alias: dependency.declared_alias.clone(),
                    kind: dependency.kind.clone(),
                    declared_requirement: dependency.requirement.clone(),
                    version_compatibility,
                    declared_path: dependency.path.clone(),
                    match_basis: if path_target.is_some() {
                        "resolved_path".to_owned()
                    } else if dependency.declared_alias.is_some() {
                        "npm_alias".to_owned()
                    } else {
                        "package_name".to_owned()
                    },
                    evidence_path: package.root.join(package.manifest).display().to_string(),
                    evidence_digest: package.digest.clone(),
                    constraint_source_path: dependency
                        .constraint_source
                        .as_ref()
                        .map(|(path, _)| path.display().to_string()),
                    constraint_source_digest: dependency
                        .constraint_source
                        .as_ref()
                        .map(|(_, digest)| digest.clone()),
                });
            } else if path_target.is_some() {
                limitations.push(format!("Dependency `{}` from `{}` resolves to a local path that is not among the selected repositories.", dependency.name, package.id));
            }
        }
    }
    dependencies.sort_by(|a, b| {
        (&a.from, &a.to, &a.package, &a.kind).cmp(&(&b.from, &b.to, &b.package, &b.kind))
    });
    if packages.iter().any(|p| p.ecosystem == "cargo") {
        limitations.push("Cargo compatibility is evaluated only for selected local packages with valid manifest versions and valid Cargo semver requirements; a package-name match alone does not prove a dependency edge.".to_owned());
    }
    if packages.iter().any(|p| p.ecosystem == "npm") {
        limitations.push("npm relationships are matched by package name; lockfiles, aliases, workspaces, peer resolution, and unsupported version protocols/ranges are not resolved. Supported semver ranges are compared with the selected local package manifest version.".to_owned());
    }
    if packages.iter().any(|p| p.ecosystem == "go") {
        limitations.push("Go relationships are matched by module path from go.mod require directives; local filesystem replace directives are followed only to selected repositories, and definite major-version/module-path mismatches are reported. Dependencies with remote or otherwise unsupported replacement targets are omitted with a limitation rather than mapped to the unreplaced module. Selected versions and go.work workspace resolution are not evaluated.".to_owned());
    }
    limitations.push("Only explicitly supplied local repositories and direct dependencies declared in supported manifests are included; this is not a complete dependency or impact graph.".to_owned());
    limitations.sort();
    limitations.dedup();
    let mut map = RepositoryMap {
        schema_version: 2,
        repositories,
        dependencies,
        limitations,
        digest: String::new(),
    };
    let canonical = serde_json::to_vec(&(&map.repositories, &map.dependencies, &map.limitations))
        .map_err(|e| e.to_string())?;
    map.digest = format!("sha256:{}", hex(&Sha256::digest(canonical)));
    Ok(map)
}

fn cargo_version_compatibility(requirement: Option<&str>, version: Option<&str>) -> String {
    let Some(requirement) = requirement else {
        return "not_specified".into();
    };
    let Some(version) = version else {
        return "unknown".into();
    };
    let Ok(requirement) = semver::VersionReq::parse(requirement) else {
        return "invalid_requirement".into();
    };
    let Ok(version) = semver::Version::parse(version) else {
        return "invalid_package_version".into();
    };
    if requirement.matches(&version) {
        "satisfied".into()
    } else {
        "mismatch".into()
    }
}

fn npm_version_compatibility(requirement: Option<&str>, version: Option<&str>) -> String {
    let Some(requirement) = requirement.map(str::trim).filter(|value| !value.is_empty()) else {
        return "not_specified".into();
    };
    let Some(version) = version else {
        return "unknown".into();
    };
    let Ok(version) = semver::Version::parse(version) else {
        return "invalid_package_version".into();
    };
    if [
        "workspace:",
        "file:",
        "git+",
        "github:",
        "http:",
        "https:",
        "npm:",
    ]
    .iter()
    .any(|prefix| requirement.starts_with(prefix))
    {
        return "not_evaluated".into();
    }
    let alternatives = requirement.split("||").map(str::trim).collect::<Vec<_>>();
    if alternatives.is_empty()
        || alternatives
            .iter()
            .any(|alternative| alternative.is_empty())
    {
        return "invalid_requirement".into();
    }
    let mut parsed = Vec::with_capacity(alternatives.len());
    for alternative in alternatives {
        let normalized = alternative
            .split_whitespace()
            .map(|part| {
                if semver::Version::parse(part).is_ok() {
                    format!("={part}")
                } else {
                    part.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let Ok(requirement) = semver::VersionReq::parse(&normalized) else {
            return "not_evaluated".into();
        };
        parsed.push(requirement);
    }
    if parsed
        .iter()
        .any(|requirement| requirement.matches(&version))
    {
        "satisfied"
    } else {
        "mismatch"
    }
    .into()
}

fn go_version_compatibility(requirement: Option<&str>, module_path: &str) -> String {
    let Some(requirement) = requirement.map(str::trim).filter(|value| !value.is_empty()) else {
        return "not_specified".into();
    };
    let Some(requirement) = requirement.strip_prefix('v') else {
        return "invalid_requirement".into();
    };
    let Ok(requirement) = semver::Version::parse(requirement) else {
        return "invalid_requirement".into();
    };
    let path_major = module_path
        .rsplit('/')
        .next()
        .and_then(|segment| segment.rsplit_once(".v").map(|(_, major)| major))
        .or_else(|| {
            module_path
                .rsplit('/')
                .next()
                .and_then(|segment| segment.strip_prefix('v'))
        })
        .and_then(|major| major.parse::<u64>().ok());
    let mismatch = match path_major {
        Some(path_major) if path_major >= 2 => requirement.major != path_major,
        Some(1) => requirement.major != 1,
        Some(0) => requirement.major != 0,
        Some(_) => false,
        None => requirement.major >= 2,
    };
    if mismatch {
        "mismatch".into()
    } else {
        // The local checkout's selected Go module version is not encoded in go.mod.
        "not_evaluated".into()
    }
}

fn parse_go_replace(value: &str) -> Option<GoReplacement> {
    let (old, new) = value.split_once("=>").unwrap_or((value, ""));
    let old = old.split_whitespace().collect::<Vec<_>>();
    let new = new.split_whitespace().collect::<Vec<_>>();
    if old.is_empty() {
        return None;
    }
    let replacement = new.first().copied().unwrap_or_default();
    let path = std::path::Path::new(replacement);
    let is_local = !replacement.is_empty()
        && (path.is_absolute()
            || replacement.starts_with("./")
            || replacement.starts_with("../")
            || replacement.starts_with(".\\")
            || replacement.starts_with("..\\"));
    Some(GoReplacement {
        old_module: old[0].to_owned(),
        old_version: old.get(1).map(|version| (*version).to_owned()),
        local_path: (is_local && old.len() <= 2 && new.len() == 1).then(|| replacement.to_owned()),
    })
}

fn npm_alias_target(alias: &str, requirement: &str) -> (String, Option<String>, Option<String>) {
    let Some(spec) = requirement.strip_prefix("npm:") else {
        return (alias.to_owned(), None, Some(requirement.to_owned()));
    };
    let version_separator = spec
        .rfind('@')
        .filter(|index| *index > 0 && spec[..*index].contains('/'))
        .or_else(|| {
            spec.rfind('@')
                .filter(|index| *index > 0 && !spec[..*index].starts_with('@'))
        });
    match version_separator {
        Some(index) => {
            let target = &spec[..index];
            let version = &spec[index + 1..];
            if target.is_empty() || version.is_empty() {
                (alias.to_owned(), None, None)
            } else {
                (
                    target.to_owned(),
                    Some(alias.to_owned()),
                    Some(version.to_owned()),
                )
            }
        }
        None if !spec.is_empty() => (spec.to_owned(), Some(alias.to_owned()), None),
        None => (alias.to_owned(), None, None),
    }
}

fn read_package(root: &Path) -> Result<Option<Package>, String> {
    let cargo = root.join("Cargo.toml");
    if cargo.is_file() {
        let (contents, digest) = read_bounded(&cargo)?;
        let value: toml::Value =
            toml::from_str(&contents).map_err(|e| format!("invalid {}: {e}", cargo.display()))?;
        let root_pkg = value.get("package");
        if root_pkg.is_none() {
            return Ok(None);
        }
        let name = root_pkg
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                root.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            });
        let mut dependencies = Vec::new();
        for (section, kind) in [
            ("dependencies", "runtime"),
            ("dev-dependencies", "development"),
            ("build-dependencies", "build"),
        ] {
            if let Some(table) = value.get(section).and_then(toml::Value::as_table) {
                for (alias, spec) in table {
                    let package_name = spec
                        .get("package")
                        .and_then(toml::Value::as_str)
                        .unwrap_or(alias);
                    let inherited = spec
                        .get("workspace")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(false);
                    dependencies.push(PackageDependency {
                        name: package_name.to_owned(),
                        declared_alias: (package_name != alias).then(|| alias.to_owned()),
                        kind: kind.to_owned(),
                        requirement: spec
                            .get("version")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned)
                            .or_else(|| spec.as_str().map(str::to_owned)),
                        path: spec
                            .get("path")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned),
                        inherited,
                        resolved_path: None,
                        constraint_source: None,
                        unresolved_go_replacement: false,
                    });
                }
            }
        }
        return Ok(Some(Package {
            id: name.clone(),
            root: root.to_owned(),
            ecosystem: "cargo",
            manifest: "Cargo.toml",
            digest,
            name,
            version: root_pkg
                .and_then(|p| p.get("version"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            dependencies,
        }));
    }
    let npm = root.join("package.json");
    if npm.is_file() {
        let (contents, digest) = read_bounded(&npm)?;
        let value: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| format!("invalid {}: {e}", npm.display()))?;
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{} has no package name", npm.display()))?
            .to_owned();
        let mut dependencies = Vec::new();
        for (field, kind) in [
            ("dependencies", "runtime"),
            ("devDependencies", "development"),
            ("peerDependencies", "peer"),
        ] {
            if let Some(table) = value.get(field).and_then(serde_json::Value::as_object) {
                dependencies.extend(table.iter().map(|(name, requirement)| {
                    let (package_name, declared_alias, requirement) = requirement
                        .as_str()
                        .map(|requirement| npm_alias_target(name, requirement))
                        .unwrap_or_else(|| (name.clone(), None, None));
                    PackageDependency {
                        name: package_name,
                        declared_alias,
                        kind: kind.to_owned(),
                        requirement,
                        path: None,
                        inherited: false,
                        resolved_path: None,
                        constraint_source: None,
                        unresolved_go_replacement: false,
                    }
                }));
            }
        }
        return Ok(Some(Package {
            id: name.clone(),
            root: root.to_owned(),
            ecosystem: "npm",
            manifest: "package.json",
            digest,
            name,
            version: value
                .get("version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            dependencies,
        }));
    }
    let go = root.join("go.mod");
    if go.is_file() {
        let (contents, digest) = read_bounded(&go)?;
        let mut module = None;
        let mut dependencies = Vec::new();
        let mut replacements = Vec::new();
        let mut in_require = false;
        let mut in_replace = false;
        for line in contents.lines() {
            let line = line
                .split_once("//")
                .map_or(line, |(before, _)| before)
                .trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("module ") {
                module = Some(rest.trim().trim_matches('"').to_owned());
                in_require = false;
                in_replace = false;
            } else if line == "require (" {
                in_require = true;
            } else if line == "replace (" {
                in_replace = true;
            } else if (in_require || in_replace) && line == ")" {
                in_require = false;
                in_replace = false;
            } else if let Some(rest) = line.strip_prefix("require ") {
                if let Some(path) = rest.split_whitespace().next() {
                    dependencies.push(PackageDependency {
                        name: path.to_owned(),
                        declared_alias: None,
                        kind: "runtime".to_owned(),
                        requirement: rest.split_whitespace().nth(1).map(str::to_owned),
                        path: None,
                        inherited: false,
                        resolved_path: None,
                        constraint_source: None,
                        unresolved_go_replacement: false,
                    });
                }
            } else if let Some(rest) = line.strip_prefix("replace ") {
                if let Some(replacement) = parse_go_replace(rest) {
                    replacements.push(replacement);
                }
            } else if in_replace {
                if let Some(replacement) = parse_go_replace(line) {
                    replacements.push(replacement);
                }
            } else if in_require {
                if let Some(path) = line.split_whitespace().next() {
                    dependencies.push(PackageDependency {
                        name: path.to_owned(),
                        declared_alias: None,
                        kind: "runtime".to_owned(),
                        requirement: line.split_whitespace().nth(1).map(str::to_owned),
                        path: None,
                        inherited: false,
                        resolved_path: None,
                        constraint_source: None,
                        unresolved_go_replacement: false,
                    });
                }
            }
        }
        let name = module.ok_or_else(|| format!("{} has no module directive", go.display()))?;
        for dependency in &mut dependencies {
            let replacement = replacements
                .iter()
                .filter(|replacement| {
                    replacement.old_module == dependency.name
                        && replacement.old_version.as_deref().is_none_or(|version| {
                            dependency.requirement.as_deref() == Some(version)
                        })
                })
                .max_by_key(|replacement| replacement.old_version.is_some());
            if let Some(replacement) = replacement {
                if let Some(path) = &replacement.local_path {
                    dependency.path = Some(path.clone());
                    dependency.resolved_path = root.join(path).canonicalize().ok();
                } else {
                    dependency.unresolved_go_replacement = true;
                }
            }
        }
        return Ok(Some(Package {
            id: name.clone(),
            root: root.to_owned(),
            ecosystem: "go",
            manifest: "go.mod",
            digest,
            name,
            version: None,
            dependencies,
        }));
    }
    Ok(None)
}

fn read_workspace_members(root: &Path) -> Result<(Vec<Package>, Vec<String>), String> {
    let manifest = root.join("Cargo.toml");
    if !manifest.is_file() {
        return Ok((Vec::new(), Vec::new()));
    }
    let (contents, manifest_digest) = read_bounded(&manifest)?;
    let value: toml::Value =
        toml::from_str(&contents).map_err(|e| format!("invalid {}: {e}", manifest.display()))?;
    let Some(workspace) = value.get("workspace") else {
        return Ok((Vec::new(), Vec::new()));
    };
    let workspace_dependencies = workspace
        .get("dependencies")
        .and_then(toml::Value::as_table);
    let members = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let excluded: Vec<&str> = workspace
        .get("exclude")
        .and_then(toml::Value::as_array)
        .map(|items| items.iter().filter_map(toml::Value::as_str).collect())
        .unwrap_or_default();
    let mut paths = Vec::new();
    let mut limitations = Vec::new();
    for pattern in members {
        let pattern_path = Path::new(pattern);
        if pattern_path.is_absolute()
            || pattern_path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            limitations.push(format!(
                "{}: unsafe Cargo workspace member `{pattern}` was skipped",
                root.display()
            ));
            continue;
        }
        let candidates = if let Some((parent, leaf)) = pattern.rsplit_once("/*") {
            if leaf.is_empty() && !parent.contains('*') {
                let directory = root.join(parent);
                match std::fs::read_dir(&directory) {
                    Ok(entries) => entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .collect::<Vec<_>>(),
                    Err(error) => {
                        limitations.push(format!(
                            "{}: cannot enumerate workspace member pattern `{pattern}`: {error}",
                            root.display()
                        ));
                        Vec::new()
                    }
                }
            } else {
                limitations.push(format!(
                    "{}: unsupported Cargo workspace member pattern `{pattern}` was not expanded",
                    root.display()
                ));
                Vec::new()
            }
        } else if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            limitations.push(format!(
                "{}: unsupported Cargo workspace member pattern `{pattern}` was not expanded",
                root.display()
            ));
            Vec::new()
        } else {
            vec![root.join(pattern)]
        };
        for candidate in candidates {
            let Ok(canonical) = candidate.canonicalize() else {
                limitations.push(format!(
                    "{}: workspace member `{pattern}` is missing or inaccessible",
                    root.display()
                ));
                continue;
            };
            if !canonical.starts_with(root) || !canonical.is_dir() {
                limitations.push(format!("{}: workspace member `{pattern}` resolves outside the checkout or is not a directory", root.display()));
                continue;
            }
            let relative = canonical.strip_prefix(root).unwrap_or(Path::new(""));
            let rel = relative.to_string_lossy().replace('\\', "/");
            if excluded
                .iter()
                .any(|exclude| rel == *exclude || rel.starts_with(&format!("{exclude}/")))
            {
                continue;
            }
            paths.push(canonical);
        }
    }
    paths.sort();
    paths.dedup();
    let mut packages = Vec::new();
    for path in paths {
        if let Some(mut package) = read_package(&path)? {
            for dependency in &mut package.dependencies {
                if dependency.inherited {
                    if let Some(spec) =
                        workspace_dependencies.and_then(|table| table.get(&dependency.name))
                    {
                        dependency.name = spec
                            .get("package")
                            .and_then(toml::Value::as_str)
                            .unwrap_or(&dependency.name)
                            .to_owned();
                        dependency.requirement = spec
                            .get("version")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned)
                            .or_else(|| spec.as_str().map(str::to_owned));
                        dependency.path = spec
                            .get("path")
                            .and_then(toml::Value::as_str)
                            .map(str::to_owned);
                        dependency.resolved_path = dependency
                            .path
                            .as_ref()
                            .and_then(|path| root.join(path).canonicalize().ok());
                        dependency.constraint_source =
                            Some((manifest.clone(), manifest_digest.clone()));
                        dependency.inherited = false;
                    } else {
                        limitations.push(format!("{}: inherited dependency `{}` has no matching workspace dependency declaration", package.id, dependency.name));
                    }
                }
            }
            packages.push(package);
        } else {
            limitations.push(format!(
                "{}: workspace member has no supported package manifest",
                path.display()
            ));
        }
    }
    Ok((packages, limitations))
}

fn read_bounded(path: &Path) -> Result<(String, String), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{} must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "{} exceeds the 2 MiB manifest limit",
            path.display()
        ));
    }
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if data.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "{} exceeds the 2 MiB manifest limit",
            path.display()
        ));
    }
    let digest = format!("sha256:{}", hex(&Sha256::digest(&data)));
    let text = String::from_utf8(data).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    Ok((text, digest))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn rust_analyzer_definition_protocol_resolves_and_filters_same_name_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        let changed = producer.join("src/lib.rs");
        let first = consumer.join("src/first.rs");
        let second = consumer.join("src/second.rs");
        std::fs::write(&changed, "pub fn changed_api() {}\n").unwrap();
        std::fs::write(&first, "fn first() { changed_api(); }\n").unwrap();
        std::fs::write(&second, "fn second() { changed_api(); }\n").unwrap();

        let fake_server = workspace.path().join("fake-rust-analyzer.py");
        let script = format!(
            "#!/usr/bin/python3\nimport json,sys\nproducer={:?}\nconsumer={:?}\nseen=set()\ndef read_msg():\n h=b''\n while not h.endswith(b'\\r\\n\\r\\n'):\n  c=sys.stdin.buffer.read(1)\n  if not c: return None\n  h+=c\n n=int(next(x.split(b':',1)[1] for x in h.split(b'\\r\\n') if x.lower().startswith(b'content-length:')))\n return json.loads(sys.stdin.buffer.read(n))\ndef send(x):\n b=json.dumps(x).encode()\n sys.stdout.buffer.write(b'Content-Length: '+str(len(b)).encode()+b'\\r\\n\\r\\n'+b);sys.stdout.buffer.flush()\nwhile True:\n m=read_msg()\n if m is None: break\n if 'id' in m:\n  assert m['id'] not in seen\n  seen.add(m['id'])\n method=m.get('method')\n if method=='initialize': send({{'jsonrpc':'2.0','id':m['id'],'result':{{'capabilities':{{'definitionProvider':True}}}}}})\n elif method=='textDocument/definition':\n  pos=m['params']['position']\n  if pos=={{'line':0,'character':13}}: path=producer\n  elif pos=={{'line':1,'character':14}}: path=consumer\n  else: send({{'jsonrpc':'2.0','id':m['id'],'result':[]}}); continue\n  send({{'jsonrpc':'2.0','id':m['id'],'result':{{'uri':'file://'+path,'range':{{'start':{{'line':0,'character':0}},'end':{{'line':0,'character':1}}}}}}}})\n elif m.get('id') is not None: send({{'jsonrpc':'2.0','id':m['id'],'result':None}})\n",
            changed.canonicalize().unwrap().to_string_lossy(),
            second.canonicalize().unwrap().to_string_lossy(),
        );
        std::fs::write(&fake_server, script).unwrap();
        let mut permissions = std::fs::metadata(&fake_server).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_server, permissions).unwrap();
        let previous = std::env::var_os("VERO_RUST_ANALYZER");
        std::env::set_var("VERO_RUST_ANALYZER", &fake_server);

        let mut references = vec![
            super::ConsumerSymbolReference {
                consumer_repository: consumer.canonicalize().unwrap().display().to_string(),
                path: "src/first.rs".into(),
                line: 1,
                symbol: "changed_api".into(),
                column: Some(14),
                certainty: "syntax_inferred".into(),
                match_context: "call".into(),
                source_digest: "sha256:first".into(),
                consumer_package_id: None,
                dependency_status: "package_unresolved".into(),
                dependency_paths: Vec::new(),
            },
            super::ConsumerSymbolReference {
                consumer_repository: consumer.canonicalize().unwrap().display().to_string(),
                path: "src/second.rs".into(),
                line: 2,
                symbol: "changed_api".into(),
                column: Some(15),
                certainty: "syntax_inferred".into(),
                match_context: "call".into(),
                source_digest: "sha256:second".into(),
                consumer_package_id: None,
                dependency_status: "package_unresolved".into(),
                dependency_paths: Vec::new(),
            },
        ];
        let impact = crate::ImpactAssessment {
            schema_version: 1,
            snapshot_id: "snapshot".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/lib.rs".into()],
            changed_symbols: Vec::new(),
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let (complete, limitations) = super::resolve_rust_consumer_references(
            &mut references,
            &[0, 1],
            &impact,
            &producer,
            std::slice::from_ref(&consumer),
        );
        if let Some(previous) = previous {
            std::env::set_var("VERO_RUST_ANALYZER", previous);
        } else {
            std::env::remove_var("VERO_RUST_ANALYZER");
        }

        assert!(complete, "{limitations:?}");
        assert!(limitations.is_empty(), "{limitations:?}");
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].path, "src/first.rs");
        assert_eq!(references[0].certainty, "semantic_resolved");
    }

    #[test]
    fn rust_consumer_scan_finds_calls_inside_macro_arguments() {
        let source = "fn f(x: Thing) {\n    assert!(api::changed(1) > 0, \"{}\", x.changed_method());\n    println!(\"{:?}\", vec![api::changed(2)]);\n}\nmacro_rules! m { ($e:expr) => { changed($e) }; }\n";
        let syntax = syn::parse_file(source).unwrap();
        let symbols: std::collections::BTreeSet<String> =
            ["changed".to_owned(), "changed_method".to_owned()].into();
        let mut visitor = ConsumerSymbolVisitor {
            symbols: &symbols,
            file: "src/lib.rs".into(),
            root: PathBuf::from("/consumer"),
            source_digest: "sha256:test".into(),
            source,
            found: Vec::new(),
        };
        syn::visit::Visit::visit_file(&mut visitor, &syntax);
        let found: Vec<_> = visitor
            .found
            .iter()
            .map(|reference| {
                (
                    reference.symbol.as_str(),
                    reference.line,
                    reference.column,
                    reference.match_context.as_str(),
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                ("changed", 2, Some(18), "function_call"),
                ("changed_method", 2, Some(42), "method_call"),
                ("changed", 3, Some(32), "function_call"),
            ]
        );
    }

    #[test]
    fn rust_call_columns_are_one_based_utf16_even_after_non_bmp_text() {
        let source = "fn call() { let marker = \"🛡️\"; changed_api(); }";
        let symbols = std::collections::BTreeSet::from(["changed_api".to_owned()]);
        let syntax = syn::parse_file(source).unwrap();
        let mut visitor = super::ConsumerSymbolVisitor {
            symbols: &symbols,
            file: "src/lib.rs".into(),
            root: std::path::PathBuf::from("/consumer"),
            source_digest: "sha256:test".into(),
            source,
            found: Vec::new(),
        };

        syn::visit::Visit::visit_file(&mut visitor, &syntax);

        let byte_column = source.find("changed_api").unwrap();
        let expected_column = source[..byte_column].encode_utf16().count() as u32 + 1;
        assert_eq!(visitor.found.len(), 1);
        assert_eq!(visitor.found[0].line, 1);
        assert_eq!(visitor.found[0].column, Some(expected_column));
    }

    #[test]
    fn schema_compatibility_detects_nested_enum_and_numeric_range_directionality() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  request: {type: string, enum: [alpha, beta], minimum: 0, maximum: 10}\n  response: {type: integer, enum: [1], minimum: 0, maximum: 10}\n",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  request: {type: string, enum: [alpha], minimum: 2, maximum: 8}\n  response: {type: integer, enum: [1, 2], minimum: -1, maximum: 12}\n",
        )
        .unwrap();
        let mut request_issues = Vec::new();
        super::collect_nested_schema_issues(
            &baseline,
            &current,
            "request",
            "schema",
            0,
            &mut request_issues,
        );
        assert!(request_issues.iter().any(|(issue, path)| {
            issue == "request_enum_narrowed" && path == "schema.properties.request.enum"
        }));
        assert!(request_issues.iter().any(|(issue, path)| {
            issue == "request_numeric_range_narrowed" && path == "schema.properties.request"
        }));

        let mut response_issues = Vec::new();
        super::collect_nested_schema_issues(
            &baseline,
            &current,
            "response",
            "schema",
            0,
            &mut response_issues,
        );
        assert!(response_issues.iter().any(|(issue, path)| {
            issue == "response_enum_broadened" && path == "schema.properties.response.enum"
        }));
        assert!(response_issues.iter().any(|(issue, path)| {
            issue == "response_numeric_range_broadened" && path == "schema.properties.response"
        }));
    }

    #[test]
    fn schema_size_constraints_follow_request_and_response_direction() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  text: {type: string, minLength: 2, maxLength: 12}\n  list: {type: array, minItems: 1, maxItems: 10}\n  record: {type: object, minProperties: 1, maxProperties: 10}\n",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  text: {type: string, minLength: 4, maxLength: 16}\n  list: {type: array, minItems: 0, maxItems: 8}\n  record: {type: object, minProperties: 0, maxProperties: 8}\n",
        )
        .unwrap();
        let mut request_issues = Vec::new();
        super::collect_nested_schema_issues(
            &baseline,
            &current,
            "request",
            "schema",
            0,
            &mut request_issues,
        );
        assert!(request_issues.iter().any(|(issue, path)| {
            issue == "request_schema_size_range_narrowed"
                && path == "schema.properties.text.minLength"
        }));
        assert!(request_issues.iter().any(|(issue, path)| {
            issue == "request_schema_size_range_narrowed"
                && path == "schema.properties.list.maxItems"
        }));
        assert!(request_issues.iter().any(|(issue, path)| {
            issue == "request_schema_size_range_narrowed"
                && path == "schema.properties.record.maxProperties"
        }));

        let mut response_issues = Vec::new();
        super::collect_nested_schema_issues(
            &baseline,
            &current,
            "response",
            "schema",
            0,
            &mut response_issues,
        );
        assert!(response_issues.iter().any(|(issue, path)| {
            issue == "response_schema_size_range_broadened"
                && path == "schema.properties.text.maxLength"
        }));
        assert!(response_issues.iter().any(|(issue, path)| {
            issue == "response_schema_size_range_broadened"
                && path == "schema.properties.list.minItems"
        }));
        assert!(response_issues.iter().any(|(issue, path)| {
            issue == "response_schema_size_range_broadened"
                && path == "schema.properties.record.minProperties"
        }));
    }

    #[test]
    fn schema_pattern_changes_are_reported_without_claiming_regex_equivalence() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  value: {type: string, pattern: '^[a-z]+$'}\n",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  value: {type: string, pattern: '^[a-z0-9]+$'}\n",
        )
        .unwrap();
        for direction in ["request", "response"] {
            let mut issues = Vec::new();
            super::collect_nested_schema_issues(
                &baseline,
                &current,
                direction,
                "schema",
                0,
                &mut issues,
            );
            assert!(issues.iter().any(|(issue, path)| {
                issue == &format!("{direction}_schema_pattern_changed")
                    && path == "schema.properties.value.pattern"
            }));
        }
    }

    #[test]
    fn schema_type_changes_follow_request_and_response_compatibility_direction() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let old_integer: serde_yaml::Value = serde_yaml::from_str("{type: integer}").unwrap();
        let new_number: serde_yaml::Value = serde_yaml::from_str("{type: number}").unwrap();
        let request = super::schema_change_issues(
            &old_integer,
            &new_number,
            &document,
            &document,
            "request",
            "application/json",
        );
        assert!(request.is_empty(), "integer to number broadens requests");
        let response = super::schema_change_issues(
            &old_integer,
            &new_number,
            &document,
            &document,
            "response",
            "application/json",
        );
        assert!(response
            .iter()
            .any(|(issue, _)| issue == "response_schema_type_changed"));

        let new_integer: serde_yaml::Value = serde_yaml::from_str("{type: integer}").unwrap();
        let old_number: serde_yaml::Value = serde_yaml::from_str("{type: number}").unwrap();
        let request = super::schema_change_issues(
            &old_number,
            &new_integer,
            &document,
            &document,
            "request",
            "application/json",
        );
        assert!(request
            .iter()
            .any(|(issue, _)| issue == "request_schema_type_changed"));
        let response = super::schema_change_issues(
            &old_number,
            &new_integer,
            &document,
            &document,
            "response",
            "application/json",
        );
        assert!(response.is_empty(), "number to integer narrows responses");

        let old_union: serde_yaml::Value =
            serde_yaml::from_str("{type: [integer, string]}").unwrap();
        let new_union: serde_yaml::Value =
            serde_yaml::from_str("{type: [number, string]}").unwrap();
        assert!(super::schema_change_issues(
            &old_union,
            &new_union,
            &document,
            &document,
            "request",
            "application/json",
        )
        .is_empty());
        let response_union_issue = super::schema_change_issues(
            &old_union,
            &new_union,
            &document,
            &document,
            "response",
            "application/json",
        );
        assert!(response_union_issue
            .iter()
            .any(|(issue, _)| issue == "response_schema_type_changed"));

        let old_object: serde_yaml::Value =
            serde_yaml::from_str("{type: object, properties: {amount: {type: integer}}}").unwrap();
        let new_object: serde_yaml::Value =
            serde_yaml::from_str("{type: object, properties: {amount: {type: number}}}").unwrap();
        assert!(super::schema_change_issues(
            &old_object,
            &new_object,
            &document,
            &document,
            "request",
            "application/json",
        )
        .iter()
        .all(|(issue, _)| issue != "request_property_type_changed"));
        assert!(super::schema_change_issues(
            &old_object,
            &new_object,
            &document,
            &document,
            "response",
            "application/json",
        )
        .iter()
        .any(|(issue, _)| issue == "response_property_type_changed"));

        let old_array: serde_yaml::Value =
            serde_yaml::from_str("{type: array, items: {type: integer}}").unwrap();
        let new_array: serde_yaml::Value =
            serde_yaml::from_str("{type: array, items: {type: number}}").unwrap();
        let request_array = super::schema_change_issues(
            &old_array,
            &new_array,
            &document,
            &document,
            "request",
            "application/json",
        );
        assert!(request_array
            .iter()
            .all(|(issue, _)| issue != "request_schema_type_changed"));
        let response_array = super::schema_change_issues(
            &old_array,
            &new_array,
            &document,
            &document,
            "response",
            "application/json",
        );
        assert!(response_array.iter().any(|(issue, path)| {
            issue == "response_schema_type_changed" && path.ends_with("items.type")
        }));

        let old_map: serde_yaml::Value =
            serde_yaml::from_str("{type: object, additionalProperties: {type: integer}}").unwrap();
        let new_map: serde_yaml::Value =
            serde_yaml::from_str("{type: object, additionalProperties: {type: number}}").unwrap();
        let response_map = super::schema_change_issues(
            &old_map,
            &new_map,
            &document,
            &document,
            "response",
            "application/json",
        );
        assert!(response_map.iter().any(|(issue, path)| {
            issue == "response_schema_type_changed" && path.ends_with("additionalProperties.type")
        }));

        let old_parameter: serde_yaml::Value =
            serde_yaml::from_str("{schema: {type: integer}}").unwrap();
        let new_parameter: serde_yaml::Value =
            serde_yaml::from_str("{schema: {type: number}}").unwrap();
        assert!(super::parameter_schema_changes(
            &old_parameter,
            &new_parameter,
            &document,
            &document,
            "parameters.limit",
        )
        .0
        .iter()
        .all(|(issue, _)| issue != "parameter_type_changed"));
    }

    #[test]
    fn parameter_size_constraints_report_directional_narrowing() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        for (name, previous, current, bound) in [
            (
                "token",
                "{schema: {type: string, minLength: 2, maxLength: 64}}",
                "{schema: {type: string, minLength: 8, maxLength: 64}}",
                "minLength",
            ),
            (
                "page",
                "{schema: {type: array, minItems: 1, maxItems: 50}}",
                "{schema: {type: array, minItems: 1, maxItems: 20}}",
                "maxItems",
            ),
            (
                "filter",
                "{schema: {type: object, minProperties: 1, maxProperties: 40}}",
                "{schema: {type: object, minProperties: 5, maxProperties: 40}}",
                "minProperties",
            ),
        ] {
            let previous: serde_yaml::Value = serde_yaml::from_str(previous).unwrap();
            let current: serde_yaml::Value = serde_yaml::from_str(current).unwrap();
            let component_path = format!("parameters[query:{name}]");
            let (changes, unresolved) = super::parameter_schema_changes(
                &previous,
                &current,
                &document,
                &document,
                &component_path,
            );
            assert!(!unresolved);
            assert!(changes.iter().any(|(issue, path)| {
                issue == "parameter_size_range_narrowed"
                    && path == &format!("{component_path}.schema.{bound}")
            }));
        }
    }

    #[test]
    fn parameter_pattern_changes_include_the_parameter_path() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let previous: serde_yaml::Value =
            serde_yaml::from_str("{schema: {type: string, pattern: '^[a-z]+$'}}").unwrap();
        let current: serde_yaml::Value =
            serde_yaml::from_str("{schema: {type: string, pattern: '^[a-z0-9]+$'}}").unwrap();
        let (changes, unresolved) = super::parameter_schema_changes(
            &previous,
            &current,
            &document,
            &document,
            "parameters[query:slug]",
        );
        assert!(!unresolved);
        assert!(changes.iter().any(|(issue, path)| {
            issue == "parameter_pattern_changed" && path == "parameters[query:slug].schema.pattern"
        }));
    }

    #[test]
    fn explicit_parameter_serialization_changes_are_reported_without_assuming_defaults() {
        let previous: serde_yaml::Value = serde_yaml::from_str(
            "{name: tags, in: query, style: form, explode: true, allowReserved: false}",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "{name: tags, in: query, style: pipeDelimited, explode: false, allowReserved: true}",
        )
        .unwrap();
        let changes =
            super::parameter_serialization_changes(&previous, &current, "parameters[query:tags]");
        assert_eq!(changes.len(), 3);
        assert!(changes
            .iter()
            .all(|(issue, _)| { issue == "parameter_serialization_changed" }));
        assert!(changes
            .iter()
            .any(|(_, path)| path == "parameters[query:tags].style"));
        assert!(changes
            .iter()
            .any(|(_, path)| path == "parameters[query:tags].explode"));
        assert!(changes
            .iter()
            .any(|(_, path)| path == "parameters[query:tags].allowReserved"));

        let omitted: serde_yaml::Value = serde_yaml::from_str("{name: tags, in: query}").unwrap();
        assert!(super::parameter_serialization_changes(
            &omitted,
            &previous,
            "parameters[query:tags]",
        )
        .is_empty());
    }

    #[test]
    fn matching_single_media_parameter_content_schemas_are_compared() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let previous: serde_yaml::Value = serde_yaml::from_str(
            "{name: filter, in: query, content: {text/plain: {schema: {type: string, enum: [a, b]}}}}",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "{name: filter, in: query, content: {text/plain: {schema: {type: string, enum: [a]}}}}",
        )
        .unwrap();
        let (changes, unresolved) = super::parameter_schema_changes(
            &previous,
            &current,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(!unresolved);
        assert!(changes.iter().any(|(issue, path)| {
            issue == "parameter_enum_narrowed"
                && path == "parameters[query:filter].content.text/plain.schema.enum"
        }));

        let media_type_changed: serde_yaml::Value = serde_yaml::from_str(
            "{name: filter, in: query, content: {application/json: {schema: {type: string}}}}",
        )
        .unwrap();
        let (changes, unresolved) = super::parameter_schema_changes(
            &previous,
            &media_type_changed,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(!unresolved);
        assert!(changes.iter().any(|(issue, path)| {
            issue == "parameter_content_media_type_changed"
                && path == "parameters[query:filter].content"
        }));

        let previous_document: serde_yaml::Value = serde_yaml::from_str(
            "components: {schemas: {Filter: {type: string, enum: [alpha, beta]}}}",
        )
        .unwrap();
        let current_document: serde_yaml::Value =
            serde_yaml::from_str("components: {schemas: {Filter: {type: string, enum: [alpha]}}}")
                .unwrap();
        let previous_reference: serde_yaml::Value = serde_yaml::from_str(
            "{name: filter, in: query, content: {text/plain: {schema: {$ref: '#/components/schemas/Filter'}}}}",
        )
        .unwrap();
        let current_reference = previous_reference.clone();
        let (changes, unresolved) = super::parameter_schema_changes(
            &previous_reference,
            &current_reference,
            &previous_document,
            &current_document,
            "parameters[query:filter]",
        );
        assert!(!unresolved);
        assert!(changes
            .iter()
            .any(|(issue, _)| issue == "parameter_enum_narrowed"));

        let multiple_media: serde_yaml::Value = serde_yaml::from_str(
            "{name: filter, in: query, content: {text/plain: {schema: {type: string}}, application/json: {schema: {type: string}}}}",
        )
        .unwrap();
        let (_, unresolved) = super::parameter_schema_changes(
            &previous,
            &multiple_media,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(unresolved);

        let malformed_content: serde_yaml::Value =
            serde_yaml::from_str("{name: filter, in: query, content: {}} ").unwrap();
        let (_, unresolved) = super::parameter_schema_changes(
            &malformed_content,
            &malformed_content,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(unresolved);

        let schema_parameter: serde_yaml::Value =
            serde_yaml::from_str("{name: filter, in: query, schema: {type: string}} ").unwrap();
        let (_, unresolved) = super::parameter_schema_changes(
            &schema_parameter,
            &previous,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(unresolved);

        let unspecified: serde_yaml::Value =
            serde_yaml::from_str("{name: filter, in: query}").unwrap();
        let (_, unresolved) = super::parameter_schema_changes(
            &unspecified,
            &unspecified,
            &document,
            &document,
            "parameters[query:filter]",
        );
        assert!(!unresolved);
    }

    #[test]
    fn openapi_30_nullable_changes_follow_request_and_response_direction() {
        let document_30: serde_yaml::Value =
            serde_yaml::from_str("openapi: 3.0.3\npaths: {}\n").unwrap();
        let document_31: serde_yaml::Value =
            serde_yaml::from_str("openapi: 3.1.0\npaths: {}\n").unwrap();
        let nullable: serde_yaml::Value =
            serde_yaml::from_str("type: string\nnullable: true\n").unwrap();
        let non_nullable: serde_yaml::Value = serde_yaml::from_str("type: string\n").unwrap();

        let request = super::schema_change_issues(
            &nullable,
            &non_nullable,
            &document_30,
            &document_30,
            "request",
            "application/json",
        );
        assert!(request.iter().any(|(issue, path)| {
            issue == "request_nullable_removed" && path.ends_with("schema.nullable")
        }));

        let response = super::schema_change_issues(
            &non_nullable,
            &nullable,
            &document_30,
            &document_30,
            "response",
            "application/json",
        );
        assert!(response.iter().any(|(issue, path)| {
            issue == "response_nullable_added" && path.ends_with("schema.nullable")
        }));

        let openapi_31 = super::schema_change_issues(
            &nullable,
            &non_nullable,
            &document_31,
            &document_31,
            "request",
            "application/json",
        );
        assert!(openapi_31.is_empty());

        let nested_nullable: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nproperties:\n  id:\n    type: string\n    nullable: true\n",
        )
        .unwrap();
        let nested_non_nullable: serde_yaml::Value =
            serde_yaml::from_str("type: object\nproperties:\n  id:\n    type: string\n").unwrap();
        let nested_request = super::schema_change_issues(
            &nested_nullable,
            &nested_non_nullable,
            &document_30,
            &document_30,
            "request",
            "application/json",
        );
        assert!(nested_request.iter().any(|(issue, path)| {
            issue == "request_nullable_removed" && path.ends_with("schema.properties.id.nullable")
        }));

        let previous_parameter: serde_yaml::Value = serde_yaml::from_str(
            "name: id\nin: query\nschema:\n  type: string\n  nullable: true\n",
        )
        .unwrap();
        let current_parameter: serde_yaml::Value =
            serde_yaml::from_str("name: id\nin: query\nschema:\n  type: string\n").unwrap();
        let (parameter_changes, unresolved) = super::parameter_schema_changes(
            &previous_parameter,
            &current_parameter,
            &document_30,
            &document_30,
            "parameters.query.id",
        );
        assert!(!unresolved);
        assert!(parameter_changes.iter().any(|(issue, path)| {
            issue == "parameter_nullable_removed" && path == "parameters.query.id.schema.nullable"
        }));
    }

    #[test]
    fn schema_compatibility_treats_const_as_a_singleton_enum() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let contradictory: serde_yaml::Value =
            serde_yaml::from_str("{const: stable, enum: [preview]}").unwrap();
        assert!(super::resolve_openapi_schema(&document, &contradictory).is_err());

        let previous_request: serde_yaml::Value =
            serde_yaml::from_str("{type: string, enum: [stable, preview]}").unwrap();
        let current_request: serde_yaml::Value =
            serde_yaml::from_str("{type: string, const: stable}").unwrap();
        let mut issues = Vec::new();
        super::collect_nested_schema_issues(
            &previous_request,
            &current_request,
            "request",
            "schema",
            0,
            &mut issues,
        );
        assert!(issues
            .iter()
            .any(|(issue, path)| { issue == "request_enum_narrowed" && path == "schema.const" }));

        let previous_response: serde_yaml::Value =
            serde_yaml::from_str("{type: string, const: stable}").unwrap();
        let current_response: serde_yaml::Value =
            serde_yaml::from_str("{type: string, enum: [stable, preview]}").unwrap();
        let mut issues = Vec::new();
        super::collect_nested_schema_issues(
            &previous_response,
            &current_response,
            "response",
            "schema",
            0,
            &mut issues,
        );
        assert!(issues
            .iter()
            .any(|(issue, path)| { issue == "response_enum_broadened" && path == "schema.enum" }));

        let removed_constraint: serde_yaml::Value = serde_yaml::from_str("{type: string}").unwrap();
        let mut issues = Vec::new();
        super::collect_nested_schema_issues(
            &previous_response,
            &removed_constraint,
            "response",
            "schema",
            0,
            &mut issues,
        );
        assert!(issues
            .iter()
            .any(|(issue, _)| issue == "response_enum_broadened"));
    }

    #[test]
    fn schema_composition_compatibility_reports_directional_variant_changes() {
        let baseline: serde_yaml::Value =
            serde_yaml::from_str("oneOf: [{type: string}, {type: integer}, {type: integer}]")
                .unwrap();
        let current: serde_yaml::Value =
            serde_yaml::from_str("oneOf: [{type: integer}, {type: string}]").unwrap();
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let request = super::directional_composition_issues(
            &document,
            &baseline,
            &document,
            &current,
            "request",
            "request.schema",
        );
        assert_eq!(request.len(), 1);
        assert_eq!(request[0].0, "request_composition_branch_removed");

        let response = super::directional_composition_issues(
            &document,
            &current,
            &document,
            &baseline,
            "response",
            "response.schema",
        );
        assert_eq!(response.len(), 1);
        assert_eq!(response[0].0, "response_composition_branch_added");

        let baseline_document: serde_yaml::Value = serde_yaml::from_str(
            "components: {schemas: {Payload: {type: object, properties: {kind: {oneOf: [{type: string}, {type: integer}]}}}}}",
        )
        .unwrap();
        let current_document: serde_yaml::Value = serde_yaml::from_str(
            "components: {schemas: {Payload: {type: object, properties: {kind: {oneOf: [{type: string}]}}}}}",
        )
        .unwrap();
        let reference: serde_yaml::Value =
            serde_yaml::from_str("{$ref: '#/components/schemas/Payload'}").unwrap();
        let referenced = super::directional_composition_issues(
            &baseline_document,
            &reference,
            &current_document,
            &reference,
            "request",
            "request.schema",
        );
        assert_eq!(referenced.len(), 1);
        assert!(referenced[0].1.contains("properties.kind.oneOf"));

        let cyclic_document: serde_yaml::Value = serde_yaml::from_str(
            "components: {schemas: {Payload: {properties: {kind: {oneOf: [{$ref: '#/components/schemas/Payload'}]}}}}}",
        )
        .unwrap();
        let cyclic = super::directional_composition_issues(
            &cyclic_document,
            &reference,
            &cyclic_document,
            &reference,
            "request",
            "request.schema",
        );
        assert!(cyclic.is_empty());
    }

    #[test]
    fn schema_composition_matches_unique_types_to_report_branch_constraint_changes() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "oneOf: [{type: string, enum: [stable, preview]}, {type: integer}]",
        )
        .unwrap();
        let request_current: serde_yaml::Value =
            serde_yaml::from_str("oneOf: [{type: string, enum: [stable]}, {type: integer}]")
                .unwrap();
        let request = super::directional_composition_issues(
            &document,
            &baseline,
            &document,
            &request_current,
            "request",
            "request.schema",
        );
        assert!(request.iter().any(|(issue, path)| {
            issue == "request_enum_narrowed" && path == "request.schema.oneOf.branch[0].enum"
        }));
        assert!(!request
            .iter()
            .any(|(issue, _)| issue == "request_composition_branch_removed"));

        let response_current: serde_yaml::Value = serde_yaml::from_str(
            "anyOf: [{type: object, properties: {kind: {type: string, enum: [stable, preview]}}}, {type: integer}]",
        )
        .unwrap();
        let response_baseline: serde_yaml::Value = serde_yaml::from_str(
            "anyOf: [{type: object, properties: {kind: {type: string, enum: [stable]}}}, {type: integer}]",
        )
        .unwrap();
        let response = super::directional_composition_issues(
            &document,
            &response_baseline,
            &document,
            &response_current,
            "response",
            "response.schema",
        );
        assert!(response.iter().any(|(issue, path)| {
            issue == "response_enum_broadened"
                && path == "response.schema.anyOf.branch[0].properties.kind.enum"
        }));
        assert!(!response
            .iter()
            .any(|(issue, _)| issue == "response_composition_branch_added"));
    }

    #[test]
    fn all_of_branch_reordering_does_not_create_composition_changes() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: object, properties: {payload: {oneOf: [{type: string}, {type: integer}]}}}, {required: [payload]}]",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{required: [payload]}, {type: object, properties: {payload: {oneOf: [{type: integer}, {type: string}]}}}]",
        )
        .unwrap();
        assert!(
            super::schema_composition_changes(&baseline, &current, "schema")
                .unwrap()
                .is_empty(),
            "{:?}",
            super::schema_composition_changes(&baseline, &current, "schema").unwrap()
        );
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        assert!(super::directional_composition_issues(
            &document, &baseline, &document, &current, "request", "schema",
        )
        .is_empty());
    }

    #[test]
    fn all_of_merges_compatible_nested_constraints_before_comparison() {
        let document: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: object, properties: {value: {type: integer, minimum: 0}}}, {properties: {value: {maximum: 10}}}]",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: object, properties: {value: {type: integer, minimum: 5}}}, {properties: {value: {maximum: 8}}}]",
        )
        .unwrap();
        let merged = super::resolve_openapi_schema(&document, &baseline).unwrap();
        let value =
            super::yaml_field(super::yaml_field(&merged, "properties").unwrap(), "value").unwrap();
        assert_eq!(
            super::yaml_field(value, "minimum").unwrap().as_i64(),
            Some(0)
        );
        assert_eq!(
            super::yaml_field(value, "maximum").unwrap().as_i64(),
            Some(10)
        );
        let issues = super::schema_change_issues(
            &baseline,
            &current,
            &document,
            &document,
            "request",
            "application/json",
        );
        assert!(issues
            .iter()
            .any(|(issue, _)| issue == "request_numeric_range_narrowed"));

        let conflicting: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: object, properties: {value: {type: integer}}}, {properties: {value: {type: string}}}]",
        )
        .unwrap();
        assert!(super::resolve_openapi_schema(&document, &conflicting).is_err());

        let compatible_numeric_types: serde_yaml::Value =
            serde_yaml::from_str("allOf: [{type: number}, {type: integer}]").unwrap();
        let merged = super::resolve_openapi_schema(&document, &compatible_numeric_types).unwrap();
        assert_eq!(super::yaml_string_field(&merged, "type"), Some("integer"));

        let impossible_numeric_range: serde_yaml::Value =
            serde_yaml::from_str("allOf: [{type: integer, minimum: 10}, {maximum: 5}]").unwrap();
        assert!(super::resolve_openapi_schema(&document, &impossible_numeric_range).is_err());

        let impossible_nested_range: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: object, properties: {value: {type: string, minLength: 8}}}, {properties: {value: {maxLength: 3}}}]",
        )
        .unwrap();
        assert!(super::resolve_openapi_schema(&document, &impossible_nested_range).is_err());

        let numeric_exclusive: serde_yaml::Value =
            serde_yaml::from_str("allOf: [{type: number, minimum: 2}, {exclusiveMinimum: 4}]")
                .unwrap();
        let merged = super::resolve_openapi_schema(&document, &numeric_exclusive).unwrap();
        let lower = super::numeric_schema_bound(&merged, true).unwrap();
        assert_eq!(lower.value, 4.0);
        assert!(lower.exclusive);

        let looser_exclusive: serde_yaml::Value =
            serde_yaml::from_str("{type: number, minimum: 10, exclusiveMinimum: 5}").unwrap();
        let lower = super::numeric_schema_bound(&looser_exclusive, true).unwrap();
        assert_eq!(lower.value, 10.0);
        assert!(!lower.exclusive);

        let impossible_exclusive_range: serde_yaml::Value = serde_yaml::from_str(
            "allOf: [{type: number, exclusiveMinimum: 4}, {exclusiveMaximum: 4}]",
        )
        .unwrap();
        assert!(super::resolve_openapi_schema(&document, &impossible_exclusive_range).is_err());

        let incompatible_const_enum: serde_yaml::Value =
            serde_yaml::from_str("allOf: [{type: string, const: stable}, {enum: [preview]}]")
                .unwrap();
        assert!(super::resolve_openapi_schema(&document, &incompatible_const_enum).is_err());
    }

    #[test]
    fn schema_compatibility_traverses_additional_property_value_schemas() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nadditionalProperties: {type: string, properties: {label: {type: string}}}\n",
        )
        .unwrap();
        let current: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nadditionalProperties: {type: integer, properties: {label: {type: integer}}}\n",
        )
        .unwrap();
        let mut issues = Vec::new();
        super::collect_nested_schema_issues(
            &baseline,
            &current,
            "response",
            "schema",
            0,
            &mut issues,
        );
        assert!(issues.iter().any(|(issue, path)| {
            issue == "response_schema_type_changed" && path == "schema.additionalProperties.type"
        }));
        assert!(issues.iter().any(|(issue, path)| {
            issue == "response_property_type_changed"
                && path == "schema.additionalProperties.properties.label.type"
        }));

        let document: serde_yaml::Value =
            serde_yaml::from_str("components:\n  schemas:\n    Value: {type: string}\n").unwrap();
        let schema: serde_yaml::Value = serde_yaml::from_str(
            "type: object\nadditionalProperties: {$ref: '#/components/schemas/Value'}\n",
        )
        .unwrap();
        let resolved = super::resolve_openapi_schema(&document, &schema).unwrap();
        assert_eq!(
            super::yaml_string_field(
                super::yaml_field(&resolved, "additionalProperties").unwrap(),
                "type"
            ),
            Some("string")
        );
    }

    #[test]
    fn schema_compatibility_detects_exclusive_numeric_bounds() {
        let cases = [
            (
                "type: object\nproperties:\n  value: {type: number, minimum: 0, exclusiveMinimum: false}\n",
                "type: object\nproperties:\n  value: {type: number, minimum: 0, exclusiveMinimum: true}\n",
                "request",
                "request_numeric_range_narrowed",
            ),
            (
                "type: object\nproperties:\n  value: {type: number, minimum: 0, exclusiveMinimum: true}\n",
                "type: object\nproperties:\n  value: {type: number, minimum: 0, exclusiveMinimum: false}\n",
                "response",
                "response_numeric_range_broadened",
            ),
            (
                "type: object\nproperties:\n  value: {type: number, exclusiveMinimum: 0}\n",
                "type: object\nproperties:\n  value: {type: number, exclusiveMinimum: 1}\n",
                "request",
                "request_numeric_range_narrowed",
            ),
            (
                "type: object\nproperties:\n  value: {type: number, exclusiveMaximum: 10}\n",
                "type: object\nproperties:\n  value: {type: number, exclusiveMaximum: 9}\n",
                "request",
                "request_numeric_range_narrowed",
            ),
        ];

        for (baseline, current, direction, expected_issue) in cases {
            let baseline: serde_yaml::Value = serde_yaml::from_str(baseline).unwrap();
            let current: serde_yaml::Value = serde_yaml::from_str(current).unwrap();
            let mut issues = Vec::new();
            super::collect_nested_schema_issues(
                &baseline,
                &current,
                direction,
                "schema",
                0,
                &mut issues,
            );
            assert!(
                issues.iter().any(|(issue, path)| {
                    issue == expected_issue && path == "schema.properties.value"
                }),
                "expected {expected_issue} for {direction} schema; got {issues:?}"
            );
        }
    }

    #[test]
    fn asyncapi_single_local_message_references_resolve_and_unsafe_refs_remain_unknown() {
        let document: serde_yaml::Value = serde_yaml::from_str(
            "asyncapi: 2.6.0\nchannels:\n  user/signedup:\n    publish:\n      operationId: signup\n      message: {$ref: '#/components/messages/UserSignedUp'}\ncomponents:\n  messages:\n    UserSignedUp: {$ref: '#/components/messages/UserSignedUpV2'}\n    UserSignedUpV2: {name: UserSignedUp, payload: {$ref: '#/components/schemas/User'}}\n  schemas:\n    User: {type: object, properties: {id: {type: string}}}\n",
        )
        .unwrap();
        let operations =
            super::asyncapi_operations(serde_yaml::to_string(&document).unwrap().as_bytes())
                .unwrap()
                .unwrap();
        let operation = operations
            .get(&("PUBLISH".into(), "user/signedup".into()))
            .unwrap();
        let payload = operation.payload.as_ref().unwrap();
        let issues = super::schema_change_issues(
            payload,
            &serde_yaml::from_str("{type: object, properties: {id: {type: integer}}}").unwrap(),
            &operation.document,
            &serde_yaml::from_str(
                "components:\n  schemas:\n    User: {type: object, properties: {id: {type: integer}}}\n",
            )
            .unwrap(),
            "response",
            "application/json",
        );
        assert!(issues.iter().any(|(issue, path)| {
            issue == "response_property_type_changed" && path.contains("properties.id.type")
        }));

        let external: serde_yaml::Value = serde_yaml::from_str(
            "asyncapi: 2.6.0\nchannels:\n  user/signedup:\n    publish:\n      operationId: signup\n      message: {$ref: 'https://example.invalid/message'}\n",
        )
        .unwrap();
        let operations =
            super::asyncapi_operations(serde_yaml::to_string(&external).unwrap().as_bytes())
                .unwrap()
                .unwrap();
        assert!(operations
            .get(&("PUBLISH".into(), "user/signedup".into()))
            .unwrap()
            .payload
            .is_none());
    }

    #[test]
    fn asyncapi_3_operations_resolve_channel_and_single_message_payload() {
        let document = r##"
asyncapi: 3.0.0
channels:
  userSignedup:
    address: user/signedup
    messages:
      UserSignedUp:
        payload:
          type: object
          properties:
            id: {type: string}
operations:
  receiveUserSignup:
    action: receive
    channel: {$ref: '#/channels/userSignedup'}
    messages:
      - {$ref: '#/channels/userSignedup/messages/UserSignedUp'}
"##;
        let operations = super::asyncapi_operations(document.as_bytes())
            .unwrap()
            .unwrap();
        let operation = operations
            .get(&("RECEIVE".into(), "userSignedup".into()))
            .unwrap();
        assert_eq!(operation.operation_id, "receiveUserSignup");
        assert_eq!(operation.route, "user/signedup");
        assert_eq!(operation.component_path, "operations.receiveUserSignup");
        assert_eq!(
            super::yaml_string_field(operation.payload.as_ref().unwrap(), "type"),
            Some("object")
        );
    }

    #[test]
    fn asyncapi_3_multi_message_and_external_payloads_remain_unknown() {
        let document = r##"
asyncapi: 3.0.0
channels:
  events:
    address: events
    messages:
      First: {payload: {type: string}}
      Second: {payload: {type: integer}}
operations:
  receiveEvents:
    action: receive
    channel: {$ref: '#/channels/events'}
    messages:
      - {$ref: '#/channels/events/messages/First'}
      - {$ref: '#/channels/events/messages/Second'}
"##;
        let operations = super::asyncapi_operations(document.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(operations.len(), 1);
        assert!(operations
            .get(&("RECEIVE".into(), "events".into()))
            .unwrap()
            .payload
            .is_none());

        let external = r##"
asyncapi: 3.0.0
channels:
  events:
    address: events
operations:
  receiveExternal:
    action: receive
    channel: {$ref: '#/channels/events'}
    messages:
      - {$ref: 'https://example.invalid/messages/External'}
"##;
        let operations = super::asyncapi_operations(external.as_bytes())
            .unwrap()
            .unwrap();
        assert!(operations
            .get(&("RECEIVE".into(), "events".into()))
            .unwrap()
            .payload
            .is_none());
    }

    #[test]
    fn local_openapi_schema_references_resolve_and_unsafe_refs_remain_unknown() {
        let document: serde_yaml::Value = serde_yaml::from_str(
            "components:\n  schemas:\n    Thing:\n      type: object\n      properties:\n        id: {type: string}\n    Recursive:\n      type: object\n      properties:\n        next: {$ref: '#/components/schemas/Recursive'}\n",
        )
        .unwrap();
        let local_ref: serde_yaml::Value =
            serde_yaml::from_str("{$ref: '#/components/schemas/Thing'}").unwrap();
        let resolved = super::resolve_openapi_schema(&document, &local_ref).unwrap();
        assert_eq!(
            super::yaml_string_field(
                super::yaml_field(&resolved, "properties")
                    .unwrap()
                    .as_mapping()
                    .unwrap()
                    .get(serde_yaml::Value::String("id".into()))
                    .unwrap(),
                "type"
            ),
            Some("string")
        );

        let external_ref: serde_yaml::Value =
            serde_yaml::from_str("{$ref: 'https://example.invalid/Thing'}").unwrap();
        assert!(super::resolve_openapi_schema(&document, &external_ref).is_err());

        let recursive_ref: serde_yaml::Value =
            serde_yaml::from_str("{$ref: '#/components/schemas/Recursive'}").unwrap();
        assert!(super::resolve_openapi_schema(&document, &recursive_ref).is_err());

        let composed: serde_yaml::Value = serde_yaml::from_str(
            "{allOf: [{$ref: '#/components/schemas/Thing'}, {required: [id]}]}",
        )
        .unwrap();
        let resolved = super::resolve_openapi_schema(&document, &composed).unwrap();
        assert!(super::yaml_field(&resolved, "required")
            .unwrap()
            .as_sequence()
            .unwrap()
            .contains(&serde_yaml::Value::String("id".into())));

        let conflicting: serde_yaml::Value =
            serde_yaml::from_str("{allOf: [{type: object}, {type: string}]}").unwrap();
        assert!(super::resolve_openapi_schema(&document, &conflicting).is_err());

        let exclusive: serde_yaml::Value =
            serde_yaml::from_str("{oneOf: [{type: string}, {type: integer}]}").unwrap();
        assert!(super::resolve_openapi_schema(&document, &exclusive).is_err());
    }

    #[test]
    fn cargo_version_compatibility_reports_matches_mismatches_and_invalid_inputs() {
        assert_eq!(
            super::cargo_version_compatibility(Some("^0.2"), Some("0.2.7")),
            "satisfied"
        );
        assert_eq!(
            super::cargo_version_compatibility(Some("^0.2"), Some("0.1.9")),
            "mismatch"
        );
        assert_eq!(
            super::cargo_version_compatibility(Some("nonsense"), Some("0.1.0")),
            "invalid_requirement"
        );
        assert_eq!(
            super::cargo_version_compatibility(Some("*"), Some("not-semver")),
            "invalid_package_version"
        );
        assert_eq!(
            super::cargo_version_compatibility(None, Some("0.1.0")),
            "not_specified"
        );
        assert_eq!(
            super::cargo_version_compatibility(Some("*"), None),
            "unknown"
        );
    }

    #[test]
    fn npm_version_compatibility_checks_supported_semver_and_preserves_unknowns() {
        assert_eq!(
            super::npm_version_compatibility(Some("1.2.3"), Some("1.2.3")),
            "satisfied"
        );
        assert_eq!(
            super::npm_version_compatibility(Some("1.2.3"), Some("1.2.4")),
            "mismatch"
        );
        assert_eq!(
            super::npm_version_compatibility(Some("^1.2.0 || ^2.0.0"), Some("2.4.1")),
            "satisfied"
        );
        assert_eq!(
            super::npm_version_compatibility(Some(">=1.2.0 <2.0.0"), Some("1.8.0")),
            "satisfied"
        );
        assert_eq!(
            super::npm_version_compatibility(Some("workspace:*"), Some("1.0.0")),
            "not_evaluated"
        );
        assert_eq!(
            super::npm_version_compatibility(Some("nonsense"), Some("1.0.0")),
            "not_evaluated"
        );
    }

    #[test]
    fn npm_alias_target_resolves_scoped_and_unscoped_aliases() {
        assert_eq!(
            super::npm_alias_target("short", "npm:@scope/real-package@^2.0.0"),
            (
                "@scope/real-package".to_owned(),
                Some("short".to_owned()),
                Some("^2.0.0".to_owned())
            )
        );
        assert_eq!(
            super::npm_alias_target("short", "npm:real-package@~1.4.0"),
            (
                "real-package".to_owned(),
                Some("short".to_owned()),
                Some("~1.4.0".to_owned())
            )
        );
        assert_eq!(
            super::npm_alias_target("real-package", "^1.4.0"),
            ("real-package".to_owned(), None, Some("^1.4.0".to_owned()))
        );
    }

    #[test]
    fn npm_dependency_map_reports_selected_local_version_compatibility() {
        let consumer = tempfile::tempdir().unwrap();
        let provider = tempfile::tempdir().unwrap();
        std::fs::write(
            consumer.path().join("package.json"),
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"short-lib":"npm:@scope/lib@^1.2.0 || ^2.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            provider.path().join("package.json"),
            r#"{"name":"@scope/lib","version":"2.4.1"}"#,
        )
        .unwrap();
        let compatible =
            super::build(&[consumer.path().to_path_buf(), provider.path().to_path_buf()]).unwrap();
        assert_eq!(compatible.dependencies.len(), 1);
        assert_eq!(compatible.dependencies[0].package, "@scope/lib");
        assert_eq!(
            compatible.dependencies[0].declared_alias.as_deref(),
            Some("short-lib")
        );
        assert_eq!(compatible.dependencies[0].match_basis, "npm_alias");
        assert_eq!(
            compatible.dependencies[0].version_compatibility,
            "satisfied"
        );

        std::fs::write(
            provider.path().join("package.json"),
            r#"{"name":"@scope/lib","version":"3.0.0"}"#,
        )
        .unwrap();
        let incompatible =
            super::build(&[consumer.path().to_path_buf(), provider.path().to_path_buf()]).unwrap();
        assert_eq!(incompatible.dependencies.len(), 1);
        assert_eq!(
            incompatible.dependencies[0].version_compatibility,
            "mismatch"
        );
        assert!(incompatible.limitations.iter().any(|limitation| {
            limitation.contains("npm dependency `@scope/lib`")
                && limitation.contains("selected local package version is `3.0.0`")
        }));
    }

    use super::*;

    use vero_core::ports::*;

    #[cfg(unix)]
    #[test]
    fn executable_resolution_preserves_symlink_name_for_rustup_dispatch() {
        use std::{
            os::unix::fs::{symlink, PermissionsExt},
            process::Command,
        };

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("rustup-proxy");
        let shim = directory.path().join("rust-analyzer");
        std::fs::write(&target, "#!/bin/sh\nprintf '%s' \"$0\"\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &shim).unwrap();

        let resolved = absolute_executable_path(&shim).unwrap();
        assert_eq!(resolved, shim);
        let output = Command::new(resolved).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            shim.to_string_lossy()
        );
    }

    fn remote_state(number: u64, state: &str, local_head_matches: bool) -> RemotePullRequestState {
        RemotePullRequestState {
            pull_request: vero_hosting::PullRequestRef {
                repository: vero_hosting::RepositoryRef {
                    host: "github.com".into(),
                    full_name: "team/service".into(),
                },
                number,
            },
            provider: "github".into(),
            state: state.into(),
            base_oid: "base".into(),
            head_oid: "head".into(),
            revision: format!("revision-{number}"),
            local_head_matches,
        }
    }

    #[test]
    fn pull_request_lifecycle_summary_distinguishes_unrefreshed_partial_mixed_and_stale() {
        assert_eq!(
            summarize_pull_request_lifecycle(0, &[]).status,
            "no_linked_pull_requests"
        );
        assert_eq!(
            summarize_pull_request_lifecycle(2, &[]).status,
            "unrefreshed"
        );
        assert_eq!(
            summarize_pull_request_lifecycle(2, &[remote_state(1, "open", true)]).status,
            "partially_refreshed"
        );
        assert_eq!(
            summarize_pull_request_lifecycle(
                2,
                &[
                    remote_state(1, "open", true),
                    remote_state(2, "merged", true)
                ]
            )
            .status,
            "mixed"
        );
        let closed = summarize_pull_request_lifecycle(
            2,
            &[
                remote_state(1, "closed", true),
                remote_state(2, "closed", true),
            ],
        );
        assert_eq!(closed.status, "all_closed");
        assert_eq!(closed.closed_count, 2);
        assert_eq!(
            summarize_pull_request_lifecycle(
                2,
                &[
                    remote_state(1, "merged", true),
                    remote_state(2, "merged", true)
                ]
            )
            .status,
            "all_merged"
        );
        let mismatch = summarize_pull_request_lifecycle(1, &[remote_state(1, "open", false)]);
        assert_eq!(mismatch.status, "local_head_mismatch");
        assert_eq!(mismatch.local_head_mismatch_count, 1);
    }

    #[test]
    fn cross_impact_rejects_source_or_inventory_mutation_after_capture() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("client.rs");
        std::fs::write(&source, "fn client() {}\n").unwrap();
        let root = directory.path().canonicalize().unwrap();
        let source = root.join("client.rs");
        let original = std::fs::read(&source).unwrap();
        let digest = format!("sha256:{}", hex(&Sha256::digest(&original)));
        let inventory = BTreeMap::from([(root.clone(), vec![source.clone()])]);
        verify_scanned_sources(&[(source.clone(), digest)]).unwrap();
        verify_source_inventory(&inventory).unwrap();

        std::fs::write(&source, "fn changed() {}\n").unwrap();
        assert!(verify_scanned_sources(&[(
            source.clone(),
            format!("sha256:{}", hex(&Sha256::digest(original)))
        )])
        .unwrap_err()
        .contains("source changed"));
        verify_source_inventory(&inventory).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            std::fs::remove_file(&source).unwrap();
            symlink(root.join("new.ts"), &source).unwrap();
            assert!(verify_scanned_sources(&[(
                source.clone(),
                format!("sha256:{}", hex(&Sha256::digest(b"fn changed() {}\n")))
            )])
            .unwrap_err()
            .contains("changed type"));
        }

        std::fs::write(directory.path().join("new.ts"), "export const x = 1;\n").unwrap();
        assert!(verify_source_inventory(&inventory)
            .unwrap_err()
            .contains("inventory changed"));
    }

    #[test]
    fn dependency_path_traversal_is_bounded_and_reports_incomplete_coverage() {
        let workspace = tempfile::tempdir().unwrap();
        let workspace_root = workspace.path().canonicalize().unwrap();
        let mut repositories = Vec::new();
        let mut roots = Vec::new();
        for level in 0..=16 {
            let width = if level == 0 { 1 } else { 2 };
            for index in 0..width {
                let id = if level == 0 {
                    "producer".to_owned()
                } else {
                    format!("node_{level}_{index}")
                };
                let root = workspace_root.join(&id);
                std::fs::create_dir_all(&root).unwrap();
                roots.push(root.clone());
                repositories.push(RepositoryEntry {
                    id,
                    root: root.display().to_string(),
                    ecosystem: "cargo".into(),
                    manifest: "Cargo.toml".into(),
                    manifest_digest: "sha256:manifest".into(),
                });
            }
        }
        let id_for = |level: usize, index: usize| {
            if level == 0 {
                "producer".to_owned()
            } else {
                format!("node_{level}_{index}")
            }
        };
        let mut dependencies = Vec::new();
        for level in 1..=16 {
            for index in 0..2 {
                for dependency in 0..if level == 1 { 1 } else { 2 } {
                    let from = id_for(level, index);
                    let to = id_for(level - 1, dependency);
                    let source_root = repositories
                        .iter()
                        .find(|repository| repository.id == from)
                        .unwrap()
                        .root
                        .clone();
                    dependencies.push(DependencyEdge {
                        from,
                        to,
                        package: "dependency".into(),
                        declared_alias: None,
                        kind: "runtime".into(),
                        declared_requirement: None,
                        version_compatibility: "unknown".into(),
                        declared_path: None,
                        match_basis: "package_name".into(),
                        evidence_path: Path::new(&source_root)
                            .join("Cargo.toml")
                            .display()
                            .to_string(),
                        evidence_digest: "sha256:edge".into(),
                        constraint_source_path: None,
                        constraint_source_digest: None,
                    });
                }
            }
        }
        let map = RepositoryMap {
            schema_version: 1,
            repositories,
            dependencies,
            limitations: Vec::new(),
            digest: "sha256:map".into(),
        };
        let impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:snapshot".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src.rs".into()],
            changed_symbols: vec!["changed".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let consumers = [
            workspace_root.join("node_10_0"),
            workspace_root.join("node_10_1"),
            workspace_root.join("node_16_0"),
            workspace_root.join("node_16_1"),
        ];
        let (paths, complete) =
            trace_dependency_paths(&impact, &map, &workspace_root.join("producer"), &consumers)
                .unwrap();
        assert!(!complete);
        assert!(!paths.is_empty());
        assert!(paths.len() <= MAX_DEPENDENCY_PATHS);
    }

    #[test]
    fn pull_request_link_parser_rejects_ambiguous_or_unsafe_identities() {
        let (repository_id, link) =
            parse_pull_request_link("service=git.example/team/service#42").unwrap();
        assert_eq!(repository_id, "service");
        assert_eq!(link.repository.host, "git.example");
        assert_eq!(link.repository.full_name, "team/service");
        assert_eq!(link.number, 42);
        for malformed in [
            "service=https://git.example/team/service#42",
            "service=git.example/team/../service#42",
            "service=git.example/team/service#0",
            "service=git.example/team/service#4x",
            "bad id=git.example/team/service#42",
        ] {
            assert!(parse_pull_request_link(malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn saved_gate_is_exposed_only_for_the_exact_snapshot_with_policy_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = directory.path().join(".vero");
        std::fs::create_dir_all(&metadata).unwrap();
        let database = metadata.join("vero.sqlite");
        let mut store = vero_store_sqlite::ReviewStore::open(&database).unwrap();
        store
            .save_review("review-1", "snapshot-current", "config", "pass", "{}", &[])
            .unwrap();
        store
            .save_gate_decision(
                "review-1",
                &vero_core::GateDecision {
                    schema_version: 1,
                    decision_id: "decision-1".into(),
                    snapshot_id: "snapshot-current".into(),
                    effective_config_digest: "config-digest".into(),
                    policy_digest: "policy-digest".into(),
                    status: vero_core::GateStatus::Pass,
                    blocking_findings: vec![],
                    verification_run_ids: vec![],
                    evidence_digest: "evidence-digest".into(),
                    reasons: vec![],
                    replay_inputs: None,
                },
            )
            .unwrap();

        let current = exact_snapshot_gate(
            directory.path(),
            "snapshot-current",
            &vero_store_sqlite::SqliteRepositoryStores,
        )
        .unwrap();
        assert_eq!(current.review_id.as_deref(), Some("review-1"));
        assert_eq!(current.saved_gate_status, "pass");
        assert_eq!(current.gate_decision_id.as_deref(), Some("decision-1"));
        assert_eq!(
            current.effective_config_digest.as_deref(),
            Some("config-digest")
        );
        assert_eq!(current.policy_digest.as_deref(), Some("policy-digest"));

        let stale = exact_snapshot_gate(
            directory.path(),
            "snapshot-changed",
            &vero_store_sqlite::SqliteRepositoryStores,
        )
        .unwrap();
        assert_eq!(stale.review_id, None);
        assert_eq!(stale.saved_gate_status, "not_reviewed");
    }

    #[test]
    fn cross_impact_reports_lexical_languages_and_go_heuristics() {
        let consumer = tempfile::tempdir().unwrap();
        std::fs::write(
            consumer.path().join("client.ts"),
            "changed_api(); // changed_api()\nconst doc = 'changed_api()';\n",
        )
        .unwrap();
        std::fs::write(
            consumer.path().join("client.py"),
            "changed_api() # changed_api()\ndoc = \"changed_api()\"\n",
        )
        .unwrap();
        std::fs::write(consumer.path().join("Client.java"), "class Client { void use() { changed_api(); } // changed_api()\nString doc = \"changed_api()\"; }\n").unwrap();
        std::fs::write(
            consumer.path().join("client.go"),
            "package client\nfunc use() { changed_api() }\n/* changed_api() */\nvar docs = `\nchanged_api()\n`\n",
        )
        .unwrap();
        let impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: Vec::new(),
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[consumer.path().into()]).unwrap();
        let report = cross_impact(
            &impact,
            &dependency_map,
            consumer.path(),
            &[consumer.path().into()],
        )
        .unwrap();
        assert!(report.coverage_complete);
        assert_eq!(report.references.len(), 4);
        assert!(report.references.iter().any(|reference| {
            reference.path == "client.py"
                && reference.certainty == "inferred_syntax"
                && reference.match_context == "python_ast_reference"
        }));
        assert!(report.references.iter().all(|reference| {
            reference.path == "client.py" || reference.certainty == "heuristic_lexical"
        }));
        assert!(report
            .references
            .iter()
            .any(|reference| reference.path == "client.ts"));
        assert!(report
            .references
            .iter()
            .any(|reference| reference.path == "client.py"));
        assert!(report
            .references
            .iter()
            .any(|reference| reference.path == "Client.java"));
        assert!(report
            .references
            .iter()
            .any(|reference| reference.path == "client.go" && reference.match_context == "call"));
        assert!(report.limitations.iter().any(|limitation| {
            limitation.contains("Go consumer references are lexical heuristics")
        }));
    }

    #[test]
    fn historical_review_schema_accepts_bounded_verification_artifact_references() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/historical-review-report-v1.schema.json"
        ))
        .unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let report = serde_json::json!({
            "schema_version": 1,
            "benchmark": "historical_review",
            "corpus_id": "local-fixture",
            "manifest_digest": digest,
            "benchmark_config_digest": format!("sha256:{}", "b".repeat(64)),
            "vero_version": "0.1.0",
            "verifier_digest": format!("sha256:{}", "c".repeat(64)),
            "case_count": 1,
            "completed_cases": 1,
            "incomplete_cases": 0,
            "label_count_completed_cases": 1,
            "matched_labels": 0,
            "missed_labels": 1,
            "finding_recall": 0.0,
            "report_path": "historical-review-report-v1.json",
            "limitations": [],
            "cases": [{
                "verification_runs": [{
                    "profile_id": "unit",
                    "state": "failed",
                    "stdout_artifact": {
                        "digest": format!("sha256:{}", "d".repeat(64)),
                        "size_bytes": 123,
                        "path": format!("cases/case-a/verification/buggy_commit/unit/stdout-{}.bin", "d".repeat(64))
                    },
                    "stderr_artifact": null
                }]
            }]
        });
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors = validator
            .iter_errors(&report)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema errors: {errors:#?}");

        let mut malformed = report;
        malformed["cases"][0]["verification_runs"][0]["stdout_artifact"]["path"] =
            serde_json::json!("../outside.bin");
        assert!(validator.iter_errors(&malformed).next().is_some());
    }

    #[test]
    fn cross_impact_extracts_changed_openapi_operations_and_matches_consumers() {
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("api")).unwrap();
        std::fs::create_dir_all(&consumer).unwrap();
        std::fs::write(
            producer.join("api/openapi.yaml"),
            "openapi: 3.0.3\ninfo: {title: Demo, version: '1'}\npaths:\n  /users/{id}:\n    get:\n      operationId: fetchUser\n",
        )
        .unwrap();
        std::fs::write(consumer.join("client.ts"), "api.fetchUser();\n").unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-openapi".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["api/openapi.yaml".into()],
            changed_symbols: Vec::new(),
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report = cross_impact(
            &producer_impact,
            &dependency_map,
            &producer,
            std::slice::from_ref(&consumer),
        )
        .unwrap();
        assert_eq!(report.schema_version, 16);
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.api_contract_changes.len(), 1);
        let operation = &report.api_contract_changes[0];
        assert_eq!(operation.method, "GET");
        assert_eq!(operation.route, "/users/{id}");
        assert_eq!(operation.operation_id, "fetchUser");
        assert!(operation.producer_digest.starts_with("sha256:"));
        assert!(report.changed_symbols.contains(&"fetchUser".into()));
        assert!(report
            .references
            .iter()
            .any(|reference| { reference.symbol == "fetchUser" && reference.path == "client.ts" }));
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/cross-repository-impact-v16.schema.json"
        ))
        .unwrap();
        let serialized = serde_json::to_value(&report).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors = validator
            .iter_errors(&serialized)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema errors: {errors:#?}");
        std::fs::write(
            producer.join("Cargo.toml"),
            "[package]\nname = \"producer\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let consumer_manifest = consumer.join("Cargo.toml");
        std::fs::write(
            &consumer_manifest,
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nproducer = { path = \"../producer\" }\n",
        )
        .unwrap();
        let stale_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        std::fs::write(
            &consumer_manifest,
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nproducer = { path = \"../producer\" }\n# changed after index capture\n",
        )
        .unwrap();
        assert!(cross_impact(
            &producer_impact,
            &stale_map,
            &producer,
            std::slice::from_ref(&consumer),
        )
        .expect_err("stale dependency map must be rejected")
        .contains("manifests changed before"));
        let contract_path = producer.join("api/openapi.yaml").canonicalize().unwrap();
        verify_producer_contracts(&[(contract_path.clone(), operation.producer_digest.clone())])
            .unwrap();
        std::fs::write(&contract_path, "openapi: changed\n").unwrap();
        assert!(
            verify_producer_contracts(&[(contract_path, operation.producer_digest.clone(),)])
                .is_err()
        );
    }

    #[test]
    fn cross_impact_resolves_go_consumer_references_to_local_producer_with_gopls() {
        if find_gopls_executable().is_none() {
            eprintln!("skipping Go semantic cross-impact fixture: gopls was not found on PATH");
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(&producer).unwrap();
        std::fs::create_dir_all(&consumer).unwrap();
        std::fs::write(
            producer.join("go.mod"),
            "module example.com/producer\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(
            producer.join("api.go"),
            "package producer\nfunc Changed() {}\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("go.mod"),
            "module example.com/consumer\n\ngo 1.23\n\nrequire example.com/producer v0.0.0\nreplace example.com/producer => ../producer\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("client.go"),
            "package client\nimport \"example.com/producer\"\nfunc Changed() {}\nfunc call() { producer.Changed(); Changed() }\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: Vec::new(),
            changed_symbols: vec!["Changed".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 1);
        assert_eq!(report.references[0].certainty, "semantic_resolved");
        assert_eq!(report.references[0].symbol, "Changed");
        assert_eq!(report.references[0].path, "client.go");
    }

    #[test]
    fn cross_impact_resolves_rust_consumer_references_with_rust_analyzer() {
        if find_rust_analyzer_executable().is_none() {
            eprintln!("skipping Rust semantic cross-impact fixture: rust-analyzer was not found");
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("Cargo.toml"),
            "[package]\nname = \"producer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(producer.join("src/lib.rs"), "pub fn changed_api() {}\n").unwrap();
        std::fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nproducer = { path = \"../producer\" }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/lib.rs"),
            "pub fn call() { producer::changed_api(); }\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-rust".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/lib.rs".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report = cross_impact(
            &producer_impact,
            &dependency_map,
            &producer,
            std::slice::from_ref(&consumer),
        )
        .unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 1, "{:?}", report.references);
        assert_eq!(
            report.references[0].certainty, "semantic_resolved",
            "{:?}",
            report.limitations
        );
        assert_eq!(report.references[0].symbol, "changed_api");
        assert_eq!(report.references[0].path, "src/lib.rs");
    }

    #[test]
    fn cross_impact_resolves_rust_calls_inside_standard_macros() {
        if find_rust_analyzer_executable().is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("Cargo.toml"),
            "[package]\nname = \"producer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            producer.join("src/lib.rs"),
            "pub fn changed_api() -> u8 { 1 }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nproducer = { path = \"../producer\" }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/lib.rs"),
            "pub fn call() -> String {\n    assert!(producer::changed_api() > 0);\n    format!(\"{}\", producer::changed_api())\n}\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-rust-macros".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/lib.rs".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report = cross_impact(
            &producer_impact,
            &dependency_map,
            &producer,
            std::slice::from_ref(&consumer),
        )
        .unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 2, "{:?}", report.references);
        for reference in &report.references {
            assert_eq!(
                reference.certainty, "semantic_resolved",
                "{reference:?} {:?}",
                report.limitations
            );
        }
    }

    #[test]
    fn cross_impact_resolves_typescript_consumers_to_changed_producer_files() {
        if find_typescript_server().is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("src/api.ts"),
            "export function changed_api() { return true; }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("tsconfig.json"),
            r#"{"compilerOptions":{"baseUrl":".","ignoreDeprecations":"6.0","paths":{"@producer/*":["../producer/src/*"]}}}"#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/client.ts"),
            "import { changed_api } from '@producer/api';\nchanged_api();\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/unrelated.ts"),
            "function changed_api() {}\nchanged_api();\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-ts".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/api.ts".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 2, "{:?}", report.references);
        assert!(report
            .references
            .iter()
            .all(|reference| reference.certainty == "semantic_resolved"
                && reference.path == "src/client.ts"));
    }

    #[test]
    fn cross_impact_resolves_typescript_project_reference_definitions() {
        if find_typescript_server().is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(producer.join("dist")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("src/index.ts"),
            "export function changed_api() { return true; }\n",
        )
        .unwrap();
        std::fs::write(
            producer.join("tsconfig.json"),
            r#"{"compilerOptions":{"composite":true,"declaration":true,"declarationMap":true,"outDir":"dist","rootDir":"src"},"include":["src/**/*.ts"]}"#,
        )
        .unwrap();
        std::fs::write(
            producer.join("dist/index.d.ts"),
            "export declare function changed_api(): boolean;\n//# sourceMappingURL=index.d.ts.map\n",
        )
        .unwrap();
        std::fs::write(
            producer.join("dist/index.d.ts.map"),
            r#"{"version":3,"file":"index.d.ts","sourceRoot":"","sources":["../src/index.ts"],"names":[],"mappings":""}"#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("tsconfig.json"),
            r#"{"compilerOptions":{"composite":true,"baseUrl":".","ignoreDeprecations":"6.0","paths":{"@producer":["../producer/dist/index.d.ts"]}},"references":[{"path":"../producer"}],"include":["src/**/*.ts"]}"#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/client.ts"),
            "import { changed_api } from '@producer';\nchanged_api();\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-ts-project-reference".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/index.ts".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 2, "{:?}", report.references);
        assert!(
            report.references.iter().all(|reference| {
                reference.certainty == "semantic_resolved" && reference.path == "src/client.ts"
            }),
            "{:?}",
            report.references
        );
    }

    #[test]
    fn cross_impact_marks_malformed_typescript_project_configuration_incomplete() {
        if find_typescript_server().is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("src/api.ts"),
            "export function changed_api() { return true; }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("tsconfig.json"),
            r#"{"compilerOptions":{"notACompilerOption":true}}"#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/client.ts"),
            "import { changed_api } from '../../producer/src/api';\nchanged_api();\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-ts-config-error".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/api.ts".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(
            !report.coverage_complete,
            "references={:?}; limitations={:?}",
            report.references, report.limitations
        );
        assert!(
            report.limitations.iter().any(|limitation| {
                limitation.contains("TypeScript project configuration errors")
            }),
            "{:?}",
            report.limitations
        );
    }

    #[test]
    fn cross_impact_marks_syntax_malformed_typescript_project_configuration_incomplete() {
        if find_typescript_server().is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("src/api.ts"),
            "export function changed_api() { return true; }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("tsconfig.json"),
            r#"{"compilerOptions":{"moduleResolution":"node""#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/client.ts"),
            "import { changed_api } from '../../producer/src/api';\nchanged_api();\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-ts-syntax-config-error".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/api.ts".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(
            !report.coverage_complete,
            "references={:?}; limitations={:?}",
            report.references, report.limitations
        );
        assert!(
            report.limitations.iter().any(|limitation| {
                limitation.contains("did not load discovered project configuration")
                    || limitation.contains("TypeScript project configuration errors")
            }),
            "{:?}",
            report.limitations
        );
    }

    #[cfg(unix)]
    #[test]
    fn typescript_definition_tool_respects_shared_time_budget() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("client.ts");
        std::fs::write(&source, "export const value = 1;\n").unwrap();
        let server = workspace.path().join("slow-tsserver");
        std::fs::write(&server, "#!/bin/sh\nsleep 5\n").unwrap();
        let mut permissions = std::fs::metadata(&server).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&server, permissions).unwrap();

        let started = Instant::now();
        let result = run_typescript_definition(
            &server,
            workspace.path(),
            &source,
            1,
            1,
            Duration::from_millis(150),
        );

        assert!(
            matches!(&result, Err(message) if message.contains("timed out")),
            "unexpected result: {result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cross_impact_resolves_javascript_projects_to_changed_producer_files() {
        if find_typescript_server().is_none() || find_executable("node").is_none() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let producer = workspace.path().join("producer");
        let consumer = workspace.path().join("consumer");
        std::fs::create_dir_all(producer.join("src")).unwrap();
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            producer.join("src/api.js"),
            "export function changed_api() { return true; }\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("tsconfig.json"),
            r#"{"compilerOptions":{"allowJs":true,"checkJs":true,"ignoreDeprecations":"6.0","moduleResolution":"node","noEmit":true},"include":["src/**/*.js"]}"#,
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/client.js"),
            "import { changed_api } from '../../producer/src/api.js';\nchanged_api();\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("src/unrelated.js"),
            "function changed_api() {}\nchanged_api();\n",
        )
        .unwrap();
        let producer_impact = crate::ImpactAssessment {
            schema_version: 3,
            snapshot_id: "sha256:producer-js".into(),
            coverage_complete: true,
            analyzers: Vec::new(),
            changed_paths: vec!["src/api.js".into()],
            changed_symbols: vec!["changed_api".into()],
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: Vec::new(),
        };
        let dependency_map = build(&[producer.clone(), consumer.clone()]).unwrap();
        let report =
            cross_impact(&producer_impact, &dependency_map, &producer, &[consumer]).unwrap();
        assert!(report.coverage_complete, "{:?}", report.limitations);
        assert_eq!(report.references.len(), 2, "{:?}", report.references);
        assert!(report.references.iter().all(|reference| {
            reference.certainty == "semantic_resolved" && reference.path == "src/client.js"
        }));
        assert!(!report.limitations.iter().any(
            |limitation| limitation.contains("TypeScript/JavaScript references remain lexical")
        ));
    }

    #[test]
    fn maps_only_manifest_declared_local_dependencies_with_provenance() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(
            a.path().join("Cargo.toml"),
            "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nprovider='*'\n",
        )
        .unwrap();
        std::fs::write(
            b.path().join("Cargo.toml"),
            "[package]\nname='provider'\nversion='0.1.0'\n",
        )
        .unwrap();
        let result = build(&[a.path().into(), b.path().into()]).unwrap();
        assert_eq!(result.repositories.len(), 2);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].from, "consumer");
        assert!(result.dependencies[0]
            .evidence_digest
            .starts_with("sha256:"));
        assert!(result.digest.starts_with("sha256:"));
    }

    #[test]
    fn maps_go_module_edges_and_omits_ambiguous_targets() {
        assert_eq!(
            go_version_compatibility(Some("v1.2.3"), "gopkg.in/provider.v2"),
            "mismatch"
        );
        assert_eq!(
            go_version_compatibility(Some("v2.3.4"), "gopkg.in/provider.v2"),
            "not_evaluated"
        );
        let consumer = tempfile::tempdir().unwrap();
        let provider_a = tempfile::tempdir().unwrap();
        let provider_b = tempfile::tempdir().unwrap();
        std::fs::write(consumer.path().join("go.mod"), "module example/consumer\n\ngo 1.23\n\nrequire (\n example/provider v1.2.3 // indirect\n)\n").unwrap();
        std::fs::write(
            provider_a.path().join("go.mod"),
            "module example/provider\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(
            provider_b.path().join("go.mod"),
            "module example/provider\n\ngo 1.22\n",
        )
        .unwrap();
        let ambiguous = build(&[
            consumer.path().into(),
            provider_a.path().into(),
            provider_b.path().into(),
        ])
        .unwrap();
        assert!(ambiguous.dependencies.is_empty());
        assert!(ambiguous
            .limitations
            .iter()
            .any(|item| item.contains("matches multiple")));
        let unique = build(&[consumer.path().into(), provider_a.path().into()]).unwrap();
        assert_eq!(unique.dependencies.len(), 1);
        assert_eq!(unique.dependencies[0].to, "example/provider");
        assert_eq!(unique.dependencies[0].kind, "runtime");

        std::fs::write(
            consumer.path().join("go.mod"),
            "module example/consumer\n\ngo 1.23\n\nrequire example/provider/v2 v1.2.3\n",
        )
        .unwrap();
        std::fs::write(
            provider_a.path().join("go.mod"),
            "module example/provider/v2\n\ngo 1.23\n",
        )
        .unwrap();
        let incompatible_major =
            build(&[consumer.path().into(), provider_a.path().into()]).unwrap();
        assert_eq!(incompatible_major.dependencies.len(), 1);
        assert_eq!(
            incompatible_major.dependencies[0].version_compatibility,
            "mismatch"
        );
        assert!(incompatible_major
            .limitations
            .iter()
            .any(|item| item.contains("definite major-version/module-path mismatches")));

        std::fs::write(
            consumer.path().join("go.mod"),
            "module example/consumer\n\ngo 1.23\n\nrequire example/provider/v2 v2.3.4\n",
        )
        .unwrap();
        let compatible_major = build(&[consumer.path().into(), provider_a.path().into()]).unwrap();
        assert_eq!(
            compatible_major.dependencies[0].version_compatibility,
            "not_evaluated"
        );

        std::fs::write(
            consumer.path().join("go.mod"),
            "module example/consumer\n\ngo 1.23\n\nrequire example/provider v1.2.3\nreplace example/provider => github.com/fork/provider v1.2.3\n",
        )
        .unwrap();
        std::fs::write(
            provider_a.path().join("go.mod"),
            "module example/provider\n\ngo 1.23\n",
        )
        .unwrap();
        std::fs::write(
            provider_b.path().join("go.mod"),
            "module github.com/fork/provider\n\ngo 1.23\n",
        )
        .unwrap();
        let remote_replacement = build(&[
            consumer.path().into(),
            provider_a.path().into(),
            provider_b.path().into(),
        ])
        .unwrap();
        assert!(remote_replacement.dependencies.is_empty());
        assert!(remote_replacement
            .limitations
            .iter()
            .any(|item| item.contains("replacement that is not a selected local filesystem path")));

        let local_provider = provider_a.path().canonicalize().unwrap();
        std::fs::write(
            consumer.path().join("go.mod"),
            format!(
                "module example/consumer\n\ngo 1.23\n\nrequire example/provider v1.2.3\nreplace example/provider => github.com/fork/provider v1.2.3\nreplace example/provider v1.2.3 => {}\n",
                local_provider.display()
            ),
        )
        .unwrap();
        let version_specific_replacement = build(&[
            consumer.path().into(),
            provider_a.path().into(),
            provider_b.path().into(),
        ])
        .unwrap();
        assert_eq!(version_specific_replacement.dependencies.len(), 1);
        assert_eq!(
            version_specific_replacement.dependencies[0].to,
            "example/provider"
        );
        assert_eq!(
            version_specific_replacement.dependencies[0].match_basis,
            "resolved_path"
        );
        assert!(!version_specific_replacement
            .limitations
            .iter()
            .any(|item| item.contains("replacement that is not a selected local filesystem path")));

        std::fs::write(
            consumer.path().join("go.mod"),
            "module example/consumer\n\ngo 1.23\n\nrequire example/provider v1.2.3\nreplace example/provider v1.2.3\n",
        )
        .unwrap();
        let malformed_replacement =
            build(&[consumer.path().into(), provider_a.path().into()]).unwrap();
        assert!(malformed_replacement.dependencies.is_empty());
        assert!(malformed_replacement
            .limitations
            .iter()
            .any(|item| item.contains("replacement that is not a selected local filesystem path")));
    }

    #[test]
    fn expands_cargo_workspace_members_and_reports_unsafe_or_unexpanded_entries() {
        let workspace = tempfile::tempdir().unwrap();
        let provider = workspace.path().join("crates/provider");
        let consumer = workspace.path().join("crates/consumer");
        std::fs::create_dir_all(&provider).unwrap();
        std::fs::create_dir_all(&consumer).unwrap();
        std::fs::write(workspace.path().join("Cargo.toml"), "[workspace]\nmembers=['crates/*', '../outside', 'unsupported/**']\nexclude=['crates/ignored']\n[workspace.dependencies]\nprovider={path='crates/provider', version='0.1.0'}\n").unwrap();
        std::fs::write(
            provider.join("Cargo.toml"),
            "[package]\nname='provider'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname='consumer'\nversion='0.1.0'\n[dependencies]\nprovider={workspace=true}\n",
        )
        .unwrap();
        let result = build(&[workspace.path().into()]).unwrap();
        assert_eq!(result.repositories.len(), 2);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].declared_requirement.as_deref(),
            Some("0.1.0")
        );
        assert_eq!(
            result.dependencies[0].declared_path.as_deref(),
            Some("crates/provider")
        );
        assert_eq!(result.dependencies[0].match_basis, "resolved_path");
        assert_eq!(
            result.dependencies[0].constraint_source_path.as_deref(),
            Some(
                workspace
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("Cargo.toml")
                    .to_str()
                    .unwrap()
            )
        );
        assert!(result.dependencies[0]
            .constraint_source_digest
            .as_deref()
            .unwrap()
            .starts_with("sha256:"));
        assert!(result
            .limitations
            .iter()
            .any(|item| item.contains("unsafe Cargo workspace member")));
        assert!(result
            .limitations
            .iter()
            .any(|item| item.contains("unsupported Cargo workspace member pattern")));
    }
}
