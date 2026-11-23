//! Gate & policy: gate evaluation and the effective configuration digest that makes decisions stale.

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateCheckResult {
    pub schema_version: u32,
    pub review_id: String,
    pub reviewed_snapshot_id: String,
    pub current_snapshot_id: String,
    pub effective_config_digest: String,
    pub status: GateStatus,
    pub decision_id: String,
    pub blocking_findings: Vec<String>,
    pub verification_run_ids: Vec<String>,
    pub evidence_digest: String,
    pub reasons: Vec<String>,
}

pub struct GateEvaluation<'a> {
    pub review_id: &'a str,
    pub reviewed_snapshot_id: &'a str,
    pub current: &'a ChangeSet,
    pub repository_root: &'a Path,
    pub reviewed_config_digest: &'a str,
    pub effective_config_digest: &'a str,
    pub config: &'a RepositoryConfig,
    pub findings: &'a [vee_core::Finding],
    pub policy_findings: Option<&'a [vee_core::Finding]>,
    pub reviewer_outcomes: &'a [ReviewerOutcome],
    pub analysis_complete: bool,
    pub verification_runs: &'a [VerificationRun],
}

/// Keep old verification results from satisfying a required profile after its
/// executable, arguments, time limits, output limits, or allowed environment
/// have changed. The command digest also includes executable bytes and digests
/// of present allowlisted environment values.
/// Map a gate decision's blocking IDs to the IDs users see. Reviewer findings are
/// deduplicated after policy evaluation, so policy-level IDs map to the visible
/// finding with the same fingerprint; analyzer finding IDs are already visible.
pub fn visible_blocking_findings(
    blocking: &[String],
    policy_findings: &[vee_core::Finding],
    visible_findings: &[vee_core::Finding],
) -> Vec<String> {
    let visible: std::collections::HashMap<_, _> = visible_findings
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding.id.as_str()))
        .collect();
    blocking
        .iter()
        .filter_map(|id| {
            if id.starts_with("analyzer:") {
                return Some(id.clone());
            }
            let finding = policy_findings.iter().find(|finding| finding.id == *id)?;
            visible
                .get(finding.fingerprint.as_str())
                .map(|id| (*id).to_owned())
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn gate_eligible_verification_runs(
    repository_root: &Path,
    snapshot_id: &str,
    config: &RepositoryConfig,
    verification_runs: &[VerificationRun],
) -> Vec<VerificationRun> {
    let expected_command_digests: std::collections::BTreeMap<_, _> = config
        .policy
        .required_verifications
        .iter()
        .filter_map(|profile_id| {
            let profile = config.verification.get(profile_id)?;
            let command_digest =
                vee_process::verification_command_digest(profile, repository_root).ok()?;
            Some((profile_id.as_str(), command_digest))
        })
        .collect();
    verification_runs
        .iter()
        .filter(|run| {
            run.snapshot_id == snapshot_id
                && expected_command_digests
                    .get(run.profile_id.as_str())
                    .is_some_and(|expected| expected == &run.command_digest)
        })
        .cloned()
        .collect()
}

impl GateCheckResult {
    pub fn from_decision(
        review_id: impl Into<String>,
        reviewed_snapshot_id: impl Into<String>,
        current_snapshot_id: impl Into<String>,
        decision: GateDecision,
    ) -> Self {
        Self {
            schema_version: GATE_CHECK_SCHEMA_VERSION,
            review_id: review_id.into(),
            reviewed_snapshot_id: reviewed_snapshot_id.into(),
            current_snapshot_id: current_snapshot_id.into(),
            effective_config_digest: decision.effective_config_digest.clone(),
            status: decision.status,
            decision_id: decision.decision_id,
            blocking_findings: decision.blocking_findings,
            verification_run_ids: decision.verification_run_ids,
            evidence_digest: decision.evidence_digest,
            reasons: decision.reasons,
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self.status {
            GateStatus::Pass => 0,
            GateStatus::Block => 1,
            GateStatus::Incomplete => 2,
        }
    }
}

pub fn evaluate_and_persist_gate(
    store: &mut dyn Repositories,
    input: GateEvaluation<'_>,
) -> Result<GateDecision, String> {
    let review_id = input.review_id;
    let decision = evaluate_gate(&*store, input)?;
    store.save_gate_decision(review_id, &decision)?;
    Ok(decision)
}

/// The gate decision for a saved review as of now, without recording it.
/// Read-only consumers (approval eligibility, review sessions) use it so a
/// verification that ran after the last `gate check` still counts.
pub fn evaluate_gate(
    store: &dyn Repositories,
    input: GateEvaluation<'_>,
) -> Result<GateDecision, String> {
    let GateEvaluation {
        review_id: _,
        reviewed_snapshot_id,
        current,
        repository_root,
        reviewed_config_digest,
        effective_config_digest,
        config,
        findings,
        policy_findings,
        reviewer_outcomes,
        analysis_complete,
        verification_runs,
    } = input;
    let mut gate_findings = policy_findings.unwrap_or(findings).to_vec();
    let gate_evidence =
        attach_source_evidence(repository_root, current, &mut gate_findings)?.evidence;
    let reviewer_policies = configured_reviewer_policies(config);
    let policy_digest = digest(&serde_json::to_vec(
        &serde_json::json!({"policy":config.policy,"reviewer_policies":reviewer_policies,"effective_config_digest":effective_config_digest}),
    ).map_err(|error| error.to_string())?);
    let mut decision = if current.digest == reviewed_snapshot_id
        && reviewed_config_digest == effective_config_digest
    {
        let required_reviewers_complete = config.policy.required_reviewers.iter().all(|required| {
            reviewer_outcomes.iter().any(|outcome| {
                outcome.reviewer_id == *required
                    && matches!(outcome.status.as_str(), "completed" | "cached")
            })
        });
        let policy = Policy {
            block_severities: config
                .policy
                .block_severities
                .iter()
                .filter_map(|value| match value.as_str() {
                    "critical" => Some(Severity::Critical),
                    "high" => Some(Severity::High),
                    "medium" => Some(Severity::Medium),
                    "low" => Some(Severity::Low),
                    "info" => Some(Severity::Info),
                    _ => None,
                })
                .collect(),
            minimum_confidence: config.policy.minimum_confidence,
            required_review_complete: config.policy.on_incomplete == "block"
                || !required_reviewers_complete,
            required_verifications: config.policy.required_verifications.clone(),
            analyzer_block_levels: sarif::analyzer_block_levels(config),
        };
        let gate_verification_runs = gate_eligible_verification_runs(
            repository_root,
            &current.digest,
            config,
            verification_runs,
        );
        let analyzer_reports =
            sarif::analyzer_reports(repository_root, current, config, &gate_verification_runs);
        vee_core::evaluate_gate_with_waivers_and_reviewer_policies(
            &current.digest,
            vee_core::GateDigests {
                effective_config_digest,
                policy_digest: &policy_digest,
            },
            &gate_findings,
            &policy,
            analysis_complete && required_reviewers_complete,
            vee_core::GateEvidence {
                verification_runs: &gate_verification_runs,
                source_evidence: &gate_evidence,
                analyzer_reports: &analyzer_reports,
            },
            vee_core::GateEvaluationOptions {
                waiver_evaluation: vee_core::WaiverEvaluation {
                    records: &store.waivers_for_snapshot(&current.digest)?,
                    evaluation_time_unix: current_unix_time()?,
                },
                reviewer_policies: &reviewer_policies,
            },
        )
    } else {
        let mut stale =
            stale_gate_decision(&current.digest, effective_config_digest, &policy_digest);
        stale.reasons = if current.digest != reviewed_snapshot_id {
            vec!["review is stale: source snapshot changed".into()]
        } else {
            vec!["review is stale: effective configuration changed".into()]
        };
        stale.evidence_digest =
            digest(&serde_json::to_vec(&stale.reasons).map_err(|error| error.to_string())?);
        stale.decision_id = digest(
            &serde_json::to_vec(&(
                "vee-gate-stale-v1",
                stale.snapshot_id.as_str(),
                stale.effective_config_digest.as_str(),
                stale.policy_digest.as_str(),
                stale.evidence_digest.as_str(),
            ))
            .map_err(|error| error.to_string())?,
        );
        stale
    };
    if let Some(policy_findings) = policy_findings {
        decision.blocking_findings =
            visible_blocking_findings(&decision.blocking_findings, policy_findings, findings);
    }
    Ok(decision)
}

pub(crate) fn severity_from_config(value: &str) -> Option<Severity> {
    match value {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

pub(crate) fn configured_reviewer_policies(
    config: &RepositoryConfig,
) -> std::collections::BTreeMap<String, vee_core::ReviewerPolicy> {
    config
        .reviewers
        .iter()
        .filter(|(_, reviewer)| !reviewer.policy.block_severities.is_empty())
        .map(|(reviewer_id, reviewer)| {
            (
                reviewer_id.clone(),
                vee_core::ReviewerPolicy {
                    block_severities: reviewer
                        .policy
                        .block_severities
                        .iter()
                        .filter_map(|value| severity_from_config(value))
                        .collect(),
                    minimum_confidence: reviewer
                        .policy
                        .minimum_confidence
                        .unwrap_or(config.policy.minimum_confidence),
                },
            )
        })
        .collect()
}

/// Digest of everything that shapes a review's configuration, including the
/// `active_approvals` (see [`active_rule_approvals`]).
pub fn effective_config_digest(
    config: &RepositoryConfig,
    root: &Path,
    active_approvals: &[vee_core::RuleApproval],
) -> Result<String, String> {
    let instruction_digests: std::collections::BTreeMap<_, _> = config
        .reviewers
        .iter()
        .map(|(id, reviewer)| {
            read_repository_file(root, Path::new(&reviewer.instructions_file))
                .map(|bytes| (id.clone(), digest(&bytes)))
                .map_err(|error| {
                    format!(
                        "reading reviewer instructions {}: {error}",
                        reviewer.instructions_file
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    let context_file_digests: std::collections::BTreeMap<_, _> = config
        .reviewers
        .iter()
        .map(|(id, reviewer)| {
            let digests = reviewer
                .context_files
                .iter()
                .map(|path| {
                    read_repository_file(root, Path::new(path))
                        .map(|bytes| (path.clone(), digest(&bytes)))
                        .map_err(|error| format!("reading reviewer context file {path}: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((id.clone(), digests))
        })
        .collect::<Result<_, String>>()?;
    let active_rule_approvals = active_approvals;
    let mut execution_config = serde_json::to_value(config).map_err(|error| error.to_string())?;
    if let Some(providers) = execution_config
        .get_mut("providers")
        .and_then(serde_json::Value::as_object_mut)
    {
        for provider in providers.values_mut() {
            if let Some(provider) = provider.as_object_mut() {
                // Pricing is an analytics-only annotation and must not stale review approval.
                provider.remove("pricing");
            }
        }
    }
    // Approval guards decide what happens after the gate, not what the
    // review or gate saw, so changing them must not make reviews stale.
    if let Some(config) = execution_config.as_object_mut() {
        config.remove("approval");
    }
    let bytes = serde_json::to_vec(&serde_json::json!({"config":execution_config,"policy":config.policy,"policy_profile":config.active_policy_profile,"instruction_digests":instruction_digests,"context_file_digests":context_file_digests,"active_rule_approvals":active_rule_approvals}))
        .map_err(|error| error.to_string())?;
    Ok(digest(&bytes))
}

pub fn effective_review_config_digest(
    config: &RepositoryConfig,
    root: &Path,
    selected_reviewers: &[String],
    active_approvals: &[vee_core::RuleApproval],
) -> Result<String, String> {
    let provider_versions = capture_provider_versions(config, root, selected_reviewers, None);
    let base = effective_review_config_digest_with_provider_versions(
        config,
        root,
        selected_reviewers,
        active_approvals,
        &provider_versions,
    )?;
    bind_work_item_digest(&base, None)
}

pub fn effective_review_config_digest_with_work_item(
    config: &RepositoryConfig,
    root: &Path,
    reviewer_ids: &[String],
    active_approvals: &[vee_core::RuleApproval],
    work_item: Option<&vee_hosting::WorkItemSnapshot>,
) -> Result<String, String> {
    if let Some(item) = work_item {
        item.validate()?;
    }
    let provider_versions = capture_provider_versions(config, root, reviewer_ids, None);
    let base = effective_review_config_digest_with_provider_versions(
        config,
        root,
        reviewer_ids,
        active_approvals,
        &provider_versions,
    )?;
    bind_work_item_digest(&base, work_item.map(|item| item.content_digest.as_str()))
}

pub(crate) fn bind_work_item_digest(
    base_digest: &str,
    work_item_digest: Option<&str>,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "base_config_digest": base_digest,
        "work_item_digest": work_item_digest,
    }))
    .map_err(|error| error.to_string())?;
    Ok(digest(&bytes))
}

pub(crate) fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub fn effective_review_config_digest_with_provider_versions(
    config: &RepositoryConfig,
    root: &Path,
    selected_reviewers: &[String],
    active_approvals: &[vee_core::RuleApproval],
    provider_versions: &std::collections::BTreeMap<String, Option<String>>,
) -> Result<String, String> {
    let config_digest = effective_config_digest(config, root, active_approvals)?;
    let provider_environment_digests =
        provider_environment_digests(config, selected_reviewers, |name| std::env::var(name).ok())?;
    let mut selected = selected_reviewers.to_vec();
    selected.sort();
    selected.dedup();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "effective_config_digest": config_digest,
        "selected_reviewers": selected,
        "provider_versions": provider_versions,
        "provider_environment_digests": provider_environment_digests,
    }))
    .map_err(|error| error.to_string())?;
    Ok(digest(&bytes))
}

pub(crate) fn provider_environment_digests<F>(
    config: &RepositoryConfig,
    selected_reviewers: &[String],
    mut lookup: F,
) -> Result<std::collections::BTreeMap<String, String>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut digests = std::collections::BTreeMap::new();
    for reviewer_id in selected_reviewers {
        let Some(reviewer) = config.reviewers.get(reviewer_id) else {
            continue;
        };
        let Some(provider) = config.providers.get(&reviewer.provider) else {
            continue;
        };
        if digests.contains_key(&reviewer.provider) {
            continue;
        }
        let environment =
            vee_core::resolve_environment_allowlist(&provider.env_allowlist, |name| lookup(name))?;
        let bytes = serde_json::to_vec(&environment).map_err(|error| error.to_string())?;
        digests.insert(reviewer.provider.clone(), digest(&bytes));
    }
    Ok(digests)
}

pub(crate) fn capture_provider_versions(
    config: &RepositoryConfig,
    root: &Path,
    selected_reviewers: &[String],
    cancellation: Option<&tokio_util::sync::CancellationToken>,
) -> std::collections::BTreeMap<String, Option<String>> {
    let mut versions = std::collections::BTreeMap::new();
    for reviewer_id in selected_reviewers {
        let Some(reviewer) = config.reviewers.get(reviewer_id) else {
            continue;
        };
        let Some(provider) = config.providers.get(&reviewer.provider) else {
            continue;
        };
        if versions.contains_key(&reviewer.provider) {
            continue;
        }
        let version = if provider.kind == vee_core::ProviderKind::CodexCli
            || provider.kind == vee_core::ProviderKind::GeminiCli
            || provider.kind == vee_core::ProviderKind::AntigravityCli
            || provider.kind == vee_core::ProviderKind::ClaudeCli
            || !provider.version_args.is_empty()
        {
            let probed = vee_core::resolve_environment_allowlist(&provider.env_allowlist, |name| {
                std::env::var(name).ok()
            })
            .and_then(|environment| {
                probe_provider_version(provider, root, &environment, cancellation)
            });
            match probed {
                Ok(version) => version,
                Err(error) => {
                    // The outcome only records version_probe_failed; say why.
                    eprintln!(
                        "vee: provider {} version probe failed: {error}",
                        reviewer.provider
                    );
                    None
                }
            }
        } else {
            None
        };
        versions.insert(reviewer.provider.clone(), version);
    }
    versions
}

#[cfg(test)]
#[path = "tests/gate.rs"]
mod tests;
