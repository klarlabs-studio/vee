//! Learning context: approved rules from reviewer feedback and the guidance they add to reviews.

use super::*;

/// The rule approvals currently active in `rules`; they shape reviewer guidance
/// and are bound into the effective config digest.
pub fn active_rule_approvals(
    rules: &dyn RuleApprovalRepository,
) -> Result<Vec<vero_core::RuleApproval>, String> {
    let approvals = rules.list_rule_approvals()?;
    Ok(approvals
        .into_iter()
        .filter(|approval| approval.is_active())
        .collect())
}

/// Active local approvals plus rules from pinned packs; a local approval wins
/// when both carry the same approval ID.
pub(crate) fn applicable_rule_guidance(
    active_approvals: &[vero_core::RuleApproval],
    pack_rules: &[vero_core::RuleApproval],
    files: &[vero_core::SnapshotFile],
) -> Result<Vec<vero_core::RuleApproval>, String> {
    let mut active = active_approvals.to_vec();
    for rule in pack_rules {
        if !active
            .iter()
            .any(|approval| approval.approval_id == rule.approval_id)
        {
            active.push(rule.clone());
        }
    }
    let mut matches = active
        .into_iter()
        .filter(|approval| {
            let scope = approval.scope.trim().trim_end_matches('/');
            scope == "."
                || files
                    .iter()
                    .any(|file| file.path == scope || file.path.starts_with(&format!("{scope}/")))
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
    if matches.len() > 128 {
        return Err("more than 128 active reviewer guidance approvals apply; resolve or revoke excess approvals".into());
    }
    let total_bytes = matches
        .iter()
        .map(|approval| approval.instruction.len())
        .sum::<usize>();
    if total_bytes > 64 * 1024 {
        return Err(
            "applicable approved reviewer guidance exceeds the 64 KiB context limit".into(),
        );
    }
    Ok(matches)
}

pub(crate) fn rule_feedback_label_name(label: vero_core::FindingFeedbackLabel) -> &'static str {
    match label {
        vero_core::FindingFeedbackLabel::Confirmed => "confirmed",
        vero_core::FindingFeedbackLabel::FalsePositive => "false_positive",
        vero_core::FindingFeedbackLabel::Actionable => "actionable",
        vero_core::FindingFeedbackLabel::NotActionable => "not_actionable",
    }
}
