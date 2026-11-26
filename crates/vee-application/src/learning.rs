//! Learning context: approved rules from reviewer feedback and the guidance they add to reviews.

use super::*;

/// The rule approvals currently active in `rules`; they shape reviewer guidance
/// and are bound into the effective config digest.
pub fn active_rule_approvals(
    rules: &dyn RuleApprovalRepository,
) -> Result<Vec<vee_core::RuleApproval>, String> {
    let approvals = rules.list_rule_approvals()?;
    Ok(approvals
        .into_iter()
        .filter(|approval| approval.is_active())
        .collect())
}

/// Active local approvals plus rules from pinned packs; a local approval wins
/// when both carry the same approval ID.
pub(crate) fn applicable_rule_guidance(
    active_approvals: &[vee_core::RuleApproval],
    pack_rules: &[vee_core::RuleApproval],
    files: &[vee_core::SnapshotFile],
) -> Result<Vec<vee_core::RuleApproval>, String> {
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

pub(crate) fn rule_feedback_label_name(label: vee_core::FindingFeedbackLabel) -> &'static str {
    match label {
        vee_core::FindingFeedbackLabel::Confirmed => "confirmed",
        vee_core::FindingFeedbackLabel::FalsePositive => "false_positive",
        vee_core::FindingFeedbackLabel::Actionable => "actionable",
        vee_core::FindingFeedbackLabel::NotActionable => "not_actionable",
    }
}

#[cfg(test)]
#[path = "tests/learning.rs"]
mod tests;

/// Rejected findings an approved rule must draw before Vee suspends it.
pub const NOISY_RULE_MIN_REJECTED: usize = 5;
/// The share of a rule's findings that must be rejected, in percent.
pub const NOISY_RULE_REJECTED_PERCENT: usize = 50;

/// An active rule whose findings people keep rejecting (ADR 0031).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoisyRule {
    pub approval_id: String,
    /// Distinct findings that cite the rule.
    pub attributed: usize,
    /// Of those, findings explicitly marked false positive or not actionable
    /// since the rule was approved or last restored.
    pub rejected: usize,
}

impl NoisyRule {
    pub fn reason(&self) -> String {
        format!(
            "Suspended by Vee: {} of the {} findings citing this rule were marked false positive or not actionable. Restore it with `vee rules restore {}`.",
            self.rejected, self.attributed, self.approval_id
        )
    }
}

/// The active approvals whose findings were rejected at least
/// [`NOISY_RULE_MIN_REJECTED`] times and at least
/// [`NOISY_RULE_REJECTED_PERCENT`] percent of the time. Only explicit
/// feedback counts, and only feedback given after the last restore.
pub fn noisy_rules(
    approvals: &[vee_core::RuleApproval],
    records: &[vee_core::FindingRecord],
    feedback: &[vee_core::FindingFeedback],
) -> Vec<NoisyRule> {
    use std::collections::BTreeSet;
    approvals
        .iter()
        .filter(|approval| approval.is_active())
        .filter_map(|approval| {
            let since = approval
                .events
                .iter()
                .rev()
                .find(|event| event.event == "restored")
                .map(|event| event.created_at.as_str());
            let attributed: Vec<&vee_core::FindingRecord> = records
                .iter()
                .filter(|record| {
                    record
                        .finding
                        .rule_attributions
                        .iter()
                        .any(|attribution| attribution.approval_id == approval.approval_id)
                })
                .collect();
            let ids: BTreeSet<&str> = attributed
                .iter()
                .map(|record| record.finding.id.as_str())
                .collect();
            let fingerprints: BTreeSet<&str> = attributed
                .iter()
                .map(|record| record.finding.fingerprint.as_str())
                .collect();
            let rejected: BTreeSet<&str> = feedback
                .iter()
                .filter(|item| {
                    ids.contains(item.finding_id.as_str())
                        && matches!(
                            item.label,
                            vee_core::FindingFeedbackLabel::FalsePositive
                                | vee_core::FindingFeedbackLabel::NotActionable
                        )
                        && since.is_none_or(|since| item.created_at.as_str() >= since)
                })
                .filter_map(|item| {
                    attributed
                        .iter()
                        .find(|record| record.finding.id == item.finding_id)
                        .map(|record| record.finding.fingerprint.as_str())
                })
                .collect();
            let noisy = rejected.len() >= NOISY_RULE_MIN_REJECTED
                && rejected.len() * 100 >= fingerprints.len() * NOISY_RULE_REJECTED_PERCENT;
            noisy.then(|| NoisyRule {
                approval_id: approval.approval_id.clone(),
                attributed: fingerprints.len(),
                rejected: rejected.len(),
            })
        })
        .collect()
}

/// Marks the section `vee rules export` owns in a standards file.
pub const RULES_SECTION_START: &str = "<!-- vee:rules:start -->";
pub const RULES_SECTION_END: &str = "<!-- vee:rules:end -->";

/// The active approved rules as a Markdown section (ADR 0031).
pub fn rules_section(approvals: &[vee_core::RuleApproval]) -> String {
    let mut section = format!(
        "{RULES_SECTION_START}\n## Approved review rules\n\nPeople approved these rules in Vee from repeated review feedback. `vee rules export --write` keeps this section current; edit the rules in Vee, not here.\n\n"
    );
    let active: Vec<&vee_core::RuleApproval> = approvals
        .iter()
        .filter(|approval| approval.is_active())
        .collect();
    if active.is_empty() {
        section.push_str("No rules are approved yet.\n");
    }
    for approval in active {
        let instruction = approval
            .instruction
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        section.push_str(&format!(
            "- **{}** in `{}`: {instruction} _(approved by {}; `{}`)_\n",
            approval.category.trim(),
            approval.scope.trim(),
            approval.approver,
            approval.approval_id
        ));
    }
    section.push_str(RULES_SECTION_END);
    section.push('\n');
    section
}

/// `document` with its rules section replaced by `section`, or with the
/// section appended when it has none.
pub fn with_rules_section(document: &str, section: &str) -> String {
    match (
        document.find(RULES_SECTION_START),
        document.find(RULES_SECTION_END),
    ) {
        (Some(start), Some(end)) if end > start => {
            let after = &document[end + RULES_SECTION_END.len()..];
            let after = after.strip_prefix('\n').unwrap_or(after);
            format!("{}{section}{after}", &document[..start])
        }
        _ if document.trim().is_empty() => section.to_owned(),
        _ => {
            let separator = if document.ends_with("\n\n") {
                ""
            } else if document.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            format!("{document}{separator}{section}")
        }
    }
}
