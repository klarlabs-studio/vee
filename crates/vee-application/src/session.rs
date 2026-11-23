//! Review sessions: several saved reviews read together, such as the commits
//! or branches one coding-agent session produced.
//!
//! Each change keeps its own gate, so a session never hides a failing change
//! behind passing ones, and a change that moved after its review makes the
//! session incomplete rather than passing on a stale verdict
//! (`docs/research/review-literature.md`, section 6).

use super::*;

/// Version of the review session document (`review-session-v1`).
pub const REVIEW_SESSION_SCHEMA_VERSION: u32 = 1;
/// Reviews one session may combine.
pub const MAX_SESSION_REVIEWS: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReview {
    pub review_id: String,
    pub scope: String,
    pub snapshot_id: String,
    /// The latest gate decision: `pass`, `block`, or `incomplete`.
    pub gate: String,
    /// Whether the checkout still matches the reviewed snapshot.
    pub snapshot_current: bool,
    /// Change risk, when the snapshot is current.
    pub risk_tier: Option<RiskTier>,
    /// Open findings, by severity.
    pub open_findings: std::collections::BTreeMap<String, u32>,
    pub approval_eligible: bool,
    /// Why the change does not pass, from its gate and approval stages.
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSession {
    pub schema_version: u32,
    /// `pass` only when every change passed on a current snapshot; `block`
    /// when any change blocked; otherwise `incomplete`.
    pub verdict: String,
    pub reviews: Vec<SessionReview>,
    pub open_findings: u32,
    /// Changes eligible for approval without a human.
    pub approval_eligible: u32,
}

/// One change's line in a session, from its review detail and approval.
pub fn session_review(
    review: &ReviewResult,
    findings: &[vee_core::FindingRecord],
    risk: Option<&ChangeRisk>,
    approval: &ApprovalEligibility,
) -> SessionReview {
    let mut open_findings = std::collections::BTreeMap::<String, u32>::new();
    for record in findings {
        if record.status == vee_core::FindingStatus::Open {
            let severity = match record.finding.severity {
                vee_core::Severity::Critical => "critical",
                vee_core::Severity::High => "high",
                vee_core::Severity::Medium => "medium",
                vee_core::Severity::Low => "low",
                vee_core::Severity::Info => "info",
            };
            *open_findings.entry(severity.to_owned()).or_default() += 1;
        }
    }
    let snapshot_current = approval
        .stages
        .iter()
        .any(|stage| stage.id == "snapshot" && stage.passed);
    let mut reasons: Vec<String> = Vec::new();
    if !snapshot_current {
        reasons.push("The change moved after its review.".into());
    }
    if review.gate.status != vee_core::GateStatus::Pass {
        reasons.extend(review.gate.reasons.iter().cloned());
    }
    SessionReview {
        review_id: review.review_id.clone(),
        scope: review.change_set.scope.clone(),
        snapshot_id: review.snapshot_id.clone(),
        gate: match review.gate.status {
            vee_core::GateStatus::Pass => "pass",
            vee_core::GateStatus::Block => "block",
            vee_core::GateStatus::Incomplete => "incomplete",
        }
        .into(),
        snapshot_current,
        risk_tier: risk.map(|risk| risk.tier),
        open_findings,
        approval_eligible: approval.eligible,
        reasons,
    }
}

/// Combine per-change lines into a session verdict.
pub fn review_session(reviews: Vec<SessionReview>) -> ReviewSession {
    let verdict = if reviews.iter().any(|review| review.gate == "block") {
        "block"
    } else if !reviews.is_empty()
        && reviews
            .iter()
            .all(|review| review.gate == "pass" && review.snapshot_current)
    {
        "pass"
    } else {
        "incomplete"
    };
    ReviewSession {
        schema_version: REVIEW_SESSION_SCHEMA_VERSION,
        verdict: verdict.into(),
        open_findings: reviews
            .iter()
            .flat_map(|review| review.open_findings.values())
            .sum(),
        approval_eligible: reviews
            .iter()
            .filter(|review| review.approval_eligible)
            .count() as u32,
        reviews,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(gate: &str, current: bool, eligible: bool) -> SessionReview {
        SessionReview {
            review_id: format!("rev_{gate}"),
            scope: "commit".into(),
            snapshot_id: "sha256:snap".into(),
            gate: gate.into(),
            snapshot_current: current,
            risk_tier: Some(RiskTier::Low),
            open_findings: std::collections::BTreeMap::from([("high".into(), 1)]),
            approval_eligible: eligible,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn a_session_is_only_as_good_as_its_worst_change() {
        assert_eq!(
            review_session(vec![line("pass", true, true)]).verdict,
            "pass"
        );
        let mixed = review_session(vec![line("pass", true, true), line("block", true, false)]);
        assert_eq!(mixed.verdict, "block");
        assert_eq!(mixed.open_findings, 2);
        assert_eq!(mixed.approval_eligible, 1);
        assert_eq!(
            review_session(vec![line("pass", true, true), line("pass", false, false)]).verdict,
            "incomplete",
            "a change that moved after its review cannot pass the session"
        );
        assert_eq!(review_session(Vec::new()).verdict, "incomplete");
    }
}
