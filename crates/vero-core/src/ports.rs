//! Repository ports: how application services persist and load domain state.
//!
//! Each trait covers one bounded context. Adapters (such as the SQLite store)
//! implement all of them; [`Repositories`] names that combination.

use crate::*;
use std::collections::BTreeSet;
use std::path::Path;

/// Saved reviews, their snapshot manifests, and their evidence.
pub trait ReviewRepository {
    fn get(&self, id: &str) -> Result<Option<String>, String>;

    /// Record the manifest of a snapshot that a verification ran on, so reports
    /// can reconstruct its changes without a review. Existing manifests are kept.
    fn record_snapshot_manifest(
        &mut self,
        snapshot_id: &str,
        manifest_json: &str,
    ) -> Result<(), String>;

    fn snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<String>, String>;

    fn list_reviews(&self) -> Result<Vec<ReviewSummary>, String>;

    fn save_review_with_decision(&mut self, write: ReviewWrite<'_>) -> Result<(), String>;

    fn evidence_for_review(&self, review_id: &str) -> Result<Vec<Evidence>, String>;
}

/// Consolidated findings across reviews, their lifecycle status, and human feedback on them.
pub trait FindingRepository {
    fn set_finding_status(&mut self, id: &str, change: &FindingStatusChange) -> Result<(), String>;

    fn add_finding_feedback(
        &mut self,
        finding_id: &str,
        snapshot_id: &str,
        label: FindingFeedbackLabel,
        reason: &Reason,
        reviewer: &ActorName,
    ) -> Result<FindingFeedback, String>;

    fn list_finding_feedback(&self) -> Result<Vec<FindingFeedback>, String>;

    fn finding(&self, id: &str) -> Result<Option<FindingRecord>, String>;

    fn list_findings(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
    ) -> Result<Vec<FindingRecord>, String>;

    fn list_findings_page(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<FindingRecord>, usize), String>;
}

/// Gate decisions and the waivers that can lift a blocking finding for one snapshot.
pub trait GateRepository {
    fn save_gate_decision(
        &mut self,
        review_id: &str,
        decision: &GateDecision,
    ) -> Result<(), String>;

    fn gate_decisions_for_review(&self, review_id: &str) -> Result<Vec<GateDecision>, String>;

    fn create_waiver(&mut self, waiver: &Waiver) -> Result<(), String>;

    fn waivers_for_snapshot(&self, snapshot_id: &str) -> Result<Vec<Waiver>, String>;
}

/// Verification runs bound to snapshots, with their captured output artifacts.
pub trait VerificationRepository {
    fn save_verification(&mut self, run: &VerificationRun) -> Result<(), String>;

    fn save_verification_with_artifacts(&mut self, run: &VerificationRun) -> Result<(), String>;

    fn verification_artifact(
        &self,
        run_id: &str,
        stream: &str,
    ) -> Result<Option<ArtifactReference>, String>;

    fn verification(&self, run_id: &str) -> Result<Option<VerificationRun>, String>;

    fn verifications_for_snapshot(&self, snapshot_id: &str)
        -> Result<Vec<VerificationRun>, String>;

    /// Returns local verification runs explicitly attached to a finding.
    /// These runs are distinct from snapshot-wide checks used by gate policy.
    fn verifications_for_finding(&self, finding_id: &str) -> Result<Vec<VerificationRun>, String>;

    /// Returns newest verification metadata first, plus the total row count.
    /// This query deliberately avoids deserializing payloads or reading logs.
    fn recent_verification_summaries(
        &self,
        limit: usize,
    ) -> Result<(Vec<VerificationSummary>, usize), String>;
}

/// Approved repository rules learned from feedback; revocation is append-only.
pub trait RuleApprovalRepository {
    fn create_rule_approval(&mut self, approval: &RuleApproval) -> Result<(), String>;

    fn revoke_rule_approval(
        &mut self,
        approval_id: &str,
        actor: &ActorName,
        reason: &Reason,
    ) -> Result<(), String>;

    fn list_rule_approvals(&self) -> Result<Vec<RuleApproval>, String>;
}

/// Reviewer provider responses cached under an exact request fingerprint.
pub trait ProviderResponseCache {
    /// Retrieve a successful provider response keyed by the complete request and tool identity.
    fn provider_cache_get(&self, request_key: &str) -> Result<Option<Vec<u8>>, String>;

    /// Store a validated successful response. Callers must validate the provider schema first.
    fn provider_cache_put(
        &mut self,
        request_key: &str,
        provider_version: &str,
        stdout: &[u8],
    ) -> Result<(), String>;
}

/// Idempotent, leased processing of hosted-provider webhooks and the review threads Vero published.
pub trait HostedDeliveryRepository {
    fn hosted_finding_threads(&self, target_key: &str) -> Result<BTreeSet<String>, String>;

    fn replace_hosted_finding_threads(
        &mut self,
        target_key: &str,
        fingerprints: &BTreeSet<String>,
    ) -> Result<(), String>;

    /// Atomically claim a signature-verified webhook event. A repeated event ID
    /// with different content is rejected. Expired leases can be reclaimed so
    /// a crashed worker does not permanently lose the delivery.
    #[allow(clippy::too_many_arguments)]
    fn claim_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        event_type: &str,
        delivery_attempt: u32,
        payload_digest: &str,
        now_unix: i64,
        lease_seconds: i64,
    ) -> Result<WebhookClaim, String>;

    /// Extend the processing lease only when the caller still owns it.
    fn renew_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
        now_unix: i64,
        lease_seconds: i64,
    ) -> Result<(), String>;

    /// Mark a delivery complete only for the worker that currently owns its lease.
    fn complete_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
        now_unix: i64,
    ) -> Result<(), String>;

    /// Count or remove completed webhook receipts older than a caller-selected
    /// cutoff. In-flight and retryable deliveries are never eligible.
    fn prune_processed_webhook_deliveries_before(
        &mut self,
        cutoff_unix: i64,
        apply: bool,
    ) -> Result<u64, String>;

    /// Release a failed delivery so the hosting provider can retry immediately.
    fn release_webhook_delivery(
        &mut self,
        provider: &str,
        event_id: &str,
        lease_token: &str,
    ) -> Result<(), String>;
}

/// Every repository port; what a store adapter provides to application services.
pub trait Repositories:
    ReviewRepository
    + FindingRepository
    + GateRepository
    + VerificationRepository
    + RuleApprovalRepository
    + ProviderResponseCache
    + HostedDeliveryRepository
{
}

impl<
        T: ReviewRepository
            + FindingRepository
            + GateRepository
            + VerificationRepository
            + RuleApprovalRepository
            + ProviderResponseCache
            + HostedDeliveryRepository,
    > Repositories for T
{
}

/// Opens the local store of a repository checkout, for use cases that span
/// several repositories (such as a multi-repository change package).
pub trait RepositoryStores {
    /// The store of the checkout at `root`, creating its local state on first use.
    fn open(&self, root: &Path) -> Result<Box<dyn Repositories>, String>;

    /// The store of the checkout at `root`, or `None` when it has no Vero state yet.
    fn open_existing(&self, root: &Path) -> Result<Option<Box<dyn Repositories>>, String>;
}
