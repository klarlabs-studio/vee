use serde::{Deserialize, Serialize};
pub mod acceptance;
pub mod analytics;
mod approval;
pub mod approval_report;
pub mod attestation;
pub mod ci;
mod config;
mod context_budget;
pub mod coverage;
pub mod evidence_bundle;
pub mod exploration;
pub mod failure;
pub mod finding_task;
mod focused_review;
mod gate;
pub mod hooks;
pub mod hosting;
mod impact;
pub mod imported_history;
pub mod incremental;
mod learning;
pub mod local_analytics;
pub mod operations;
pub mod ownership;
pub mod packs;
pub mod patch_sandbox;
pub mod pr_commands;
pub mod pr_description;
pub mod pr_feedback;
mod pr_fix;
pub mod proposals;
mod providers;
pub mod publication;
pub mod repository_map;
mod review;
pub mod review_progress;
mod review_standards;
mod risk;
pub mod rule_candidates;
pub mod sarif;
pub mod security_presets;
mod session;
pub mod setup;
pub mod signing;
mod source;
pub mod standards;
pub mod test_effectiveness;
pub mod test_generation;
pub mod test_proposals;
pub mod test_recommendations;
mod verification;
pub mod verification_diagnosis;
pub mod walkthrough;
pub mod work_items;

pub use approval::*;
pub use config::*;
pub use gate::*;
pub use impact::*;
pub use learning::*;
pub use providers::*;
pub use review::*;
pub use review_progress::{ReviewProgress, ReviewProgressSink, ReviewerProgress};
pub use risk::*;
pub use session::*;
pub use source::*;
pub use verification::*;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use vee_core::ports::{Repositories, RuleApprovalRepository};
use vee_core::{
    digest, stale_gate_decision, ChangeSet, Evidence, EvidenceClassification, EvidenceKind,
    EvidenceVerification, GateDecision, GateStatus, Policy, ProviderRequest, ProviderResult,
    RepositoryConfig, ReviewWrite, Severity, VerificationRun, WebhookClaim,
};

pub const GATE_CHECK_SCHEMA_VERSION: u32 = 1;
const MAX_CHANGED_LINE_DIFF_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct WebhookDispatchClaim {
    pub envelope: vee_hosting::WebhookEnvelope,
    pub claim: WebhookClaim,
}

/// Verify a hosting webhook before writing its delivery identity to durable
/// storage. Consumers should dispatch only `Acquired` claims, complete the
/// lease after their action succeeds, and release it when processing fails.
pub fn verify_and_claim_webhook_delivery<P: vee_hosting::GitHostingProvider + ?Sized>(
    provider: &P,
    store: &mut dyn Repositories,
    headers: &std::collections::BTreeMap<String, String>,
    body: &[u8],
    lease_seconds: i64,
) -> Result<WebhookDispatchClaim, String> {
    let envelope = provider
        .verify_webhook(headers, body)
        .map_err(|error| error.to_string())?;
    envelope.validate()?;
    if envelope.provider != provider.provider_id() {
        return Err("webhook provider identity does not match its verifier".into());
    }
    let now = current_unix_time()?;
    let claim = store.claim_webhook_delivery(
        &envelope.provider,
        &envelope.event_id,
        &envelope.event_type,
        envelope.delivery_attempt,
        &digest(body),
        now,
        lease_seconds,
    )?;
    Ok(WebhookDispatchClaim { envelope, claim })
}
#[cfg(test)]
const MAX_CONTEXT_FILE_BYTES: usize = 128 * 1024;
// 2: reviewer instructions moved from the CLI payload into the prompt.
const REVIEW_CACHE_CONTRACT_VERSION: u32 = 2;

pub fn current_unix_time() -> Result<i64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    i64::try_from(duration.as_secs()).map_err(|error| error.to_string())
}

pub fn capture_change_set(
    repository: &Path,
    scope: vee_git::ChangeScope,
) -> Result<ChangeSet, String> {
    vee_git::capture(repository, scope)
}

pub fn capture_current_change_set(
    repository: &Path,
    previous: &ChangeSet,
) -> Result<ChangeSet, String> {
    vee_git::capture_current(repository, previous)
}

#[cfg(test)]
mod webhook_dispatch_tests {
    use super::*;
    use std::collections::BTreeMap;
    use vee_core::ports::HostedDeliveryRepository;
    use vee_store_sqlite::ReviewStore;

    struct StubHostingProvider {
        signature_verified: bool,
    }
    impl vee_hosting::GitHostingProvider for StubHostingProvider {
        fn provider_id(&self) -> &'static str {
            "github"
        }
        fn get_pull_request(
            &self,
            _: &vee_hosting::PullRequestRef,
        ) -> Result<vee_hosting::PullRequestSnapshot, vee_hosting::HostingError> {
            unreachable!()
        }
        fn list_changed_files(
            &self,
            _: &vee_hosting::PullRequestRef,
            _: &str,
        ) -> Result<Vec<vee_hosting::PullRequestFile>, vee_hosting::HostingError> {
            unreachable!()
        }
        fn publish_review(
            &self,
            _: vee_hosting::ReviewPublication,
        ) -> Result<vee_hosting::PublicationReceipt, vee_hosting::HostingError> {
            unreachable!()
        }
        fn verify_webhook(
            &self,
            _: &BTreeMap<String, String>,
            _: &[u8],
        ) -> Result<vee_hosting::WebhookEnvelope, vee_hosting::HostingError> {
            Ok(vee_hosting::WebhookEnvelope {
                provider: "github".into(),
                event_id: "delivery-app-test".into(),
                event_type: "pull_request".into(),
                delivery_attempt: 1,
                pull_request: None,
                action: None,
                base_oid: None,
                head_oid: None,
                signature_verified: self.signature_verified,
            })
        }
    }

    #[test]
    fn application_verifies_before_durable_webhook_claim_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("webhook-app.sqlite")).unwrap();
        let headers = BTreeMap::new();
        let body = b"delivery payload";
        let valid = StubHostingProvider {
            signature_verified: true,
        };
        let first =
            verify_and_claim_webhook_delivery(&valid, &mut store, &headers, body, 30).unwrap();
        let WebhookClaim::Acquired { lease_token } = first.claim else {
            panic!("valid event should claim a lease");
        };
        store
            .complete_webhook_delivery(
                "github",
                "delivery-app-test",
                &lease_token,
                current_unix_time().unwrap(),
            )
            .unwrap();
        let repeat =
            verify_and_claim_webhook_delivery(&valid, &mut store, &headers, body, 30).unwrap();
        assert_eq!(repeat.claim, WebhookClaim::AlreadyProcessed);
        let invalid = StubHostingProvider {
            signature_verified: false,
        };
        assert!(verify_and_claim_webhook_delivery(
            &invalid,
            &mut store,
            &headers,
            b"bad payload",
            30
        )
        .is_err());
    }
}
