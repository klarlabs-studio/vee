//! Self-contained gate evidence bundles: a saved review with one persisted gate
//! decision, bound together by a digest manifest, optionally signed with an
//! Ed25519 key, and verifiable offline by replaying the deterministic gate.

use crate::failure::{configuration_failure, usage_failure};
use crate::imported_history::MAX_IMPORTED_REVIEW_BYTES;
use crate::operations::Workspace;
use crate::ReviewResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::path::Path;
use vee_core::ports::Repositories;
use vee_core::GateStatus;

const BUNDLE_LIMITATIONS: [&str; 3] = [
    "The bundle proves integrity and internal consistency, not that the source or provider output is correct.",
    "Unsigned bundles do not provide cryptographic tamper protection; use sign-bundle and verify-bundle with a trusted key for authenticity.",
    "Gate replay checks deterministic policy evaluation against retained inputs; it does not rerun providers or verification commands.",
];

/// `evidence-bundle-v1`, as `vee reviews bundle` exports it (unsigned).
///
/// Digests are computed over the sorted-key JSON form, so serialize the bundle
/// through a `serde_json::Value` to reproduce the exported bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub manifest: BundleManifest,
    pub manifest_digest: String,
    pub review: ReviewResult,
    pub limitations: Vec<String>,
}

/// The identities, digests and record counts an evidence bundle commits to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub effective_config_digest: String,
    pub policy_digest: String,
    pub decision_id: String,
    pub gate_status: GateStatus,
    pub review_digest: String,
    pub finding_count: usize,
    pub evidence_count: usize,
    pub verification_count: usize,
}

/// The result of `vee reviews verify-bundle`. Bindings are present only when
/// the bundle's digests and internal references are consistent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleVerification {
    pub schema_version: u32,
    pub valid: bool,
    pub message: String,
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub bindings: Option<BundleBindings>,
}

/// What a consistent bundle binds, and whether its gate decision replays.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleBindings {
    pub signature_valid: bool,
    /// `replayed`, or `unavailable` when the bundle retains no replay inputs.
    pub replay_status: String,
    /// Whether the replayed decision equals the stored one; `None` when not replayed.
    pub replay_matches: Option<bool>,
    pub replay_message: String,
    pub review_id: String,
    pub snapshot_id: String,
    pub gate_status: String,
    pub manifest_digest: String,
}

impl BundleVerification {
    fn invalid(message: &str) -> Self {
        Self {
            schema_version: 1,
            valid: false,
            message: message.to_owned(),
            bindings: None,
        }
    }

    /// Valid bindings whose gate decision does not contradict its replay.
    pub fn passed(&self) -> bool {
        self.valid
            && self
                .bindings
                .as_ref()
                .is_none_or(|bindings| bindings.replay_matches != Some(false))
    }
}

/// The result of `vee reviews sign-bundle`: the bundle file now carries a signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBundle {
    pub path: String,
    pub algorithm: String,
    pub key_id: String,
    pub manifest_digest: String,
}

/// A saved review with its `gate` replaced by the selected persisted decision
/// (default: the latest), checked to belong to the same snapshot, configuration,
/// and replay inputs. Shared by evidence bundles and attestations.
pub fn review_with_decision(
    store: &dyn Repositories,
    id: &str,
    decision_id: Option<&str>,
) -> Result<ReviewResult> {
    let payload = store
        .get(id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("review {id} was not found"))?;
    let mut review =
        crate::deserialize_review_result(&payload).map_err(|error| anyhow::anyhow!(error))?;
    let decisions = store
        .gate_decisions_for_review(id)
        .map_err(anyhow::Error::msg)?;
    let selected = match decision_id {
        Some(wanted) => decisions
            .into_iter()
            .find(|decision| decision.decision_id == wanted)
            .ok_or_else(|| {
                usage_failure("requested gate decision was not found for this review")
            })?,
        None => decisions
            .into_iter()
            .last()
            .unwrap_or_else(|| review.gate.clone()),
    };
    if selected.snapshot_id != review.snapshot_id {
        return Err(configuration_failure("selected gate decision belongs to a different snapshot and cannot be exported with this review"));
    }
    if selected.effective_config_digest != review.effective_config_digest
        || selected.replay_inputs != review.gate.replay_inputs
    {
        return Err(configuration_failure("selected gate decision uses configuration or replay inputs not retained by the original review; export the original review decision or create a new review"));
    }
    review.effective_config_digest = selected.effective_config_digest.clone();
    review.status = match selected.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    }
    .into();
    review.gate = selected;
    Ok(review)
}

/// Bundle `review` (whose `gate` is the selected decision) with its manifest.
pub fn bundle(review: &ReviewResult) -> Result<EvidenceBundle> {
    let review_bytes = serde_json::to_vec(&serde_json::to_value(review)?)?;
    let manifest = BundleManifest {
        schema_version: 1,
        review_id: review.review_id.clone(),
        snapshot_id: review.snapshot_id.clone(),
        effective_config_digest: review.gate.effective_config_digest.clone(),
        policy_digest: review.gate.policy_digest.clone(),
        decision_id: review.gate.decision_id.clone(),
        gate_status: review.gate.status,
        review_digest: vee_core::digest(&review_bytes),
        finding_count: review.findings.len(),
        evidence_count: review.evidence.len(),
        verification_count: review.verification_runs.len(),
    };
    let manifest_digest = vee_core::digest(&serde_json::to_vec(&serde_json::to_value(&manifest)?)?);
    Ok(EvidenceBundle {
        schema_version: 1,
        manifest,
        manifest_digest,
        review: review.clone(),
        limitations: BUNDLE_LIMITATIONS.map(str::to_owned).to_vec(),
    })
}

/// `vee reviews bundle`: the evidence bundle for a saved review and decision.
pub fn export_bundle(
    workspace: &Workspace,
    review_id: &str,
    decision_id: Option<&str>,
) -> Result<EvidenceBundle> {
    let store = workspace.store()?;
    let review = review_with_decision(store.as_ref(), review_id, decision_id)?;
    let bundle = bundle(&review)?;
    let bytes = serde_json::to_vec(&serde_json::to_value(&bundle)?)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "evidence bundle exceeds 10 MiB and cannot be verified by Vee"
    );
    Ok(bundle)
}

/// Read at most the import limit from `path`, failing when the file is larger.
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening evidence bundle {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading evidence bundle {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "evidence bundle exceeds 10 MiB"
    );
    Ok(bytes)
}

/// `vee reviews verify-bundle`: verify the bundle file at `path`.
pub fn verify_file(path: &Path, public_key: Option<&Path>) -> Result<BundleVerification> {
    let bytes = read_bounded(path)?;
    let bundle: Value =
        serde_json::from_slice(&bytes).context("evidence bundle is not valid JSON")?;
    Ok(verify(&bundle, public_key))
}

/// `vee reviews sign-bundle`: sign a valid, unsigned bundle file in place.
pub fn sign_file(path: &Path, private_key: &Path, key_id: &str) -> Result<SignedBundle> {
    if key_id.trim().is_empty() {
        return Err(usage_failure("--key-id cannot be empty"));
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("reading evidence bundle {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_IMPORTED_REVIEW_BYTES,
        "evidence bundle exceeds 10 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading evidence bundle")?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "evidence bundle exceeds 10 MiB"
    );
    let mut bundle: Value =
        serde_json::from_slice(&bytes).context("evidence bundle is not valid JSON")?;
    if !verify(&bundle, None).passed() {
        return Err(configuration_failure(
            "cannot sign an invalid evidence bundle",
        ));
    }
    if bundle.get("signature").is_some() {
        return Err(usage_failure(
            "bundle is already signed; export a fresh bundle to create another signature",
        ));
    }
    let key = crate::signing::load_private_key(private_key)?;
    let digest = bundle["manifest_digest"]
        .as_str()
        .ok_or_else(|| configuration_failure("bundle manifest digest is missing"))?
        .to_owned();
    let signature = key.sign(digest.as_bytes());
    bundle["signature"] = serde_json::json!({
        "algorithm": "ed25519",
        "key_id": key_id,
        "signature": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.as_ref()),
    });
    let mut output = serde_json::to_vec_pretty(&bundle)?;
    output.push(b'\n');
    anyhow::ensure!(
        output.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "signed evidence bundle exceeds 10 MiB and cannot be verified by Vee"
    );
    std::fs::write(path, output)
        .with_context(|| format!("writing signed evidence bundle {}", path.display()))?;
    Ok(SignedBundle {
        path: path.display().to_string(),
        algorithm: "ed25519".into(),
        key_id: key_id.to_owned(),
        manifest_digest: digest,
    })
}

/// Check a bundle's digests, internal bindings and (with a key) its signature,
/// then replay its gate decision from the retained inputs.
pub fn verify(bundle: &Value, public_key_path: Option<&Path>) -> BundleVerification {
    let invalid = BundleVerification::invalid;
    if bundle["schema_version"] != 1 {
        return invalid("unsupported evidence bundle schema version");
    }
    let Some(manifest) = bundle.get("manifest") else {
        return invalid("bundle manifest is missing");
    };
    let Some(review) = bundle.get("review") else {
        return invalid("bundled review is missing");
    };
    if !manifest.is_object() || !review.is_object() {
        return invalid("bundle manifest and review must be JSON objects");
    }
    let text = |key: &str| manifest.get(key).and_then(Value::as_str);
    if [
        "review_id",
        "snapshot_id",
        "effective_config_digest",
        "policy_digest",
        "decision_id",
        "gate_status",
        "review_digest",
    ]
    .into_iter()
    .any(|key| text(key).is_none())
    {
        return invalid("bundle manifest is missing a required identity or digest field");
    }
    if ["finding_count", "evidence_count", "verification_count"]
        .into_iter()
        .any(|key| manifest.get(key).and_then(Value::as_u64).is_none())
    {
        return invalid("bundle manifest is missing a required record count");
    }
    let Ok(decoded) = serde_json::from_value::<ReviewResult>(review.clone()) else {
        return invalid("bundled review does not match the Vee review contract");
    };
    let review_snapshot = review["snapshot_id"].as_str();
    if review_snapshot.is_none()
        || review["change_set"]["digest"].as_str() != review_snapshot
        || review["gate"]["snapshot_id"].as_str() != review_snapshot
    {
        return invalid("review, change set, and gate must reference the same snapshot");
    }
    let Ok(manifest_bytes) = serde_json::to_vec(manifest) else {
        return invalid("manifest could not be canonicalized");
    };
    if bundle["manifest_digest"].as_str() != Some(vee_core::digest(&manifest_bytes).as_str()) {
        return invalid("manifest digest does not match");
    }
    let Ok(review_bytes) = serde_json::to_vec(review) else {
        return invalid("review could not be canonicalized");
    };
    if text("review_digest") != Some(vee_core::digest(&review_bytes).as_str()) {
        return invalid("review digest does not match");
    }
    for (manifest_key, review_value) in [
        ("review_id", &review["review_id"]),
        ("snapshot_id", &review["snapshot_id"]),
        (
            "effective_config_digest",
            &review["effective_config_digest"],
        ),
        ("policy_digest", &review["gate"]["policy_digest"]),
        ("decision_id", &review["gate"]["decision_id"]),
        ("gate_status", &review["gate"]["status"]),
    ] {
        if &manifest[manifest_key] != review_value {
            return invalid("manifest and review identity fields do not agree");
        }
    }
    for (manifest_key, review_key) in [
        ("finding_count", "findings"),
        ("evidence_count", "evidence"),
        ("verification_count", "verification_runs"),
    ] {
        if manifest[manifest_key].as_u64()
            != review[review_key]
                .as_array()
                .map(|values| values.len() as u64)
        {
            return invalid("manifest record counts do not agree with bundled review");
        }
    }
    let signature_valid = match (bundle.get("signature"), public_key_path) {
        (Some(signature), Some(path)) => {
            if let Err(message) = verify_signature(bundle, signature, path) {
                return invalid(message);
            }
            true
        }
        (Some(_), None) => {
            return invalid("bundle is signed; provide --public-key to verify its signer")
        }
        (None, Some(_)) => return invalid("bundle has no signature"),
        (None, None) => false,
    };
    let replay = replay_gate(&decoded);
    let manifest_text = |key: &str| text(key).unwrap_or_default().to_owned();
    BundleVerification {
        schema_version: 1,
        valid: true,
        message: if signature_valid {
            "bundle digests and signature are valid; signer trust is determined by the supplied public key"
        } else {
            "bundle internal bindings are consistent but it is unsigned; this is not cryptographic tamper protection"
        }
        .to_owned(),
        bindings: Some(BundleBindings {
            signature_valid,
            replay_status: replay.status.to_owned(),
            replay_matches: replay.matches,
            replay_message: replay.message,
            review_id: manifest_text("review_id"),
            snapshot_id: manifest_text("snapshot_id"),
            gate_status: manifest_text("gate_status"),
            manifest_digest: bundle["manifest_digest"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        }),
    }
}

fn verify_signature(
    bundle: &Value,
    signature: &Value,
    public_key: &Path,
) -> Result<(), &'static str> {
    let key = match std::fs::read(public_key) {
        Ok(value) if value.len() == 32 => value,
        _ => return Err("Ed25519 public key must be a readable raw 32-byte key"),
    };
    let encoded = signature["signature"]
        .as_str()
        .ok_or("bundle signature is malformed")?;
    let signature_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| "bundle signature is not valid base64")?;
    let message = bundle["manifest_digest"]
        .as_str()
        .ok_or("manifest digest is missing")?
        .as_bytes();
    if signature["algorithm"] != "ed25519" {
        return Err("unsupported bundle signature algorithm");
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message, &signature_bytes)
        .map_err(|_| "bundle signature verification failed")
}

struct Replay {
    status: &'static str,
    matches: Option<bool>,
    message: String,
}

/// Re-evaluate the gate from the decision's retained deterministic inputs.
fn replay_gate(review: &ReviewResult) -> Replay {
    let unavailable = |message: &str| Replay {
        status: "unavailable",
        matches: None,
        message: message.to_owned(),
    };
    let Some(inputs) = review.gate.replay_inputs.as_ref() else {
        return unavailable("bundle does not contain retained deterministic gate inputs");
    };
    if inputs.schema_version != 1 {
        return unavailable("unsupported retained gate replay schema");
    }
    let findings = review
        .policy_findings
        .as_deref()
        .unwrap_or(&review.findings);
    let mut replayed = vee_core::evaluate_gate_with_waivers_and_reviewer_policies(
        &review.snapshot_id,
        vee_core::GateDigests {
            effective_config_digest: &review.effective_config_digest,
            policy_digest: &review.gate.policy_digest,
        },
        findings,
        &inputs.policy,
        inputs.complete,
        vee_core::GateEvidence {
            verification_runs: &inputs.verification_runs,
            source_evidence: &inputs.evidence,
            analyzer_reports: &inputs.analyzer_reports,
        },
        vee_core::GateEvaluationOptions {
            waiver_evaluation: vee_core::WaiverEvaluation {
                records: &inputs.waivers,
                evaluation_time_unix: inputs.evaluation_time_unix,
            },
            reviewer_policies: &inputs.reviewer_policies,
        },
    );
    replayed.blocking_findings =
        crate::visible_blocking_findings(&replayed.blocking_findings, findings, &review.findings);
    let matches = replayed == review.gate;
    Replay {
        status: "replayed",
        matches: Some(matches),
        message: if matches {
            "deterministic gate replay matches the stored decision"
        } else {
            "replayed gate decision differs from the stored decision"
        }
        .to_owned(),
    }
}
