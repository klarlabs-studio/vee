//! Portable policy packs.
//!
//! A pack is a directory containing `pack.yaml` and the reviewer instruction
//! files it names. Repositories commit packs (conventionally under
//! `.vee/packs/<name>/`) and pin each one in `.vee.yaml` by content digest:
//!
//! ```yaml
//! packs:
//!   - path: .vee/packs/acme-security
//!     digest: sha256:…
//!     provider: default   # provider for the pack's reviewers
//! ```
//!
//! Loading verifies the digest, then merges the pack into the repository
//! configuration. Reviewers, verification profiles, and policy profiles are added
//! (repository entries win on ID collisions). Policy merges by strictness, so a
//! repository can tighten a pack's policy but never loosen it. Approved rules
//! carry their original approval provenance.

use crate::{
    PolicyConfig, RepositoryConfig, ReviewerConfig, ReviewerPolicyConfig, RuleApproval,
    VerificationProfile,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

pub const PACK_MANIFEST: &str = "pack.yaml";
const MAX_PACK_FILES: usize = 512;
const MAX_PACK_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_PACK_PROVIDER: &str = "default";

/// A pinned pack reference in `.vee.yaml`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackReference {
    /// Repository-relative directory containing `pack.yaml`.
    pub path: String,
    /// `sha256:` content digest of the pack directory (`vee packs digest`).
    pub digest: String,
    /// Provider that runs the pack's reviewers (default `default`, the provider
    /// `vee init` configures on each machine).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// `pack.yaml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Baseline policy; repositories can only make it stricter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy_profiles: BTreeMap<String, PolicyConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reviewers: BTreeMap<String, PackReviewer>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub verification: BTreeMap<String, VerificationProfile>,
    /// Approved reviewer guidance, with the approval's provenance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleApproval>,
}

/// A reviewer in a pack. Paths are relative to the pack directory, and the
/// provider is chosen by the repository that uses the pack.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackReviewer {
    pub instructions_file: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_files: Vec<String>,
    #[serde(default = "enabled", skip_serializing_if = "is_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub policy: ReviewerPolicyConfig,
}

fn enabled() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

/// A pack loaded from disk with its verified digest.
#[derive(Clone, Debug)]
pub struct LoadedPack {
    pub reference: PackReference,
    pub manifest: PolicyPack,
}

/// Content digest of a pack directory: every regular file, sorted by relative
/// path, hashed as `path NUL length NUL bytes`. Symlinks are rejected.
pub fn pack_digest(directory: &Path) -> Result<String, String> {
    let files = pack_files(directory)?;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    for (relative, bytes) in &files {
        sha2::Digest::update(&mut hasher, relative.as_bytes());
        sha2::Digest::update(&mut hasher, [0]);
        sha2::Digest::update(&mut hasher, bytes.len().to_string().as_bytes());
        sha2::Digest::update(&mut hasher, [0]);
        sha2::Digest::update(&mut hasher, bytes);
    }
    Ok(format!("sha256:{:x}", sha2::Digest::finalize(hasher)))
}

fn pack_files(directory: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let absolute = directory.join(&relative);
        let entries = std::fs::read_dir(&absolute)
            .map_err(|error| format!("{}: {error}", absolute.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            let child = relative.join(entry.file_name());
            if kind.is_symlink() {
                return Err(format!("pack contains a symlink: {}", child.display()));
            } else if kind.is_dir() {
                pending.push(child);
            } else if kind.is_file() {
                let name = child
                    .to_str()
                    .ok_or_else(|| format!("pack path is not UTF-8: {}", child.display()))?
                    .replace('\\', "/");
                let bytes = std::fs::read(entry.path()).map_err(|error| error.to_string())?;
                total += bytes.len() as u64;
                if files.len() >= MAX_PACK_FILES || total > MAX_PACK_BYTES {
                    return Err(format!(
                        "pack exceeds {MAX_PACK_FILES} files or {MAX_PACK_BYTES} bytes"
                    ));
                }
                files.insert(name, bytes);
            } else {
                return Err(format!("pack contains a special file: {}", child.display()));
            }
        }
    }
    if !files.contains_key(PACK_MANIFEST) {
        return Err(format!("{} has no {PACK_MANIFEST}", directory.display()));
    }
    Ok(files)
}

/// Parse and validate a pack directory's manifest (without digest pinning).
pub fn read_pack(directory: &Path) -> Result<PolicyPack, String> {
    let manifest_path = directory.join(PACK_MANIFEST);
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let pack: PolicyPack = serde_yaml::from_str(&raw)
        .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    validate_pack(directory, &pack)?;
    Ok(pack)
}

fn validate_pack(directory: &Path, pack: &PolicyPack) -> Result<(), String> {
    if pack.schema_version != 1 {
        return Err(format!(
            "pack {}: unsupported schema_version {}",
            pack.name, pack.schema_version
        ));
    }
    validate_pack_name(&pack.name)?;
    if pack.version.trim().is_empty() || pack.version.len() > 64 {
        return Err(format!(
            "pack {}: version must be 1 to 64 characters",
            pack.name
        ));
    }
    for (id, reviewer) in &pack.reviewers {
        for file in std::iter::once(&reviewer.instructions_file).chain(&reviewer.context_files) {
            let relative = safe_relative(file).ok_or_else(|| {
                format!(
                    "pack {} reviewer {id}: {file} must be a relative path inside the pack",
                    pack.name
                )
            })?;
            if !directory.join(relative).is_file() {
                return Err(format!(
                    "pack {} reviewer {id}: {file} does not exist in the pack",
                    pack.name
                ));
            }
        }
    }
    for rule in &pack.rules {
        if !rule.is_active() {
            return Err(format!(
                "pack {}: rule {} must be active (got {})",
                pack.name,
                rule.approval_id,
                rule.status.as_str()
            ));
        }
    }
    Ok(())
}

/// Pack names: lowercase ASCII letters, digits, `.`, `_`, `-`, starting with a
/// letter or digit, at most 64 characters.
pub fn validate_pack_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "pack name {name:?} must be 1 to 64 lowercase letters, digits, '.', '_', or '-'"
        ))
    }
}

/// A relative path made only of normal components.
fn safe_relative(path: &str) -> Option<&Path> {
    let candidate = Path::new(path);
    (!path.is_empty()
        && candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_))))
    .then_some(candidate)
}

/// Load every referenced pack below `root`, verify its pinned digest, and merge
/// it into `config`.
pub fn apply_packs(config: &mut RepositoryConfig, root: &Path) -> Result<(), String> {
    if config.packs.is_empty() {
        return Ok(());
    }
    let mut names = BTreeSet::new();
    let mut pack_reviewers = BTreeMap::new();
    let mut pack_verification = BTreeMap::new();
    let mut pack_profiles = BTreeMap::new();
    let mut origin = BTreeMap::<String, String>::new();
    for reference in config.packs.clone() {
        let pack = load_pinned(root, &reference)?;
        let name = pack.manifest.name.clone();
        if !names.insert(name.clone()) {
            return Err(format!("pack {name} is referenced more than once"));
        }
        let provider = reference
            .provider
            .clone()
            .unwrap_or_else(|| DEFAULT_PACK_PROVIDER.to_owned());
        let base = reference.path.trim_end_matches('/');
        let mut claim = |kind: &str, id: &str| -> Result<(), String> {
            let key = format!("{kind}:{id}");
            match origin.insert(key, name.clone()) {
                Some(other) => Err(format!(
                    "{kind} {id} is defined by both packs {other} and {name}"
                )),
                None => Ok(()),
            }
        };
        for (id, reviewer) in pack.manifest.reviewers {
            claim("reviewer", &id)?;
            pack_reviewers.insert(
                id,
                ReviewerConfig {
                    provider: provider.clone(),
                    instructions_file: format!("{base}/{}", reviewer.instructions_file),
                    context_files: reviewer
                        .context_files
                        .iter()
                        .map(|file| format!("{base}/{file}"))
                        .collect(),
                    enabled: reviewer.enabled,
                    include: reviewer.include,
                    exclude: reviewer.exclude,
                    policy: reviewer.policy,
                    // Packs do not choose the provider, and the focused
                    // strategy depends on the provider kind.
                    strategy: crate::ReviewStrategy::default(),
                },
            );
        }
        for (id, profile) in pack.manifest.verification {
            claim("verification profile", &id)?;
            pack_verification.insert(id, profile);
        }
        for (id, profile) in pack.manifest.policy_profiles {
            claim("policy profile", &id)?;
            pack_profiles.insert(id, profile);
        }
        if let Some(policy) = &pack.manifest.policy {
            config.policy = strictest(&config.policy, policy);
        }
        for rule in pack.manifest.rules {
            if !config
                .pack_rules
                .iter()
                .any(|existing| existing.approval_id == rule.approval_id)
            {
                config.pack_rules.push(rule);
            }
        }
    }
    // Repository definitions win on ID collisions, like user providers.
    for (id, reviewer) in pack_reviewers {
        config.reviewers.entry(id).or_insert(reviewer);
    }
    for (id, profile) in pack_verification {
        config.verification.entry(id).or_insert(profile);
    }
    for (id, profile) in pack_profiles {
        config.policy_profiles.entry(id).or_insert(profile);
    }
    config
        .pack_rules
        .sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
    Ok(())
}

fn load_pinned(root: &Path, reference: &PackReference) -> Result<LoadedPack, String> {
    let relative = safe_relative(reference.path.trim_end_matches('/')).ok_or_else(|| {
        format!(
            "pack path {} must be a relative path inside the repository",
            reference.path
        )
    })?;
    let directory = root.join(relative);
    let actual = pack_digest(&directory)?;
    if actual != reference.digest {
        return Err(format!(
            "pack {} changed: pinned digest {} but content is {actual}; review the change, then update the pin (`vee packs digest {}`)",
            reference.path, reference.digest, reference.path
        ));
    }
    Ok(LoadedPack {
        reference: reference.clone(),
        manifest: read_pack(&directory)?,
    })
}

/// The stricter of two policies: union of required reviewers, verifications,
/// acceptance profiles, and blocking severities; the lower confidence threshold;
/// `block` on incomplete if either blocks.
pub fn strictest(repository: &PolicyConfig, pack: &PolicyConfig) -> PolicyConfig {
    let union = |left: &[String], right: &[String]| {
        let mut values: Vec<String> = left.to_vec();
        for value in right {
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
        values
    };
    let mut merged = repository.clone();
    merged.required_reviewers = union(&repository.required_reviewers, &pack.required_reviewers);
    merged.required_verifications = union(
        &repository.required_verifications,
        &pack.required_verifications,
    );
    merged.block_severities = union(&repository.block_severities, &pack.block_severities);
    merged.minimum_confidence = repository.minimum_confidence.min(pack.minimum_confidence);
    if pack.on_incomplete == "block" {
        merged.on_incomplete = "block".into();
    }
    merged.acceptance.require_passing_verification |= pack.acceptance.require_passing_verification;
    merged.acceptance.required_verification_profiles = union(
        &repository.acceptance.required_verification_profiles,
        &pack.acceptance.required_verification_profiles,
    );
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(yaml: &str) -> PolicyConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn a_repository_can_tighten_but_not_loosen_pack_policy() {
        let pack = policy(
            "required_verifications: [security]\nblock_severities: [critical]\nminimum_confidence: 70\non_incomplete: block\n",
        );
        let repository = policy(
            "required_reviewers: [correctness]\nblock_severities: [high]\nminimum_confidence: 90\non_incomplete: allow\n",
        );
        let merged = strictest(&repository, &pack);
        assert_eq!(merged.required_reviewers, ["correctness"]);
        assert_eq!(merged.required_verifications, ["security"]);
        assert_eq!(merged.block_severities, ["high", "critical"]);
        assert_eq!(merged.minimum_confidence, 70);
        assert_eq!(merged.on_incomplete, "block");
    }

    #[test]
    fn digests_cover_every_file_and_reject_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let pack = directory.path();
        std::fs::write(pack.join(PACK_MANIFEST), "schema_version: 1\n").unwrap();
        std::fs::create_dir(pack.join("reviewers")).unwrap();
        std::fs::write(pack.join("reviewers/a.md"), "one").unwrap();
        let first = pack_digest(pack).unwrap();
        assert_eq!(first, pack_digest(pack).unwrap(), "digest is deterministic");
        std::fs::write(pack.join("reviewers/a.md"), "two").unwrap();
        assert_ne!(first, pack_digest(pack).unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", pack.join("link")).unwrap();
            assert!(pack_digest(pack).unwrap_err().contains("symlink"));
        }
    }

    #[test]
    fn pack_names_and_paths_are_confined() {
        assert!(validate_pack_name("acme-security.v2").is_ok());
        for bad in ["", "Acme", "-x", "a/b", "../x", &"a".repeat(65)] {
            assert!(validate_pack_name(bad).is_err(), "{bad:?}");
        }
        assert!(safe_relative("reviewers/a.md").is_some());
        for bad in ["", "/etc/passwd", "../a.md", "a/../../b"] {
            assert!(safe_relative(bad).is_none(), "{bad:?}");
        }
    }
}
