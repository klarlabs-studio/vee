//! Repository configuration: loading, user-level defaults, validation, and protected local policy.

use super::*;

/// Load repository configuration together with per-user provider defaults. Repository
/// provider entries override same-ID user entries; the merged value is validated and
/// later included in the review configuration digest.
pub fn load_repository_config(root: &Path) -> Result<RepositoryConfig, String> {
    let repository_config = root.join(".vee.yaml");
    let user_config = user_config_path();
    let force_offline = offline_override_enabled()?;
    RepositoryConfig::load_for_repository(
        &repository_config,
        root,
        user_config.as_deref(),
        force_offline,
    )
}

/// Load repository configuration merged with an explicit user provider config
/// (instead of the environment-selected one).
pub fn load_repository_config_with_user_config(
    root: &Path,
    user_config: Option<&Path>,
) -> Result<RepositoryConfig, String> {
    RepositoryConfig::load_for_repository(
        &root.join(".vee.yaml"),
        root,
        user_config.filter(|path| path.exists()),
        offline_override_enabled()?,
    )
}

/// Where the per-user provider configuration lives, whether or not it exists yet:
/// `$VEE_CONFIG`, else `$XDG_CONFIG_HOME/vee/config.yaml` (`%APPDATA%` on Windows),
/// else `~/.config/vee/config.yaml`.
pub fn user_config_location() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("VEE_CONFIG") {
        return Some(PathBuf::from(path));
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    base.map(|path| path.join("vee").join("config.yaml"))
}

pub(crate) fn user_config_path() -> Option<PathBuf> {
    user_config_location().filter(|path| path.exists())
}

/// Validate a proposed repository YAML configuration with the same schema,
/// provider defaults, and protected-policy checks used for normal commands.
pub fn validate_repository_config_yaml(
    root: &Path,
    yaml: &str,
) -> Result<RepositoryConfig, String> {
    let temporary_dir = root.join(".vee");
    std::fs::create_dir_all(&temporary_dir).map_err(|error| error.to_string())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(temporary_dir).map_err(|error| error.to_string())?;
    use std::io::Write;
    temporary
        .write_all(yaml.as_bytes())
        .map_err(|error| error.to_string())?;
    let force_offline = offline_override_enabled()?;
    let mut config = RepositoryConfig::load_for_repository(
        temporary.path(),
        root,
        user_config_path().as_deref(),
        force_offline,
    )?;
    apply_protected_policy(root, &mut config)?;
    Ok(config)
}

pub(crate) fn offline_override_enabled() -> Result<bool, String> {
    match std::env::var("VEE_OFFLINE") {
        Ok(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ) =>
        {
            Ok(true)
        }
        Ok(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ) =>
        {
            Ok(false)
        }
        Ok(_) => Err("VEE_OFFLINE must be one of: 1, true, yes, on, 0, false, no, off".into()),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(format!("read VEE_OFFLINE: {error}")),
    }
}

/// Merge a trusted local policy over repository configuration. The local policy can only
/// strengthen review requirements; it cannot relax repository policy or be overridden by it.
pub fn apply_protected_policy(root: &Path, config: &mut RepositoryConfig) -> Result<(), String> {
    let path = root.join(".vee/policy.yaml");
    if !path.exists() {
        return Ok(());
    }
    let protected: vee_core::PolicyConfig = serde_yaml::from_slice(
        &std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    if protected.minimum_confidence > 100 {
        return Err("protected policy minimum_confidence must be 0..=100".into());
    }
    for severity in &protected.block_severities {
        if !matches!(
            severity.as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ) {
            return Err(format!(
                "protected policy has unknown blocking severity {severity}"
            ));
        }
    }
    if protected.on_incomplete != "block" && protected.on_incomplete != "allow" {
        return Err("protected policy on_incomplete must be 'block' or 'allow'".into());
    }
    if protected.on_unreviewed != "block" && protected.on_unreviewed != "allow" {
        return Err("protected policy on_unreviewed must be 'block' or 'allow'".into());
    }
    for reviewer in &protected.required_reviewers {
        if !config.reviewers.contains_key(reviewer) {
            return Err(format!(
                "protected policy requires unknown reviewer {reviewer}"
            ));
        }
    }
    for profile in &protected.required_verifications {
        if !config.verification.contains_key(profile) {
            return Err(format!(
                "protected policy requires unknown verification profile {profile}"
            ));
        }
    }
    for profile in &protected.acceptance.required_verification_profiles {
        if !config.verification.contains_key(profile) {
            return Err(format!(
                "protected acceptance policy requires unknown verification profile {profile}"
            ));
        }
    }
    config
        .policy
        .required_reviewers
        .extend(protected.required_reviewers);
    config.policy.required_reviewers.sort();
    config.policy.required_reviewers.dedup();
    config
        .policy
        .required_verifications
        .extend(protected.required_verifications);
    config.policy.required_verifications.sort();
    config.policy.required_verifications.dedup();
    config
        .policy
        .block_severities
        .extend(protected.block_severities);
    config.policy.block_severities.sort();
    config.policy.block_severities.dedup();
    config.policy.minimum_confidence = config
        .policy
        .minimum_confidence
        .max(protected.minimum_confidence);
    if protected.on_incomplete == "block" {
        config.policy.on_incomplete = "block".into();
    }
    if protected.on_unreviewed == "block" {
        config.policy.on_unreviewed = "block".into();
    }
    config.policy.acceptance.require_passing_verification |=
        protected.acceptance.require_passing_verification;
    config
        .policy
        .acceptance
        .required_verification_profiles
        .extend(protected.acceptance.required_verification_profiles);
    config
        .policy
        .acceptance
        .required_verification_profiles
        .sort();
    config
        .policy
        .acceptance
        .required_verification_profiles
        .dedup();
    Ok(())
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
