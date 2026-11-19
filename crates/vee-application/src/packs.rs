//! Policy pack operations: export a repository's policy as a pack, add (pin) a
//! pack to a repository, list pinned packs, and compute pack digests.
//! The pack format and merge rules live in `vee_core::packs`.

use crate::failure::usage_failure;
use crate::operations::Workspace;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use vee_core::packs::{self, PackReviewer, PolicyPack, PACK_MANIFEST};

/// Where `vee packs add` installs packs inside a repository.
pub const PACKS_DIRECTORY: &str = ".vee/packs";

/// `pack-summary-v1`: the result of exporting or adding a pack.
#[derive(Debug, Serialize)]
pub struct PackSummary {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub path: String,
    pub digest: String,
    pub reviewers: Vec<String>,
    pub verification_profiles: Vec<String>,
    pub policy_profiles: Vec<String>,
    pub rules: usize,
    pub includes_policy: bool,
    /// Whether `.vee.yaml` now pins this digest (add only).
    pub pinned: bool,
    pub warnings: Vec<String>,
}

/// `packs-list-v1`.
#[derive(Debug, Serialize)]
pub struct PackList {
    pub schema_version: u32,
    pub packs: Vec<PinnedPack>,
}

#[derive(Debug, Serialize)]
pub struct PinnedPack {
    pub path: String,
    pub pinned_digest: String,
    pub provider: String,
    /// `ok`, `changed` (content differs from the pin), or `invalid`.
    pub status: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub problem: Option<String>,
}

pub struct ExportRequest<'a> {
    pub destination: &'a Path,
    pub name: &'a str,
    pub version: &'a str,
    pub description: Option<&'a str>,
    /// Reviewers to include; empty means all configured reviewers.
    pub reviewers: &'a [String],
    /// Verification profiles to include. Commands are repository-specific, so
    /// none are exported unless named.
    pub verification: &'a [String],
    pub include_policy: bool,
    pub include_rules: bool,
}

/// Write the repository's reviewers, policy, policy profiles, selected
/// verification profiles, and active approved rules as a pack directory.
pub fn export(workspace: &Workspace, request: ExportRequest<'_>) -> Result<PackSummary> {
    packs::validate_pack_name(request.name).map_err(usage_failure)?;
    if request.version.trim().is_empty() || request.version.len() > 64 {
        return Err(usage_failure("--version must be 1 to 64 characters"));
    }
    let destination = request.destination;
    if destination.exists()
        && std::fs::read_dir(destination)
            .with_context(|| format!("reading {}", destination.display()))?
            .next()
            .is_some()
    {
        return Err(usage_failure(format!(
            "{} already exists and is not empty",
            destination.display()
        )));
    }
    let config = workspace.effective_config(None)?;
    let root = workspace.root();
    for id in request.reviewers {
        if !config.reviewers.contains_key(id) {
            return Err(usage_failure(format!("unknown reviewer {id}")));
        }
    }
    for id in request.verification {
        if !config.verification.contains_key(id) {
            return Err(usage_failure(format!("unknown verification profile {id}")));
        }
    }
    std::fs::create_dir_all(destination.join("reviewers"))
        .with_context(|| format!("creating {}", destination.display()))?;

    let mut reviewers = std::collections::BTreeMap::new();
    for (id, reviewer) in &config.reviewers {
        if !request.reviewers.is_empty() && !request.reviewers.contains(id) {
            continue;
        }
        let instructions_file = format!("reviewers/{id}.md");
        copy_repository_file(
            root,
            &reviewer.instructions_file,
            &destination.join(&instructions_file),
        )?;
        let mut context_files = Vec::new();
        for (index, file) in reviewer.context_files.iter().enumerate() {
            let name = Path::new(file)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("context");
            let packed = format!("reviewers/{id}.context/{index}-{name}");
            copy_repository_file(root, file, &destination.join(&packed))?;
            context_files.push(packed);
        }
        reviewers.insert(
            id.clone(),
            PackReviewer {
                instructions_file,
                context_files,
                enabled: reviewer.enabled,
                include: reviewer.include.clone(),
                exclude: reviewer.exclude.clone(),
                policy: reviewer.policy.clone(),
            },
        );
    }
    let verification = config
        .verification
        .iter()
        .filter(|(id, _)| request.verification.contains(id))
        .map(|(id, profile)| (id.clone(), profile.clone()))
        .collect();
    let rules = if request.include_rules {
        let mut rules: Vec<_> = crate::operations::list_rule_approvals(workspace)?
            .into_iter()
            .filter(|approval| approval.is_active())
            .collect();
        for rule in &config.pack_rules {
            if !rules
                .iter()
                .any(|existing| existing.approval_id == rule.approval_id)
            {
                rules.push(rule.clone());
            }
        }
        rules.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
        rules
    } else {
        Vec::new()
    };
    let pack = PolicyPack {
        schema_version: 1,
        name: request.name.to_owned(),
        version: request.version.to_owned(),
        description: request.description.map(str::to_owned),
        policy: request.include_policy.then(|| config.policy.clone()),
        policy_profiles: config.policy_profiles.clone(),
        reviewers,
        verification,
        rules,
    };
    let manifest = format!(
        "# Vee policy pack. Pin it in .vee.yaml with `vee packs add <directory>`.\n{}",
        serde_yaml::to_string(&pack).context("serializing pack.yaml")?
    );
    std::fs::write(destination.join(PACK_MANIFEST), manifest)
        .with_context(|| format!("writing {}", destination.display()))?;
    // Validate what was written exactly as consumers will read it.
    packs::read_pack(destination).map_err(anyhow::Error::msg)?;
    summarize(
        &pack,
        destination.display().to_string(),
        destination,
        false,
        Vec::new(),
    )
}

fn copy_repository_file(root: &Path, relative: &str, destination: &Path) -> Result<()> {
    let bytes = crate::read_repository_file(root, Path::new(relative))
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("reading {relative}"))?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(destination, bytes).with_context(|| format!("writing {}", destination.display()))
}

fn summarize(
    pack: &PolicyPack,
    path: String,
    directory: &Path,
    pinned: bool,
    warnings: Vec<String>,
) -> Result<PackSummary> {
    Ok(PackSummary {
        schema_version: 1,
        name: pack.name.clone(),
        version: pack.version.clone(),
        path,
        digest: packs::pack_digest(directory).map_err(anyhow::Error::msg)?,
        reviewers: pack.reviewers.keys().cloned().collect(),
        verification_profiles: pack.verification.keys().cloned().collect(),
        policy_profiles: pack.policy_profiles.keys().cloned().collect(),
        rules: pack.rules.len(),
        includes_policy: pack.policy.is_some(),
        pinned,
        warnings,
    })
}

/// Copy a pack into `.vee/packs/<name>/` and pin its digest in `.vee.yaml`.
/// Re-adding identical content is a no-op; different content for an installed
/// pack requires `replace` (an upgrade), which re-pins the new digest.
pub fn add(
    workspace: &Workspace,
    source: &Path,
    provider: Option<&str>,
    replace: bool,
) -> Result<PackSummary> {
    let pack = packs::read_pack(source).map_err(usage_failure)?;
    let source_digest = packs::pack_digest(source).map_err(usage_failure)?;
    let root = workspace.root();
    let relative = format!("{PACKS_DIRECTORY}/{}", pack.name);
    let installed = root.join(&relative);
    let same_location =
        std::fs::canonicalize(source).ok() == std::fs::canonicalize(&installed).ok();
    if installed.exists() && !same_location {
        let installed_digest = packs::pack_digest(&installed).ok();
        if installed_digest.as_deref() != Some(source_digest.as_str()) {
            if !replace {
                return Err(usage_failure(format!(
                    "{relative} already holds different content; pass --replace to upgrade it"
                )));
            }
            std::fs::remove_dir_all(&installed)
                .with_context(|| format!("removing {}", installed.display()))?;
        }
    }
    if !installed.exists() {
        copy_directory(source, &installed)?;
    }
    let digest = packs::pack_digest(&installed).map_err(anyhow::Error::msg)?;
    let config_path = root.join(".vee.yaml");
    let yaml = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let pinned_yaml = pin(&yaml, &relative, &digest, provider).map_err(usage_failure)?;
    // Validate the pinned configuration before writing it.
    crate::validate_repository_config_yaml(root, &pinned_yaml).map_err(|error| {
        usage_failure(format!("the pack does not fit this repository: {error}"))
    })?;
    std::fs::write(&config_path, pinned_yaml)
        .with_context(|| format!("writing {}", config_path.display()))?;
    let mut warnings = Vec::new();
    if is_git_ignored(root, &relative) {
        warnings.push(format!(
            "{relative} is ignored by git; commit it (for example add `!{PACKS_DIRECTORY}/` to .gitignore) or teammates will not get the pack"
        ));
    }
    summarize(&pack, relative, &installed, true, warnings)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else {
            anyhow::bail!(
                "pack contains a symlink or special file: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn is_git_ignored(root: &Path, relative: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "check-ignore",
            "-q",
            "--",
            &format!("{relative}/{PACK_MANIFEST}"),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

/// Insert or update the pin for `path` in `.vee.yaml` text, preserving the rest
/// of the file (comments included). Supports a block-style top-level `packs:`
/// list, an empty flow list, or no `packs` key.
pub fn pin(yaml: &str, path: &str, digest: &str, provider: Option<&str>) -> Result<String, String> {
    let entry = |indent: &str| {
        let mut text = format!("{indent}- path: {path}\n{indent}  digest: {digest}\n");
        if let Some(provider) = provider {
            text.push_str(&format!("{indent}  provider: {provider}\n"));
        }
        text
    };
    let lines: Vec<&str> = yaml.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.starts_with("packs:") && !line.starts_with(' '));
    let Some(header) = header else {
        let mut out = yaml.to_owned();
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str("packs:\n");
        out.push_str(&entry("  "));
        return Ok(out);
    };
    let rest = lines[header].trim_start_matches("packs:").trim();
    if rest == "[]" {
        let mut out: Vec<String> = lines.iter().map(|line| (*line).to_owned()).collect();
        out[header] = format!("packs:\n{}", entry("  ").trim_end());
        return Ok(out.join("\n") + "\n");
    }
    if !rest.is_empty() && !rest.starts_with('#') {
        return Err("`packs:` uses flow style; add the pin by hand".into());
    }
    // The block runs until the next non-indented, non-empty line.
    let end = lines[header + 1..]
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with(' ') && !line.starts_with('-'))
        .map_or(lines.len(), |offset| header + 1 + offset);
    let block = &lines[header + 1..end];
    let item_indent = block
        .iter()
        .find_map(|line| {
            let trimmed = line.trim_start();
            trimmed
                .starts_with("- ")
                .then(|| line[..line.len() - trimmed.len()].to_owned())
        })
        .unwrap_or_else(|| "  ".into());
    let mut out: Vec<String> = lines[..=header]
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    let mut replaced = false;
    let mut index = 0;
    while index < block.len() {
        let line = block[index];
        let is_item = line.trim_start().starts_with("- ");
        let item_path = line
            .trim_start()
            .strip_prefix("- ")
            .and_then(|item| item.trim().strip_prefix("path:"))
            .map(str::trim);
        if is_item && item_path == Some(path) {
            // Replace this whole item.
            index += 1;
            while index < block.len()
                && !block[index].trim_start().starts_with("- ")
                && block[index].starts_with(&format!("{item_indent}  "))
            {
                index += 1;
            }
            out.push(entry(&item_indent).trim_end().to_owned());
            replaced = true;
            continue;
        }
        out.push(line.to_owned());
        index += 1;
    }
    if !replaced {
        out.push(entry(&item_indent).trim_end().to_owned());
    }
    out.extend(lines[end..].iter().map(|line| (*line).to_owned()));
    Ok(out.join("\n") + "\n")
}

/// Pinned packs and whether their content still matches the pin. Unlike config
/// loading, this reports a changed pack instead of failing.
pub fn list(workspace: &Workspace) -> Result<PackList> {
    let root = workspace.root();
    let config_path = root.join(".vee.yaml");
    let yaml = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    #[derive(serde::Deserialize)]
    struct PacksOnly {
        #[serde(default)]
        packs: Vec<vee_core::PackReference>,
    }
    let references: PacksOnly = serde_yaml::from_str(&yaml)
        .map_err(|error| usage_failure(format!(".vee.yaml: {error}")))?;
    let packs = references
        .packs
        .into_iter()
        .map(|reference| {
            let directory: PathBuf = root.join(reference.path.trim_end_matches('/'));
            let manifest = packs::read_pack(&directory);
            let digest = packs::pack_digest(&directory);
            let (status, problem) = match (&manifest, &digest) {
                (Err(error), _) | (_, Err(error)) => ("invalid", Some(error.clone())),
                (Ok(_), Ok(actual)) if *actual != reference.digest => {
                    ("changed", Some(format!("content digest is {actual}")))
                }
                _ => ("ok", None),
            };
            PinnedPack {
                provider: reference
                    .provider
                    .clone()
                    .unwrap_or_else(|| "default".into()),
                name: manifest.as_ref().ok().map(|pack| pack.name.clone()),
                version: manifest.as_ref().ok().map(|pack| pack.version.clone()),
                path: reference.path,
                pinned_digest: reference.digest,
                status: status.into(),
                problem,
            }
        })
        .collect();
    Ok(PackList {
        schema_version: 1,
        packs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111";
    const D2: &str = "sha256:2222";

    #[test]
    fn pin_appends_a_packs_block_when_none_exists() {
        let out = pin("version: 1\n# keep me\n", ".vee/packs/a", D1, None).unwrap();
        assert_eq!(
            out,
            "version: 1\n# keep me\npacks:\n  - path: .vee/packs/a\n    digest: sha256:1111\n"
        );
    }

    #[test]
    fn pin_replaces_an_empty_flow_list() {
        let out = pin("packs: []\npolicy: {}\n", ".vee/packs/a", D1, Some("codex")).unwrap();
        assert_eq!(out, "packs:\n  - path: .vee/packs/a\n    digest: sha256:1111\n    provider: codex\npolicy: {}\n");
    }

    #[test]
    fn pin_updates_an_existing_entry_and_keeps_others_and_trailing_keys() {
        let yaml = "version: 1\npacks:\n  - path: .vee/packs/a\n    digest: sha256:1111\n    provider: codex\n  - path: .vee/packs/b\n    digest: sha256:9999\npolicy:\n  minimum_confidence: 80\n";
        let out = pin(yaml, ".vee/packs/a", D2, None).unwrap();
        assert_eq!(
            out,
            "version: 1\npacks:\n  - path: .vee/packs/a\n    digest: sha256:2222\n  - path: .vee/packs/b\n    digest: sha256:9999\npolicy:\n  minimum_confidence: 80\n",
            "the entry is replaced in place, and its old provider is dropped"
        );
        let appended = pin(yaml, ".vee/packs/c", D2, None).unwrap();
        assert!(appended.contains("  - path: .vee/packs/b\n    digest: sha256:9999\n  - path: .vee/packs/c\n    digest: sha256:2222\npolicy:"));
    }

    #[test]
    fn pin_refuses_non_empty_flow_style() {
        assert!(pin("packs: [{path: x, digest: y}]\n", "a", D1, None).is_err());
    }
}
