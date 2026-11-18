use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use vee_core::{ChangeSet, VerificationProfile, VerificationStatus};

const MAX_PATCH_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CORPUS_BYTES: u64 = 1024 * 1024;
const MAX_CORPUS_MUTANTS: usize = 50;
const MAX_CORPUS_PATCH_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TREE_FILES: usize = 200_000;
const MAX_TREE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MutantCorpusManifest {
    schema_version: u32,
    corpus_id: String,
    #[serde(default)]
    dataset_kind: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    source_revision: Option<String>,
    #[serde(default)]
    license: Option<String>,
    mutants: Vec<MutantCorpusEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MutantCorpusEntry {
    id: String,
    patch: PathBuf,
    patch_digest: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CorpusMutantResult {
    pub id: String,
    pub patch_digest: String,
    pub mutant_snapshot_id: Option<String>,
    pub mutant_paths: Vec<String>,
    pub outcome: String,
    pub baseline_status: String,
    pub mutated_status: String,
    pub mutant_failure_signal: Option<String>,
    pub mutated_stdout_digest: Option<String>,
    pub mutated_stderr_digest: Option<String>,
    pub changed_line_coverage: Vec<MutantFileCoverage>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CorpusEffectivenessReport {
    pub schema_version: u32,
    pub proposal_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub baseline_verification_run_id: String,
    pub verification_command_digest: String,
    pub coverage_run: Option<CoverageRunProvenance>,
    pub corpus_id: String,
    pub corpus_digest: String,
    pub provenance: CorpusProvenance,
    pub sample_size: usize,
    pub killed: usize,
    pub survived: usize,
    pub inconclusive: usize,
    pub results: Vec<CorpusMutantResult>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CorpusProvenance {
    pub dataset_kind: String,
    pub source: Option<String>,
    pub source_revision: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct EffectivenessReport {
    pub schema_version: u32,
    pub proposal_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub baseline_verification_run_id: String,
    pub verification_command_digest: String,
    pub coverage_run: Option<CoverageRunProvenance>,
    pub changed_line_coverage: Vec<MutantFileCoverage>,
    pub mutant_patch_digest: String,
    pub mutant_snapshot_id: String,
    pub mutant_paths: Vec<String>,
    pub baseline_status: String,
    pub mutated_status: String,
    pub outcome: String,
    pub mutant_failure_signal: Option<String>,
    pub baseline_stdout_digest: String,
    pub baseline_stderr_digest: String,
    pub mutated_stdout_digest: String,
    pub mutated_stderr_digest: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct CoverageRunProvenance {
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub stream: String,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct MutantFileCoverage {
    pub path: String,
    pub changed_line_count: Option<u64>,
    pub changed_executable_lines: Option<u64>,
    pub changed_covered_lines: Option<u64>,
    pub changed_percent: Option<f64>,
}

pub fn attach_coverage(
    report: &mut EffectivenessReport,
    coverage: Option<&crate::coverage::CoverageReport>,
) {
    let Some(coverage) = coverage.filter(|coverage| coverage.snapshot_id == report.snapshot_id)
    else {
        report.limitations.push("Changed-line coverage was unavailable for the exact mutation baseline snapshot; mutation outcomes remain valid without coverage data.".into());
        return;
    };
    report.coverage_run = Some(CoverageRunProvenance {
        run_id: coverage.run_id.clone(),
        snapshot_id: coverage.snapshot_id.clone(),
        profile_id: coverage.profile_id.clone(),
        stream: coverage.stream.clone(),
    });
    report.changed_line_coverage = coverage_for_paths(coverage, &report.mutant_paths);
}

pub fn attach_corpus_coverage(
    report: &mut CorpusEffectivenessReport,
    coverage: Option<&crate::coverage::CoverageReport>,
) {
    let Some(coverage) = coverage.filter(|coverage| coverage.snapshot_id == report.snapshot_id)
    else {
        report.limitations.push("Changed-line coverage was unavailable for the exact mutation baseline snapshot; mutation outcomes remain valid without coverage data.".into());
        return;
    };
    report.coverage_run = Some(CoverageRunProvenance {
        run_id: coverage.run_id.clone(),
        snapshot_id: coverage.snapshot_id.clone(),
        profile_id: coverage.profile_id.clone(),
        stream: coverage.stream.clone(),
    });
    for mutant in &mut report.results {
        mutant.changed_line_coverage = coverage_for_paths(coverage, &mutant.mutant_paths);
    }
}

fn coverage_for_paths(
    coverage: &crate::coverage::CoverageReport,
    paths: &[String],
) -> Vec<MutantFileCoverage> {
    let paths = paths.iter().collect::<std::collections::BTreeSet<_>>();
    coverage
        .files
        .iter()
        .filter(|file| paths.contains(&file.path))
        .map(|file| MutantFileCoverage {
            path: file.path.clone(),
            changed_line_count: file.changed_line_count,
            changed_executable_lines: file.changed_executable_lines,
            changed_covered_lines: file.changed_covered_lines,
            changed_percent: file.changed_percent,
        })
        .collect()
}

fn corpus_digest(
    manifest_version: u32,
    corpus_id: &str,
    provenance: &CorpusProvenance,
    patch_identities: &[(String, String)],
) -> Result<String, String> {
    let bytes = if manifest_version == 1 {
        serde_json::to_vec(&("vee-mutant-corpus-v1", corpus_id, patch_identities))
    } else {
        serde_json::to_vec(&(
            "vee-mutant-corpus-v2",
            corpus_id,
            provenance,
            patch_identities,
        ))
    }
    .map_err(|error| error.to_string())?;
    Ok(vee_core::digest(&bytes))
}

struct ReportContext<'a> {
    proposal_id: &'a str,
    snapshot: &'a ChangeSet,
    profile_id: &'a str,
    baseline_verification_run_id: &'a str,
    verification_command_digest: String,
    mutant_patch_digest: String,
    mutant_snapshot_id: String,
    mutant_paths: Vec<String>,
}

pub fn assess(
    root: &Path,
    snapshot: &ChangeSet,
    proposal_id: &str,
    profile_id: &str,
    baseline_verification_run_id: &str,
    profile: &VerificationProfile,
    mutant_patch: &[u8],
) -> Result<EffectivenessReport, String> {
    if mutant_patch.is_empty() || mutant_patch.len() as u64 > MAX_PATCH_BYTES {
        return Err("mutant patch must be non-empty and no larger than 2 MiB".into());
    }
    let patch_file = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
    std::fs::write(patch_file.path(), mutant_patch).map_err(|error| error.to_string())?;
    let validated = crate::patch_sandbox::validate(root, patch_file.path())?;
    let source_paths = snapshot
        .files
        .iter()
        .filter(|file| {
            !crate::test_generation::is_test_path(&file.path) && file.status != "deleted"
        })
        .map(|file| file.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if validated.result_files.is_empty()
        || validated.result_files.iter().any(|file| {
            crate::test_generation::is_test_path(&file.path)
                || !source_paths.contains(file.path.as_str())
        })
    {
        return Err(
            "mutant patch must modify only changed production files in the reviewed snapshot"
                .into(),
        );
    }
    let patch_digest = vee_core::digest(mutant_patch);
    let mutant_snapshot_id = vee_core::digest(
        &serde_json::to_vec(&("vee-test-mutant-v1", &snapshot.digest, &patch_digest))
            .map_err(|error| error.to_string())?,
    );
    let mut report_context = ReportContext {
        proposal_id,
        snapshot,
        profile_id,
        baseline_verification_run_id,
        verification_command_digest: vee_process::verification_command_digest(profile, root)?,
        mutant_patch_digest: patch_digest,
        mutant_snapshot_id: mutant_snapshot_id.clone(),
        mutant_paths: validated
            .result_files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
    };
    let sandbox = tempfile::tempdir().map_err(|error| error.to_string())?;
    validate_snapshot_scope(root, snapshot)?;
    let ignored = ignored_repository_paths(root)?;
    let mut budget = CopyBudget {
        files: 0,
        bytes: 0,
        entries: 0,
    };
    copy_tree(root, sandbox.path(), Path::new(""), &ignored, &mut budget)?;
    overlay_snapshot(root, sandbox.path(), snapshot)?;
    verify_snapshot_files(sandbox.path(), snapshot)?;

    let baseline = vee_process::execute_verification_capture(
        &snapshot.digest,
        profile_id,
        sandbox.path(),
        profile,
    )?;
    report_context.verification_command_digest = baseline.run.command_digest.clone();
    if baseline.run.status != VerificationStatus::Passed {
        return Ok(report(
            report_context,
            "inconclusive",
            &baseline,
            None,
            None,
            "isolated baseline verification did not pass; mutant outcome was not evaluated",
        ));
    }
    apply_patch(sandbox.path(), patch_file.path())?;
    let mutated = vee_process::execute_verification_capture(
        &mutant_snapshot_id,
        profile_id,
        sandbox.path(),
        profile,
    )?;
    let failure_signal =
        crate::verification_diagnosis::test_failure_signal(&mutated.stdout, &mutated.stderr);
    let outcome = match mutated.run.status {
        VerificationStatus::Failed if failure_signal.is_some() => "killed",
        VerificationStatus::Failed => "inconclusive",
        VerificationStatus::Passed => "survived",
        VerificationStatus::TimedOut => "inconclusive",
        VerificationStatus::Incomplete => "inconclusive",
    };
    Ok(report(
        report_context,
        outcome,
        &baseline,
        Some(&mutated),
        failure_signal,
        "One supplied mutant is a reproducible signal, not a calibrated estimate of test quality. The temporary copy is not an OS security sandbox.",
    ))
}

/// Assess a bounded, digest-pinned corpus against the same approved snapshot and
/// trusted verification profile. Patch files are read-only inputs and must live
/// beneath the manifest directory.
pub fn assess_corpus(
    root: &Path,
    snapshot: &ChangeSet,
    proposal_id: &str,
    profile_id: &str,
    baseline_verification_run_id: &str,
    profile: &VerificationProfile,
    manifest_path: &Path,
) -> Result<CorpusEffectivenessReport, String> {
    let manifest_meta = std::fs::symlink_metadata(manifest_path)
        .map_err(|error| format!("reading mutant corpus manifest: {error}"))?;
    if !manifest_meta.file_type().is_file() || manifest_meta.len() > MAX_CORPUS_BYTES {
        return Err("mutant corpus manifest must be a regular file no larger than 1 MiB".into());
    }
    let manifest_path = vee_core::paths::canonicalize(manifest_path)
        .map_err(|error| format!("resolving mutant corpus manifest: {error}"))?;
    let corpus_root = manifest_path
        .parent()
        .ok_or("mutant corpus manifest has no parent directory")?;
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|error| format!("reading mutant corpus manifest: {error}"))?;
    let mut manifest: MutantCorpusManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid mutant corpus manifest: {error}"))?;
    if !matches!(manifest.schema_version, 1 | 2)
        || !valid_corpus_token(&manifest.corpus_id)
        || manifest.mutants.is_empty()
        || manifest.mutants.len() > MAX_CORPUS_MUTANTS
    {
        return Err(
            "mutant corpus requires schema_version 1 or 2, a valid corpus_id, and 1..=50 mutants"
                .into(),
        );
    }
    let provenance = match manifest.schema_version {
        1 => {
            if manifest.dataset_kind.is_some()
                || manifest.source.is_some()
                || manifest.source_revision.is_some()
                || manifest.license.is_some()
            {
                return Err(
                    "schema_version 1 mutant corpora cannot include provenance fields".into(),
                );
            }
            CorpusProvenance {
                dataset_kind: "unclassified".into(),
                source: None,
                source_revision: None,
                license: None,
            }
        }
        2 => {
            let kind = manifest.dataset_kind.as_deref().unwrap_or_default();
            let source = manifest.source.as_deref().unwrap_or_default().trim();
            if !matches!(kind, "seeded" | "historical")
                || source.is_empty()
                || source.len() > 2048
                || manifest
                    .source_revision
                    .as_ref()
                    .is_some_and(|value| value.len() > 256)
                || manifest
                    .license
                    .as_ref()
                    .is_some_and(|value| value.len() > 256)
            {
                return Err("schema_version 2 mutant corpora require dataset_kind seeded|historical and a bounded non-empty source; optional revision and license must be bounded".into());
            }
            CorpusProvenance {
                dataset_kind: kind.into(),
                source: Some(source.into()),
                source_revision: manifest.source_revision,
                license: manifest.license,
            }
        }
        _ => unreachable!("manifest version was validated"),
    };
    let manifest_version = manifest.schema_version;
    manifest
        .mutants
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut ids = std::collections::BTreeSet::new();
    let mut total_patch_bytes = 0u64;
    let mut patch_inputs = Vec::with_capacity(manifest.mutants.len());
    for entry in manifest.mutants {
        if !valid_corpus_token(&entry.id) || !ids.insert(entry.id.clone()) {
            return Err(
                "mutant IDs must be unique and use only ASCII letters, digits, '.', '_' or '-'"
                    .into(),
            );
        }
        if entry.patch.as_os_str().is_empty() || entry.patch.is_absolute() {
            return Err(format!(
                "mutant {} patch path must be relative to the manifest",
                entry.id
            ));
        }
        let patch_path = vee_core::paths::canonicalize(corpus_root.join(&entry.patch))
            .map_err(|error| format!("resolving patch for mutant {}: {error}", entry.id))?;
        if !patch_path.starts_with(corpus_root) {
            return Err(format!(
                "mutant {} patch path escapes the corpus directory",
                entry.id
            ));
        }
        let metadata = std::fs::symlink_metadata(&patch_path)
            .map_err(|error| format!("reading patch for mutant {}: {error}", entry.id))?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_PATCH_BYTES
        {
            return Err(format!(
                "mutant {} patch must be a regular non-empty file no larger than 2 MiB",
                entry.id
            ));
        }
        total_patch_bytes = total_patch_bytes.saturating_add(metadata.len());
        if total_patch_bytes > MAX_CORPUS_PATCH_BYTES {
            return Err("mutant corpus patch data exceeds the 32 MiB aggregate limit".into());
        }
        let patch = std::fs::read(&patch_path)
            .map_err(|error| format!("reading patch for mutant {}: {error}", entry.id))?;
        let patch_digest = vee_core::digest(&patch);
        if entry.patch_digest != patch_digest {
            return Err(format!(
                "mutant {} patch digest does not match the manifest",
                entry.id
            ));
        }
        patch_inputs.push((entry.id, patch, patch_digest));
    }

    let corpus_id = manifest.corpus_id;
    let patch_identities = patch_inputs
        .iter()
        .map(|(id, _, digest)| (id.clone(), digest.clone()))
        .collect::<Vec<_>>();
    let corpus_digest =
        corpus_digest(manifest_version, &corpus_id, &provenance, &patch_identities)?;
    let mut results = Vec::with_capacity(patch_inputs.len());
    let mut verification_command_digest: Option<String> = None;
    for (id, patch, patch_digest) in patch_inputs {
        let report = assess(
            root,
            snapshot,
            proposal_id,
            profile_id,
            baseline_verification_run_id,
            profile,
            &patch,
        )
        .map_err(|error| format!("assessing mutant {id}: {error}"))?;
        if verification_command_digest
            .as_ref()
            .is_some_and(|digest| digest != &report.verification_command_digest)
        {
            return Err("verification executable or allowlisted environment changed during corpus assessment".into());
        }
        verification_command_digest = Some(report.verification_command_digest.clone());
        let mutant_was_run = report.mutated_status != "not_run";
        results.push(CorpusMutantResult {
            id,
            patch_digest,
            mutant_snapshot_id: mutant_was_run.then_some(report.mutant_snapshot_id),
            mutant_paths: if !mutant_was_run {
                Vec::new()
            } else {
                report.mutant_paths
            },
            outcome: report.outcome,
            baseline_status: report.baseline_status,
            mutated_status: report.mutated_status,
            mutant_failure_signal: report.mutant_failure_signal,
            mutated_stdout_digest: mutant_was_run.then_some(report.mutated_stdout_digest),
            mutated_stderr_digest: mutant_was_run.then_some(report.mutated_stderr_digest),
            changed_line_coverage: Vec::new(),
        });
    }
    let killed = results
        .iter()
        .filter(|result| result.outcome == "killed")
        .count();
    let survived = results
        .iter()
        .filter(|result| result.outcome == "survived")
        .count();
    let inconclusive = results
        .iter()
        .filter(|result| result.outcome == "inconclusive")
        .count();
    Ok(CorpusEffectivenessReport {
        schema_version: 6,
        proposal_id: proposal_id.into(),
        snapshot_id: snapshot.digest.clone(),
        profile_id: profile_id.into(),
        baseline_verification_run_id: baseline_verification_run_id.into(),
        verification_command_digest: verification_command_digest
            .unwrap_or(vee_process::verification_command_digest(profile, root)?),
        coverage_run: None,
        corpus_id,
        corpus_digest,
        provenance,
        sample_size: results.len(),
        killed,
        survived,
        inconclusive,
        results,
        limitations: vec![
            "Corpus outcomes are descriptive for these exact mutants and this trusted profile; they are not a calibrated estimate of general test quality.".into(),
            "Each evaluated mutant records its exact mutated snapshot ID, modified production paths, and output digests; baseline-inconclusive mutants have no mutated execution evidence.".into(),
            "Inconclusive mutants remain in the sample denominator and are not counted as killed.".into(),
            "The command digest binds the configured profile, resolved executable identity and content digest, and digests of present allowlisted environment values. It does not fingerprint transitive tools, operating-system state, or external services.".into(),
            "The temporary repository copy is not an OS security sandbox.".into(),
        ],
    })
}

fn valid_corpus_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn report(
    context: ReportContext<'_>,
    outcome: &str,
    baseline: &vee_core::VerificationExecution,
    mutated: Option<&vee_core::VerificationExecution>,
    mutant_failure_signal: Option<String>,
    limitation: &str,
) -> EffectivenessReport {
    let baseline_status = format_status(baseline.run.status);
    let mutated_status = mutated
        .map(|run| format_status(run.run.status))
        .unwrap_or_else(|| "not_run".into());
    EffectivenessReport {
        schema_version: 4,
        proposal_id: context.proposal_id.into(),
        snapshot_id: context.snapshot.digest.clone(),
        profile_id: context.profile_id.into(),
        baseline_verification_run_id: context.baseline_verification_run_id.into(),
        verification_command_digest: context.verification_command_digest,
        coverage_run: None,
        changed_line_coverage: Vec::new(),
        mutant_patch_digest: context.mutant_patch_digest,
        mutant_snapshot_id: context.mutant_snapshot_id,
        mutant_paths: context.mutant_paths,
        baseline_status,
        mutated_status,
        outcome: outcome.into(),
        mutant_failure_signal,
        baseline_stdout_digest: vee_core::digest(&baseline.stdout),
        baseline_stderr_digest: vee_core::digest(&baseline.stderr),
        mutated_stdout_digest: mutated
            .map(|run| vee_core::digest(&run.stdout))
            .unwrap_or_default(),
        mutated_stderr_digest: mutated
            .map(|run| vee_core::digest(&run.stderr))
            .unwrap_or_default(),
        limitations: vec![
            limitation.into(),
            "The trusted verification profile is the measured test set; unrelated tests in the profile may also kill the mutant.".into(),
            "The command digest binds configured executable, arguments, environment allowlist, and limits; it does not fingerprint executable bytes, tool version, or environment values.".into(),
        ],
    }
}

fn format_status(status: VerificationStatus) -> String {
    match status {
        VerificationStatus::Passed => "passed",
        VerificationStatus::Failed => "failed",
        VerificationStatus::TimedOut => "timed_out",
        VerificationStatus::Incomplete => "incomplete",
    }
    .into()
}

struct CopyBudget {
    files: usize,
    bytes: u64,
    entries: usize,
}

fn copy_tree(
    root: &Path,
    destination: &Path,
    relative: &Path,
    ignored: &std::collections::BTreeSet<PathBuf>,
    budget: &mut CopyBudget,
) -> Result<(), String> {
    let source = root.join(relative);
    let metadata = std::fs::symlink_metadata(&source).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        for entry in std::fs::read_dir(&source).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            budget.entries += 1;
            if budget.entries > MAX_TREE_FILES || relative.components().count() > 256 {
                return Err(
                    "repository tree exceeds the effectiveness assessment entry/depth bounds"
                        .into(),
                );
            }
            if excluded(relative, &name) {
                continue;
            }
            let child = relative.join(name);
            if ignored.contains(&child) {
                continue;
            }
            let target = destination.join(&child);
            let child_metadata =
                std::fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if child_metadata.is_dir() {
                std::fs::create_dir_all(&target).map_err(|error| error.to_string())?;
                copy_tree(root, destination, &child, ignored, budget)?;
            } else if child_metadata.file_type().is_symlink() {
                let link = std::fs::read_link(entry.path()).map_err(|error| error.to_string())?;
                validate_link(&child, &link)?;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                create_symlink(&link, &target)?;
            } else if child_metadata.is_file() {
                budget.files += 1;
                budget.bytes = budget.bytes.saturating_add(child_metadata.len());
                if budget.files > MAX_TREE_FILES || budget.bytes > MAX_TREE_BYTES {
                    return Err(
                        "repository copy exceeds the effectiveness assessment bounds".into(),
                    );
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                std::fs::copy(entry.path(), &target).map_err(|error| error.to_string())?;
                copy_mode(&entry.path(), &target)?;
            } else {
                return Err(format!(
                    "unsupported repository entry during assessment: {}",
                    child.display()
                ));
            }
        }
    }
    Ok(())
}

fn excluded(_parent: &Path, name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name == ".git" || name == ".vee" || name == "node_modules" || name == "target"
}

fn validate_link(path: &Path, link: &Path) -> Result<(), String> {
    if link.is_absolute() {
        return Err(format!(
            "absolute symlink is not allowed in assessment copy: {}",
            path.display()
        ));
    }
    let mut depth = path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    for component in link.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "symlink escapes assessment copy: {}",
                    path.display()
                ));
            }
            Component::CurDir => {}
        }
    }
    Ok(())
}

fn verify_snapshot_files(root: &Path, snapshot: &ChangeSet) -> Result<(), String> {
    let paths = snapshot
        .files
        .iter()
        .map(|file| PathBuf::from(&file.path))
        .collect::<Vec<_>>();
    let copied = vee_git::snapshot_files(root, &paths)?;
    for expected in &snapshot.files {
        let actual = copied.iter().find(|file| file.path == expected.path);
        if expected.status == "deleted" {
            if actual.is_some() {
                return Err(format!(
                    "assessment copy unexpectedly contains deleted path {}",
                    expected.path
                ));
            }
        } else if let Some(actual) = actual {
            if actual.mode != normalized_snapshot_mode(expected.mode) {
                return Err(format!(
                    "assessment copy mode {} does not match reviewed mode {} at {}",
                    actual.mode,
                    normalized_snapshot_mode(expected.mode),
                    expected.path
                ));
            }
            if actual.content_digest != expected.content_digest {
                return Err(format!(
                    "assessment copy content digest does not match reviewed snapshot at {}",
                    expected.path
                ));
            }
        } else {
            return Err(format!(
                "assessment copy is missing reviewed snapshot path {}",
                expected.path
            ));
        }
    }
    Ok(())
}

fn normalized_snapshot_mode(mode: u32) -> u32 {
    if mode & 0o170000 == 0o100000 {
        mode & 0o777
    } else {
        mode
    }
}

fn validate_snapshot_scope(root: &Path, snapshot: &ChangeSet) -> Result<(), String> {
    let selected = snapshot
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let head = snapshot
        .head_oid
        .as_deref()
        .ok_or("effectiveness assessment requires a mutable snapshot with a captured HEAD")?;
    let changed = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--name-only", "-z", head, "--"])
        .output()
        .map_err(|error| error.to_string())?;
    if !changed.status.success() {
        return Err("could not verify repository changes outside the selected snapshot".into());
    }
    let untracked = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .map_err(|error| error.to_string())?;
    if !untracked.status.success() {
        return Err("could not enumerate untracked repository files".into());
    }
    for raw in changed
        .stdout
        .split(|byte| *byte == 0)
        .chain(untracked.stdout.split(|byte| *byte == 0))
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(raw).map_err(|_| "repository path is not UTF-8")?;
        if path != ".vee.yaml" && !path.starts_with(".vee/") && !selected.contains(path) {
            return Err(format!(
                "repository has out-of-snapshot changes that could affect the effectiveness run: {path}"
            ));
        }
    }
    Ok(())
}

fn ignored_repository_paths(root: &Path) -> Result<std::collections::BTreeSet<PathBuf>, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("could not enumerate ignored repository files".into());
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            std::str::from_utf8(raw)
                .map(PathBuf::from)
                .map_err(|_| "ignored repository path is not UTF-8".into())
        })
        .collect()
}

fn overlay_snapshot(
    source_root: &Path,
    sandbox_root: &Path,
    snapshot: &ChangeSet,
) -> Result<(), String> {
    for file in &snapshot.files {
        let relative = Path::new(&file.path);
        let target = sandbox_root.join(relative);
        if file.status == "deleted" {
            match std::fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    std::fs::remove_dir_all(&target).map_err(|error| error.to_string())?
                }
                Ok(_) => std::fs::remove_file(&target).map_err(|error| error.to_string())?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
            continue;
        }
        let bytes = vee_git::read_snapshot_file(source_root, snapshot, relative)?
            .ok_or_else(|| format!("snapshot file is missing: {}", file.path))?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        match std::fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&target).map_err(|error| error.to_string())?
            }
            Ok(_) => std::fs::remove_file(&target).map_err(|error| error.to_string())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if file.mode == 0o120000 {
            let link = PathBuf::from(
                std::str::from_utf8(&bytes).map_err(|_| "snapshot symlink target is not UTF-8")?,
            );
            validate_link(relative, &link)?;
            create_symlink(&link, &target)?;
        } else {
            std::fs::write(&target, bytes).map_err(|error| error.to_string())?;
            set_mode(&target, file.mode)?;
        }
    }
    Ok(())
}

fn apply_patch(root: &Path, patch: &Path) -> Result<(), String> {
    for (args, final_pass) in [
        (&["apply", "--no-index", "--check", "--"][..], false),
        (&["apply", "--no-index", "--"][..], true),
    ] {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .arg(patch)
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "mutant patch could not be applied in the temporary copy: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        if final_pass {
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_mode(source: &Path, target: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(source)
        .map_err(|error| error.to_string())?
        .permissions()
        .mode();
    let mut permissions = std::fs::metadata(target)
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_mode(mode & 0o777);
    std::fs::set_permissions(target, permissions).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_mode(mode & 0o777);
    std::fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn copy_mode(_source: &Path, _target: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, target).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_file(source, target).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{assess_corpus, corpus_digest, CorpusEffectivenessReport, CorpusProvenance};
    use std::{fs, path::Path, process::Command};
    use vee_core::{ChangeSet, VerificationProfile};

    #[test]
    fn corpus_v2_digest_binds_provenance_and_v1_digest_stays_compatible() {
        let patches = vec![("mutation-1".into(), "sha256:patch".into())];
        let provenance = CorpusProvenance {
            dataset_kind: "historical".into(),
            source: Some("https://example.invalid/dataset".into()),
            source_revision: Some("abc123".into()),
            license: Some("MIT".into()),
        };
        let first = corpus_digest(2, "sample", &provenance, &patches).unwrap();
        let changed = CorpusProvenance {
            source_revision: Some("def456".into()),
            ..provenance
        };
        assert_ne!(
            first,
            corpus_digest(2, "sample", &changed, &patches).unwrap()
        );

        let legacy = corpus_digest(1, "sample", &changed, &patches).unwrap();
        let expected = vee_core::digest(
            &serde_json::to_vec(&("vee-mutant-corpus-v1", "sample", patches)).unwrap(),
        );
        assert_eq!(legacy, expected);
    }

    fn git(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .status()
                .unwrap()
                .success(),
            "git {args:?} failed"
        );
    }

    fn assess_language_fixture(
        language: &str,
        source_path: &str,
        base_source: &str,
        reviewed_source: &str,
        context_files: &[(&str, &str)],
        verification_profile: VerificationProfile,
    ) -> CorpusEffectivenessReport {
        assess_language_fixture_with_mutation(
            language,
            source_path,
            base_source,
            reviewed_source,
            context_files,
            verification_profile,
            None,
        )
    }

    fn assess_language_fixture_with_mutation(
        language: &str,
        source_path: &str,
        base_source: &str,
        reviewed_source: &str,
        context_files: &[(&str, &str)],
        verification_profile: VerificationProfile,
        target_mutation: Option<(&str, &str)>,
    ) -> CorpusEffectivenessReport {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("repo");
        fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.email", "vee@example.invalid"]);
        git(&root, &["config", "user.name", "Vee test"]);
        fs::write(root.join(source_path), base_source).unwrap();
        for (path, contents) in context_files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "base"]);
        let base = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();

        fs::write(root.join(source_path), reviewed_source).unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "reviewed source"]);
        let head = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let snapshot = crate::capture_change_set(
            &root,
            vee_git::commit_scope(&format!("{base}..{head}")).unwrap(),
        )
        .unwrap();

        let source = fs::read_to_string(root.join(source_path)).unwrap();
        let source_lines = source.lines().collect::<Vec<_>>();
        let target_index = source_lines
            .iter()
            .position(|line| line.contains("TARGET"))
            .unwrap();
        let unrelated_index = source_lines
            .iter()
            .position(|line| line.contains("UNRELATED"))
            .unwrap();
        let patch_for = |changed_index: usize, replacement: String| {
            let mut patch = format!(
                "diff --git a/{source_path} b/{source_path}\n--- a/{source_path}\n+++ b/{source_path}\n@@ -1,{} +1,{} @@\n",
                source_lines.len(),
                source_lines.len()
            );
            for (index, line) in source_lines.iter().enumerate() {
                if index == changed_index {
                    patch.push_str(&format!("-{line}\n+{replacement}\n"));
                } else {
                    patch.push_str(&format!(" {line}\n"));
                }
            }
            patch
        };
        let killed_line = if let Some((from, to)) = target_mutation {
            assert!(
                source_lines[target_index].contains(from),
                "target mutant source line must contain {from:?}"
            );
            source_lines[target_index].replacen(from, to, 1)
        } else {
            source_lines[target_index]
                .replace("false", "true")
                .replace("False", "True")
        };
        let killed_patch = patch_for(target_index, killed_line);
        let survived_patch = patch_for(
            unrelated_index,
            source_lines[unrelated_index].replace("0", "1"),
        );
        let corpus_dir = workspace.path().join("corpus");
        fs::create_dir_all(&corpus_dir).unwrap();
        fs::write(corpus_dir.join("killed.patch"), &killed_patch).unwrap();
        fs::write(corpus_dir.join("survived.patch"), &survived_patch).unwrap();
        let manifest_path = corpus_dir.join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "corpus_id": format!("{language}-v1"),
                "mutants": [
                    {"id":"survives", "patch":"survived.patch", "patch_digest":vee_core::digest(survived_patch.as_bytes())},
                    {"id":"kills", "patch":"killed.patch", "patch_digest":vee_core::digest(killed_patch.as_bytes())}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let direct = Command::new(&verification_profile.executable)
            .args(&verification_profile.args)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            direct.status.success(),
            "{language} fixture baseline failed: stdout={} stderr={}",
            String::from_utf8_lossy(&direct.stdout),
            String::from_utf8_lossy(&direct.stderr)
        );
        let report = assess_corpus(
            &root,
            &snapshot,
            &vee_core::digest(format!("{language}-proposal").as_bytes()),
            language,
            &vee_core::digest(format!("{language}-baseline").as_bytes()),
            &verification_profile,
            &manifest_path,
        )
        .unwrap_or_else(|error| panic!("{error}\nSurviving patch:\n{survived_patch}"));
        assert_eq!(report.sample_size, 2, "{language}");
        assert_eq!(report.killed, 1, "{language}: {:?}", report.results);
        assert_eq!(report.survived, 1, "{language}: {:?}", report.results);
        assert_eq!(report.inconclusive, 0, "{language}");
        assert_eq!(report.provenance.dataset_kind, "unclassified", "{language}");
        assert!(report.provenance.source.is_none(), "{language}");
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/test-effectiveness-corpus-v6.schema.json"
        ))
        .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&report).unwrap()));
        assert!(report.results.iter().all(|result| {
            result
                .mutant_snapshot_id
                .as_deref()
                .is_some_and(|snapshot_id| snapshot_id.starts_with("sha256:"))
                && result.mutant_paths == [source_path]
                && result.mutated_stdout_digest.is_some()
                && result.mutated_stderr_digest.is_some()
        }));
        report
    }

    #[test]
    fn rust_python_java_go_node_typescript_and_ruby_corpora_detect_killed_and_surviving_mutants() {
        let rust = assess_language_fixture(
            "rust",
            "src/lib.rs",
            "pub const TARGET: bool = true;\npub const UNRELATED: i32 = 0;\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn target_is_true() { assert!(super::TARGET); }\n}\n",
            "pub const TARGET: bool = false;\npub const UNRELATED: i32 = 0;\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn target_is_false() { assert!(!super::TARGET); }\n}\n",
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"vee-effectiveness-rust-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "Cargo.lock",
                    "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"vee-effectiveness-rust-fixture\"\nversion = \"0.1.0\"\n",
                ),
                (".gitignore", "/target/\n"),
            ],
            VerificationProfile {
                egress: Default::default(),
                executable: "cargo".into(),
                args: vec!["test".into(), "--offline".into(), "--quiet".into()],
                env_allowlist: vec![
                    "PATH".into(),
                    "HOME".into(),
                    "CARGO_HOME".into(),
                    "RUSTUP_HOME".into(),
                ],
                timeout_seconds: 60,
                output_limit_bytes: 65_536,
                sarif: None,
            },
        );
        assert_eq!(rust.corpus_id, "rust-v1");

        let python = assess_language_fixture(
            "python",
            "src/logic.py",
            "TARGET = True\nUNRELATED = 0\n",
            "TARGET = False\nUNRELATED = 0\n",
            &[
                ("tests/__init__.py", ""),
                (
                    "tests/test_logic.py",
                    "import unittest\nimport sys\nsys.path.insert(0, 'src')\nimport logic\nclass LogicTest(unittest.TestCase):\n    def test_target(self):\n        self.assertFalse(logic.TARGET)\nif __name__ == '__main__':\n    unittest.main()\n",
                ),
            ],
            VerificationProfile {
                egress: Default::default(),
                executable: if cfg!(windows) {
                    "python".into()
                } else {
                    "python3".into()
                },
                args: vec!["-B".into(), "tests/test_logic.py".into()],
                env_allowlist: vec!["PATH".into(), "PYTHONPATH".into()],
                timeout_seconds: 30,
                output_limit_bytes: 65_536,
                sarif: None,
            },
        );
        assert_eq!(python.corpus_id, "python-v1");
        let java = assess_language_fixture(
            "java",
            "src/Target.java",
            "public class Target { public static boolean TARGET = true;\n    public static int UNRELATED = 0;\n    public static void main(String[] args) { assert !TARGET : \"target should be false\"; }\n}\n",
            "public class Target { public static boolean TARGET = false;\n    public static int UNRELATED = 0;\n    public static void main(String[] args) { assert !TARGET : \"target should be false\"; }\n}\n",
            &[],
            VerificationProfile {
                egress: Default::default(),
                executable: "java".into(),
                args: vec!["-ea".into(), "src/Target.java".into()],
                env_allowlist: vec!["PATH".into(), "JAVA_HOME".into()],
                timeout_seconds: 30,
                output_limit_bytes: 65_536,
                sarif: None,
            },
        );
        assert_eq!(java.corpus_id, "java-v1");

        let go_available = Command::new("go")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success());
        assert!(
            go_available || std::env::var_os("CI").is_none(),
            "Go must be installed in CI for the mutation-effectiveness fixture"
        );
        if go_available {
            let go = assess_language_fixture(
                "go",
                "src/logic.go",
                "package logic\n\nconst TARGET = true\nconst UNRELATED = 0\n",
                "package logic\n\nconst TARGET = false\nconst UNRELATED = 0\n",
                &[
                    ("go.mod", "module example.invalid/vee-fixture\n\ngo 1.20\n"),
                    (
                        "src/logic_test.go",
                        "package logic\n\nimport \"testing\"\n\nfunc TestTarget(t *testing.T) { if TARGET { t.Fatal(\"target should be false\") } }\n",
                    ),
                ],
                VerificationProfile {
                    egress: Default::default(),
                    executable: "go".into(),
                    args: vec!["test".into(), "./...".into()],
                    env_allowlist: vec!["PATH".into(), "HOME".into(), "GOMODCACHE".into()],
                    timeout_seconds: 60,
                    output_limit_bytes: 65_536,
                    sarif: None,
                },
            );
            assert_eq!(go.corpus_id, "go-v1");
        }

        let node_available = Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        assert!(
            node_available || std::env::var_os("CI").is_none(),
            "Node.js must be installed in CI for the mutation-effectiveness fixture"
        );
        if node_available {
            let node = assess_language_fixture(
                "node",
                "src/logic.cjs",
                "exports.TARGET = true;\nexports.UNRELATED = 0;\n",
                "exports.TARGET = false;\nexports.UNRELATED = 0;\n",
                &[(
                    "tests/logic.test.cjs",
                    "const test = require('node:test');\nconst assert = require('node:assert/strict');\nconst { TARGET } = require('../src/logic.cjs');\ntest('target remains false', () => assert.equal(TARGET, false));\n",
                )],
                VerificationProfile {
                    egress: Default::default(),
                    executable: "node".into(),
                    args: vec!["--test".into(), "tests/logic.test.cjs".into()],
                    env_allowlist: vec!["PATH".into(), "HOME".into()],
                    timeout_seconds: 30,
                    output_limit_bytes: 65_536,
                    sarif: None,
                },
            );
            assert_eq!(node.corpus_id, "node-v1");

            let typescript = assess_language_fixture_with_mutation(
                "typescript",
                "src/logic.ts",
                "export function shouldRetry(status: number): boolean {\n  return status === 429 || (status >= 500 && false); // TARGET\n}\nexport const UNRELATED: number = 0;\n",
                "export function shouldRetry(status: number): boolean {\n  return status === 429 || (status >= 500 && true); // TARGET\n}\nexport const UNRELATED: number = 0;\n",
                &[
                    ("package.json", "{\"type\":\"module\"}\n"),
                    (
                        "tests/logic.test.ts",
                        "import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { shouldRetry } from '../src/logic.ts';\ntest('retries rate limits and server errors but not client errors', () => {\n  assert.equal(shouldRetry(429), true);\n  assert.equal(shouldRetry(503), true);\n  assert.equal(shouldRetry(400), false);\n});\n",
                    ),
                ],
                VerificationProfile {
                    egress: Default::default(),
                    executable: "node".into(),
                    args: vec![
                        "--experimental-strip-types".into(),
                        "--test".into(),
                        "tests/logic.test.ts".into(),
                    ],
                    env_allowlist: vec!["PATH".into(), "HOME".into()],
                    timeout_seconds: 30,
                    output_limit_bytes: 65_536,
                    sarif: None,
                },
                Some(("true", "false")),
            );
            assert_eq!(typescript.corpus_id, "typescript-v1");
        }

        let ruby_available = Command::new("ruby")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        assert!(
            ruby_available || std::env::var_os("CI").is_none(),
            "Ruby must be installed in CI for the mutation-effectiveness fixture"
        );
        if ruby_available {
            let ruby = assess_language_fixture(
                "ruby",
                "src/logic.rb",
                "module Logic\n  TARGET = true\n  UNRELATED = 0\nend\n",
                "module Logic\n  TARGET = false\n  UNRELATED = 0\nend\n",
                &[(
                    "tests/test_logic.rb",
                    "require 'minitest/autorun'\nrequire_relative '../src/logic'\n\nclass LogicTest < Minitest::Test\n  def test_target\n    assert_equal false, Logic::TARGET\n  end\nend\n",
                )],
                VerificationProfile {
                    egress: Default::default(),
                    executable: "ruby".into(),
                    args: vec!["tests/test_logic.rb".into()],
                    env_allowlist: vec!["PATH".into(), "GEM_PATH".into(), "GEM_HOME".into()],
                    timeout_seconds: 30,
                    output_limit_bytes: 65_536,
                    sarif: None,
                },
            );
            assert_eq!(ruby.corpus_id, "ruby-v1");
        }
    }

    #[test]
    fn rust_retry_boundary_corpus_kills_off_by_one_mutant() {
        let report = assess_language_fixture_with_mutation(
            "rust-retry-boundary",
            "src/lib.rs",
            "pub fn should_retry(status: u16) -> bool { false } // TARGET\npub const UNRELATED: i32 = 0;\n",
            "pub fn should_retry(status: u16) -> bool { (status == 429 || status >= 500) && status < 600 } // TARGET\npub const UNRELATED: i32 = 0;\n",
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"vee-retry-boundary-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "Cargo.lock",
                    "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"vee-retry-boundary-fixture\"\nversion = \"0.1.0\"\n",
                ),
                (".gitignore", "/target/\n"),
                (
                    "tests/retry.rs",
                    "use vee_retry_boundary_fixture::should_retry;\n\n#[test]\nfn retry_boundaries_are_explicit() {\n    assert!(should_retry(429));\n    assert!(should_retry(500));\n    assert!(should_retry(599));\n    assert!(!should_retry(400));\n    assert!(!should_retry(600));\n}\n",
                ),
            ],
            VerificationProfile {
                egress: Default::default(),
                executable: "cargo".into(),
                args: vec!["test".into(), "--offline".into(), "--quiet".into()],
                env_allowlist: vec![
                    "PATH".into(),
                    "HOME".into(),
                    "CARGO_HOME".into(),
                    "RUSTUP_HOME".into(),
                ],
                timeout_seconds: 60,
                output_limit_bytes: 65_536,
                sarif: None,
            },
            Some(("status < 600", "status <= 600")),
        );

        assert_eq!(report.corpus_id, "rust-retry-boundary-v1");
        assert_eq!(report.sample_size, 2);
        assert_eq!(report.killed, 1);
        assert_eq!(report.survived, 1);
        assert_eq!(report.inconclusive, 0);
        assert!(report
            .results
            .iter()
            .any(|result| { result.id == "kills" && result.outcome == "killed" }));
        assert!(report
            .results
            .iter()
            .any(|result| { result.id == "survives" && result.outcome == "survived" }));
    }

    #[test]
    fn rust_path_traversal_corpus_kills_segment_validation_mutant() {
        let report = assess_language_fixture_with_mutation(
            "rust-path-traversal",
            "src/lib.rs",
            "pub fn is_safe_relative_path(path: &str) -> bool { false } // TARGET\npub const UNRELATED: i32 = 0;\n",
            "pub fn is_safe_relative_path(path: &str) -> bool { !path.is_empty() && !path.starts_with('/') && !path.split('/').any(|segment| segment == \"..\") } // TARGET\npub const UNRELATED: i32 = 0;\n",
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"vee-path-traversal-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "Cargo.lock",
                    "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"vee-path-traversal-fixture\"\nversion = \"0.1.0\"\n",
                ),
                (".gitignore", "/target/\n"),
                (
                    "tests/path.rs",
                    "use vee_path_traversal_fixture::is_safe_relative_path;\n\n#[test]\nfn rejects_absolute_empty_and_traversal_paths() {\n    assert!(is_safe_relative_path(\"reports/summary.txt\"));\n    assert!(!is_safe_relative_path(\"\"));\n    assert!(!is_safe_relative_path(\"/etc/passwd\"));\n    assert!(!is_safe_relative_path(\"../secret\"));\n    assert!(!is_safe_relative_path(\"reports/../../secret\"));\n}\n",
                ),
            ],
            VerificationProfile {
                egress: Default::default(),
                executable: "cargo".into(),
                args: vec!["test".into(), "--offline".into(), "--quiet".into()],
                env_allowlist: vec![
                    "PATH".into(),
                    "HOME".into(),
                    "CARGO_HOME".into(),
                    "RUSTUP_HOME".into(),
                ],
                timeout_seconds: 60,
                output_limit_bytes: 65_536,
                sarif: None,
            },
            Some(("segment == \"..\"", "segment == \"...\"")),
        );

        assert_eq!(report.corpus_id, "rust-path-traversal-v1");
        assert_eq!(report.sample_size, 2);
        assert_eq!(report.killed, 1);
        assert_eq!(report.survived, 1);
        assert_eq!(report.inconclusive, 0);
    }

    #[cfg(unix)]
    #[test]
    fn corpus_assessment_reports_killed_and_survived_counts_for_the_exact_snapshot() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("repo");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.email", "vee@example.invalid"]);
        git(&root, &["config", "user.name", "Vee test"]);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "const TARGET: &str = \"before\";\nconst UNUSED: u8 = 0;\n",
        )
        .unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "base"]);
        let base = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(
            root.join("src/lib.rs"),
            "const TARGET: &str = \"baseline\";\nconst UNUSED: u8 = 0;\n",
        )
        .unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "reviewed source"]);
        let head = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let snapshot = crate::capture_change_set(
            &root,
            vee_git::commit_scope(&format!("{base}..{head}")).unwrap(),
        )
        .unwrap();

        let corpus_dir = workspace.path().join("corpus");
        fs::create_dir_all(&corpus_dir).unwrap();
        let killed_patch = b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n-const TARGET: &str = \"baseline\";\n+const TARGET: &str = \"mutated\";\n const UNUSED: u8 = 0;\n";
        let survived_patch = b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n const TARGET: &str = \"baseline\";\n-const UNUSED: u8 = 0;\n+const UNUSED: u8 = 1;\n";
        fs::write(corpus_dir.join("killed.patch"), killed_patch).unwrap();
        fs::write(corpus_dir.join("survived.patch"), survived_patch).unwrap();
        let manifest_path = corpus_dir.join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 2,
                "corpus_id": "fixture-v1",
                "dataset_kind": "seeded",
                "source": "unit test generated fixture",
                "source_revision": "fixture-revision",
                "license": "test-only",
                "mutants": [
                    {"id":"survives","patch":"survived.patch","patch_digest":vee_core::digest(survived_patch)},
                    {"id":"kills","patch":"killed.patch","patch_digest":vee_core::digest(killed_patch)}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let profile = vee_core::VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "grep -q 'TARGET: &str = \\\"baseline\\\"' src/lib.rs || { echo 'test result: FAILED'; exit 1; }; echo 'test result: ok'".into(),
            ],
            env_allowlist: vec!["PATH".into()],
            timeout_seconds: 5,
            output_limit_bytes: 65_536,
            sarif: None,
        };
        let report = assess_corpus(
            &root,
            &snapshot,
            &vee_core::digest(b"proposal"),
            "fixture",
            "verify_baseline",
            &profile,
            &manifest_path,
        )
        .unwrap();
        assert_eq!(report.corpus_id, "fixture-v1");
        assert_eq!(report.schema_version, 6);
        assert_eq!(report.provenance.dataset_kind, "seeded");
        assert_eq!(
            report.provenance.source.as_deref(),
            Some("unit test generated fixture")
        );
        assert_eq!(
            report.provenance.source_revision.as_deref(),
            Some("fixture-revision")
        );
        assert_eq!(report.provenance.license.as_deref(), Some("test-only"));
        assert_eq!(
            report.verification_command_digest,
            vee_process::verification_command_digest(&profile, &root).unwrap()
        );
        assert_eq!(report.sample_size, 2);
        assert_eq!(report.killed, 1);
        assert_eq!(report.survived, 1);
        assert_eq!(report.inconclusive, 0);
        assert_eq!(report.results[0].id, "kills");
        assert_eq!(report.results[0].outcome, "killed");
        assert_eq!(report.results[1].id, "survives");
        assert_eq!(report.results[1].outcome, "survived");
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/test-effectiveness-corpus-v6.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&serde_json::to_value(&report).unwrap()));

        let baseline_inconclusive_profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "echo 'attempting to make an HTTP request, but --offline was specified' >&2; exit 101".into(),
            ],
            env_allowlist: vec!["PATH".into()],
            timeout_seconds: 5,
            output_limit_bytes: 65_536,
            sarif: None,
        };
        let inconclusive = assess_corpus(
            &root,
            &snapshot,
            &vee_core::digest(b"proposal"),
            "fixture",
            "verify_baseline_inconclusive",
            &baseline_inconclusive_profile,
            &manifest_path,
        )
        .unwrap();
        assert_eq!(inconclusive.inconclusive, 2);
        assert_eq!(inconclusive.results[0].baseline_status, "incomplete");
        assert_eq!(inconclusive.results[0].mutated_status, "not_run");
        assert_eq!(inconclusive.results[0].mutant_snapshot_id, None);
        assert!(inconclusive.results[0].mutant_paths.is_empty());
        assert_eq!(inconclusive.results[0].mutated_stdout_digest, None);
        assert_eq!(inconclusive.results[0].mutated_stderr_digest, None);
        assert!(validator.is_valid(&serde_json::to_value(&inconclusive).unwrap()));
    }

    #[test]
    fn corpus_manifest_rejects_patch_path_escape() {
        let workspace = tempfile::tempdir().unwrap();
        let corpus_dir = workspace.path().join("corpus");
        fs::create_dir_all(&corpus_dir).unwrap();
        let patch = b"not used before path validation";
        fs::write(workspace.path().join("outside.patch"), patch).unwrap();
        let manifest_path = corpus_dir.join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "corpus_id": "fixture-v1",
                "mutants": [{"id":"escape","patch":"../outside.patch","patch_digest":vee_core::digest(patch)}]
            }))
            .unwrap(),
        )
        .unwrap();
        let snapshot = ChangeSet::from_entries(None, None, "commit", vec![]);
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "false".into(),
            args: vec![],
            env_allowlist: vec![],
            timeout_seconds: 1,
            output_limit_bytes: 1024,
            sarif: None,
        };
        let error = assess_corpus(
            workspace.path(),
            &snapshot,
            "proposal",
            "profile",
            "baseline",
            &profile,
            &manifest_path,
        )
        .unwrap_err();
        assert!(error.contains("escapes the corpus directory"), "{error}");
    }
}
