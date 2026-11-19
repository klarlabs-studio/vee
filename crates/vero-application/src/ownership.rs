use globset::{GlobBuilder, GlobMatcher};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_CODEOWNERS_BYTES: u64 = 256 * 1024;
const MAX_CODEOWNERS_RULES: usize = 4096;
const MAX_OWNER_PATHS: usize = 256;

#[derive(Debug, Serialize)]
pub struct OwnershipReport {
    pub schema_version: u32,
    pub advisory_only: bool,
    pub repository_root: String,
    pub codeowners_path: Option<String>,
    pub codeowners_digest: Option<String>,
    pub coverage_complete: bool,
    pub results: Vec<OwnershipResult>,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Serialize)]
pub struct OwnershipResult {
    pub path: String,
    pub status: String,
    pub owners: Vec<String>,
    pub matching_rule_line: Option<u32>,
    pub matching_pattern: Option<String>,
}

struct Rule {
    line: u32,
    pattern: String,
    matcher: GlobMatcher,
    owners: Vec<String>,
}

pub fn analyze(root: &Path, paths: &[PathBuf]) -> Result<OwnershipReport, String> {
    if paths.is_empty() {
        return Err("provide at least one path to resolve ownership".into());
    }
    if paths.len() > MAX_OWNER_PATHS {
        return Err(format!("ownership path limit is {MAX_OWNER_PATHS}"));
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    if !root.is_dir() {
        return Err("repository root is not a directory".into());
    }
    let mut normalized_paths = Vec::with_capacity(paths.len());
    for path in paths {
        let candidate = if path.is_absolute() {
            path.clone()
        } else {
            root.join(path)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|error| format!("cannot resolve path {}: {error}", path.display()))?;
        let relative = canonical
            .strip_prefix(&root)
            .map_err(|_| format!("path escapes repository root: {}", path.display()))?;
        normalized_paths.push(relative.to_string_lossy().replace('\\', "/"));
    }
    normalized_paths.sort();
    normalized_paths.dedup();

    let codeowners = find_codeowners(&root)?;
    let mut limitations = Vec::new();
    let mut coverage_complete = true;
    let (codeowners_path, codeowners_digest, rules) = if let Some((path, bytes)) = codeowners {
        let digest = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "CODEOWNERS file is not valid UTF-8".to_owned())?;
        let (rules, mut parse_limitations) = parse_rules(text);
        if !parse_limitations.is_empty() {
            coverage_complete = false;
            limitations.append(&mut parse_limitations);
        }
        (Some(path), Some(digest), rules)
    } else {
        limitations
            .push("No CODEOWNERS file was found in the supported repository locations.".into());
        (None, None, Vec::new())
    };

    let results = normalized_paths
        .into_iter()
        .map(|path| resolve_path(path, &rules, codeowners_digest.is_some()))
        .collect();
    limitations.push(
        "Ownership is advisory routing context; CODEOWNERS does not establish authorization or gate approval.".into(),
    );
    limitations.push(
        "Only GitHub-style CODEOWNERS patterns are recognized; negation, escaped whitespace, and inline comments are not supported.".into(),
    );
    limitations.sort();
    limitations.dedup();
    let mut report = OwnershipReport {
        schema_version: 1,
        advisory_only: true,
        repository_root: root.display().to_string(),
        codeowners_path: codeowners_path.map(|path| path.display().to_string()),
        codeowners_digest,
        coverage_complete,
        results,
        limitations,
        digest: String::new(),
    };
    let bytes = serde_json::to_vec(&(
        report.schema_version,
        report.advisory_only,
        &report.repository_root,
        &report.codeowners_path,
        &report.codeowners_digest,
        report.coverage_complete,
        &report.results,
        &report.limitations,
    ))
    .map_err(|error| error.to_string())?;
    report.digest = format!("sha256:{}", hex(&Sha256::digest(bytes)));
    Ok(report)
}

fn find_codeowners(root: &Path) -> Result<Option<(PathBuf, Vec<u8>)>, String> {
    for relative in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] {
        let candidate = root.join(relative);
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot inspect {}: {error}", candidate.display())),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "CODEOWNERS must be a regular file, not a symlink: {}",
                candidate.display()
            ));
        }
        let canonical = candidate
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", candidate.display()))?;
        if !canonical.starts_with(root) {
            return Err(format!(
                "CODEOWNERS escapes repository root: {}",
                candidate.display()
            ));
        }
        if metadata.len() > MAX_CODEOWNERS_BYTES {
            return Err(format!(
                "{} exceeds the {MAX_CODEOWNERS_BYTES} byte limit",
                candidate.display()
            ));
        }
        let bytes = std::fs::read(&canonical)
            .map_err(|error| format!("cannot read {}: {error}", canonical.display()))?;
        if bytes.len() as u64 > MAX_CODEOWNERS_BYTES {
            return Err(format!(
                "{} grew past the {MAX_CODEOWNERS_BYTES} byte limit while being read",
                canonical.display()
            ));
        }
        return Ok(Some((canonical, bytes)));
    }
    Ok(None)
}

fn parse_rules(contents: &str) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut limitations = Vec::new();
    for (line_index, raw) in contents.lines().enumerate() {
        if line_index >= MAX_CODEOWNERS_RULES {
            limitations.push(format!(
                "CODEOWNERS rule scan stopped at the {MAX_CODEOWNERS_RULES} line limit."
            ));
            break;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pattern) = parts.next() else {
            continue;
        };
        let owners: Vec<_> = parts.map(str::to_owned).collect();
        if owners.is_empty() {
            limitations.push(format!(
                "CODEOWNERS line {} has no owner tokens and was skipped.",
                line_index + 1
            ));
            continue;
        }
        let Some(glob) = normalize_pattern(pattern) else {
            limitations.push(format!(
                "CODEOWNERS line {} uses unsupported pattern `{pattern}` and was skipped.",
                line_index + 1
            ));
            continue;
        };
        let matcher = match GlobBuilder::new(&glob)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
        {
            Ok(glob) => glob.compile_matcher(),
            Err(error) => {
                limitations.push(format!(
                    "CODEOWNERS line {} has invalid pattern `{pattern}` ({error}) and was skipped.",
                    line_index + 1
                ));
                continue;
            }
        };
        rules.push(Rule {
            line: (line_index + 1) as u32,
            pattern: pattern.to_owned(),
            matcher,
            owners,
        });
    }
    (rules, limitations)
}

fn normalize_pattern(pattern: &str) -> Option<String> {
    if pattern.starts_with('!') || pattern.contains("\\ ") {
        return None;
    }
    let mut normalized = pattern.trim_start_matches('/').to_owned();
    if normalized.is_empty() {
        return None;
    }
    if normalized.ends_with('/') {
        normalized.push_str("**");
    } else if !normalized.contains('/') {
        normalized = format!("**/{normalized}");
    }
    Some(normalized)
}

fn resolve_path(path: String, rules: &[Rule], has_codeowners: bool) -> OwnershipResult {
    let matching = rules.iter().rfind(|rule| rule.matcher.is_match(&path));
    match matching {
        Some(rule) => OwnershipResult {
            path,
            status: "owned".into(),
            owners: rule.owners.clone(),
            matching_rule_line: Some(rule.line),
            matching_pattern: Some(rule.pattern.clone()),
        },
        None => OwnershipResult {
            path,
            status: if has_codeowners {
                "unowned"
            } else {
                "no_codeowners"
            }
            .into(),
            owners: Vec::new(),
            matching_rule_line: None,
            matching_pattern: None,
        },
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_matching_rule_wins_and_report_binds_rule_file_digest() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/private")).unwrap();
        std::fs::write(root.path().join("src/a.rs"), "").unwrap();
        std::fs::write(root.path().join("src/private/b.rs"), "").unwrap();
        std::fs::write(
            root.path().join("CODEOWNERS"),
            "* @team/all\nsrc/** @team/backend\nsrc/private/* @team/security\n",
        )
        .unwrap();
        let report = analyze(root.path(), &["src/a.rs".into(), "src/private/b.rs".into()]).unwrap();
        assert!(report.advisory_only);
        assert_eq!(report.results[0].owners, vec!["@team/backend"]);
        assert_eq!(report.results[0].matching_rule_line, Some(2));
        assert_eq!(report.results[1].owners, vec!["@team/security"]);
        assert_eq!(report.results[1].matching_rule_line, Some(3));
        assert!(report
            .codeowners_digest
            .as_deref()
            .unwrap()
            .starts_with("sha256:"));
        assert!(report.digest.starts_with("sha256:"));
    }

    #[test]
    fn codeowners_file_precedence_and_unowned_paths_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".github")).unwrap();
        std::fs::write(
            root.path().join(".github/CODEOWNERS"),
            "* @first\nsrc/* @first-subteam\n",
        )
        .unwrap();
        std::fs::write(root.path().join("CODEOWNERS"), "src/* @second\n").unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/file.rs"), "").unwrap();
        std::fs::write(root.path().join("README.md"), "").unwrap();
        let report = analyze(root.path(), &["src/file.rs".into(), "README.md".into()]).unwrap();
        assert!(report
            .codeowners_path
            .as_deref()
            .unwrap()
            .ends_with(".github/CODEOWNERS"));
        assert_eq!(report.results[0].owners, vec!["@first"]);
        assert_eq!(report.results[1].owners, vec!["@first-subteam"]);
    }

    #[test]
    fn ownership_paths_cannot_escape_repository_and_symlinked_codeowners_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "").unwrap();
        assert!(analyze(root.path(), &[outside.path().join("secret")])
            .unwrap_err()
            .contains("escapes repository"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("secret"),
                root.path().join("CODEOWNERS"),
            )
            .unwrap();
            assert!(analyze(root.path(), &[".".into()])
                .unwrap_err()
                .contains("must be a regular file"));
        }
    }
}
