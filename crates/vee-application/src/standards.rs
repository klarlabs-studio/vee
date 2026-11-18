use schemars::JsonSchema;
use serde::Serialize;
use std::path::{Component, Path, PathBuf};

const MAX_RULE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;
const MAX_SOURCES: usize = 128;
const MAX_DISCOVERY_PER_DIRECTORY: usize = 256;

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct StandardsReport {
    pub schema_version: u32,
    pub target_path: Option<String>,
    pub sources: Vec<StandardSource>,
    pub potential_conflicts: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct StandardSource {
    pub path: String,
    pub kind: String,
    pub precedence: u8,
    pub scope: String,
    /// Hash of the bounded content excerpt returned in `content`.
    pub content_digest: String,
    /// Whether bytes were pinned before fetch or merely hashed after retrieval.
    pub integrity: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct RemoteSourceRecord {
    schema_version: u32,
    id: String,
    url: String,
    scope: String,
    content_digest: String,
    integrity: String,
}

#[derive(Clone, Debug)]
struct Candidate {
    relative: PathBuf,
    kind: &'static str,
    precedence: u8,
    scope: String,
}

pub fn resolve(root: &Path, target: Option<&Path>) -> Result<StandardsReport, String> {
    let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let target = target.map(normalize_target).transpose()?;
    let mut candidates = Vec::new();
    let mut discovery_truncated = false;

    let mut add = |relative: PathBuf,
                   kind: &'static str,
                   precedence: u8,
                   scope: String|
     -> Result<(), String> {
        if has_symlink_parent(&root, &relative) {
            return Ok(());
        }
        let path = root.join(&relative);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("inspect {}: {error}", relative.display())),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(());
        }
        candidates.push(Candidate {
            relative,
            kind,
            precedence,
            scope,
        });
        Ok(())
    };

    for (file, kind, precedence) in [
        ("AGENTS.md", "agent_instructions", 50),
        ("CLAUDE.md", "agent_instructions", 50),
        ("GEMINI.md", "agent_instructions", 50),
        (".github/copilot-instructions.md", "agent_instructions", 50),
        (".vee/policy.yaml", "protected_policy", 100),
    ] {
        add(
            PathBuf::from(file),
            kind,
            precedence,
            "repository-wide".into(),
        )?;
    }

    if let Some(target) = &target {
        let mut parent = target.parent();
        while let Some(directory) = parent {
            if !directory.as_os_str().is_empty() {
                for file in ["AGENTS.md", "CLAUDE.md", "GEMINI.md"] {
                    let relative = directory.join(file);
                    add(
                        relative,
                        "agent_instructions",
                        (60 + directory.components().count().min(30)) as u8,
                        format!("applies to {}/ descendants", directory.display()),
                    )?;
                }
            }
            if directory.as_os_str().is_empty() {
                break;
            }
            parent = directory.parent();
        }
    }

    for (directory, extension, kind, precedence) in [
        (".vee/reviewers", "md", "reviewer_instructions", 80),
        (".cursor/rules", "mdc", "editor_rule", 50),
        (".claude/rules", "md", "agent_instructions", 50),
    ] {
        let base = root.join(directory);
        if has_symlink_parent(&root, Path::new(directory))
            || std::fs::symlink_metadata(&base)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            continue;
        }
        let entries = match std::fs::read_dir(&base) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("read {}: {error}", directory)),
        };
        let mut paths = std::collections::BTreeSet::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("read entry in {directory}: {error}"))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(extension) {
                continue;
            }
            if std::fs::symlink_metadata(&path)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            {
                paths.insert(path);
                if paths.len() > MAX_DISCOVERY_PER_DIRECTORY {
                    paths.pop_last();
                    discovery_truncated = true;
                }
            }
        }
        for path in paths {
            let relative = path
                .strip_prefix(&root)
                .expect("discovered below repository root");
            add(
                relative.to_path_buf(),
                kind,
                precedence,
                "repository-wide; editor frontmatter scope is not interpreted".into(),
            )?;
        }
    }

    candidates.sort_by(|left, right| {
        right
            .precedence
            .cmp(&left.precedence)
            .then_with(|| left.relative.cmp(&right.relative))
    });
    let mut omitted_by_source_cap = candidates.len().saturating_sub(MAX_SOURCES);
    candidates.truncate(MAX_SOURCES);

    let mut total_content = 0usize;
    let mut sources = Vec::new();
    let mut omitted_by_byte_cap = 0usize;
    let mut tier_counts = std::collections::BTreeMap::<u8, Vec<String>>::new();
    for candidate in candidates {
        if total_content >= MAX_TOTAL_BYTES {
            omitted_by_byte_cap += 1;
            continue;
        }
        let remaining = MAX_TOTAL_BYTES - total_content;
        let read_limit = remaining.min(MAX_RULE_BYTES);
        let (bytes, extra_byte) = read_bounded(&root.join(&candidate.relative), read_limit)?;
        let mut content = String::from_utf8_lossy(&bytes).into_owned();
        let decoded_truncated = content.len() > read_limit;
        if decoded_truncated {
            let boundary = content
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|index| *index <= read_limit)
                .last()
                .unwrap_or(0);
            content.truncate(boundary);
        }
        total_content += content.len();
        let path = candidate.relative.to_string_lossy().replace('\\', "/");
        tier_counts
            .entry(candidate.precedence)
            .or_default()
            .push(path.clone());
        sources.push(StandardSource {
            path,
            kind: candidate.kind.into(),
            precedence: candidate.precedence,
            scope: candidate.scope,
            content_digest: vee_core::digest(content.as_bytes()),
            integrity: "local-content-hash".into(),
            content,
            truncated: extra_byte || decoded_truncated,
        });
    }

    let remote_dir = root.join(".vee/standards-cache");
    let remote_cache_safe = !std::fs::symlink_metadata(root.join(".vee"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && !std::fs::symlink_metadata(&remote_dir)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
    if remote_cache_safe && remote_dir.is_dir() {
        let mut records = std::fs::read_dir(&remote_dir)
            .map_err(|error| format!("read remote standards cache: {error}"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        records.sort();
        for record_path in records {
            if sources.len() >= MAX_SOURCES {
                omitted_by_source_cap += 1;
                continue;
            }
            if total_content >= MAX_TOTAL_BYTES {
                omitted_by_byte_cap += 1;
                continue;
            }
            let (record_bytes, _) = read_bounded(&record_path, 4096)?;
            let record: RemoteSourceRecord = serde_json::from_slice(&record_bytes)
                .map_err(|error| format!("parse {}: {error}", record_path.display()))?;
            if record.schema_version != 1 || !valid_source_id(&record.id) {
                return Err(format!(
                    "invalid remote standards record {}",
                    record_path.display()
                ));
            }
            let record_url = reqwest::Url::parse(&record.url).map_err(|error| {
                format!("invalid URL in standards record {}: {error}", record.id)
            })?;
            if record_url.scheme() != "https"
                || record_url.host_str().is_none()
                || !record_url.username().is_empty()
                || record_url.password().is_some()
                || record_url.query().is_some()
                || record_url.fragment().is_some()
                || !matches!(
                    record.integrity.as_str(),
                    "sha256-pinned" | "post-fetch-hash-only"
                )
            {
                return Err(format!(
                    "invalid provenance in remote standards record {}",
                    record.id
                ));
            }
            let content_path = remote_dir.join(format!("{}.md", record.id));
            let remaining = MAX_TOTAL_BYTES - total_content;
            let metadata = std::fs::symlink_metadata(&content_path)
                .map_err(|error| format!("inspect {}: {error}", content_path.display()))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "remote standards cache entry {} is not a regular file",
                    content_path.display()
                ));
            }
            if metadata.len() > remaining.min(MAX_RULE_BYTES) as u64 {
                omitted_by_byte_cap += 1;
                continue;
            }
            let (bytes, extra_byte) = read_bounded(&content_path, remaining.min(MAX_RULE_BYTES))?;
            let content = String::from_utf8_lossy(&bytes).into_owned();
            let actual_digest = vee_core::digest(content.as_bytes());
            if actual_digest != record.content_digest {
                return Err(format!(
                    "remote standards cache digest mismatch for {}",
                    record.id
                ));
            }
            total_content += content.len();
            sources.push(StandardSource {
                path: format!("remote:{} ({})", record.id, record.url),
                kind: "remote_standard".into(),
                precedence: 40,
                scope: record.scope,
                content_digest: actual_digest,
                integrity: record.integrity,
                content,
                truncated: extra_byte,
            });
            tier_counts
                .entry(40)
                .or_default()
                .push(format!("remote:{}", record.id));
        }
    }
    sources.sort_by(|left, right| {
        right
            .precedence
            .cmp(&left.precedence)
            .then_with(|| left.path.cmp(&right.path))
    });

    let potential_conflicts = tier_counts
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(tier, paths)| {
            format!(
                "multiple independent standards sources share precedence {tier}: {}; review for semantic conflicts (Vee does not infer contradiction from prose)",
                paths.join(", ")
            )
        })
        .collect();
    let mut limitations = vec![
        "Standards are reported with provenance; Vee does not infer semantic contradictions between prose rules.".into(),
        "Editor-rule frontmatter and path globs are not evaluated; those files are marked repository-wide.".into(),
        "Only repository-root agent files and ancestor AGENTS.md/CLAUDE.md/GEMINI.md files are discovered.".into(),
        "Each source is capped at 64 KiB; total returned source content is capped at 256 KiB.".into(),
        "Remote standards are guidance only; they cannot define or weaken Vee gate policy.".into(),
    ];
    if omitted_by_source_cap > 0 {
        limitations.push(format!(
            "{} lower-precedence standards sources omitted after the {MAX_SOURCES}-source cap",
            omitted_by_source_cap
        ));
    }
    if discovery_truncated {
        limitations.push(format!(
            "only the {MAX_DISCOVERY_PER_DIRECTORY} lexicographically earliest matching files per rule directory are retained"
        ));
    }
    if omitted_by_byte_cap > 0 {
        limitations.push(format!(
            "{omitted_by_byte_cap} standards sources omitted after the {MAX_TOTAL_BYTES}-byte aggregate read cap"
        ));
    }
    Ok(StandardsReport {
        schema_version: 1,
        target_path: target.map(|path| path.to_string_lossy().replace('\\', "/")),
        sources,
        potential_conflicts,
        limitations,
    })
}

pub fn sync_remote(
    root: &Path,
    id: &str,
    url: &str,
    scope: &str,
    expected_digest: Option<&str>,
) -> Result<String, String> {
    use std::io::Read;
    if !valid_source_id(id) {
        return Err(
            "source ID must contain only ASCII letters, digits, '-' or '_' (1–64 chars)".into(),
        );
    }
    if scope.trim().is_empty() || scope.len() > 512 {
        return Err("source scope must be non-empty and at most 512 bytes".into());
    }
    let parsed =
        reqwest::Url::parse(url).map_err(|error| format!("invalid source URL: {error}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
    {
        return Err("remote standards URL must be HTTPS, have a host, and contain no credentials, query, or fragment".into());
    }
    let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let cache = root.join(".vee/standards-cache");
    if std::fs::symlink_metadata(root.join(".vee"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("standards cache path cannot be a symlink".into());
    }
    std::fs::create_dir_all(&cache).map_err(|error| format!("create standards cache: {error}"))?;
    if std::fs::symlink_metadata(&cache).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("standards cache path cannot be a symlink".into());
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("build standards HTTP client: {error}"))?;
    let response = client
        .get(parsed)
        .header(reqwest::header::USER_AGENT, "vee-standards/0.1")
        .send()
        .map_err(|error| format!("fetch remote standards: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "remote standards server returned {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RULE_BYTES as u64)
    {
        return Err(format!(
            "remote standards document exceeds {MAX_RULE_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::new();
    response
        .take((MAX_RULE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read remote standards response: {error}"))?;
    if bytes.len() > MAX_RULE_BYTES {
        return Err(format!(
            "remote standards document exceeds {MAX_RULE_BYTES} bytes"
        ));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| "remote standards document must be UTF-8".to_string())?;
    let digest = vee_core::digest(content.as_bytes());
    let integrity = if let Some(expected) = expected_digest {
        if expected != digest {
            return Err(format!(
                "remote standards digest mismatch: expected {expected}, received {digest}"
            ));
        }
        "sha256-pinned"
    } else {
        "post-fetch-hash-only"
    };
    let record = RemoteSourceRecord {
        schema_version: 1,
        id: id.into(),
        url: url.into(),
        scope: scope.into(),
        content_digest: digest.clone(),
        integrity: integrity.into(),
    };
    atomic_write(&cache.join(format!("{id}.md")), content.as_bytes())?;
    atomic_write(
        &cache.join(format!("{id}.json")),
        &serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
    )?;
    Ok(digest)
}

pub fn remove_remote(root: &Path, id: &str) -> Result<(), String> {
    if !valid_source_id(id) {
        return Err(
            "source ID must contain only ASCII letters, digits, '-' or '_' (1–64 chars)".into(),
        );
    }
    let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let vee_dir = root.join(".vee");
    let cache = vee_dir.join("standards-cache");
    for path in [&vee_dir, &cache] {
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err("standards cache path cannot be a symlink".into());
        }
    }
    let record = cache.join(format!("{id}.json"));
    let content = cache.join(format!("{id}.md"));
    let record_metadata = std::fs::symlink_metadata(&record)
        .map_err(|error| format!("remote standards source {id} is not cached: {error}"))?;
    let content_metadata = std::fs::symlink_metadata(&content)
        .map_err(|error| format!("remote standards content {id} is not cached: {error}"))?;
    if !record_metadata.is_file()
        || record_metadata.file_type().is_symlink()
        || !content_metadata.is_file()
        || content_metadata.file_type().is_symlink()
    {
        return Err(format!(
            "remote standards cache entry {id} is not a pair of regular files"
        ));
    }
    std::fs::remove_file(&record)
        .map_err(|error| format!("remove {}: {error}", record.display()))?;
    std::fs::remove_file(&content)
        .map_err(|error| format!("remove {}: {error}", content.display()))?;
    Ok(())
}

fn valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| format!("create {}: {error}", temp.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", temp.display()))?;
    file.sync_all()
        .map_err(|error| format!("flush {}: {error}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|error| format!("install {}: {error}", path.display()))
}

fn read_bounded(path: &Path, limit: usize) -> Result<(Vec<u8>, bool), String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("open standards source {}: {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| format!("inspect standards source {}: {error}", path.display()))?
        .is_file()
    {
        return Err(format!(
            "standards source {} is no longer a regular file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read standards source {}: {error}", path.display()))?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, truncated))
}

fn normalize_target(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(
                    "target path must be repository-relative and cannot escape the repository"
                        .into(),
                )
            }
        }
    }
    Ok(normalized)
}

fn has_symlink_parent(root: &Path, relative: &Path) -> bool {
    let mut parent = PathBuf::new();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        parent.push(component);
        if std::fs::symlink_metadata(root.join(&parent))
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standards_content_and_source_counts_are_bounded_before_return() {
        let root = tempfile::tempdir().unwrap();
        let rules = root.path().join(".vee/reviewers");
        std::fs::create_dir_all(&rules).unwrap();
        for index in 0..6 {
            std::fs::write(
                rules.join(format!("rule-{index:02}.md")),
                vec![b'x'; MAX_RULE_BYTES],
            )
            .unwrap();
        }
        let report = resolve(root.path(), None).unwrap();
        let content_bytes = report
            .sources
            .iter()
            .map(|source| source.content.len())
            .sum::<usize>();
        assert_eq!(content_bytes, MAX_TOTAL_BYTES);
        assert_eq!(report.sources.len(), 4);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("2 standards sources omitted")));
    }

    #[test]
    fn standards_source_count_is_capped() {
        let root = tempfile::tempdir().unwrap();
        let rules = root.path().join(".vee/reviewers");
        std::fs::create_dir_all(&rules).unwrap();
        for index in 0..140 {
            std::fs::write(rules.join(format!("rule-{index:03}.md")), "rule\n").unwrap();
        }
        let report = resolve(root.path(), None).unwrap();
        assert_eq!(report.sources.len(), MAX_SOURCES);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("12 lower-precedence")));
    }

    #[test]
    fn excerpt_digest_matches_utf8_safe_returned_content() {
        let root = tempfile::tempdir().unwrap();
        let rules = root.path().join(".vee/reviewers");
        std::fs::create_dir_all(&rules).unwrap();
        let mut bytes = vec![b'x'; MAX_RULE_BYTES - 1];
        bytes.extend_from_slice("€".as_bytes());
        std::fs::write(rules.join("multibyte.md"), bytes).unwrap();

        let report = resolve(root.path(), None).unwrap();
        let source = report
            .sources
            .iter()
            .find(|source| source.path.ends_with("multibyte.md"))
            .unwrap();
        assert!(source.truncated);
        assert!(source.content.is_char_boundary(source.content.len()));
        assert!(source.content.len() <= MAX_RULE_BYTES);
        assert_eq!(
            source.content_digest,
            vee_core::digest(source.content.as_bytes())
        );
    }

    #[test]
    fn remote_sync_requires_explicit_safe_source_metadata() {
        let root = tempfile::tempdir().unwrap();
        assert!(sync_remote(
            root.path(),
            "bad/id",
            "https://example.com/rules.md",
            "repo",
            None
        )
        .unwrap_err()
        .contains("source ID"));
        assert!(sync_remote(
            root.path(),
            "team-rules",
            "http://example.com/rules.md",
            "repo",
            None
        )
        .unwrap_err()
        .contains("HTTPS"));
        assert!(sync_remote(
            root.path(),
            "team-rules",
            "https://user:pass@example.com/rules.md",
            "repo",
            None
        )
        .unwrap_err()
        .contains("credentials"));
        assert!(sync_remote(
            root.path(),
            "team-rules",
            "https://example.com/rules.md?token=secret",
            "repo",
            None
        )
        .unwrap_err()
        .contains("query"));
        assert!(!root.path().join(".vee").exists());
    }

    #[test]
    fn cached_remote_standards_keep_provenance_and_cannot_become_policy() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join(".vee/standards-cache");
        std::fs::create_dir_all(&cache).unwrap();
        let content = "Prefer explicit error types.\n";
        let record = RemoteSourceRecord {
            schema_version: 1,
            id: "team-guidance".into(),
            url: "https://standards.example/team/guidance.md".into(),
            scope: "organization/team-a".into(),
            content_digest: vee_core::digest(content.as_bytes()),
            integrity: "sha256-pinned".into(),
        };
        std::fs::write(cache.join("team-guidance.md"), content).unwrap();
        std::fs::write(
            cache.join("team-guidance.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        let report = resolve(root.path(), None).unwrap();
        let source = report
            .sources
            .iter()
            .find(|source| source.kind == "remote_standard")
            .unwrap();
        assert_eq!(source.integrity, "sha256-pinned");
        assert_eq!(source.scope, "organization/team-a");
        assert_eq!(source.content, content);
        assert_ne!(source.kind, "protected_policy");
    }

    #[test]
    fn removing_remote_standards_deletes_only_the_selected_cache_pair() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join(".vee/standards-cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("keep.md"), "keep\n").unwrap();
        std::fs::write(cache.join("keep.json"), "{}\n").unwrap();
        std::fs::write(cache.join("remove.md"), "remove\n").unwrap();
        std::fs::write(cache.join("remove.json"), "{}\n").unwrap();

        remove_remote(root.path(), "remove").unwrap();
        assert!(!cache.join("remove.md").exists());
        assert!(!cache.join("remove.json").exists());
        assert!(cache.join("keep.md").exists());
        assert!(cache.join("keep.json").exists());
        assert!(remove_remote(root.path(), "../keep").is_err());
    }
}
