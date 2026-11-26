//! Context & impact: changed symbols and the code that references them, per language analyzer.

use super::*;
use vee_core::paths::CanonicalPath as _;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactEdge {
    pub source_path: String,
    pub affected_path: String,
    pub relationship: String,
    pub symbol: String,
    pub certainty: String,
    /// Line of the reference in `affected_path`; 0 for a `co_change` edge,
    /// which has no line.
    pub evidence_line: u32,
    /// For a `co_change` edge, how often the two files changed together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_change: Option<CoChange>,
}

/// History evidence for a `co_change` edge: of the `source_commits` commits
/// that changed the source file, `together` also changed the affected file.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoChange {
    pub together: u32,
    pub source_commits: u32,
}

/// Commits of history mined for co-change, newest first before the base.
const CO_CHANGE_HISTORY_COMMITS: usize = 1_000;
/// Commits touching more files than this are bulk or tangled changes
/// (formatting, renames, vendoring) and say nothing about coupling.
const CO_CHANGE_MAX_COMMIT_FILES: usize = 30;
/// A pair must have changed together at least this often (the support
/// Zimmermann et al. 2005 use when precision matters; two shared commits in
/// a short history is close to chance)...
const CO_CHANGE_MIN_SUPPORT: u32 = 3;
/// ...and in at least this share (percent) of the source file's commits.
const CO_CHANGE_MIN_CONFIDENCE_PERCENT: u32 = 30;
/// ...and that share must be at least this many times (lift) the affected
/// file's base rate of change, so hub files that change with nearly every
/// commit (changelogs, central registries) are not reported as coupling.
const CO_CHANGE_MIN_LIFT: u32 = 2;
/// Strongest co-change edges kept per changed file.
const CO_CHANGE_MAX_EDGES_PER_FILE: usize = 5;

/// Files that historically changed together with each changed file, mined
/// from first-parent history before the change's base, so the result is
/// fixed for a snapshot. Edges are a second, independent signal to code
/// references: co-change finds coupling that has no reference (schemas,
/// configuration, docs), and union with references beats either alone.
pub(crate) fn co_change_edges(
    commits: &[Vec<String>],
    changed: &std::collections::BTreeSet<String>,
    eligible: &dyn Fn(&str) -> bool,
) -> Vec<ImpactEdge> {
    let commits: Vec<&Vec<String>> = commits
        .iter()
        .filter(|paths| !paths.is_empty() && paths.len() <= CO_CHANGE_MAX_COMMIT_FILES)
        .collect();
    let total = commits.len() as u64;
    let mut changes = std::collections::HashMap::<&str, u64>::new();
    for paths in &commits {
        for path in paths.iter() {
            *changes.entry(path.as_str()).or_default() += 1;
        }
    }
    let mut edges = Vec::new();
    for source in changed.iter().filter(|path| !is_documentation_path(path)) {
        let mut source_commits = 0u32;
        let mut together = std::collections::BTreeMap::<&str, u32>::new();
        for paths in &commits {
            if !paths.iter().any(|path| path == source) {
                continue;
            }
            source_commits += 1;
            for path in paths.iter() {
                if path != source
                    && !changed.contains(path)
                    && !is_documentation_path(path)
                    && eligible(path)
                {
                    *together.entry(path.as_str()).or_default() += 1;
                }
            }
        }
        let mut candidates: Vec<(&str, u32)> = together
            .into_iter()
            .filter(|(path, count)| {
                // Lift: count / source_commits >= MIN_LIFT * changes(path) / total.
                let base_rate = changes.get(path).copied().unwrap_or_default();
                *count >= CO_CHANGE_MIN_SUPPORT
                    && count * 100 >= source_commits * CO_CHANGE_MIN_CONFIDENCE_PERCENT
                    && u64::from(*count) * total
                        >= u64::from(CO_CHANGE_MIN_LIFT) * u64::from(source_commits) * base_rate
            })
            .collect();
        // Strongest first: the denominator is shared, so more shared commits
        // means higher confidence; ties break by path.
        candidates.sort_by(|(left_path, left), (right_path, right)| {
            right.cmp(left).then(left_path.cmp(right_path))
        });
        edges.extend(
            candidates
                .into_iter()
                .take(CO_CHANGE_MAX_EDGES_PER_FILE)
                .map(|(path, count)| ImpactEdge {
                    source_path: source.clone(),
                    affected_path: path.to_owned(),
                    relationship: "co_change".into(),
                    symbol: String::new(),
                    certainty: "historical".into(),
                    evidence_line: 0,
                    co_change: Some(CoChange {
                        together: count,
                        source_commits,
                    }),
                }),
        );
    }
    edges
}

/// Rank an impact edge for the bounded reviewer context; lower sorts first.
///
/// Production references come before tests, so same-package tests cannot
/// crowd callers out of the context cap. Within a relationship, files in the
/// changed file's directory come first, then stronger certainty.
pub(crate) fn impact_context_edge_priority(edge: &ImpactEdge) -> (u8, u8, u8) {
    let relationship = match edge.relationship.as_str() {
        "resolved_symbol_reference" => 0,
        "syntactic_symbol_reference" => 1,
        "textual_symbol_reference" => 2,
        "likely_test_reference" => 3,
        "inferred_import" | "co_change" => 4,
        "shared_local_dependency" => 5,
        _ => 6,
    };
    let directory =
        (Path::new(&edge.source_path).parent() != Path::new(&edge.affected_path).parent()) as u8;
    let certainty = match edge.certainty.as_str() {
        "resolved_semantic" => 0,
        "inferred_heuristic" => 1,
        "inferred_import" => 2,
        _ => 3,
    };
    (relationship, directory, certainty)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactGroup {
    pub package_id: String,
    pub changed_paths: Vec<String>,
    pub member_paths: Vec<String>,
    pub certainty: String,
}

/// Version of the impact assessment document (`impact-assessment-v4`).
pub const IMPACT_SCHEMA_VERSION: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactAssessment {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub coverage_complete: bool,
    pub analyzers: Vec<ImpactAnalyzer>,
    pub changed_paths: Vec<String>,
    pub changed_symbols: Vec<String>,
    pub groups: Vec<ImpactGroup>,
    pub paths: Vec<ImpactEdge>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactAnalyzer {
    pub id: String,
    pub version: Option<String>,
    pub status: String,
}

pub(crate) struct GoImpactAnalysis {
    pub(crate) analyzer: ImpactAnalyzer,
    pub(crate) edges: Vec<ImpactEdge>,
    pub(crate) resolved_symbols: std::collections::BTreeSet<(String, String)>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) struct TypeScriptImpactAnalysis {
    pub(crate) analyzer: ImpactAnalyzer,
    pub(crate) edges: Vec<ImpactEdge>,
    pub(crate) resolved_symbols: std::collections::BTreeSet<(String, String)>,
    pub(crate) limitations: Vec<String>,
}

#[derive(Default)]
pub(crate) struct PythonImpactAnalysis {
    pub(crate) interpreter_version: Option<String>,
    pub(crate) status: String,
    pub(crate) edges: Vec<ImpactEdge>,
    pub(crate) parse_error_paths: std::collections::BTreeSet<String>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) type GoReferenceQuery = (
    String,
    Vec<ImpactEdge>,
    std::collections::BTreeSet<(String, String)>,
    bool,
    bool,
);

pub(crate) type TypeScriptReferenceQuery = (
    Option<String>,
    Vec<ImpactEdge>,
    std::collections::BTreeSet<(String, String)>,
    bool,
    bool,
);

/// Analyze the likely impact of `change_set`.
///
/// The analysis parses every candidate source file, and the dashboard and MCP
/// server ask for the same snapshot repeatedly (each review and finding open),
/// so results are memoized per process while their inputs are unchanged: the
/// change set, the tracked paths, the live checkout state (which covers the
/// `Cargo.toml` files and, for semantic analyzers, the workspace they read),
/// and the tool lookup path. Results from a failed or partial semantic
/// analyzer are not memoized, so a timeout is retried on the next request.
///
/// Paths outside the repository review filter (`review.include` and
/// `review.exclude`, such as generated bundles) are neither scanned nor used
/// as changed-symbol sources; a repository without a readable configuration
/// is analyzed unfiltered.
pub fn analyze_impact(root: &Path, change_set: &ChangeSet) -> Result<ImpactAssessment, String> {
    let typescript_server = find_typescript_server();
    let review_filter = impact_review_filter(root);
    let key = impact_memo_key(
        root,
        change_set,
        typescript_server.as_deref(),
        review_filter.as_ref(),
    );
    if let Some(hit) = key.as_ref().and_then(memoized_impact) {
        return Ok(hit);
    }
    let assessment = analyze_impact_with_typescript_server(
        root,
        change_set,
        typescript_server.as_deref(),
        review_filter.as_ref(),
    )?;
    if let Some(key) = key {
        memoize_impact(key, &assessment);
    }
    Ok(assessment)
}

/// The repository review filter, or `None` when the configuration cannot be
/// read (an unconfigured repository is analyzed unfiltered).
pub(crate) fn impact_review_filter(root: &Path) -> Option<vee_core::ReviewConfig> {
    crate::load_repository_config(root)
        .ok()
        .map(|config| config.review)
}

const IMPACT_MEMO_CAPACITY: usize = 8;

type ImpactMemoKey = [u8; 32];

fn impact_memo(
) -> &'static std::sync::Mutex<std::collections::VecDeque<(ImpactMemoKey, ImpactAssessment)>> {
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::VecDeque<(ImpactMemoKey, ImpactAssessment)>>,
    > = std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

/// `None` when an input cannot be read; the analysis then runs unmemoized.
fn impact_memo_key(
    root: &Path,
    change_set: &ChangeSet,
    typescript_server: Option<&Path>,
    review_filter: Option<&vee_core::ReviewConfig>,
) -> Option<ImpactMemoKey> {
    use sha2::{Digest, Sha256};
    let change = serde_json::to_vec(change_set).ok()?;
    let tracked = vee_git::tracked_paths(root).ok()?;
    let live = vee_git::workspace_state(root).ok()?;
    let lookup_path = std::env::var_os("PATH").unwrap_or_default();
    let filter =
        serde_json::to_vec(&review_filter.map(|filter| (&filter.include, &filter.exclude))).ok()?;
    let mut hasher = Sha256::new();
    let mut part = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    part(root.as_os_str().as_encoded_bytes());
    part(&change);
    part(&live);
    part(typescript_server.map_or(&[][..], |path| path.as_os_str().as_encoded_bytes()));
    part(lookup_path.as_encoded_bytes());
    part(&filter);
    for path in &tracked {
        part(path.as_os_str().as_encoded_bytes());
    }
    Some(hasher.finalize().into())
}

fn memoized_impact(key: &ImpactMemoKey) -> Option<ImpactAssessment> {
    let memo = impact_memo().lock().ok()?;
    memo.iter()
        .find(|(entry, _)| entry == key)
        .map(|(_, assessment)| assessment.clone())
}

fn memoize_impact(key: ImpactMemoKey, assessment: &ImpactAssessment) {
    if assessment
        .analyzers
        .iter()
        .any(|analyzer| matches!(analyzer.status.as_str(), "failed" | "partial"))
    {
        return;
    }
    let Ok(mut memo) = impact_memo().lock() else {
        return;
    };
    memo.retain(|(entry, _)| *entry != key);
    if memo.len() >= IMPACT_MEMO_CAPACITY {
        memo.pop_front();
    }
    memo.push_back((key, assessment.clone()));
}

pub(crate) fn analyze_impact_with_typescript_server(
    root: &Path,
    change_set: &ChangeSet,
    typescript_server: Option<&Path>,
    review_filter: Option<&vee_core::ReviewConfig>,
) -> Result<ImpactAssessment, String> {
    const MAX_SOURCE_FILES: usize = 10_000;
    const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
    const MAX_FILE_BYTES: usize = 512 * 1024;
    // Changed paths outside the review filter (include and exclude) seed no
    // symbols; excluded files are not scanned for references. Files merely
    // outside `include` still are, since their callers remain real impact.
    let in_review_filter = |path: &str| {
        review_filter.is_none_or(|filter| crate::review::review_path_is_included(path, filter))
    };
    let not_excluded = |path: &str| {
        review_filter.is_none_or(|filter| {
            !filter
                .exclude
                .iter()
                .any(|pattern| crate::review::glob_matches(pattern, path))
        })
    };
    let all_changed: std::collections::BTreeSet<String> = change_set
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let changed: std::collections::BTreeSet<String> = all_changed
        .iter()
        .filter(|path| in_review_filter(path))
        .cloned()
        .collect();
    let mut candidates = vee_git::tracked_paths(root)?;
    let candidates_all = candidates.clone();
    candidates.extend(
        change_set
            .files
            .iter()
            .map(|file| Path::new(&file.path).to_path_buf()),
    );
    candidates.retain(|path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "go" | "ts" | "tsx" | "js" | "jsx" | "mts" | "cts" | "py" | "java" | "vue")
        ) && not_excluded(&path.to_string_lossy().replace('\\', "/"))
    });
    candidates.sort_by_key(|path| {
        let relative = path.to_string_lossy().replace('\\', "/");
        (!changed.contains(&relative), relative)
    });
    candidates.dedup();
    let mut source = std::collections::BTreeMap::<String, String>::new();
    let mut coverage_complete = true;
    let mut scanned_bytes = 0usize;
    let mut scan_limit_reached = false;
    // Read in chunks through one `git cat-file --batch` per chunk; a chunk is
    // small enough that stopping at a limit wastes little reading.
    const READ_CHUNK: usize = 256;
    let mut pending = std::collections::VecDeque::new();
    for (index, path) in candidates.iter().enumerate() {
        if index >= MAX_SOURCE_FILES {
            coverage_complete = false;
            scan_limit_reached = true;
            break;
        }
        if pending.is_empty() {
            let end = (index + READ_CHUNK)
                .min(candidates.len())
                .min(MAX_SOURCE_FILES);
            pending.extend(vee_git::read_snapshot_files(
                root,
                change_set,
                &candidates[index..end],
            )?);
        }
        let relative = path.to_string_lossy().replace('\\', "/");
        let bytes = pending
            .pop_front()
            .ok_or("batched snapshot read returned too few files")?;
        if let Some(bytes) = bytes {
            if bytes.len() <= MAX_FILE_BYTES
                && scanned_bytes.saturating_add(bytes.len()) <= MAX_SOURCE_BYTES
            {
                scanned_bytes += bytes.len();
                if let Ok(text) = String::from_utf8(bytes) {
                    // Only a component's script blocks are code; template and
                    // style lines are blanked so line numbers stay true.
                    let text = if is_vue_path(&relative) {
                        vue_script_code(&text)
                    } else {
                        text
                    };
                    source.insert(relative, text);
                } else {
                    coverage_complete = false;
                    scan_limit_reached = true;
                }
            } else {
                coverage_complete = false;
                scan_limit_reached = scanned_bytes.saturating_add(bytes.len()) > MAX_SOURCE_BYTES;
                if scan_limit_reached {
                    break;
                }
            }
        }
    }
    let has_rust_changes = changed.iter().any(|path| path.ends_with(".rs"));
    let has_go_changes = changed.iter().any(|path| path.ends_with(".go"));
    let has_typescript_changes = changed.iter().any(|path| is_typescript_path(path));
    let has_python_changes = changed.iter().any(|path| is_python_path(path));
    let has_java_changes = changed.iter().any(|path| is_java_path(path));
    let go_analysis = analyze_go_references(root, change_set, &changed, &source, coverage_complete);
    let go_module_path = if has_go_changes {
        snapshot_go_module_path(root, change_set)?
    } else {
        None
    };
    let typescript_analysis = analyze_typescript_references(
        root,
        change_set,
        &changed,
        &source,
        coverage_complete,
        typescript_server,
    );
    let mut changed_symbols_by_path = std::collections::BTreeMap::new();
    let mut symbols = std::collections::BTreeSet::new();
    // One Git process reads every changed source file's base side.
    let symbol_paths: Vec<&String> = changed
        .iter()
        .filter(|path| declares_symbols(path))
        .collect();
    let mut base_bytes: std::collections::HashMap<&str, Vec<u8>> =
        vee_git::read_snapshot_base_files(
            root,
            change_set,
            &symbol_paths
                .iter()
                .map(|path| PathBuf::from(path.as_str()))
                .collect::<Vec<_>>(),
        )?
        .into_iter()
        .zip(&symbol_paths)
        .filter_map(|(bytes, path)| Some((path.as_str(), bytes?)))
        .collect();
    // Changed Rust symbols that no declaration exports beyond its crate.
    let mut crate_private_symbols =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    // Declaration kinds of each changed Rust file's changed symbols, from both
    // sides; absent when a side does not parse, so any occurrence matches.
    let mut rust_kinds_by_path = std::collections::BTreeMap::<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeSet<RustDeclKind>>,
    >::new();
    for path in &changed {
        let base = base_bytes.remove(path.as_str());
        let path_symbols =
            changed_file_symbols(path, source.get(path), base.clone(), &mut coverage_complete);
        if path.ends_with(".rs") {
            let base_text = base.and_then(|bytes| String::from_utf8(bytes).ok());
            let kinds = [source.get(path).map(String::as_str), base_text.as_deref()]
                .into_iter()
                .flatten()
                .map(rust_declaration_kinds)
                .collect::<Option<Vec<_>>>();
            if let Some(kinds) = kinds {
                let mut merged = std::collections::BTreeMap::<
                    String,
                    std::collections::BTreeSet<RustDeclKind>,
                >::new();
                for side in kinds {
                    for (name, side_kinds) in side {
                        if path_symbols.contains(&name) {
                            merged.entry(name).or_default().extend(side_kinds);
                        }
                    }
                }
                rust_kinds_by_path.insert(path.clone(), merged);
            }
            let exported = [source.get(path).map(String::as_str), base_text.as_deref()]
                .into_iter()
                .flatten()
                .map(rust_exported_symbols)
                .collect::<Option<Vec<_>>>();
            if let Some(exported) = exported {
                let exported: std::collections::BTreeSet<_> =
                    exported.into_iter().flatten().collect();
                crate_private_symbols.insert(
                    path.clone(),
                    path_symbols
                        .iter()
                        .filter(|symbol| !exported.contains(*symbol))
                        .cloned()
                        .collect(),
                );
            }
        }
        symbols.extend(path_symbols.iter().cloned());
        changed_symbols_by_path.insert(path.clone(), path_symbols);
    }
    let python_analysis = if has_python_changes {
        analyze_python_references(&source, &changed_symbols_by_path)
    } else {
        PythonImpactAnalysis::default()
    };
    if python_analysis.status == "partial" || python_analysis.status == "failed" {
        coverage_complete = false;
    }
    let rust_test_modules = rust_test_module_paths(&source);
    let packages: std::collections::BTreeMap<&str, Option<String>> = source
        .iter()
        .map(|(path, text)| (path.as_str(), package_id(root, path, text)))
        .collect();
    let mut analyzers = Vec::new();
    if has_rust_changes {
        analyzers.push(ImpactAnalyzer {
            id: "syn-rust".into(),
            version: None,
            status: "used".into(),
        });
    }
    if has_go_changes {
        analyzers.push(go_analysis.analyzer.clone());
        analyzers.push(ImpactAnalyzer {
            id: "local-go-imports".into(),
            version: None,
            status: if go_module_path.is_some() {
                "used"
            } else {
                "unavailable"
            }
            .into(),
        });
    }
    if has_typescript_changes {
        analyzers.push(typescript_analysis.analyzer.clone());
    }
    if has_python_changes {
        analyzers.push(ImpactAnalyzer {
            id: "python-ast".into(),
            version: python_analysis.interpreter_version.clone(),
            status: python_analysis.status.clone(),
        });
    }
    if has_java_changes {
        analyzers.push(ImpactAnalyzer {
            id: "lexical-java".into(),
            version: None,
            status: "partial".into(),
        });
    }
    let mut paths = go_analysis.edges.clone();
    paths.extend(typescript_analysis.edges.clone());
    paths.extend(python_analysis.edges.clone());
    if let Some(module_path) = go_module_path.as_deref() {
        paths.extend(go_local_dependency_edges(module_path, &changed, &source));
    }
    // Each Rust candidate is parsed once and queried for every changed file.
    // A candidate that names no changed symbol is not parsed, and only
    // identifiers some changed file declares are kept, so each query scans a
    // few occurrences rather than every identifier in the candidate.
    let changed_symbol_filter = ChangedSymbolFilter::new(
        changed_symbols_by_path
            .values()
            .flatten()
            .map(String::as_str),
    );
    let mut rust_occurrences = std::collections::HashMap::<&str, Option<RustOccurrences>>::new();
    // Comment- and string-stripped TypeScript, Python, and Java, computed once per file.
    let mut stripped_code = std::collections::HashMap::<&str, String>::new();
    for changed_path in &changed {
        let local_symbols: Vec<_> = changed_symbols_by_path
            .get(changed_path)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let crate_private = crate_private_symbols.get(changed_path);
        let exported_symbols: Vec<_> = local_symbols
            .iter()
            .filter(|symbol| crate_private.is_none_or(|private| !private.contains(*symbol)))
            .cloned()
            .collect();
        let symbol_matcher = SymbolMatcher::new(&local_symbols);
        let exported_matcher = SymbolMatcher::new(&exported_symbols);
        let local_wanted: std::collections::HashSet<&str> =
            local_symbols.iter().map(String::as_str).collect();
        let exported_wanted: std::collections::HashSet<&str> =
            exported_symbols.iter().map(String::as_str).collect();
        let changed_package = packages.get(changed_path.as_str()).cloned().flatten();
        let rust_kinds = rust_kinds_by_path.get(changed_path);
        for (candidate_path, candidate_text) in &source {
            let same_file_rust = candidate_path == changed_path && candidate_path.ends_with(".rs");
            // Only Rust keeps same-file edges, for in-file test modules; any
            // other file naming its own declarations is not impact.
            if (candidate_path == changed_path && !same_file_rust)
                || !should_scan_impact_candidate(&changed, changed_path, candidate_path)
                || !same_language_family(changed_path, candidate_path)
            {
                continue;
            }
            // Crate-private items are only reachable from their own package.
            let same_package = changed_package.is_some()
                && packages
                    .get(candidate_path.as_str())
                    .and_then(Option::as_ref)
                    == changed_package.as_ref();
            let (symbol_matcher, wanted) = if same_package {
                (&symbol_matcher, &local_wanted)
            } else {
                (&exported_matcher, &exported_wanted)
            };
            if candidate_path.ends_with(".rs") {
                let occurrences = rust_occurrences
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| {
                        if changed_symbol_filter.may_mention(candidate_text) {
                            rust_identifier_occurrences_matching(candidate_text, &|name| {
                                changed_symbol_filter.contains(name)
                            })
                        } else {
                            Some(RustOccurrences::default())
                        }
                    });
                let mut mentioned = std::collections::HashMap::<String, bool>::new();
                let mut mentions = |owner: &str| {
                    *mentioned
                        .entry(owner.to_owned())
                        .or_insert_with(|| contains_identifier(candidate_text, owner))
                };
                let references = occurrences.as_ref().map(|occurrences| {
                    let mut references: Vec<(String, u32, bool)> = occurrences
                        .found
                        .iter()
                        .filter(|occurrence| {
                            same_file_rust || !occurrences.names_local_item(occurrence)
                        })
                        .filter(|(name, _, _, role)| {
                            wanted.contains(name.as_str())
                                && rust_kinds.and_then(|kinds| kinds.get(name)).is_none_or(
                                    |kinds| rust_role_matches(kinds, role, &mut mentions),
                                )
                        })
                        .map(|(name, line, in_test, _)| (name.clone(), *line, *in_test))
                        .collect();
                    references.dedup();
                    references
                });
                match references {
                    Some(references) => {
                        for (symbol, line, in_test_context) in references {
                            if same_file_rust && !in_test_context {
                                continue;
                            }
                            paths.push(ImpactEdge {
                                source_path: changed_path.clone(),
                                affected_path: candidate_path.clone(),
                                relationship: if is_test_path(candidate_path)
                                    || in_test_context
                                    || rust_test_modules.contains_key(candidate_path)
                                {
                                    "likely_test_reference"
                                } else {
                                    "syntactic_symbol_reference"
                                }
                                .into(),
                                symbol,
                                certainty: "inferred_syntax".into(),
                                evidence_line: line,
                                co_change: None,
                            });
                        }
                    }
                    None => {
                        coverage_complete = false;
                        if same_file_rust {
                            continue;
                        }
                        for (line_index, line) in candidate_text.lines().enumerate() {
                            for symbol in symbol_matcher.matches(line) {
                                {
                                    paths.push(ImpactEdge {
                                        source_path: changed_path.clone(),
                                        affected_path: candidate_path.clone(),
                                        relationship: if is_test_path(candidate_path)
                                            || rust_test_modules.contains_key(candidate_path)
                                        {
                                            "likely_test_reference"
                                        } else {
                                            "textual_symbol_reference"
                                        }
                                        .into(),
                                        symbol: symbol.clone(),
                                        certainty: "inferred_heuristic".into(),
                                        evidence_line: (line_index + 1) as u32,
                                        co_change: None,
                                    });
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if is_typescript_path(candidate_path) || is_vue_path(candidate_path) {
                let code = stripped_code
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| {
                        typescript_code_without_comments_and_strings(candidate_text)
                    });
                // tsserver does not load components, so its answer never
                // covers references from a `.vue` file.
                let resolved_by_server = !is_vue_path(candidate_path);
                for (line_index, line) in code.lines().enumerate() {
                    for symbol in symbol_matcher.matches(line) {
                        if resolved_by_server
                            && typescript_analysis
                                .resolved_symbols
                                .contains(&(changed_path.clone(), symbol.clone()))
                        {
                            // A complete tsserver query is authoritative for this
                            // declaration; lexical matching would reintroduce false
                            // edges for aliases and same-named unrelated symbols.
                            continue;
                        }
                        {
                            paths.push(ImpactEdge {
                                source_path: changed_path.clone(),
                                affected_path: candidate_path.clone(),
                                relationship: if is_test_path(candidate_path) {
                                    "likely_test_reference"
                                } else {
                                    "textual_symbol_reference"
                                }
                                .into(),
                                symbol: symbol.clone(),
                                certainty: "inferred_heuristic".into(),
                                evidence_line: (line_index + 1) as u32,
                                co_change: None,
                            });
                        }
                    }
                }
                continue;
            }
            if is_python_path(candidate_path) {
                if is_python_path(changed_path)
                    && !python_analysis.parse_error_paths.contains(candidate_path)
                {
                    continue;
                }
                let code = stripped_code
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| python_code_without_comments_and_strings(candidate_text));
                for (line_index, line) in code.lines().enumerate() {
                    for symbol in symbol_matcher.matches(line) {
                        {
                            paths.push(ImpactEdge {
                                source_path: changed_path.clone(),
                                affected_path: candidate_path.clone(),
                                relationship: if is_test_path(candidate_path) {
                                    "likely_test_reference"
                                } else {
                                    "textual_symbol_reference"
                                }
                                .into(),
                                symbol: symbol.clone(),
                                certainty: "inferred_heuristic".into(),
                                evidence_line: (line_index + 1) as u32,
                                co_change: None,
                            });
                        }
                    }
                }
                continue;
            }
            if is_java_path(candidate_path) {
                let code = stripped_code
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| java_code_without_comments_and_strings(candidate_text));
                for (line_index, line) in code.lines().enumerate() {
                    for symbol in symbol_matcher.matches(line) {
                        {
                            paths.push(ImpactEdge {
                                source_path: changed_path.clone(),
                                affected_path: candidate_path.clone(),
                                relationship: if is_test_path(candidate_path) {
                                    "likely_test_reference"
                                } else {
                                    "textual_symbol_reference"
                                }
                                .into(),
                                symbol: symbol.clone(),
                                certainty: "inferred_heuristic".into(),
                                evidence_line: (line_index + 1) as u32,
                                co_change: None,
                            });
                        }
                    }
                }
                continue;
            }
            for (line_index, line) in candidate_text.lines().enumerate() {
                let code_line = go_code_without_comments_and_strings(line);
                for symbol in symbol_matcher.matches(&code_line) {
                    if go_analysis
                        .resolved_symbols
                        .contains(&(changed_path.clone(), symbol.clone()))
                    {
                        continue;
                    }
                    {
                        paths.push(ImpactEdge {
                            source_path: changed_path.clone(),
                            affected_path: candidate_path.clone(),
                            relationship: if is_test_path(candidate_path) {
                                "likely_test_reference"
                            } else {
                                "textual_symbol_reference"
                            }
                            .into(),
                            symbol: symbol.clone(),
                            certainty: "inferred_heuristic".into(),
                            evidence_line: (line_index + 1) as u32,
                            co_change: None,
                        });
                    }
                }
            }
        }
    }
    let history_revision = change_set
        .base_oid
        .as_deref()
        .or(change_set.head_oid.as_deref());
    let tracked: std::collections::HashSet<String> = candidates_all
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect();
    let history = history_revision
        .map(|revision| vee_git::commit_paths(root, revision, CO_CHANGE_HISTORY_COMMITS));
    analyzers.push(ImpactAnalyzer {
        id: "git-co-change".into(),
        version: None,
        status: match &history {
            Some(Ok(_)) => "used",
            Some(Err(_)) => "failed",
            None => "unavailable",
        }
        .into(),
    });
    if let Some(Ok(commits)) = &history {
        paths.extend(co_change_edges(commits, &changed, &|path| {
            tracked.contains(path) && not_excluded(path)
        }));
    }
    paths.sort_by(|a, b| {
        (&a.source_path, &a.affected_path, a.evidence_line, &a.symbol).cmp(&(
            &b.source_path,
            &b.affected_path,
            b.evidence_line,
            &b.symbol,
        ))
    });
    paths.dedup();
    let mut group_map = std::collections::BTreeMap::<String, (Vec<String>, Vec<String>)>::new();
    for path in source.keys() {
        if let Some(package) = packages.get(path.as_str()).cloned().flatten() {
            let entry = group_map.entry(package).or_default();
            entry.1.push(path.clone());
            if changed.contains(path) {
                entry.0.push(path.clone());
            }
        }
    }
    let affected_paths: std::collections::BTreeSet<_> = paths
        .iter()
        .map(|edge| edge.affected_path.as_str())
        .collect();
    let groups = group_map
        .into_iter()
        .filter_map(|(package_id, (mut changed_paths, mut member_paths))| {
            if changed_paths.is_empty()
                && !member_paths
                    .iter()
                    .any(|path| affected_paths.contains(path.as_str()))
            {
                return None;
            }
            changed_paths.sort();
            member_paths.sort();
            Some(ImpactGroup {
                package_id,
                changed_paths,
                member_paths,
                certainty: "heuristic_package_membership".into(),
            })
        })
        .collect();
    let mut limitations = vec![
        "Rust references are syntax-derived identifier paths, not type-resolved; aliases and dynamic dispatch may be missed.".into(),
        "Package membership is inferred from Rust Cargo.toml ancestry or Go package declarations.".into(),
        "Generated code, reflection, cross-service calls, and runtime behavior are not modeled.".into(),
        format!("Co-change edges come from the {CO_CHANGE_HISTORY_COMMITS} most recent first-parent commits before the base, skip commits touching more than {CO_CHANGE_MAX_COMMIT_FILES} files, and need {CO_CHANGE_MIN_SUPPORT}+ shared commits in at least {CO_CHANGE_MIN_CONFIDENCE_PERCENT}% of the changed file's commits and {CO_CHANGE_MIN_LIFT}x the other file's base rate of change; they show coupling, not a code dependency."),
        "Vue components contribute their script blocks and, when PascalCase, their file name; template-only usages are not scanned.".into(),
        "TypeScript and JavaScript references use tsserver project resolution when the reviewed snapshot matches the live workspace; otherwise lexical heuristics may miss aliases, overloads, dynamic imports, template expressions, and runtime dispatch.".into(),
        "Python references are lexical heuristics; imports, aliases, decorators, dynamic dispatch, and runtime behavior are not resolved.".into(),
        "Java references are lexical heuristics; overloads, imports, inheritance, generated code, and runtime dispatch are not resolved.".into(),
    ];
    limitations.extend(go_analysis.limitations);
    if has_go_changes {
        limitations.push("Go local dependency links are derived from module import paths; packages sharing an import are context leads, not proven runtime call relationships.".into());
        if go_module_path.is_none() {
            limitations.push("Local Go dependency analysis was unavailable because the captured snapshot has no readable go.mod module path.".into());
        }
    }
    limitations.extend(typescript_analysis.limitations);
    limitations.extend(python_analysis.limitations);
    if !coverage_complete {
        limitations.push("Some source files were omitted because they were binary, invalid UTF-8, larger than 512 KiB, or the scan reached its file or 32 MiB content limit.".into());
    }
    let filtered_out = all_changed.len() - changed.len();
    if filtered_out > 0 {
        limitations.push(format!("{filtered_out} changed path(s) outside the repository review filter were not analyzed for changed symbols, and files it excludes were not scanned for references."));
    }
    if scan_limit_reached {
        limitations.push("Impact scanning is bounded to 10,000 source files and 32 MiB of decoded source content per assessment.".into());
    }
    Ok(ImpactAssessment {
        schema_version: IMPACT_SCHEMA_VERSION,
        snapshot_id: change_set.digest.clone(),
        coverage_complete,
        analyzers,
        changed_paths: all_changed.into_iter().collect(),
        changed_symbols: symbols.into_iter().collect(),
        groups,
        paths,
        limitations,
    })
}

/// Whether impact analysis extracts declared symbols from files at `path`.
pub(crate) fn declares_symbols(path: &str) -> bool {
    is_vue_path(path)
        || path.ends_with(".rs")
        || path.ends_with(".go")
        || is_typescript_path(path)
        || is_python_path(path)
        || is_java_path(path)
}

/// Symbols declared by a changed file in its current and base versions.
/// The symbols a change adds, removes, or modifies in one file.
///
/// Each declaration is fingerprinted on both sides of the change, and only
/// names whose fingerprints differ are reported. Treating every declaration
/// in a touched file as changed would make one edited function pull in every
/// caller of its unrelated siblings.
pub(crate) fn changed_file_symbols(
    path: &str,
    current: Option<&String>,
    base: Option<Vec<u8>>,
    coverage_complete: &mut bool,
) -> std::collections::BTreeSet<String> {
    if !declares_symbols(path) {
        return std::collections::BTreeSet::new();
    }
    if is_vue_path(path) {
        // A component is referenced by the name it is imported under, which by
        // convention is its PascalCase file name; any edit to it changes it.
        return vue_component_name(path).into_iter().collect();
    }
    let base = match base.map(String::from_utf8) {
        Some(Ok(text)) => Some(text),
        Some(Err(_)) => {
            // Without a readable base side every current declaration may have changed.
            *coverage_complete = false;
            return current
                .map(|text| declaration_fingerprints(path, text, coverage_complete))
                .unwrap_or_default()
                .into_keys()
                .collect();
        }
        None => None,
    };
    let rust_sides = path.ends_with(".rs").then(|| {
        (
            current.map(|text| rust_declaration_fingerprints(text)),
            base.as_deref().map(rust_declaration_fingerprints),
        )
    });
    // Compare like with like: if either Rust side fails to parse, both sides
    // fall back to the lexical fingerprints.
    let (current_fingerprints, base_fingerprints) = match rust_sides {
        Some((current_side, base_side))
            if current_side.as_ref().is_none_or(Option::is_some)
                && base_side.as_ref().is_none_or(Option::is_some) =>
        {
            (
                current_side.flatten().unwrap_or_default(),
                base_side.flatten().unwrap_or_default(),
            )
        }
        rust_sides => {
            if rust_sides.is_some() {
                *coverage_complete = false;
            }
            (
                current
                    .map(|text| lexical_declaration_fingerprints(path, text))
                    .unwrap_or_default(),
                base.as_deref()
                    .map(|text| lexical_declaration_fingerprints(path, text))
                    .unwrap_or_default(),
            )
        }
    };
    let mut changed: std::collections::BTreeSet<String> = current_fingerprints
        .keys()
        .chain(base_fingerprints.keys())
        .filter(|name| current_fingerprints.get(*name) != base_fingerprints.get(*name))
        .cloned()
        .collect();
    if let Some(helpers) = current
        .filter(|_| path.ends_with(".rs"))
        .and_then(|text| rust_test_helper_mentions(text))
    {
        extend_with_test_helpers(&mut changed, &helpers);
        // Helpers private to a test module carry the change but are not
        // themselves reachable from other files.
        changed.retain(|name| {
            current_fingerprints.contains_key(name) || base_fingerprints.contains_key(name)
        });
    }
    changed
}

/// Every declaration in a file, keyed by name, with one fingerprint per
/// declaration of that name (sorted, so reordering is not a change).
pub(crate) type DeclarationFingerprints = std::collections::BTreeMap<String, Vec<String>>;

fn declaration_fingerprints(
    path: &str,
    text: &str,
    coverage_complete: &mut bool,
) -> DeclarationFingerprints {
    if path.ends_with(".rs") {
        if let Some(found) = rust_declaration_fingerprints(text) {
            return found;
        }
        *coverage_complete = false;
    }
    lexical_declaration_fingerprints(path, text)
}

/// Lexical fingerprints: a declaration spans from its declaring line to the
/// next declaring line, compared with whitespace trimmed.
pub(crate) fn lexical_declaration_fingerprints(path: &str, text: &str) -> DeclarationFingerprints {
    let code = if is_typescript_path(path) {
        typescript_code_without_comments_and_strings(text)
    } else if is_python_path(path) {
        python_code_without_comments_and_strings(text)
    } else if is_java_path(path) {
        java_code_without_comments_and_strings(text)
    } else {
        text.to_owned()
    };
    let mut fingerprints = DeclarationFingerprints::new();
    let mut open: Vec<String> = Vec::new();
    let mut region = String::new();
    let mut close = |open: &mut Vec<String>, region: &mut String| {
        for name in open.drain(..) {
            fingerprints.entry(name).or_default().push(region.clone());
        }
        region.clear();
    };
    let top_level = declaration_line_mask(path, &code);
    for (line, top_level) in code.lines().zip(top_level) {
        let names = if !top_level {
            Vec::new()
        } else if is_java_path(path) {
            java_line_declared_symbols(line)
        } else {
            line_declared_symbol(path, line).into_iter().collect()
        };
        if !names.is_empty() {
            close(&mut open, &mut region);
            open = names;
        }
        let trimmed = line.trim();
        if !open.is_empty() && !trimmed.is_empty() {
            region.push_str(trimmed);
            region.push('\n');
        }
    }
    close(&mut open, &mut region);
    for regions in fingerprints.values_mut() {
        regions.sort();
    }
    fingerprints
}

pub(crate) fn snapshot_go_module_path(
    root: &Path,
    change_set: &ChangeSet,
) -> Result<Option<String>, String> {
    let Some(bytes) = vee_git::read_snapshot_file(root, change_set, Path::new("go.mod"))? else {
        return Ok(None);
    };
    let Ok(contents) = String::from_utf8(bytes) else {
        return Ok(None);
    };
    Ok(contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? == "module" {
            Some(fields.next()?.trim_matches(['"', '`']).to_owned())
        } else {
            None
        }
    }))
}

pub(crate) fn go_import_paths(source: &str) -> Vec<(String, u32)> {
    fn import_path(line: &str) -> Option<String> {
        for delimiter in ['"', '`'] {
            if let Some(start) = line.find(delimiter) {
                let rest = &line[start + delimiter.len_utf8()..];
                if let Some(end) = rest.find(delimiter) {
                    return Some(rest[..end].to_owned());
                }
            }
        }
        None
    }

    let mut imports = Vec::new();
    let mut in_block = false;
    for (index, line) in source.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let trimmed = line.trim_start();
        if in_block {
            if trimmed.starts_with(')') {
                in_block = false;
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(path) = import_path(trimmed) {
                imports.push((path, line_number));
            }
            continue;
        }
        let Some(declaration) = trimmed.strip_prefix("import") else {
            continue;
        };
        if declaration.starts_with(char::is_whitespace) {
            let declaration = declaration.trim_start();
            if declaration.starts_with('(') {
                in_block = true;
                continue;
            }
            if let Some(path) = import_path(declaration) {
                imports.push((path, line_number));
            }
        }
    }
    imports
}

/// Find local Go packages that import dependencies also used by changed
/// packages. Shared imports are useful composition context, but remain
/// explicitly heuristic because they do not prove a call relationship.
pub(crate) fn go_local_dependency_edges(
    module_path: &str,
    changed: &std::collections::BTreeSet<String>,
    source: &std::collections::BTreeMap<String, String>,
) -> Vec<ImpactEdge> {
    const MAX_EDGES: usize = 512;
    let imports: std::collections::BTreeMap<_, _> = source
        .iter()
        .filter(|(path, _)| path.ends_with(".go"))
        .map(|(path, text)| (path.clone(), go_import_paths(text)))
        .collect();
    let prefix = format!("{}/", module_path.trim_end_matches('/'));
    let mut edges = Vec::new();
    for changed_path in changed.iter().filter(|path| path.ends_with(".go")) {
        let Some(changed_imports) = imports.get(changed_path) else {
            continue;
        };
        let local_imports: std::collections::BTreeSet<_> = changed_imports
            .iter()
            .filter_map(|(path, _)| path.strip_prefix(&prefix).map(str::to_owned))
            .collect();
        for import_path in &local_imports {
            let package_dir = import_path.trim_end_matches('/');
            for path in source.keys() {
                if !path.ends_with(".go") || path.starts_with(&format!("{package_dir}/")) {
                    continue;
                }
                let Some(peer_imports) = imports.get(path) else {
                    continue;
                };
                let Some((_, evidence_line)) = peer_imports
                    .iter()
                    .find(|(candidate, _)| candidate == &format!("{module_path}/{package_dir}"))
                else {
                    continue;
                };
                if changed.contains(path) {
                    continue;
                }
                edges.push(ImpactEdge {
                    source_path: changed_path.clone(),
                    affected_path: path.clone(),
                    relationship: "shared_local_dependency".into(),
                    symbol: format!("{module_path}/{package_dir}"),
                    certainty: "inferred_import".into(),
                    evidence_line: *evidence_line,
                    co_change: None,
                });
                if edges.len() >= MAX_EDGES {
                    return edges;
                }
            }
        }
    }
    edges
}

/// Whether two paths are in the same language family. Lexical matches
/// across languages (a Rust `run` against Python's `subprocess.run`) are noise.
fn same_language_family(changed_path: &str, candidate_path: &str) -> bool {
    fn family(path: &str) -> Option<&'static str> {
        if path.ends_with(".rs") {
            Some("rust")
        } else if path.ends_with(".go") {
            Some("go")
        } else if is_typescript_path(path) || is_vue_path(path) {
            Some("typescript")
        } else if is_python_path(path) {
            Some("python")
        } else if is_java_path(path) {
            Some("java")
        } else {
            None
        }
    }
    match (family(changed_path), family(candidate_path)) {
        (Some(changed), Some(candidate)) => changed == candidate,
        _ => true,
    }
}

pub(crate) fn should_scan_impact_candidate(
    changed: &std::collections::BTreeSet<String>,
    changed_path: &str,
    candidate_path: &str,
) -> bool {
    let same_file_rust = candidate_path == changed_path && candidate_path.ends_with(".rs");
    !changed.contains(candidate_path)
        || same_file_rust
        || candidate_path.ends_with(".rs")
        || is_test_path(candidate_path)
}

pub(crate) fn analyze_go_references(
    root: &Path,
    change_set: &ChangeSet,
    changed: &std::collections::BTreeSet<String>,
    source: &std::collections::BTreeMap<String, String>,
    coverage_complete: bool,
) -> GoImpactAnalysis {
    #[cfg(test)]
    static GO_SEMANTIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let go_changes: Vec<_> = changed
        .iter()
        .filter(|path| path.ends_with(".go") && source.contains_key(*path))
        .collect();
    let fallback = |status: &str, reason: &str| GoImpactAnalysis {
        analyzer: ImpactAnalyzer {
            id: "gopls".into(),
            version: None,
            status: status.into(),
        },
        edges: Vec::new(),
        resolved_symbols: std::collections::BTreeSet::new(),
        limitations: vec![reason.into()],
    };
    if go_changes.is_empty() {
        return GoImpactAnalysis {
            analyzer: ImpactAnalyzer {
                id: "gopls".into(),
                version: None,
                status: "not_applicable".into(),
            },
            edges: Vec::new(),
            resolved_symbols: std::collections::BTreeSet::new(),
            limitations: Vec::new(),
        };
    }
    if !coverage_complete {
        return fallback(
            "skipped",
            "gopls semantic references were skipped because source scanning was incomplete; Go references use textual fallback.",
        );
    }
    let snapshot_matches_worktree = if change_set.scope == "staged" {
        vee_git::working_tree_matches_index(root).unwrap_or(false)
    } else if change_set.scope == "working_tree" || change_set.scope == "base_and_worktree" {
        capture_current_change_set(root, change_set)
            .is_ok_and(|current| current.digest == change_set.digest)
    } else {
        false
    };
    if !snapshot_matches_worktree {
        return fallback(
            "skipped",
            "gopls semantic references were skipped because the reviewed snapshot does not exactly match the live Go workspace; Go references use textual fallback.",
        );
    }
    let Some(executable) = find_executable("gopls") else {
        return fallback(
            "unavailable",
            "gopls was not found on PATH; Go references use textual fallback.",
        );
    };
    #[cfg(test)]
    let _gopls_test_guard = GO_SEMANTIC_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match query_gopls_references(root, &executable, &go_changes, source) {
        Ok((version, edges, resolved_symbols, failures, limited)) => {
            let status = if failures || limited {
                if resolved_symbols.is_empty() {
                    "failed"
                } else {
                    "partial"
                }
            } else if resolved_symbols.is_empty() {
                "not_applicable"
            } else {
                "used"
            };
            let mut limitations = Vec::new();
            if failures {
                limitations.push("Some gopls reference queries failed; those Go symbols use textual fallback.".into());
            }
            if limited {
                limitations.push("gopls reference analysis reached its 32 declaration or 45 second bound; remaining Go symbols use textual fallback.".into());
            }
            GoImpactAnalysis {
                analyzer: ImpactAnalyzer {
                    id: "gopls".into(),
                    version: Some(version),
                    status: status.into(),
                },
                edges,
                resolved_symbols,
                limitations,
            }
        }
        Err(error) => GoImpactAnalysis {
            analyzer: ImpactAnalyzer {
                id: "gopls".into(),
                version: None,
                status: "failed".into(),
            },
            edges: Vec::new(),
            resolved_symbols: std::collections::BTreeSet::new(),
            limitations: vec![format!("gopls semantic reference analysis failed ({error}); Go references use textual fallback.")],
        },
    }
}

/// Find the program `name` on PATH, as `name.exe` on Windows.
pub(crate) fn find_executable(name: &str) -> Option<PathBuf> {
    let executable = if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(&executable))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.canonical().ok())
}

pub(crate) fn analyze_typescript_references(
    root: &Path,
    change_set: &ChangeSet,
    changed: &std::collections::BTreeSet<String>,
    source: &std::collections::BTreeMap<String, String>,
    coverage_complete: bool,
    configured_server: Option<&Path>,
) -> TypeScriptImpactAnalysis {
    let ts_changes: Vec<_> = changed
        .iter()
        .filter(|path| is_typescript_path(path) && source.contains_key(*path))
        .collect();
    let fallback = |status: &str, reason: &str| TypeScriptImpactAnalysis {
        analyzer: ImpactAnalyzer {
            id: "typescript-language-service".into(),
            version: None,
            status: status.into(),
        },
        edges: Vec::new(),
        resolved_symbols: std::collections::BTreeSet::new(),
        limitations: vec![reason.into()],
    };
    if ts_changes.is_empty() {
        return TypeScriptImpactAnalysis {
            analyzer: ImpactAnalyzer {
                id: "typescript-language-service".into(),
                version: None,
                status: "not_applicable".into(),
            },
            edges: Vec::new(),
            resolved_symbols: std::collections::BTreeSet::new(),
            limitations: Vec::new(),
        };
    }
    if !coverage_complete {
        return fallback(
            "skipped",
            "TypeScript project references were skipped because repository source scanning was incomplete; TypeScript and JavaScript references use lexical fallback.",
        );
    }
    let snapshot_matches_worktree = match change_set.scope.as_str() {
        "staged" => vee_git::working_tree_matches_index(root).unwrap_or(false),
        "working_tree" | "base_and_worktree" => capture_current_change_set(root, change_set)
            .is_ok_and(|current| current.digest == change_set.digest),
        "commit" | "commit_range" => false,
        _ => false,
    };
    if !snapshot_matches_worktree {
        return fallback(
            "skipped",
            "TypeScript project references were skipped because the reviewed snapshot does not exactly match the live workspace; TypeScript and JavaScript references use lexical fallback.",
        );
    }
    let server = configured_server.map(Path::to_path_buf);
    let Some(executable) = server else {
        return fallback(
            "unavailable",
            "tsserver was not found on PATH; TypeScript and JavaScript references use lexical fallback. Install TypeScript and expose its tsserver executable to enable project-aware references.",
        );
    };
    match query_typescript_references(root, &executable, &ts_changes, source) {
        Ok((version, edges, resolved_symbols, failures, limited)) => {
            let status = if failures || limited {
                if resolved_symbols.is_empty() {
                    "failed"
                } else {
                    "partial"
                }
            } else if resolved_symbols.is_empty() {
                "not_applicable"
            } else {
                "used"
            };
            let mut limitations = Vec::new();
            if failures {
                limitations.push("Some TypeScript language-service reference queries failed; those declarations use lexical fallback.".into());
            }
            if limited {
                limitations.push("TypeScript project reference analysis reached its 32-declaration or 45-second bound; remaining declarations use lexical fallback.".into());
            }
            TypeScriptImpactAnalysis {
                analyzer: ImpactAnalyzer {
                    id: "typescript-language-service".into(),
                    version,
                    status: status.into(),
                },
                edges,
                resolved_symbols,
                limitations,
            }
        }
        Err(error) => TypeScriptImpactAnalysis {
            analyzer: ImpactAnalyzer {
                id: "typescript-language-service".into(),
                version: None,
                status: "failed".into(),
            },
            edges: Vec::new(),
            resolved_symbols: std::collections::BTreeSet::new(),
            limitations: vec![format!("TypeScript project reference analysis failed ({error}); TypeScript and JavaScript references use lexical fallback.")],
        },
    }
}

pub(crate) fn typescript_declaration_positions(
    path: &str,
    source: &str,
) -> Vec<(String, u32, u32)> {
    const DECLARATIONS: &[&str] = &[
        "function",
        "class",
        "interface",
        "type",
        "enum",
        "namespace",
        "const",
        "let",
        "var",
    ];
    let code = typescript_code_without_comments_and_strings(source);
    let symbols = declared_symbols(path, &code);
    let mut declarations = Vec::new();
    for (line_index, line) in code.lines().enumerate() {
        let mut search_start = 0usize;
        while let Some(keyword) = DECLARATIONS.iter().find_map(|keyword| {
            line[search_start..]
                .find(keyword)
                .map(|offset| (keyword, search_start + offset))
        }) {
            let (keyword, keyword_start) = keyword;
            let after_keyword = keyword_start + keyword.len();
            let suffix = &line[after_keyword..];
            let whitespace = suffix.len() - suffix.trim_start().len();
            let name_start = after_keyword + whitespace;
            let tail = &line[name_start..];
            let name_len = tail
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'$')
                .count();
            if name_len == 0 {
                search_start = after_keyword;
                continue;
            }
            let name = &tail[..name_len];
            let next = tail[name_len..].trim_start();
            let is_function =
                *keyword == "function" && (next.starts_with('(') || next.starts_with('<'));
            let is_declaration = symbols.contains(name) && (is_function || *keyword != "function");
            if is_declaration {
                let column = line[..name_start].encode_utf16().count().saturating_add(1) as u32;
                declarations.push((name.to_owned(), line_index as u32 + 1, column));
            }
            search_start = name_start + name_len;
            if search_start >= line.len() {
                break;
            }
        }
    }
    declarations.sort();
    declarations.dedup();
    declarations
}

pub(crate) fn find_typescript_server() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("VEE_TSSERVER") {
        return PathBuf::from(configured)
            .canonical()
            .ok()
            .filter(|path| path.is_file());
    }
    find_executable("tsserver")
}

/// Read one `Content-Length`-framed tsserver message; `Ok(None)` at end of
/// output.
///
/// tsserver sets `Content-Length` to the JSON length plus one newline byte but
/// writes the platform newline after the JSON. On Windows that is `\r\n`, so
/// one `\n` is left before the next headers. Blank lines before the first
/// header are therefore skipped rather than read as the end of the headers.
pub(crate) fn read_tsserver_message(
    reader: &mut impl std::io::BufRead,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut content_length = None;
    let mut saw_header = false;
    loop {
        let mut header = Vec::new();
        if reader
            .read_until(b'\n', &mut header)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Ok(None);
        }
        if header.len() > 8192 {
            return Err("tsserver response header exceeded 8 KiB".into());
        }
        if header == b"\r\n" || header == b"\n" {
            if saw_header {
                break;
            }
            continue;
        }
        saw_header = true;
        if let Some(value) = header.strip_prefix(b"Content-Length:") {
            content_length = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok());
        }
    }
    let length = content_length.ok_or("tsserver response omitted Content-Length")?;
    if length > max_bytes {
        return Err(format!(
            "tsserver response exceeded {} MiB",
            max_bytes / (1024 * 1024)
        ));
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(Some(body))
}

pub(crate) fn query_typescript_references(
    root: &Path,
    executable: &Path,
    changed_paths: &[&String],
    source: &std::collections::BTreeMap<String, String>,
) -> Result<TypeScriptReferenceQuery, String> {
    use std::io::{BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    const MAX_REFERENCE_QUERIES: usize = 32;
    const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
    const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
    // A language server's first answer includes loading the project, which
    // takes seconds on a cold or busy machine; the total still bounds it.
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let root = root.canonical().map_err(|error| error.to_string())?;
    let mut command = if executable
        .extension()
        .is_some_and(|extension| extension == "js")
    {
        let node = find_executable("node").ok_or("node was not found on PATH for VEE_TSSERVER")?;
        let mut command = Command::new(node);
        command.arg(executable);
        command
    } else {
        Command::new(executable)
    };
    command
        .arg("--disableAutomaticTypingAcquisition")
        .arg("--maxNodeModuleJsDepth")
        .arg("0")
        .current_dir(&root)
        .env_clear()
        .envs(vee_process::platform_environment())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ["PATH", "HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start tsserver: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("tsserver stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("tsserver stdout unavailable")?;
    let (sender, receiver) = mpsc::channel::<Result<Vec<u8>, String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_tsserver_message(&mut reader, MAX_MESSAGE_BYTES) {
                Ok(Some(body)) => {
                    if sender.send(Ok(body)).is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    });

    fn send(stdin: &mut impl Write, value: &serde_json::Value) -> Result<(), String> {
        let request = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        stdin
            .write_all(&request)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|error| error.to_string())
    }

    fn receive_response(
        receiver: &mpsc::Receiver<Result<Vec<u8>, String>>,
        seq: u64,
        timeout: std::time::Duration,
        server_version: &mut Option<String>,
    ) -> Result<serde_json::Value, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("tsserver request timed out".into());
            }
            let body = receiver
                .recv_timeout(remaining)
                .map_err(|error| error.to_string())??;
            let message: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            if message.get("event").and_then(serde_json::Value::as_str) == Some("telemetry")
                && message
                    .pointer("/body/telemetryEventName")
                    .and_then(serde_json::Value::as_str)
                    == Some("projectInfo")
            {
                *server_version = message
                    .pointer("/body/payload/version")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
            }
            if message
                .get("request_seq")
                .and_then(serde_json::Value::as_u64)
                == Some(seq)
            {
                if message.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(message
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("tsserver request failed")
                        .to_owned());
                }
                return Ok(message
                    .get("body")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
        }
    }

    let outcome = (|| {
        let declaration_count: usize = changed_paths
            .iter()
            .filter_map(|path| source.get(path.as_str()))
            .map(|text| typescript_declaration_positions("source.ts", text).len())
            .sum();
        let mut limited = declaration_count > MAX_REFERENCE_QUERIES;
        let mut query_seq = 1u64;
        let mut failures = false;
        let mut queried = 0usize;
        let mut server_version = None;
        let deadline = std::time::Instant::now() + TOTAL_TIMEOUT;
        let mut edges = Vec::new();
        let mut resolved_symbols = std::collections::BTreeSet::new();
        for changed_path in changed_paths {
            let Some(text) = source.get(changed_path.as_str()) else {
                continue;
            };
            // Outside a tsconfig or jsconfig project the server sees only the
            // open file and what it imports, so it would miss references from
            // other files; those files keep the labelled heuristic edges.
            if !in_typescript_project(&root, changed_path) {
                continue;
            }
            let absolute = root.join(changed_path);
            if !absolute.starts_with(&root) {
                failures = true;
                continue;
            }
            let Ok(absolute) = absolute.canonical() else {
                failures = true;
                continue;
            };
            if !absolute.starts_with(&root) {
                failures = true;
                continue;
            }
            let declarations = typescript_declaration_positions(changed_path, text);
            let mut declaration_counts = std::collections::BTreeMap::<String, usize>::new();
            let mut resolved_counts = std::collections::BTreeMap::<String, usize>::new();
            for (symbol, _, _) in &declarations {
                *declaration_counts.entry(symbol.clone()).or_default() += 1;
            }
            for (symbol, line, offset) in declarations {
                if queried >= MAX_REFERENCE_QUERIES || std::time::Instant::now() >= deadline {
                    limited = true;
                    break;
                }
                send(
                    &mut stdin,
                    &serde_json::json!({
                        "seq": query_seq,
                        "type": "request",
                        "command": "open",
                        "arguments": {"file": absolute}
                    }),
                )?;
                query_seq += 1;
                let reference_seq = query_seq;
                query_seq += 1;
                queried += 1;
                send(
                    &mut stdin,
                    &serde_json::json!({
                        "seq": reference_seq,
                        "type": "request",
                        "command": "references",
                        "arguments": {
                            "file": absolute,
                            "line": line,
                            "offset": offset
                        }
                    }),
                )?;
                let timeout = deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(REQUEST_TIMEOUT);
                let response = match receive_response(
                    &receiver,
                    reference_seq,
                    timeout,
                    &mut server_version,
                ) {
                    Ok(response) => response,
                    Err(_) => {
                        failures = true;
                        continue;
                    }
                };
                let Some(references) = response.get("refs").and_then(serde_json::Value::as_array)
                else {
                    failures = true;
                    continue;
                };
                let mut saw_declaration = false;
                for reference in references {
                    let Some(file_name) = reference.get("file").and_then(serde_json::Value::as_str)
                    else {
                        continue;
                    };
                    let candidate = Path::new(file_name);
                    let Ok(candidate) = candidate.canonical() else {
                        continue;
                    };
                    let Ok(relative) = candidate.strip_prefix(&root) else {
                        continue;
                    };
                    let relative = relative.to_string_lossy().replace('\\', "/");
                    if !source.contains_key(&relative) || !is_typescript_path(&relative) {
                        continue;
                    }
                    let Some(reference_line) = reference
                        .pointer("/start/line")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| value as u32)
                    else {
                        continue;
                    };
                    let reference_offset = reference
                        .pointer("/start/offset")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| value as u32);
                    if relative == **changed_path
                        && reference_line == line
                        && reference_offset == Some(offset)
                    {
                        saw_declaration = true;
                        continue;
                    }
                    // A changed file is not impact of itself.
                    if relative == **changed_path {
                        continue;
                    }
                    edges.push(ImpactEdge {
                        source_path: (*changed_path).clone(),
                        affected_path: relative.clone(),
                        relationship: if is_test_path(&relative) {
                            "likely_test_reference"
                        } else {
                            "resolved_symbol_reference"
                        }
                        .into(),
                        symbol: symbol.clone(),
                        certainty: "resolved_semantic".into(),
                        evidence_line: reference_line,
                        co_change: None,
                    });
                }
                if saw_declaration {
                    *resolved_counts.entry(symbol).or_default() += 1;
                } else {
                    failures = true;
                }
            }
            for (symbol, count) in declaration_counts {
                if resolved_counts.get(&symbol) == Some(&count) {
                    resolved_symbols.insert(((*changed_path).clone(), symbol));
                }
            }
        }
        edges.sort_by(|a, b| {
            (&a.source_path, &a.affected_path, a.evidence_line, &a.symbol).cmp(&(
                &b.source_path,
                &b.affected_path,
                b.evidence_line,
                &b.symbol,
            ))
        });
        edges.dedup();
        Ok((server_version, edges, resolved_symbols, failures, limited))
    })();
    terminate_typescript_server(&mut child);
    outcome
}

/// Whether `relative` lies under a `tsconfig.json` or `jsconfig.json` within
/// `root`, so the TypeScript server loads the whole project around it.
fn in_typescript_project(root: &Path, relative: &str) -> bool {
    let mut directory = Path::new(relative).parent();
    while let Some(current) = directory {
        let absolute = root.join(current);
        if absolute.join("tsconfig.json").is_file() || absolute.join("jsconfig.json").is_file() {
            return true;
        }
        directory = current.parent();
    }
    false
}

#[cfg(unix)]
pub(crate) fn terminate_typescript_server(child: &mut std::process::Child) {
    use std::os::unix::process::ExitStatusExt;
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.wait().map(|status| status.into_raw());
}

#[cfg(not(unix))]
pub(crate) fn terminate_typescript_server(child: &mut std::process::Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn query_gopls_references(
    root: &Path,
    executable: &Path,
    changed_paths: &[&String],
    source: &std::collections::BTreeMap<String, String>,
) -> Result<GoReferenceQuery, String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    const MAX_REFERENCE_QUERIES: usize = 32;
    const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
    const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
    // A language server's first answer includes loading the project, which
    // takes seconds on a cold or busy machine; the total still bounds it.
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let root = root.canonical().map_err(|error| error.to_string())?;
    let root_uri = url::Url::from_directory_path(&root)
        .map_err(|_| "repository root cannot be represented as a file URI")?;
    let mut command = Command::new(executable);
    command
        .arg("serve")
        .current_dir(&root)
        .env_clear()
        .envs(vee_process::platform_environment())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ["PATH", "HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOTELEMETRY", "off");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start gopls: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("gopls stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("gopls stdout unavailable")?;
    let (sender, receiver) = mpsc::channel::<Result<Vec<u8>, String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut content_length = None;
            loop {
                let mut header = Vec::new();
                match reader.read_until(b'\n', &mut header) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        return;
                    }
                }
                if header.len() > 8192 {
                    let _ = sender.send(Err("gopls LSP header exceeded 8 KiB".into()));
                    return;
                }
                if header == b"\r\n" || header == b"\n" {
                    break;
                }
                if let Some(value) = header.strip_prefix(b"Content-Length:") {
                    content_length = std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.trim().parse::<usize>().ok());
                }
            }
            let Some(length) = content_length else {
                let _ = sender.send(Err("gopls LSP message omitted Content-Length".into()));
                return;
            };
            if length > MAX_MESSAGE_BYTES {
                let _ = sender.send(Err("gopls LSP message exceeded 2 MiB".into()));
                return;
            }
            let mut body = vec![0; length];
            if let Err(error) = reader.read_exact(&mut body) {
                let _ = sender.send(Err(error.to_string()));
                return;
            }
            if sender.send(Ok(body)).is_err() {
                return;
            }
        }
    });

    fn send(stdin: &mut impl Write, value: &serde_json::Value) -> Result<(), String> {
        let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        write!(stdin, "Content-Length: {}\r\n\r\n", body.len())
            .and_then(|_| stdin.write_all(&body))
            .and_then(|_| stdin.flush())
            .map_err(|error| error.to_string())
    }

    fn receive_response(
        receiver: &mpsc::Receiver<Result<Vec<u8>, String>>,
        id: u64,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("gopls LSP request timed out".into());
            }
            let body = receiver
                .recv_timeout(remaining)
                .map_err(|error| error.to_string())??;
            let message: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            if message.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                if let Some(error) = message.get("error") {
                    return Err(format!("gopls LSP error: {error}"));
                }
                return Ok(message
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
        }
    }

    let outcome = (|| {
        send(
            &mut stdin,
            &serde_json::json!({
                "jsonrpc":"2.0", "id":1, "method":"initialize",
                "params": {
                    "processId": std::process::id(),
                    "rootUri": root_uri.as_str(),
                    "workspaceFolders": [{"uri":root_uri.as_str(),"name":"vee-snapshot"}],
                    "capabilities": {"workspace":{"workspaceFolders":true},"textDocument":{"references":{"dynamicRegistration":false}}},
                    "initializationOptions": {"staticcheck": false}
                }
            }),
        )?;
        let initialize = receive_response(&receiver, 1, REQUEST_TIMEOUT)?;
        let version = initialize
            .pointer("/serverInfo/version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        send(
            &mut stdin,
            &serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        )?;

        let go_source_count = source.keys().filter(|path| path.ends_with(".go")).count();
        let mut uris = std::collections::BTreeMap::new();
        for (path, contents) in source
            .iter()
            .filter(|(path, _)| path.ends_with(".go"))
            .take(256)
        {
            let absolute = root.join(path);
            if !absolute.starts_with(&root) {
                continue;
            }
            let uri = url::Url::from_file_path(&absolute)
                .map_err(|_| format!("Go path is not representable as a file URI: {path}"))?;
            send(
                &mut stdin,
                &serde_json::json!({
                    "jsonrpc":"2.0","method":"textDocument/didOpen",
                    "params":{"textDocument":{"uri":uri.as_str(),"languageId":"go","version":1,"text":contents}}
                }),
            )?;
            uris.insert(path.clone(), uri);
        }

        let deadline = std::time::Instant::now() + TOTAL_TIMEOUT;
        let mut edges = Vec::new();
        let mut resolved_symbols = std::collections::BTreeSet::new();
        let mut failures = false;
        let mut limited = go_source_count > 256;
        let mut query_id = 2u64;
        let mut reference_queries = 0usize;
        for uri in uris.values().take(256) {
            if std::time::Instant::now() >= deadline {
                limited = true;
                break;
            }
            send(
                &mut stdin,
                &serde_json::json!({
                    "jsonrpc":"2.0","id":query_id,"method":"textDocument/documentSymbol",
                    "params":{"textDocument":{"uri":uri.as_str()}}
                }),
            )?;
            let timeout = deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(REQUEST_TIMEOUT);
            if receive_response(&receiver, query_id, timeout).is_err() {
                failures = true;
            }
            query_id += 1;
        }
        for changed_path in changed_paths {
            let Some(text) = source.get(changed_path.as_str()) else {
                continue;
            };
            if !uris.contains_key(changed_path.as_str()) {
                continue;
            }
            let declarations = go_declared_symbols_with_positions(text);
            let mut declaration_counts = std::collections::BTreeMap::<String, usize>::new();
            let mut resolved_declaration_counts =
                std::collections::BTreeMap::<String, usize>::new();
            for (symbol, _, _) in &declarations {
                *declaration_counts.entry(symbol.clone()).or_default() += 1;
            }
            for (symbol, line, column) in declarations {
                let mut query_positions = vec![(changed_path.to_string(), line, column)];
                query_positions.extend(go_symbol_occurrences(source, &symbol).into_iter().filter(
                    |(path, row, col)| {
                        path != changed_path.as_str() || *row != line || *col != column
                    },
                ));
                query_positions.sort();
                query_positions.dedup();
                let mut locations = Vec::new();
                let mut query_failed = false;
                let mut symbol_limited = false;
                for (query_path, query_line, query_column) in query_positions {
                    if reference_queries >= MAX_REFERENCE_QUERIES
                        || std::time::Instant::now() >= deadline
                    {
                        limited = true;
                        symbol_limited = true;
                        break;
                    }
                    let Some(query_uri) = uris.get(&query_path) else {
                        continue;
                    };
                    reference_queries += 1;
                    let position =
                        serde_json::json!({"line": query_line - 1, "character": query_column - 1});
                    send(
                        &mut stdin,
                        &serde_json::json!({
                            "jsonrpc":"2.0","id":query_id,"method":"textDocument/references",
                            "params":{"textDocument":{"uri":query_uri.as_str()},"position":position,"context":{"includeDeclaration":true}}
                        }),
                    )?;
                    let timeout = deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .min(REQUEST_TIMEOUT);
                    match receive_response(&receiver, query_id, timeout) {
                        Ok(result) => match result.as_array() {
                            Some(result_locations) => {
                                let target_found = result_locations.iter().any(|location| {
                                    let Some(uri_text) =
                                        location.pointer("/uri").and_then(|v| v.as_str())
                                    else {
                                        return false;
                                    };
                                    let Ok(uri) = url::Url::parse(uri_text) else {
                                        return false;
                                    };
                                    let Ok(path) = uri.to_file_path() else {
                                        return false;
                                    };
                                    let Ok(path) = path.canonical() else {
                                        return false;
                                    };
                                    let Ok(relative) = path.strip_prefix(&root) else {
                                        return false;
                                    };
                                    let location_line = location
                                        .pointer("/range/start/line")
                                        .and_then(serde_json::Value::as_u64)
                                        .map(|value| value as u32 + 1);
                                    relative.to_string_lossy().replace('\\', "/") == **changed_path
                                        && location_line == Some(line)
                                });
                                if target_found {
                                    locations.extend(result_locations.iter().cloned());
                                }
                            }
                            None => query_failed = true,
                        },
                        Err(_) => query_failed = true,
                    }
                    query_id += 1;
                }
                let mut saw_declaration = false;
                for location in locations {
                    let Some(uri_text) = location.pointer("/uri").and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    let Ok(file_uri) = url::Url::parse(uri_text) else {
                        continue;
                    };
                    let Ok(path) = file_uri.to_file_path() else {
                        continue;
                    };
                    let Ok(path) = path.canonical() else {
                        continue;
                    };
                    let Ok(relative) = path.strip_prefix(&root) else {
                        continue;
                    };
                    let relative = relative.to_string_lossy().replace('\\', "/");
                    if !source.contains_key(&relative) || !relative.ends_with(".go") {
                        continue;
                    }
                    let Some(evidence_line) = location
                        .pointer("/range/start/line")
                        .and_then(serde_json::Value::as_u64)
                        .map(|line| line as u32 + 1)
                    else {
                        continue;
                    };
                    if relative == **changed_path && evidence_line == line {
                        saw_declaration = true;
                        continue;
                    }
                    // A changed file is not impact of itself.
                    if relative == **changed_path {
                        continue;
                    }
                    edges.push(ImpactEdge {
                        source_path: (*changed_path).clone(),
                        affected_path: relative.clone(),
                        relationship: if is_test_path(&relative) {
                            "likely_test_reference"
                        } else {
                            "resolved_symbol_reference"
                        }
                        .into(),
                        symbol: symbol.clone(),
                        certainty: "resolved_semantic".into(),
                        evidence_line,
                        co_change: None,
                    });
                }
                if saw_declaration && !query_failed && !symbol_limited {
                    *resolved_declaration_counts.entry(symbol).or_default() += 1;
                } else {
                    failures = true;
                }
            }
            for (symbol, count) in declaration_counts {
                if resolved_declaration_counts.get(&symbol) == Some(&count) {
                    resolved_symbols.insert(((*changed_path).clone(), symbol));
                }
            }
            if limited {
                break;
            }
        }
        edges.sort_by(|a, b| {
            (&a.source_path, &a.affected_path, a.evidence_line, &a.symbol).cmp(&(
                &b.source_path,
                &b.affected_path,
                b.evidence_line,
                &b.symbol,
            ))
        });
        edges.dedup();
        let _ = send(
            &mut stdin,
            &serde_json::json!({"jsonrpc":"2.0","id":query_id,"method":"shutdown","params":null}),
        );
        Ok((version, edges, resolved_symbols, failures, limited))
    })();
    drop(stdin);
    terminate_gopls_process(&mut child);
    outcome
}

#[cfg(unix)]
pub(crate) fn terminate_gopls_process(child: &mut std::process::Child) {
    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.wait();
}

#[cfg(not(unix))]
pub(crate) fn terminate_gopls_process(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn go_declared_symbols_with_positions(source: &str) -> Vec<(String, u32, u32)> {
    let mut declarations = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        let candidate = if let Some(rest) = trimmed.strip_prefix("func ") {
            if rest.starts_with('(') {
                rest.split_once(')')
                    .map(|(_, after)| after.trim_start())
                    .unwrap_or("")
            } else {
                rest
            }
            .split(|character: char| !character.is_alphanumeric() && character != '_')
            .next()
        } else if ["type ", "var ", "const "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            trimmed.split_whitespace().nth(1)
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let symbol: String = candidate
            .chars()
            .take_while(|character| character.is_alphanumeric() || *character == '_')
            .collect();
        if symbol.len() <= 1 {
            continue;
        }
        if let Some(byte_column) = line.find(&symbol) {
            let column = line[..byte_column].encode_utf16().count() as u32 + 1;
            declarations.push((symbol, (line_index + 1) as u32, column));
        }
    }
    declarations
}

pub(crate) fn go_symbol_occurrences(
    source: &std::collections::BTreeMap<String, String>,
    symbol: &str,
) -> Vec<(String, u32, u32)> {
    let mut occurrences = Vec::new();
    for (path, contents) in source.iter().filter(|(path, _)| path.ends_with(".go")) {
        for (line_index, line) in contents.lines().enumerate() {
            let code = go_code_without_comments_and_strings(line);
            for (byte_index, matched) in code.match_indices(symbol) {
                let before = code[..byte_index].chars().next_back();
                let after = code[byte_index + matched.len()..].chars().next();
                if before.is_some_and(|character| character.is_alphanumeric() || character == '_')
                    || after
                        .is_some_and(|character| character.is_alphanumeric() || character == '_')
                {
                    continue;
                }
                let column = code[..byte_index].encode_utf16().count() as u32 + 1;
                occurrences.push((path.clone(), (line_index + 1) as u32, column));
            }
        }
    }
    occurrences
}

/// Rust declarations fingerprinted by their token streams, so formatting and
/// ordinary comments are not changes; `None` when the source does not parse.
///
/// A module records only its presence: an edit inside `mod tests` changes the
/// items it contains, not every reference to the module name.
pub(crate) fn rust_declaration_fingerprints(source: &str) -> Option<DeclarationFingerprints> {
    use quote::ToTokens;
    struct Declarations {
        fingerprints: DeclarationFingerprints,
        /// Depth of enclosing `#[cfg(test)]` modules.
        in_test: usize,
    }
    impl Declarations {
        /// Records a declaration. A private item inside a test module is
        /// unreachable from other files, and its same-file references are
        /// already test-context edges, so it is not recorded.
        fn record(&mut self, name: &syn::Ident, vis: &syn::Visibility, item: &impl ToTokens) {
            if self.in_test > 0 && matches!(vis, syn::Visibility::Inherited) {
                return;
            }
            self.record_text(name, item.to_token_stream().to_string());
        }
        fn record_text(&mut self, name: &syn::Ident, fingerprint: String) {
            self.fingerprints
                .entry(name.to_string())
                .or_default()
                .push(fingerprint);
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for Declarations {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.record(&item.sig.ident, &item.vis, item);
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_struct(self, item);
        }
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_enum(self, item);
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_trait(self, item);
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = rust_is_test_cfg(&item.attrs);
            if !test {
                self.record_text(&item.ident, "mod".into());
            }
            self.in_test += test as usize;
            syn::visit::visit_item_mod(self, item);
            self.in_test -= test as usize;
        }
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_type(self, item);
        }
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_const(self, item);
        }
        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.record(&item.ident, &item.vis, item);
            syn::visit::visit_item_static(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.record(&item.sig.ident, &item.vis, item);
            syn::visit::visit_impl_item_fn(self, item);
        }
        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            self.record(
                &item.sig.ident,
                &syn::Visibility::Public(Default::default()),
                item,
            );
            syn::visit::visit_trait_item_fn(self, item);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = Declarations {
        fingerprints: DeclarationFingerprints::new(),
        in_test: 0,
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    for fingerprints in visitor.fingerprints.values_mut() {
        fingerprints.sort();
    }
    Some(visitor.fingerprints)
}

/// Test-only Rust functions (under `#[cfg(test)]`) with the identifiers each
/// one mentions; `None` when the source does not parse.
///
/// A test helper that calls a changed function is how tests elsewhere reach
/// that change, so it is treated as changed for test selection.
/// Rust symbols declared `pub`, or reachable through a trait, so callable
/// from other crates; `None` when the source does not parse.
fn rust_exported_symbols(source: &str) -> Option<std::collections::BTreeSet<String>> {
    struct Exported {
        names: std::collections::BTreeSet<String>,
        in_trait: usize,
    }
    impl Exported {
        fn record(&mut self, name: &syn::Ident, vis: &syn::Visibility) {
            if self.in_trait > 0 || matches!(vis, syn::Visibility::Public(_)) {
                self.names.insert(name.to_string());
            }
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for Exported {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.record(&item.sig.ident, &item.vis);
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            self.record(&item.ident, &item.vis);
        }
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            self.record(&item.ident, &item.vis);
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            self.record(&item.ident, &item.vis);
            self.in_trait += 1;
            syn::visit::visit_item_trait(self, item);
            self.in_trait -= 1;
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            self.record(&item.ident, &item.vis);
            syn::visit::visit_item_mod(self, item);
        }
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.record(&item.ident, &item.vis);
        }
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.record(&item.ident, &item.vis);
        }
        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.record(&item.ident, &item.vis);
        }
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            // `macro_rules!` with `#[macro_export]` is exported; keep any macro's name.
            if let Some(ident) = &item.ident {
                self.names.insert(ident.to_string());
            }
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let trait_impl = item.trait_.is_some() as usize;
            self.in_trait += trait_impl;
            syn::visit::visit_item_impl(self, item);
            self.in_trait -= trait_impl;
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.record(&item.sig.ident, &item.vis);
            syn::visit::visit_impl_item_fn(self, item);
        }
        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            self.names.insert(item.sig.ident.to_string());
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = Exported {
        names: std::collections::BTreeSet::new(),
        in_trait: 0,
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    Some(visitor.names)
}

/// Whether attributes include a `cfg` that names `test`, such as `#[cfg(test)]`.
fn rust_is_test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, syn::Meta::List(list)
                if list.tokens.clone().into_iter().any(|tree| matches!(tree, proc_macro2::TokenTree::Ident(ident) if ident == "test")))
    })
}

fn rust_test_helper_mentions(
    source: &str,
) -> Option<Vec<(String, std::collections::BTreeSet<String>)>> {
    use quote::ToTokens;
    fn mentions(tokens: proc_macro2::TokenStream, into: &mut std::collections::BTreeSet<String>) {
        for tree in tokens {
            match tree {
                proc_macro2::TokenTree::Ident(ident) => {
                    into.insert(ident.to_string());
                }
                proc_macro2::TokenTree::Group(group) => mentions(group.stream(), into),
                _ => {}
            }
        }
    }
    struct Helpers {
        in_test: usize,
        found: Vec<(String, std::collections::BTreeSet<String>)>,
    }
    impl Helpers {
        fn record(&mut self, attrs: &[syn::Attribute], name: &syn::Ident, block: &syn::Block) {
            if self.in_test > 0 || rust_is_test_cfg(attrs) {
                let mut names = std::collections::BTreeSet::new();
                mentions(block.to_token_stream(), &mut names);
                self.found.push((name.to_string(), names));
            }
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for Helpers {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = rust_is_test_cfg(&item.attrs);
            self.in_test += test as usize;
            syn::visit::visit_item_mod(self, item);
            self.in_test -= test as usize;
        }
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.record(&item.attrs, &item.sig.ident, &item.block);
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.record(&item.attrs, &item.sig.ident, &item.block);
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = Helpers {
        in_test: 0,
        found: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    Some(visitor.found)
}

/// Adds every test helper that, directly or through another helper,
/// mentions a changed symbol.
fn extend_with_test_helpers(
    changed: &mut std::collections::BTreeSet<String>,
    helpers: &[(String, std::collections::BTreeSet<String>)],
) {
    loop {
        let before = changed.len();
        for (name, mentioned) in helpers {
            if !changed.contains(name) && mentioned.iter().any(|symbol| changed.contains(symbol)) {
                changed.insert(name.clone());
            }
        }
        if changed.len() == before {
            break;
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RustTestModuleContext {
    pub(crate) conditional: bool,
    pub(crate) module_path: Vec<String>,
}

pub(crate) fn rust_test_module_paths(
    source: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, RustTestModuleContext> {
    #[allow(clippy::too_many_arguments)]
    fn visit_items(
        items: &[syn::Item],
        base: &Path,
        source: &std::collections::BTreeMap<String, String>,
        inherited_test_cfg: bool,
        inherited_conditional_cfg: bool,
        active_files: &mut std::collections::BTreeSet<String>,
        module_names: &[String],
        output: &mut std::collections::BTreeMap<String, RustTestModuleContext>,
    ) {
        for item in items {
            let syn::Item::Mod(module) = item else {
                continue;
            };
            let test_cfg = inherited_test_cfg || is_test_context_attribute(&module.attrs);
            let conditional_cfg = inherited_conditional_cfg || has_non_test_cfg(&module.attrs);
            let module_base = base.join(module.ident.to_string());
            if let Some((_, nested)) = &module.content {
                visit_items(
                    nested,
                    &module_base,
                    source,
                    test_cfg,
                    conditional_cfg,
                    active_files,
                    &{
                        let mut nested_names = module_names.to_vec();
                        nested_names.push(module.ident.to_string());
                        nested_names
                    },
                    output,
                );
                continue;
            }

            let explicit_path = module.attrs.iter().find_map(|attribute| {
                if !attribute.path().is_ident("path") {
                    return None;
                }
                let syn::Meta::NameValue(value) = &attribute.meta else {
                    return None;
                };
                let syn::Expr::Lit(expression) = &value.value else {
                    return None;
                };
                let syn::Lit::Str(path) = &expression.lit else {
                    return None;
                };
                Some(path.value())
            });
            let candidates = if let Some(path) = explicit_path {
                vec![base.join(path)]
            } else {
                vec![
                    base.join(format!("{}.rs", module.ident)),
                    base.join(module.ident.to_string()).join("mod.rs"),
                ]
            };
            for module_path in candidates {
                let module_path = module_path.to_string_lossy().replace('\\', "/");
                if !source.contains_key(&module_path) {
                    continue;
                }
                if test_cfg {
                    output
                        .entry(module_path.clone())
                        .and_modify(|context| context.conditional |= conditional_cfg)
                        .or_insert_with(|| RustTestModuleContext {
                            conditional: conditional_cfg,
                            module_path: {
                                let mut names = module_names.to_vec();
                                names.push(module.ident.to_string());
                                names
                            },
                        });
                }
                if let Some(module_source) = source.get(&module_path) {
                    if !active_files.insert(module_path.clone()) {
                        break;
                    }
                    if let Ok(file) = syn::parse_file(module_source) {
                        let nested_base = if module_path.ends_with("/mod.rs") {
                            Path::new(&module_path)
                                .parent()
                                .unwrap_or(Path::new(""))
                                .to_path_buf()
                        } else {
                            Path::new(&module_path)
                                .parent()
                                .unwrap_or(Path::new(""))
                                .join(module.ident.to_string())
                        };
                        visit_items(
                            &file.items,
                            &nested_base,
                            source,
                            test_cfg,
                            conditional_cfg,
                            active_files,
                            &{
                                let mut nested_modules = module_names.to_vec();
                                nested_modules.push(module.ident.to_string());
                                nested_modules
                            },
                            output,
                        );
                    }
                    active_files.remove(&module_path);
                    break;
                }
            }
        }
    }

    let mut output = std::collections::BTreeMap::new();
    for (path, text) in source {
        if !path.ends_with(".rs")
            || !(path.ends_with("/lib.rs")
                || path.ends_with("/main.rs")
                || path == "lib.rs"
                || path == "main.rs")
        {
            continue;
        }
        let Ok(file) = syn::parse_file(text) else {
            continue;
        };
        let base = Path::new(path).parent().unwrap_or(Path::new(""));
        let mut active_files = std::collections::BTreeSet::from([path.clone()]);
        visit_items(
            &file.items,
            base,
            source,
            false,
            false,
            &mut active_files,
            &[],
            &mut output,
        );
    }
    output
}

/// How a Rust identifier occurrence can name an item, which decides the kinds
/// of declaration it may refer to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RustRole {
    /// A path segment. `qualifier` is the segment before it, if any; `last`
    /// is false for a module or type prefix such as `review` in `review::run`.
    Path {
        qualifier: Option<String>,
        last: bool,
    },
    /// A method call such as `value.report()`.
    Method,
    /// A name in a `use` tree.
    Use,
    /// An identifier inside macro tokens, which are not parsed.
    Macro,
}

/// What kind of item a Rust declaration is, for matching occurrences.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RustDeclKind {
    /// A free function, constant, or static: named by a final path segment.
    Value,
    /// A struct, enum, union, trait, or type alias: named by any path segment.
    Type,
    /// A module: named only by a path prefix.
    Module,
    /// A `macro_rules!` macro.
    Macro,
    /// A function or constant in an `impl` or `trait` for `owner`: named by
    /// `Owner::name`, or by a method call in a file that names its owner.
    Associated { owner: String },
}

/// One identifier occurrence: name, line, test context, and role.
pub(crate) type RustOccurrence = (String, u32, bool, RustRole);

/// A parsed file's matching occurrences, with the names of the items the
/// file itself declares (outside `impl` and `trait` blocks). An unqualified
/// path naming one of those resolves to the file's own item, which shadows
/// any glob import of a same-named item from elsewhere.
#[derive(Default)]
pub(crate) struct RustOccurrences {
    pub(crate) found: Vec<RustOccurrence>,
    pub(crate) local_items: std::collections::HashSet<String>,
}

impl RustOccurrences {
    /// Whether `occurrence` is an unqualified path to an item this file declares.
    pub(crate) fn names_local_item(&self, occurrence: &RustOccurrence) -> bool {
        matches!(
            &occurrence.3,
            RustRole::Path {
                qualifier: None,
                last: true
            }
        ) && self.local_items.contains(&occurrence.0)
    }
}

/// Whether an occurrence in `role` can name a declaration of one of `kinds`.
/// `mentions` reports whether the occurrence's file names an identifier, which
/// stands in for the type or trait being in scope at a method call.
pub(crate) fn rust_role_matches(
    kinds: &std::collections::BTreeSet<RustDeclKind>,
    role: &RustRole,
    mentions: &mut dyn FnMut(&str) -> bool,
) -> bool {
    kinds.iter().any(|kind| match (kind, role) {
        (_, RustRole::Use) => !matches!(kind, RustDeclKind::Associated { .. }),
        (RustDeclKind::Value | RustDeclKind::Macro, RustRole::Path { last, .. }) => *last,
        (RustDeclKind::Value | RustDeclKind::Type | RustDeclKind::Macro, RustRole::Macro) => true,
        (RustDeclKind::Type, RustRole::Path { .. }) => true,
        (RustDeclKind::Module, RustRole::Path { last, .. }) => !last,
        (
            RustDeclKind::Associated { owner },
            RustRole::Path {
                qualifier: Some(qualifier),
                last: true,
            },
        ) => qualifier == owner || (qualifier == "Self" && mentions(owner)),
        (RustDeclKind::Associated { owner }, RustRole::Method | RustRole::Macro) => mentions(owner),
        _ => false,
    })
}

/// The kinds of every item declared in a Rust file, by name; `None` when the
/// file does not parse.
pub(crate) fn rust_declaration_kinds(
    source: &str,
) -> Option<std::collections::BTreeMap<String, std::collections::BTreeSet<RustDeclKind>>> {
    #[derive(Default)]
    struct Kinds {
        found: std::collections::BTreeMap<String, std::collections::BTreeSet<RustDeclKind>>,
        owners: Vec<Vec<String>>,
    }
    impl Kinds {
        fn record(&mut self, name: &syn::Ident, kind: RustDeclKind) {
            self.found.entry(name.to_string()).or_default().insert(kind);
        }
        fn record_associated(&mut self, name: &syn::Ident) {
            let owners = self.owners.last().cloned().unwrap_or_default();
            for owner in owners {
                self.record(name, RustDeclKind::Associated { owner });
            }
        }
    }
    fn last_ident(path: &syn::Path) -> Option<String> {
        path.segments
            .last()
            .map(|segment| segment.ident.to_string())
    }
    impl<'ast> syn::visit::Visit<'ast> for Kinds {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.record(&item.sig.ident, RustDeclKind::Value);
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.record(&item.ident, RustDeclKind::Value);
        }
        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.record(&item.ident, RustDeclKind::Value);
        }
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            self.record(&item.ident, RustDeclKind::Type);
        }
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            self.record(&item.ident, RustDeclKind::Type);
        }
        fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
            self.record(&item.ident, RustDeclKind::Type);
        }
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.record(&item.ident, RustDeclKind::Type);
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            self.record(&item.ident, RustDeclKind::Module);
            syn::visit::visit_item_mod(self, item);
        }
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if let Some(ident) = &item.ident {
                self.record(ident, RustDeclKind::Macro);
            }
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            self.record(&item.ident, RustDeclKind::Type);
            self.owners.push(vec![item.ident.to_string()]);
            syn::visit::visit_item_trait(self, item);
            self.owners.pop();
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let mut owners = Vec::new();
            if let syn::Type::Path(path) = item.self_ty.as_ref() {
                owners.extend(last_ident(&path.path));
            }
            if let Some((_, path, _)) = &item.trait_ {
                owners.extend(last_ident(path));
            }
            self.owners.push(owners);
            syn::visit::visit_item_impl(self, item);
            self.owners.pop();
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.record_associated(&item.sig.ident);
            syn::visit::visit_impl_item_fn(self, item);
        }
        fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
            self.record_associated(&item.ident);
        }
        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            self.record_associated(&item.sig.ident);
            syn::visit::visit_trait_item_fn(self, item);
        }
        fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
            self.record_associated(&item.ident);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = Kinds::default();
    syn::visit::Visit::visit_file(&mut visitor, &file);
    Some(visitor.found)
}

/// Identifier occurrences in Rust paths, method calls, `use` trees, and macro
/// tokens whose name satisfies `keep`, sorted and deduplicated, each with the
/// role that decides what it can name. `None` when the file does not parse.
///
/// A single-segment path or macro token naming a local binding (a parameter,
/// `let`, closure, `for`, or match-arm pattern) is the binding, not an item,
/// so it is skipped.
pub(crate) fn rust_identifier_occurrences_matching(
    source: &str,
    keep: &dyn Fn(&str) -> bool,
) -> Option<RustOccurrences> {
    struct References<'a> {
        keep: &'a dyn Fn(&str) -> bool,
        found: Vec<RustOccurrence>,
        in_test_context: bool,
        /// Local bindings per enclosing scope, innermost last.
        scopes: Vec<std::collections::HashSet<String>>,
    }
    fn pattern_bindings(pat: &syn::Pat, into: &mut std::collections::HashSet<String>) {
        struct Bindings<'b>(&'b mut std::collections::HashSet<String>);
        impl<'ast> syn::visit::Visit<'ast> for Bindings<'_> {
            fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
                self.0.insert(node.ident.to_string());
                syn::visit::visit_pat_ident(self, node);
            }
        }
        syn::visit::Visit::visit_pat(&mut Bindings(into), pat);
    }
    impl References<'_> {
        fn is_local(&self, name: &str) -> bool {
            self.scopes.iter().any(|scope| scope.contains(name))
        }
        fn bind(&mut self, pat: &syn::Pat) {
            if let Some(scope) = self.scopes.last_mut() {
                pattern_bindings(pat, scope);
            }
        }
        fn push(&mut self, name: String, line: usize, role: RustRole) {
            self.found
                .push((name, line as u32, self.in_test_context, role));
        }
        fn record_path(&mut self, path: &syn::Path, local_candidate: bool) {
            let count = path.segments.len();
            if local_candidate && count == 1 && path.leading_colon.is_none() {
                let ident = &path.segments[0].ident;
                if self.is_local(&ident.to_string()) {
                    return;
                }
            }
            let mut qualifier: Option<String> = None;
            for (index, segment) in path.segments.iter().enumerate() {
                let name = segment.ident.to_string();
                if (self.keep)(&name) {
                    self.push(
                        name.clone(),
                        segment.ident.span().start().line,
                        RustRole::Path {
                            qualifier: qualifier.clone(),
                            last: index + 1 == count,
                        },
                    );
                }
                qualifier = Some(name);
            }
        }
        fn scoped(&mut self, bindings: &[&syn::Pat], visit: impl FnOnce(&mut Self)) {
            let mut scope = std::collections::HashSet::new();
            for pat in bindings {
                pattern_bindings(pat, &mut scope);
            }
            self.scopes.push(scope);
            visit(self);
            self.scopes.pop();
        }
    }
    fn fn_inputs(
        inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
    ) -> Vec<&syn::Pat> {
        inputs
            .iter()
            .filter_map(|input| match input {
                syn::FnArg::Typed(typed) => Some(typed.pat.as_ref()),
                syn::FnArg::Receiver(_) => None,
            })
            .collect()
    }
    impl<'ast> syn::visit::Visit<'ast> for References<'_> {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let previous = self.in_test_context;
            self.in_test_context |= is_test_context_attribute(&node.attrs);
            let inputs = fn_inputs(&node.sig.inputs);
            self.scoped(&inputs, |this| syn::visit::visit_item_fn(this, node));
            self.in_test_context = previous;
        }
        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            let inputs = fn_inputs(&node.sig.inputs);
            self.scoped(&inputs, |this| syn::visit::visit_impl_item_fn(this, node));
        }
        fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
            let inputs = fn_inputs(&node.sig.inputs);
            self.scoped(&inputs, |this| syn::visit::visit_trait_item_fn(this, node));
        }
        fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
            let inputs: Vec<&syn::Pat> = node.inputs.iter().collect();
            self.scoped(&inputs, |this| syn::visit::visit_expr_closure(this, node));
        }
        fn visit_block(&mut self, node: &'ast syn::Block) {
            self.scoped(&[], |this| syn::visit::visit_block(this, node));
        }
        fn visit_local(&mut self, node: &'ast syn::Local) {
            // The initializer is evaluated before its bindings exist.
            if let Some(init) = &node.init {
                syn::visit::Visit::visit_expr(self, &init.expr);
                if let Some((_, diverge)) = &init.diverge {
                    syn::visit::Visit::visit_expr(self, diverge);
                }
            }
            syn::visit::Visit::visit_pat(self, &node.pat);
            self.bind(&node.pat);
        }
        fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
            syn::visit::Visit::visit_expr(self, &node.expr);
            syn::visit::Visit::visit_pat(self, &node.pat);
            self.bind(&node.pat);
        }
        fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
            syn::visit::Visit::visit_expr(self, &node.expr);
            self.scoped(&[node.pat.as_ref()], |this| {
                syn::visit::Visit::visit_pat(this, &node.pat);
                syn::visit::Visit::visit_block(this, &node.body);
            });
        }
        fn visit_arm(&mut self, node: &'ast syn::Arm) {
            self.scoped(&[&node.pat], |this| syn::visit::visit_arm(this, node));
        }
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            let previous = self.in_test_context;
            self.in_test_context |= is_test_context_attribute(&node.attrs);
            syn::visit::visit_item_mod(self, node);
            self.in_test_context = previous;
        }
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            self.record_path(&node.path, node.qself.is_none());
            syn::visit::visit_expr_path(self, node);
        }
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            self.record_path(&node.path, false);
            syn::visit::visit_expr_struct(self, node);
        }
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            self.record_path(&node.path, false);
            syn::visit::visit_type_path(self, node);
        }
        fn visit_pat_tuple_struct(&mut self, node: &'ast syn::PatTupleStruct) {
            self.record_path(&node.path, false);
            syn::visit::visit_pat_tuple_struct(self, node);
        }
        fn visit_pat_struct(&mut self, node: &'ast syn::PatStruct) {
            self.record_path(&node.path, false);
            syn::visit::visit_pat_struct(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            if (self.keep)(&name) {
                self.push(name, node.method.span().start().line, RustRole::Method);
            }
            syn::visit::visit_expr_method_call(self, node);
        }
        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            syn::visit::visit_item_use(self, node);
            // A path prefix (`review` in `use review::*`) names a module or
            // type; only a final name or rename can import any item.
            let mut names = Vec::new();
            fn collect(tree: &syn::UseTree, names: &mut Vec<(String, RustRole)>) {
                let prefix = |name: String| {
                    (
                        name,
                        RustRole::Path {
                            qualifier: None,
                            last: false,
                        },
                    )
                };
                match tree {
                    syn::UseTree::Path(path) => {
                        names.push(prefix(path.ident.to_string()));
                        collect(&path.tree, names);
                    }
                    syn::UseTree::Name(name) => names.push((name.ident.to_string(), RustRole::Use)),
                    syn::UseTree::Rename(rename) => {
                        names.push((rename.ident.to_string(), RustRole::Use));
                        names.push((rename.rename.to_string(), RustRole::Use));
                    }
                    syn::UseTree::Group(group) => {
                        for item in &group.items {
                            collect(item, names);
                        }
                    }
                    syn::UseTree::Glob(_) => {}
                }
            }
            collect(&node.tree, &mut names);
            let line = node.tree.span().start().line;
            for (name, role) in names {
                if (self.keep)(&name) {
                    self.push(name, line, role);
                }
            }
        }
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.record_path(&node.path, false);
            // Macro bodies are unparsed tokens; `let name` (or `let mut
            // name`) inside one still binds a local for the rest of the body.
            fn visit_tokens(tokens: proc_macro2::TokenStream, visitor: &mut References<'_>) {
                let mut after_let = false;
                for token in tokens {
                    match token {
                        proc_macro2::TokenTree::Ident(ident) => {
                            let name = ident.to_string();
                            if after_let && name != "mut" {
                                if let Some(scope) = visitor.scopes.last_mut() {
                                    scope.insert(name.clone());
                                }
                            }
                            after_let = name == "let" || (after_let && name == "mut");
                            if (visitor.keep)(&name) && !visitor.is_local(&name) {
                                visitor.push(name, ident.span().start().line, RustRole::Macro);
                            }
                        }
                        proc_macro2::TokenTree::Group(group) => {
                            after_let = false;
                            visit_tokens(group.stream(), visitor)
                        }
                        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {
                            after_let = false;
                        }
                    }
                }
            }
            self.scopes.push(std::collections::HashSet::new());
            visit_tokens(node.tokens.clone(), self);
            self.scopes.pop();
            syn::visit::visit_macro(self, node);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = References {
        keep,
        found: Vec::new(),
        in_test_context: false,
        scopes: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    visitor.found.sort();
    visitor.found.dedup();
    let local_items = rust_declaration_kinds(source)
        .unwrap_or_default()
        .into_iter()
        .filter(|(name, kinds)| {
            keep(name)
                && kinds
                    .iter()
                    .any(|kind| !matches!(kind, RustDeclKind::Associated { .. }))
        })
        .map(|(name, _)| name)
        .collect();
    Some(RustOccurrences {
        found: visitor.found,
        local_items,
    })
}

/// Every identifier occurrence in a Rust file (see
/// [`rust_identifier_occurrences_matching`]); parse once, query many times.
#[cfg(test)]
pub(crate) fn rust_references(
    source: &str,
    symbols: &[String],
) -> Option<Vec<(String, u32, bool)>> {
    rust_identifier_occurrences_matching(source, &|name| {
        symbols.iter().any(|symbol| symbol == name)
    })
    .map(|found| {
        let mut triples: Vec<_> = found
            .found
            .into_iter()
            .map(|(name, line, in_test, _)| (name, line, in_test))
            .collect();
        triples.dedup();
        triples
    })
}

pub(crate) fn has_test_attribute(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test" || segment.ident == "rstest")
            || cfg_attr_has_test(attribute)
    })
}

pub(crate) fn cfg_attr_has_test(attribute: &syn::Attribute) -> bool {
    if !attribute.path().is_ident("cfg_attr") {
        return false;
    }
    let syn::Meta::List(list) = &attribute.meta else {
        return false;
    };
    let Ok(arguments) = list.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    ) else {
        return false;
    };
    arguments.iter().skip(1).any(|meta| {
        meta.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test" || segment.ident == "rstest")
    })
}

pub(crate) fn has_non_test_cfg(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        (attribute.path().is_ident("cfg")
            && !attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|ident| ident == "test"))
            || cfg_attr_has_test(attribute)
    })
}

pub(crate) fn is_test_context_attribute(attributes: &[syn::Attribute]) -> bool {
    has_test_attribute(attributes)
        || attributes.iter().any(|attribute| {
            attribute.path().is_ident("cfg")
                && attribute
                    .parse_args::<syn::Ident>()
                    .is_ok_and(|ident| ident == "test")
        })
}

/// Prose documentation: Markdown, reStructuredText, and AsciiDoc files, and
/// anything under a `docs/` directory. Plain `.txt` is not included, since it
/// also names build and dependency manifests (`CMakeLists.txt`,
/// `requirements.txt`) that do couple to code. Documentation is updated alongside features, so it says
/// nothing about code coupling or code diffusion.
pub(crate) fn is_documentation_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("docs/")
        || lower.contains("/docs/")
        || [".md", ".mdx", ".markdown", ".rst", ".adoc"]
            .iter()
            .any(|extension| lower.ends_with(extension))
}

pub(crate) fn is_vue_path(path: &str) -> bool {
    path.ends_with(".vue")
}

/// The component name a `.vue` file is conventionally imported under: its
/// file stem, when PascalCase. Lower-case stems (such as routed `index.vue`
/// pages) are not imported by name.
fn vue_component_name(path: &str) -> Option<String> {
    let stem = Path::new(path).file_stem()?.to_str()?;
    (stem.len() > 1
        && stem.starts_with(|character: char| character.is_ascii_uppercase())
        && stem.chars().all(is_identifier_character))
    .then(|| stem.to_owned())
}

/// A single-file component's `<script>` block contents, with every other
/// line (template, style, and the script tags themselves) left empty so line
/// numbers match the file.
pub(crate) fn vue_script_code(text: &str) -> String {
    let mut in_script = false;
    let mut output = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !in_script && trimmed.starts_with("<script") {
            in_script = !trimmed.contains("</script>");
        } else if in_script && trimmed.starts_with("</script>") {
            in_script = false;
        } else if in_script {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

pub(crate) fn is_typescript_path(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts")
    )
}

pub(crate) fn is_python_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("py")
}

pub(crate) const PYTHON_AST_PROGRAM: &str = r#"
import ast, json, platform, sys
request = json.load(sys.stdin)
trees = {}
parse_errors = []
for path, text in sorted(request["sources"].items()):
    try:
        trees[path] = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        parse_errors.append(path)
wanted = {}
for source_path, names in sorted(request["changed_symbols"].items()):
    for name in names:
        wanted.setdefault(name, []).append(source_path)
edges = []
truncated = False
for affected_path, tree in sorted(trees.items()):
    pending = [(tree, False)]
    while pending:
        node, in_test = pending.pop()
        is_test_function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")
        child_test = in_test or is_test_function
        name = None
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        if name in wanted:
            for source_path in wanted[name]:
                if len(edges) >= 2048:
                    truncated = True
                    break
                edges.append({
                    "source_path": source_path,
                    "affected_path": affected_path,
                    "symbol": name,
                    "evidence_line": int(getattr(node, "lineno", 1)),
                    "test_context": child_test,
                })
        if truncated:
            break
        pending.extend((child, child_test) for child in ast.iter_child_nodes(node))
    if truncated:
        break
print(json.dumps({
    "python_version": platform.python_version(),
    "edges": edges,
    "parse_error_paths": parse_errors,
    "truncated": truncated,
}, separators=(",", ":")))
"#;

#[derive(Deserialize)]
pub(crate) struct PythonAstOutput {
    pub(crate) python_version: String,
    pub(crate) edges: Vec<PythonAstEdge>,
    pub(crate) parse_error_paths: Vec<String>,
    pub(crate) truncated: bool,
}

#[derive(Deserialize)]
pub(crate) struct PythonAstEdge {
    pub(crate) source_path: String,
    pub(crate) affected_path: String,
    pub(crate) symbol: String,
    pub(crate) evidence_line: u32,
    pub(crate) test_context: bool,
}

pub(crate) fn find_python_interpreter() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let names: &[&str] = if cfg!(windows) {
        &["python.exe", "python3.exe", "python"]
    } else {
        &["python3", "python"]
    };
    std::env::split_paths(&path)
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.canonical().ok())
}

pub(crate) fn run_python_ast(
    executable: &Path,
    sources: &std::collections::BTreeMap<String, String>,
    changed_symbols: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
) -> Result<PythonAstOutput, String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const MAX_INPUT_BYTES: usize = 40 * 1024 * 1024;
    const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
    const TIME_LIMIT: Duration = Duration::from_secs(15);
    let python_sources: std::collections::BTreeMap<_, _> = sources
        .iter()
        .filter(|(path, _)| is_python_path(path))
        .collect();
    let python_symbols: std::collections::BTreeMap<_, _> = changed_symbols
        .iter()
        .filter(|(path, symbols)| is_python_path(path) && !symbols.is_empty())
        .collect();
    let request = serde_json::json!({
        "sources": python_sources,
        "changed_symbols": python_symbols,
    });
    let input = serde_json::to_vec(&request)
        .map_err(|error| format!("encoding Python AST request: {error}"))?;
    if input.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "Python AST request exceeded {MAX_INPUT_BYTES} bytes"
        ));
    }
    let isolated = tempfile::tempdir()
        .map_err(|error| format!("creating Python analyzer directory: {error}"))?;
    let mut command = Command::new(executable);
    command
        .arg("-I")
        .arg("-S")
        .arg("-c")
        .arg(PYTHON_AST_PROGRAM)
        .current_dir(isolated.path())
        .env_clear()
        .envs(vee_process::platform_environment())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("starting Python AST analyzer: {error}"))?;
    let mut stdin = child.stdin.take().expect("Python analyzer stdin is piped");
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let stdout = child
        .stdout
        .take()
        .expect("Python analyzer stdout is piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout
            .take((MAX_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let stderr = child
        .stderr
        .take()
        .expect("Python analyzer stderr is piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(64 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("waiting for Python AST analyzer: {error}"))?
        {
            break status;
        }
        if started.elapsed() >= TIME_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("Python AST analyzer exceeded its 15-second limit".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    writer
        .join()
        .map_err(|_| "Python AST analyzer input writer failed")?
        .map_err(|error| format!("writing Python AST analyzer input: {error}"))?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| "Python AST analyzer stdout reader failed")?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "Python AST analyzer stderr reader failed")?;
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err("Python AST analyzer output exceeded 2 MiB".into());
    }
    if !status.success() {
        let diagnostic = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "Python AST analyzer exited unsuccessfully: {}",
            diagnostic.trim()
        ));
    }
    serde_json::from_slice(&stdout)
        .map_err(|error| format!("invalid Python AST analyzer output: {error}"))
}

pub(crate) fn analyze_python_references(
    source: &std::collections::BTreeMap<String, String>,
    changed_symbols: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
) -> PythonImpactAnalysis {
    let Some(executable) = find_python_interpreter() else {
        return PythonImpactAnalysis {
            status: "unavailable".into(),
            limitations: vec![
                "Python interpreter was not found; Python references use lexical fallback.".into(),
            ],
            ..PythonImpactAnalysis::default()
        };
    };
    match run_python_ast(&executable, source, changed_symbols) {
        Ok(output) => {
            let parse_error_paths: std::collections::BTreeSet<_> =
                output.parse_error_paths.into_iter().collect();
            let mut limitations = vec!["Python AST references are syntax-derived, not type-resolved; imports and aliases, decorators, dynamic dispatch, and runtime behavior are not resolved.".into()];
            if !parse_error_paths.is_empty() {
                limitations.push(format!(
                    "Python AST parsing failed for {} source file(s); those paths use lexical fallback.",
                    parse_error_paths.len()
                ));
            }
            if output.truncated {
                limitations.push("Python AST reference output reached its 2,048-edge bound; remaining references are omitted.".into());
            }
            let edges = output
                .edges
                .into_iter()
                .map(|edge| ImpactEdge {
                    source_path: edge.source_path,
                    affected_path: edge.affected_path.clone(),
                    relationship: if is_test_path(&edge.affected_path) || edge.test_context {
                        "likely_test_reference"
                    } else {
                        "syntactic_symbol_reference"
                    }
                    .into(),
                    symbol: edge.symbol,
                    certainty: "inferred_syntax".into(),
                    evidence_line: edge.evidence_line,
                    co_change: None,
                })
                .collect();
            PythonImpactAnalysis {
                interpreter_version: Some(output.python_version),
                status: if parse_error_paths.is_empty() && !output.truncated {
                    "used".into()
                } else {
                    "partial".into()
                },
                edges,
                parse_error_paths,
                limitations,
            }
        }
        Err(error) => PythonImpactAnalysis {
            status: "failed".into(),
            limitations: vec![format!(
                "Python AST analysis failed ({error}); Python references use lexical fallback."
            )],
            ..PythonImpactAnalysis::default()
        },
    }
}

/// Find Python AST references to a set of changed symbol names in captured sources.
/// This is syntax-derived only; it does not resolve imports or prove that a
/// same-named reference binds to the producer declaration.
pub fn python_syntax_references(
    sources: &std::collections::BTreeMap<String, String>,
    changed_symbols: &std::collections::BTreeSet<String>,
) -> Result<PythonSyntaxReferences, String> {
    let Some(executable) = find_python_interpreter() else {
        return Err("Python interpreter was not found".into());
    };
    let symbols = std::collections::BTreeMap::from([(
        "__vee_changed_symbols__.py".to_owned(),
        changed_symbols.clone(),
    )]);
    let output = run_python_ast(&executable, sources, &symbols)?;
    Ok(PythonSyntaxReferences {
        interpreter_version: output.python_version,
        references: output
            .edges
            .into_iter()
            .map(|edge| PythonSyntaxReference {
                path: edge.affected_path,
                symbol: edge.symbol,
                line: edge.evidence_line,
                test_context: edge.test_context,
            })
            .collect(),
        parse_error_paths: output.parse_error_paths,
        truncated: output.truncated,
    })
}

#[derive(Debug, Clone)]
pub struct PythonSyntaxReferences {
    pub interpreter_version: String,
    pub references: Vec<PythonSyntaxReference>,
    pub parse_error_paths: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PythonSyntaxReference {
    pub path: String,
    pub symbol: String,
    pub line: u32,
    pub test_context: bool,
}

pub(crate) fn is_java_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("java")
}

/// Preserve line offsets while hiding Python comments and string contents.
/// This is intentionally lexical and does not parse formatted or concatenated strings.
pub fn python_code_without_comments_and_strings(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    let mut quote: Option<char> = None;
    let mut triple = false;
    let mut escaped = false;
    while index < characters.len() {
        let character = characters[index];
        if let Some(delimiter) = quote {
            if triple
                && character == delimiter
                && characters.get(index + 1) == Some(&delimiter)
                && characters.get(index + 2) == Some(&delimiter)
                && !escaped
            {
                output.push_str("   ");
                index += 3;
                quote = None;
                triple = false;
                escaped = false;
                continue;
            }
            if !triple && character == delimiter && !escaped {
                quote = None;
            }
            output.push(if character == '\n' { '\n' } else { ' ' });
            escaped = character == '\\' && !escaped;
            if character != '\\' {
                escaped = false;
            }
            index += 1;
            continue;
        }
        if character == '#' {
            while index < characters.len() && characters[index] != '\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            let is_triple = characters.get(index + 1) == Some(&character)
                && characters.get(index + 2) == Some(&character);
            quote = Some(character);
            triple = is_triple;
            let count = if is_triple { 3 } else { 1 };
            output.extend(std::iter::repeat_n(' ', count));
            index += count;
            escaped = false;
            continue;
        }
        output.push(character);
        index += 1;
    }
    output
}

/// Keep offsets by replacing comments and string contents with whitespace.
/// This is deliberately a lexical approximation, not a JavaScript parser.
pub fn typescript_code_without_comments_and_strings(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '/' && characters.get(index + 1) == Some(&'/') {
            while index < characters.len() && characters[index] != '\n' {
                output.extend(std::iter::repeat_n(' ', characters[index].len_utf16()));
                index += 1;
            }
            continue;
        }
        if characters[index] == '/' && characters.get(index + 1) == Some(&'*') {
            output.push_str("  ");
            index += 2;
            while index < characters.len() {
                if characters[index] == '*' && characters.get(index + 1) == Some(&'/') {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                let character = characters[index];
                if character == '\n' {
                    output.push('\n');
                } else {
                    output.extend(std::iter::repeat_n(' ', character.len_utf16()));
                }
                index += 1;
            }
            continue;
        }
        if matches!(characters[index], '\'' | '"' | '`') {
            let quote = characters[index];
            output.push(' ');
            index += 1;
            while index < characters.len() {
                let character = characters[index];
                if character == '\n' {
                    output.push('\n');
                } else {
                    output.extend(std::iter::repeat_n(' ', character.len_utf16()));
                }
                index += 1;
                if character == '\\' && index < characters.len() {
                    let escaped = characters[index];
                    if escaped == '\n' {
                        output.push('\n');
                    } else {
                        output.extend(std::iter::repeat_n(' ', escaped.len_utf16()));
                    }
                    index += 1;
                } else if character == quote {
                    break;
                }
            }
            continue;
        }
        output.push(characters[index]);
        index += 1;
    }
    output
}

/// Preserve line offsets while hiding Java comments, strings, chars, and text blocks.
/// This is lexical only and does not model Java's Unicode escape preprocessing.
pub fn java_code_without_comments_and_strings(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '/' && characters.get(index + 1) == Some(&'/') {
            while index < characters.len() && characters[index] != '\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if characters[index] == '/' && characters.get(index + 1) == Some(&'*') {
            output.push_str("  ");
            index += 2;
            while index < characters.len() {
                if characters[index] == '*' && characters.get(index + 1) == Some(&'/') {
                    output.push_str("  ");
                    index += 2;
                    break;
                }
                let character = characters[index];
                output.push(if character == '\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        let text_block = characters[index..].starts_with(&['"', '"', '"']);
        if text_block {
            output.push_str("   ");
            index += 3;
            while index < characters.len() {
                if characters[index..].starts_with(&['"', '"', '"']) {
                    output.push_str("   ");
                    index += 3;
                    break;
                }
                let character = characters[index];
                output.push(if character == '\n' { '\n' } else { ' ' });
                if character == '\\' && index + 1 < characters.len() {
                    index += 1;
                    output.push(if characters[index] == '\n' { '\n' } else { ' ' });
                }
                index += 1;
            }
            continue;
        }
        if matches!(characters[index], '\'' | '"') {
            let quote = characters[index];
            output.push(' ');
            index += 1;
            while index < characters.len() {
                let character = characters[index];
                output.push(if character == '\n' { '\n' } else { ' ' });
                index += 1;
                if character == '\\' && index < characters.len() {
                    output.push(if characters[index] == '\n' { '\n' } else { ' ' });
                    index += 1;
                } else if character == quote {
                    break;
                }
            }
            continue;
        }
        output.push(characters[index]);
        index += 1;
    }
    output
}

pub fn declared_symbols(path: &str, source: &str) -> std::collections::BTreeSet<String> {
    let top_level = declaration_line_mask(path, source);
    source
        .lines()
        .zip(top_level)
        .filter(|(_, top_level)| *top_level)
        .filter_map(|(line, _)| line_declared_symbol(path, line))
        .collect()
}

/// Which lines of comment- and string-free `code` may hold a declaration
/// other files can reference. For TypeScript and JavaScript only lines that
/// start outside every brace qualify: a `const` inside a function or test
/// callback is a local. Other languages keep every line.
fn declaration_line_mask(path: &str, code: &str) -> Vec<bool> {
    if !is_typescript_path(path) && !is_vue_path(path) {
        return code.lines().map(|_| true).collect();
    }
    let mut depth = 0usize;
    code.lines()
        .map(|line| {
            let top_level = depth == 0;
            for character in line.chars() {
                match character {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            top_level
        })
        .collect()
}

/// The symbol a single source line declares, by lexical keyword.
fn line_declared_symbol(path: &str, line: &str) -> Option<String> {
    {
        let trimmed = line.trim_start();
        let words: Vec<_> = trimmed.split_whitespace().collect();
        let keyword_index = if words.first() == Some(&"pub") { 1 } else { 0 };
        let keyword = words.get(keyword_index).copied().unwrap_or_default();
        let candidate = match (
            Path::new(path).extension().and_then(|e| e.to_str()),
            keyword,
        ) {
            (Some("rs"), "fn" | "struct" | "enum" | "trait" | "mod" | "type") => {
                words.get(keyword_index + 1).copied()
            }
            (Some("go"), "func") => {
                let rest = trimmed.strip_prefix("func ").unwrap_or("");
                let rest = if rest.starts_with('(') {
                    rest.split_once(')')
                        .map(|(_, after)| after.trim_start())
                        .unwrap_or("")
                } else {
                    rest
                };
                Some(
                    rest.split(|character: char| !character.is_alphanumeric() && character != '_')
                        .next()
                        .unwrap_or(""),
                )
            }
            (Some("go"), "type" | "var" | "const") => words.get(keyword_index + 1).copied(),
            (Some("py"), "def" | "class") => words.get(keyword_index + 1).copied(),
            (Some("py"), "async") if words.get(keyword_index + 1) == Some(&"def") => {
                words.get(keyword_index + 2).copied()
            }
            (Some("java"), _) => words
                .iter()
                .position(|word| matches!(*word, "class" | "interface" | "enum" | "record"))
                .and_then(|index| words.get(index + 1).copied()),
            (Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts"), _) => {
                let mut index = keyword_index;
                while words.get(index).is_some_and(|word| {
                    matches!(
                        word.trim_matches(|character: char| !character.is_alphanumeric()),
                        "export"
                            | "default"
                            | "declare"
                            | "abstract"
                            | "async"
                            | "public"
                            | "private"
                            | "protected"
                            | "static"
                            | "readonly"
                    )
                }) {
                    index += 1;
                }
                match words.get(index).copied().unwrap_or_default() {
                    "function" | "class" | "interface" | "type" | "enum" | "namespace"
                    | "const" | "let" | "var" => words.get(index + 1).copied(),
                    _ => None,
                }
            }
            _ => None,
        };
        let symbol: String = candidate?
            .chars()
            .take_while(|character| character.is_alphanumeric() || *character == '_')
            .collect();
        (symbol.len() > 1).then_some(symbol)
    }
}

pub fn java_declared_symbols(source: &str) -> std::collections::BTreeSet<String> {
    source
        .lines()
        .flat_map(java_line_declared_symbols)
        .collect()
}

/// The types and methods a single Java source line declares.
fn java_line_declared_symbols(line: &str) -> Vec<String> {
    let mut symbols: Vec<String> = line_declared_symbol("Source.java", line)
        .into_iter()
        .collect();
    const NON_DECLARATION_CALLS: &[&str] = &[
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "synchronized",
        "new",
        "return",
        "throw",
        "super",
        "this",
        "assert",
        "try",
        "do",
        "yield",
    ];
    {
        for (open, _) in line
            .char_indices()
            .filter(|(_, character)| *character == '(')
        {
            let prefix = &line[..open];
            let end = prefix.trim_end().len();
            let prefix = &prefix[..end];
            let name_start = prefix
                .char_indices()
                .rev()
                .find(|(_, character)| !character.is_ascii_alphanumeric() && *character != '_')
                .map(|(index, character)| index + character.len_utf8())
                .unwrap_or(0);
            let name = &prefix[name_start..];
            if name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                || NON_DECLARATION_CALLS.contains(&name)
            {
                continue;
            }
            let prefix_before_name = prefix[..name_start].trim();
            let boundary = prefix_before_name
                .rfind(['{', '}', ';'])
                .map(|index| index + 1)
                .unwrap_or(0);
            let declaration_prefix = prefix_before_name[boundary..].trim();
            if declaration_prefix.is_empty()
                || declaration_prefix.contains(['=', '.', ';'])
                || declaration_prefix.split_whitespace().any(|word| {
                    matches!(word, "return" | "throw" | "new")
                        || NON_DECLARATION_CALLS.contains(&word)
                })
            {
                continue;
            }
            // Java declarations have a return/constructor type before the name.
            // Calls on receivers are excluded above; this remains a lexical guess.
            if declaration_prefix
                .split_whitespace()
                .last()
                .is_some_and(|word| word.chars().any(|character| character.is_alphanumeric()))
            {
                symbols.push(name.to_owned());
            }
        }
    }
    symbols
}

/// The symbols every changed file declares, used to skip parsing candidate
/// files that cannot reference any of them.
pub(crate) struct ChangedSymbolFilter<'a> {
    all: std::collections::HashSet<&'a str>,
    /// Symbols made only of identifier characters, matched as whole tokens.
    identifiers: std::collections::HashSet<&'a str>,
    /// Symbols with other characters (for example `r#type`), matched as substrings.
    other: Vec<&'a str>,
}

impl<'a> ChangedSymbolFilter<'a> {
    pub(crate) fn new(symbols: impl IntoIterator<Item = &'a str>) -> Self {
        let all: std::collections::HashSet<&str> = symbols.into_iter().collect();
        let (identifiers, other): (Vec<&str>, Vec<&str>) = all
            .iter()
            .partition(|symbol| !symbol.is_empty() && symbol.chars().all(is_identifier_character));
        Self {
            all,
            identifiers: identifiers.into_iter().collect(),
            other,
        }
    }

    /// Whether `name` is one of the changed symbols.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.all.contains(name)
    }

    /// Whether `text` may reference a changed symbol. Never false for a text
    /// that names one; it can be true for a text that only mentions one in a
    /// comment or string.
    pub(crate) fn may_mention(&self, text: &str) -> bool {
        self.other.iter().any(|symbol| text.contains(symbol))
            || (!self.identifiers.is_empty()
                && text
                    .split(|character: char| !is_identifier_character(character))
                    .any(|token| self.identifiers.contains(token)))
    }
}

/// Finds which of a fixed list of symbols occur in a line as whole identifiers,
/// equivalent to `contains_identifier(line, symbol)` for each symbol, but
/// tokenizing the line once instead of searching it once per symbol.
pub(crate) struct SymbolMatcher<'a> {
    pub(crate) symbols: &'a [String],
    /// Identifier-only symbols by name, with every position they appear at.
    pub(crate) by_name: std::collections::HashMap<&'a str, Vec<usize>>,
    /// Symbols containing non-identifier characters (for example `r#type`),
    /// which still use substring matching.
    pub(crate) other: Vec<usize>,
}

impl<'a> SymbolMatcher<'a> {
    fn new(symbols: &'a [String]) -> Self {
        let mut by_name = std::collections::HashMap::<&str, Vec<usize>>::new();
        let mut other = Vec::new();
        for (index, symbol) in symbols.iter().enumerate() {
            if !symbol.is_empty() && symbol.chars().all(is_identifier_character) {
                by_name.entry(symbol.as_str()).or_default().push(index);
            } else {
                other.push(index);
            }
        }
        Self {
            symbols,
            by_name,
            other,
        }
    }

    /// Symbols occurring in `line`, in their original list order.
    fn matches(&self, line: &str) -> Vec<&'a String> {
        let mut indices: Vec<usize> = line
            .split(|character: char| !is_identifier_character(character))
            .filter(|token| !token.is_empty())
            .filter_map(|token| self.by_name.get(token))
            .flatten()
            .copied()
            .chain(
                self.other
                    .iter()
                    .copied()
                    .filter(|index| contains_identifier(line, &self.symbols[*index])),
            )
            .collect();
        indices.sort_unstable();
        indices.dedup();
        indices
            .into_iter()
            .map(|index| &self.symbols[index])
            .collect()
    }
}

pub(crate) fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

pub(crate) fn contains_identifier(line: &str, symbol: &str) -> bool {
    line.match_indices(symbol).any(|(start, matched)| {
        let before = line[..start].chars().next_back();
        let after = line[start + matched.len()..].chars().next();
        !before.is_some_and(|character| character.is_alphanumeric() || character == '_')
            && !after.is_some_and(|character| character.is_alphanumeric() || character == '_')
    })
}

pub fn go_code_without_comments_and_strings(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        Quoted(char),
        RawString,
    }
    let mut state = State::Code;
    let mut escaped = false;
    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        let next = chars.peek().copied();
        match state {
            State::Code => match (character, next) {
                ('/', Some('/')) => {
                    chars.next();
                    result.push_str("  ");
                    state = State::LineComment;
                }
                ('/', Some('*')) => {
                    chars.next();
                    result.push_str("  ");
                    state = State::BlockComment;
                }
                ('"' | '\'', _) => {
                    result.push(' ');
                    state = State::Quoted(character);
                    escaped = false;
                }
                ('`', _) => {
                    result.push(' ');
                    state = State::RawString;
                }
                _ => result.push(character),
            },
            State::LineComment => {
                if character == '\n' {
                    result.push('\n');
                    state = State::Code;
                } else {
                    result.push(' ');
                }
            }
            State::BlockComment => match (character, next) {
                ('*', Some('/')) => {
                    chars.next();
                    result.push_str("  ");
                    state = State::Code;
                }
                _ => result.push(if character == '\n' { '\n' } else { ' ' }),
            },
            State::Quoted(delimiter) => {
                result.push(if character == '\n' { '\n' } else { ' ' });
                if character == delimiter && !escaped {
                    state = State::Code;
                }
                escaped = character == '\\' && !escaped;
            }
            State::RawString => {
                result.push(if character == '\n' { '\n' } else { ' ' });
                if character == '`' {
                    state = State::Code;
                }
            }
        }
    }
    result
}

pub(crate) fn is_test_path(path: &str) -> bool {
    path.contains("/tests/")
        || path.starts_with("tests/")
        || path.starts_with("src/test/")
        || path.contains("/src/test/")
        || path.ends_with("_test.go")
        || path.contains("/__tests__/")
        || path.starts_with("__tests__/")
        || Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("test_")
                    || name.ends_with("Test.java")
                    || name.ends_with("Tests.java")
                    || name == "tests.rs"
                    || name.contains(".test.")
                    || name.contains(".spec.")
            })
}

pub(crate) fn package_id(root: &Path, path: &str, source: &str) -> Option<String> {
    if path.ends_with(".go") {
        let package = source
            .lines()
            .find_map(|line| line.trim().strip_prefix("package ").map(str::trim))?;
        let directory = Path::new(path).parent().unwrap_or(Path::new(""));
        return Some(format!("go:{}:{}", directory.display(), package));
    }
    let mut directory = Path::new(path).parent()?;
    loop {
        let manifest = root.join(directory).join("Cargo.toml");
        if let Ok(contents) = std::fs::read_to_string(&manifest) {
            if let Ok(parsed) = toml::from_str::<toml::Value>(&contents) {
                if let Some(name) = parsed
                    .get("package")
                    .and_then(|package| package.get("name"))
                    .and_then(toml::Value::as_str)
                {
                    let package_path = if directory.as_os_str().is_empty() {
                        ".".to_string()
                    } else {
                        directory.to_string_lossy().replace('\\', "/")
                    };
                    return Some(format!("rust:{package_path}:{name}"));
                }
            }
        }
        directory = directory.parent()?;
    }
}

#[cfg(test)]
#[path = "tests/impact.rs"]
mod tests;
