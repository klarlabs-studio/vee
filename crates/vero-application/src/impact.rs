//! Context & impact: changed symbols and the code that references them, per language analyzer.

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactEdge {
    pub source_path: String,
    pub affected_path: String,
    pub relationship: String,
    pub symbol: String,
    pub certainty: String,
    pub evidence_line: u32,
}

pub(crate) fn impact_context_edge_priority(edge: &ImpactEdge) -> (u8, u8, u8) {
    let directory =
        (Path::new(&edge.source_path).parent() != Path::new(&edge.affected_path).parent()) as u8;
    let relationship = match edge.relationship.as_str() {
        "resolved_symbol_reference" => 0,
        "likely_test_reference" => 1,
        "textual_symbol_reference" => 2,
        "inferred_import" => 3,
        "shared_local_dependency" => 4,
        _ => 5,
    };
    let certainty = match edge.certainty.as_str() {
        "resolved_semantic" => 0,
        "inferred_heuristic" => 1,
        "inferred_import" => 2,
        _ => 3,
    };
    (directory, relationship, certainty)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactGroup {
    pub package_id: String,
    pub changed_paths: Vec<String>,
    pub member_paths: Vec<String>,
    pub certainty: String,
}

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

pub fn analyze_impact(root: &Path, change_set: &ChangeSet) -> Result<ImpactAssessment, String> {
    let typescript_server = find_typescript_server();
    analyze_impact_with_typescript_server(root, change_set, typescript_server.as_deref())
}

pub(crate) fn analyze_impact_with_typescript_server(
    root: &Path,
    change_set: &ChangeSet,
    typescript_server: Option<&Path>,
) -> Result<ImpactAssessment, String> {
    const MAX_SOURCE_FILES: usize = 10_000;
    const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
    const MAX_FILE_BYTES: usize = 512 * 1024;
    let changed: std::collections::BTreeSet<String> = change_set
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let mut candidates = vero_git::tracked_paths(root)?;
    candidates.extend(
        change_set
            .files
            .iter()
            .map(|file| Path::new(&file.path).to_path_buf()),
    );
    candidates.retain(|path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "go" | "ts" | "tsx" | "js" | "jsx" | "mts" | "cts" | "py" | "java")
        )
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
            pending.extend(vero_git::read_snapshot_files(
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
    for path in &changed {
        let path_symbols = changed_file_symbols(
            root,
            change_set,
            path,
            source.get(path),
            &mut coverage_complete,
        )?;
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
    let mut rust_occurrences =
        std::collections::HashMap::<&str, Option<Vec<(String, u32, bool)>>>::new();
    // Comment- and string-stripped TypeScript, Python, and Java, computed once per file.
    let mut stripped_code = std::collections::HashMap::<&str, String>::new();
    for changed_path in &changed {
        let local_symbols: Vec<_> = changed_symbols_by_path
            .get(changed_path)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let symbol_matcher = SymbolMatcher::new(&local_symbols);
        for (candidate_path, candidate_text) in &source {
            let same_file_rust = candidate_path == changed_path && candidate_path.ends_with(".rs");
            if !should_scan_impact_candidate(&changed, changed_path, candidate_path) {
                continue;
            }
            if candidate_path.ends_with(".rs") {
                let occurrences = rust_occurrences
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| rust_identifier_occurrences(candidate_text));
                let wanted: std::collections::HashSet<&str> =
                    local_symbols.iter().map(String::as_str).collect();
                let references = occurrences.as_ref().map(|occurrences| {
                    occurrences
                        .iter()
                        .filter(|(name, _, _)| wanted.contains(name.as_str()))
                        .cloned()
                        .collect::<Vec<_>>()
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
                                    });
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if is_typescript_path(candidate_path) {
                let code = stripped_code
                    .entry(candidate_path.as_str())
                    .or_insert_with(|| {
                        typescript_code_without_comments_and_strings(candidate_text)
                    });
                for (line_index, line) in code.lines().enumerate() {
                    for symbol in symbol_matcher.matches(line) {
                        if typescript_analysis
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
                        });
                    }
                }
            }
        }
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
        if let Some(package) = package_id(root, path, &source[path]) {
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
    if scan_limit_reached {
        limitations.push("Impact scanning is bounded to 10,000 source files and 32 MiB of decoded source content per assessment.".into());
    }
    Ok(ImpactAssessment {
        schema_version: 3,
        snapshot_id: change_set.digest.clone(),
        coverage_complete,
        analyzers,
        changed_paths: changed.into_iter().collect(),
        changed_symbols: symbols.into_iter().collect(),
        groups,
        paths,
        limitations,
    })
}

pub(crate) fn changed_file_symbols(
    root: &Path,
    change_set: &ChangeSet,
    path: &str,
    current: Option<&String>,
    coverage_complete: &mut bool,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut symbols = std::collections::BTreeSet::new();
    if !path.ends_with(".rs")
        && !path.ends_with(".go")
        && !is_typescript_path(path)
        && !is_python_path(path)
        && !is_java_path(path)
    {
        return Ok(symbols);
    }
    let mut add = |text: &str| {
        if path.ends_with(".rs") {
            match rust_declared_symbols(text) {
                Some(found) => symbols.extend(found),
                None => {
                    *coverage_complete = false;
                    symbols.extend(declared_symbols(path, text));
                }
            }
        } else if is_typescript_path(path) {
            symbols.extend(declared_symbols(
                path,
                &typescript_code_without_comments_and_strings(text),
            ));
        } else if is_python_path(path) {
            symbols.extend(declared_symbols(
                path,
                &python_code_without_comments_and_strings(text),
            ));
        } else if is_java_path(path) {
            symbols.extend(java_declared_symbols(
                &java_code_without_comments_and_strings(text),
            ));
        } else {
            symbols.extend(declared_symbols(path, text));
        }
    };
    if let Some(text) = current {
        add(text);
    }
    if let Some(bytes) = vero_git::read_snapshot_base_file(root, change_set, Path::new(path))? {
        if let Ok(text) = String::from_utf8(bytes) {
            add(&text);
        } else {
            *coverage_complete = false;
        }
    }
    Ok(symbols)
}

pub(crate) fn snapshot_go_module_path(
    root: &Path,
    change_set: &ChangeSet,
) -> Result<Option<String>, String> {
    let Some(bytes) = vero_git::read_snapshot_file(root, change_set, Path::new("go.mod"))? else {
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
                });
                if edges.len() >= MAX_EDGES {
                    return edges;
                }
            }
        }
    }
    edges
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
        vero_git::working_tree_matches_index(root).unwrap_or(false)
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

pub(crate) fn find_executable(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.canonicalize().ok())
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
        "staged" => vero_git::working_tree_matches_index(root).unwrap_or(false),
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
    if let Some(configured) = std::env::var_os("VERO_TSSERVER") {
        return PathBuf::from(configured)
            .canonicalize()
            .ok()
            .filter(|path| path.is_file());
    }
    find_executable("tsserver")
}

pub(crate) fn query_typescript_references(
    root: &Path,
    executable: &Path,
    changed_paths: &[&String],
    source: &std::collections::BTreeMap<String, String>,
) -> Result<TypeScriptReferenceQuery, String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    const MAX_REFERENCE_QUERIES: usize = 32;
    const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
    const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let mut command = if executable
        .extension()
        .is_some_and(|extension| extension == "js")
    {
        let node = find_executable("node").ok_or("node was not found on PATH for VERO_TSSERVER")?;
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
                    let _ = sender.send(Err("tsserver response header exceeded 8 KiB".into()));
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
                let _ = sender.send(Err("tsserver response omitted Content-Length".into()));
                return;
            };
            if length > MAX_MESSAGE_BYTES {
                let _ = sender.send(Err("tsserver response exceeded 2 MiB".into()));
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
            let absolute = root.join(changed_path);
            if !absolute.starts_with(&root) {
                failures = true;
                continue;
            }
            let Ok(absolute) = absolute.canonicalize() else {
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
                    let Ok(candidate) = candidate.canonicalize() else {
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
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let root_uri = url::Url::from_directory_path(&root)
        .map_err(|_| "repository root cannot be represented as a file URI")?;
    let mut command = Command::new(executable);
    command
        .arg("serve")
        .current_dir(&root)
        .env_clear()
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
                    "workspaceFolders": [{"uri":root_uri.as_str(),"name":"vero-snapshot"}],
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
                                    let Ok(path) = path.canonicalize() else {
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
                    let Ok(path) = path.canonicalize() else {
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

pub(crate) fn rust_declared_symbols(source: &str) -> Option<std::collections::BTreeSet<String>> {
    struct Declarations(std::collections::BTreeSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for Declarations {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.0.insert(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_struct(self, item);
        }
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_enum(self, item);
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_trait(self, item);
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_mod(self, item);
        }
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_type(self, item);
        }
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_const(self, item);
        }
        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.0.insert(item.ident.to_string());
            syn::visit::visit_item_static(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.0.insert(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
        }
        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            self.0.insert(item.sig.ident.to_string());
            syn::visit::visit_trait_item_fn(self, item);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = Declarations(std::collections::BTreeSet::new());
    syn::visit::Visit::visit_file(&mut visitor, &file);
    Some(visitor.0)
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

/// Identifier occurrences in Rust paths, method calls, `use` trees, and macro
/// tokens whose name satisfies `keep`, as sorted, deduplicated
/// `(name, line, in_test_context)` triples. `None` when the file does not parse.
pub(crate) fn rust_identifier_occurrences_matching(
    source: &str,
    keep: &dyn Fn(&str) -> bool,
) -> Option<Vec<(String, u32, bool)>> {
    struct References<'a> {
        keep: &'a dyn Fn(&str) -> bool,
        found: Vec<(String, u32, bool)>,
        in_test_context: bool,
    }
    impl References<'_> {
        fn record_path(&mut self, path: &syn::Path) {
            for segment in &path.segments {
                let name = segment.ident.to_string();
                if (self.keep)(&name) {
                    self.found.push((
                        name,
                        segment.ident.span().start().line as u32,
                        self.in_test_context,
                    ));
                }
            }
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for References<'_> {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let previous = self.in_test_context;
            self.in_test_context |= is_test_context_attribute(&node.attrs);
            syn::visit::visit_item_fn(self, node);
            self.in_test_context = previous;
        }
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            let previous = self.in_test_context;
            self.in_test_context |= is_test_context_attribute(&node.attrs);
            syn::visit::visit_item_mod(self, node);
            self.in_test_context = previous;
        }
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            self.record_path(&node.path);
            syn::visit::visit_expr_path(self, node);
        }
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            self.record_path(&node.path);
            syn::visit::visit_expr_struct(self, node);
        }
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            self.record_path(&node.path);
            syn::visit::visit_type_path(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            if (self.keep)(&name) {
                self.found.push((
                    name,
                    node.method.span().start().line as u32,
                    self.in_test_context,
                ));
            }
            syn::visit::visit_expr_method_call(self, node);
        }
        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            syn::visit::visit_item_use(self, node);
            let mut names = Vec::new();
            fn collect(tree: &syn::UseTree, names: &mut Vec<String>) {
                match tree {
                    syn::UseTree::Path(path) => {
                        names.push(path.ident.to_string());
                        collect(&path.tree, names);
                    }
                    syn::UseTree::Name(name) => names.push(name.ident.to_string()),
                    syn::UseTree::Rename(rename) => names.push(rename.rename.to_string()),
                    syn::UseTree::Group(group) => {
                        for item in &group.items {
                            collect(item, names);
                        }
                    }
                    syn::UseTree::Glob(_) => {}
                }
            }
            collect(&node.tree, &mut names);
            for name in names {
                if (self.keep)(&name) {
                    self.found.push((
                        name,
                        node.tree.span().start().line as u32,
                        self.in_test_context,
                    ));
                }
            }
        }
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.record_path(&node.path);
            fn visit_tokens(
                tokens: proc_macro2::TokenStream,
                keep: &dyn Fn(&str) -> bool,
                in_test_context: bool,
                found: &mut Vec<(String, u32, bool)>,
            ) {
                for token in tokens {
                    match token {
                        proc_macro2::TokenTree::Ident(ident) => {
                            let name = ident.to_string();
                            if keep(&name) {
                                found.push((
                                    name,
                                    ident.span().start().line as u32,
                                    in_test_context,
                                ));
                            }
                        }
                        proc_macro2::TokenTree::Group(group) => {
                            visit_tokens(group.stream(), keep, in_test_context, found)
                        }
                        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
                    }
                }
            }
            visit_tokens(
                node.tokens.clone(),
                self.keep,
                self.in_test_context,
                &mut self.found,
            );
            syn::visit::visit_macro(self, node);
        }
    }
    let file = syn::parse_file(source).ok()?;
    let mut visitor = References {
        keep,
        found: Vec::new(),
        in_test_context: false,
    };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    visitor.found.sort();
    visitor.found.dedup();
    Some(visitor.found)
}

/// Every identifier occurrence in a Rust file (see
/// [`rust_identifier_occurrences_matching`]); parse once, query many times.
pub(crate) fn rust_identifier_occurrences(source: &str) -> Option<Vec<(String, u32, bool)>> {
    rust_identifier_occurrences_matching(source, &|_| true)
}

#[cfg(test)]
pub(crate) fn rust_references(
    source: &str,
    symbols: &[String],
) -> Option<Vec<(String, u32, bool)>> {
    rust_identifier_occurrences_matching(source, &|name| {
        symbols.iter().any(|symbol| symbol == name)
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
        .and_then(|candidate| candidate.canonicalize().ok())
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
        "__vero_changed_symbols__.py".to_owned(),
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
    let mut symbols = std::collections::BTreeSet::new();
    for line in source.lines() {
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
        if let Some(candidate) = candidate {
            let symbol: String = candidate
                .chars()
                .take_while(|character| character.is_alphanumeric() || *character == '_')
                .collect();
            if symbol.len() > 1 {
                symbols.insert(symbol);
            }
        }
    }
    symbols
}

pub fn java_declared_symbols(source: &str) -> std::collections::BTreeSet<String> {
    let mut symbols = declared_symbols("Source.java", source);
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
    for line in source.lines() {
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
                symbols.insert(name.to_owned());
            }
        }
    }
    symbols
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
