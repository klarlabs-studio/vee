use super::*;
use std::process::Command;
use vee_core::ports::*;
use vee_store_sqlite::ReviewStore;

#[test]
fn cfg_attr_test_functions_are_treated_as_conditional_tests() {
    let file = syn::parse_file(
            "#[cfg_attr(test, test)] fn conditional_case() {}\n#[cfg_attr(feature = \"test\", rstest)] fn conditional_parameterized_case() {}",
        )
        .unwrap();
    let syn::Item::Fn(test_fn) = &file.items[0] else {
        panic!("expected function item");
    };
    let syn::Item::Fn(rstest_fn) = &file.items[1] else {
        panic!("expected function item");
    };
    assert!(has_test_attribute(&test_fn.attrs));
    assert!(has_non_test_cfg(&test_fn.attrs));
    assert!(has_test_attribute(&rstest_fn.attrs));
    assert!(has_non_test_cfg(&rstest_fn.attrs));
}

#[test]
fn typescript_impact_is_heuristic_and_ignores_comments_and_strings() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("src/api.ts"),
        "export function ChangedAPI() { return 1; }\n",
    )
    .unwrap();
    std::fs::write(
            root.join("src/consumer.ts"),
            "// ChangedAPI() in a comment is not a reference\nconst label = 'ChangedAPI';\nexport function call() { return ChangedAPI(); }\n",
        )
        .unwrap();
    std::fs::write(
        root.join("tests/api.spec.ts"),
        "import { ChangedAPI } from '../src/api';\nit('calls API', () => ChangedAPI());\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "typescript baseline"]);
    std::fs::write(
        root.join("src/api.ts"),
        "export function ChangedAPI() { return 2; }\n",
    )
    .unwrap();

    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let impact = analyze_impact_with_typescript_server(root, &change_set, None).unwrap();

    assert_eq!(impact.snapshot_id, change_set.digest);
    assert!(impact.changed_symbols.contains(&"ChangedAPI".to_owned()));
    assert!(impact.analyzers.iter().any(|analyzer| {
        analyzer.id == "typescript-language-service" && analyzer.status == "unavailable"
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "src/consumer.ts"
            && edge.relationship == "textual_symbol_reference"
            && edge.certainty == "inferred_heuristic"
            && edge.evidence_line == 3
    }));
    assert!(!impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "src/consumer.ts" && edge.evidence_line < 3));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "tests/api.spec.ts"
            && edge.relationship == "likely_test_reference"
            && edge.certainty == "inferred_heuristic"
    }));
    assert!(impact
        .limitations
        .iter()
        .any(|limitation| limitation.contains("TypeScript and JavaScript references")));
    let mut historical_snapshot = change_set.clone();
    historical_snapshot.scope = "commit".into();
    let changed = std::collections::BTreeSet::from(["src/api.ts".to_owned()]);
    let source = std::collections::BTreeMap::from([(
        "src/api.ts".to_owned(),
        std::fs::read_to_string(root.join("src/api.ts")).unwrap(),
    )]);
    let historical = analyze_typescript_references(
        root,
        &historical_snapshot,
        &changed,
        &source,
        true,
        Some(Path::new("unused-tsserver")),
    );
    assert_eq!(historical.analyzer.status, "skipped");
    assert!(!historical
        .edges
        .iter()
        .any(|edge| edge.certainty == "resolved_semantic"));
}

#[test]
fn typescript_declaration_positions_preserve_utf16_offsets_and_alias_targets() {
    let source = "const label = '😀';\nexport function ChangedAPI() { return label; }\n";
    let declarations = typescript_declaration_positions("src/api.ts", source);
    assert!(declarations.contains(&("ChangedAPI".into(), 2, 17)));
    let compact = typescript_declaration_positions(
        "src/compact.ts",
        "export function ChangedAPI(value: string) { return value; }\n",
    );
    assert_eq!(compact, vec![("ChangedAPI".into(), 1, 17)]);
    assert!(!declarations.contains(&("label".into(), 2, 39)));
}

#[test]
fn typescript_project_references_resolve_aliases_without_same_name_false_edges() {
    let Some(executable) = find_typescript_server() else {
        eprintln!("skipping TypeScript semantic integration test: tsserver is unavailable");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::create_dir_all(root.join("js-project/src")).unwrap();
    std::fs::create_dir_all(root.join("js-project/tests")).unwrap();
    std::fs::write(
            root.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true,"module":"commonjs","target":"es2020","paths":{"@app/*":["src/*"]}},"include":["src/**/*.ts","tests/**/*.ts"]}"#,
        )
        .unwrap();
    std::fs::write(
            root.join("js-project/jsconfig.json"),
            r#"{"compilerOptions":{"allowJs":true,"checkJs":true,"target":"es2020","paths":{"@js/*":["src/*"]}},"include":["src/**/*.js","tests/**/*.js"]}"#,
        )
        .unwrap();
    let files = [
        ("src/api.ts", "export function ChangedAPI() { return 1; }\n"),
        (
            "src/consumer.ts",
            "import { ChangedAPI as invoke } from '@app/api';\nexport const value = invoke();\n",
        ),
        (
            "src/unrelated.ts",
            "export function ChangedAPI() { return 2; }\nexport const value = ChangedAPI();\n",
        ),
        (
            "tests/api.spec.ts",
            "import { ChangedAPI } from '../src/api';\nexport const result = ChangedAPI();\n",
        ),
        (
            "js-project/src/api.js",
            "export function ChangedJSAPI() { return 1; }\n",
        ),
        (
            "js-project/src/consumer.js",
            "import { ChangedJSAPI as invoke } from '@js/api';\nexport const value = invoke();\n",
        ),
        (
            "js-project/src/unrelated.js",
            "export function ChangedJSAPI() { return 2; }\nexport const value = ChangedJSAPI();\n",
        ),
        (
            "js-project/tests/api.spec.js",
            "import { ChangedJSAPI } from '../src/api';\nexport const result = ChangedJSAPI();\n",
        ),
    ];
    for (path, contents) in files {
        let destination = root.join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, contents).unwrap();
    }
    git(&["add", "."]);
    git(&["commit", "-qm", "TypeScript baseline"]);
    std::fs::write(
        root.join("src/api.ts"),
        "export function ChangedAPI() { return 2; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("js-project/src/api.js"),
        "export function ChangedJSAPI() { return 2; }\n",
    )
    .unwrap();

    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let impact =
        analyze_impact_with_typescript_server(root, &change_set, Some(&executable)).unwrap();

    assert!(impact.coverage_complete);
    assert!(impact.changed_symbols.contains(&"ChangedAPI".into()));
    assert!(impact.changed_symbols.contains(&"ChangedJSAPI".into()));
    assert!(
        impact.analyzers.iter().any(|analyzer| {
            analyzer.id == "typescript-language-service"
                && analyzer.status == "used"
                && analyzer.version.is_some()
        }),
        "analyzers: {:?}\nlimitations: {:#?}",
        impact.analyzers,
        impact.limitations
    );
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "src/consumer.ts"
            && edge.relationship == "resolved_symbol_reference"
            && edge.certainty == "resolved_semantic"
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "tests/api.spec.ts"
            && edge.relationship == "likely_test_reference"
            && edge.certainty == "resolved_semantic"
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "js-project/src/consumer.js"
            && edge.relationship == "resolved_symbol_reference"
            && edge.certainty == "resolved_semantic"
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "js-project/tests/api.spec.js"
            && edge.relationship == "likely_test_reference"
            && edge.certainty == "resolved_semantic"
    }));
    assert!(!impact
        .paths
        .iter()
        .any(|edge| { edge.affected_path == "src/unrelated.ts" && edge.symbol == "ChangedAPI" }));
    assert!(!impact.paths.iter().any(|edge| {
        edge.affected_path == "js-project/src/unrelated.js" && edge.symbol == "ChangedJSAPI"
    }));

    let stale_snapshot = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let stale_source = std::fs::read_to_string(root.join("src/api.ts")).unwrap();
    let stale_changed = stale_snapshot
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let stale_sources = std::collections::BTreeMap::from([("src/api.ts".to_owned(), stale_source)]);
    std::fs::write(
        root.join("src/api.ts"),
        "export function ChangedAPI() { return 3; }\n",
    )
    .unwrap();
    let stale_analysis = analyze_typescript_references(
        root,
        &stale_snapshot,
        &stale_changed,
        &stale_sources,
        true,
        Some(&executable),
    );
    assert_eq!(stale_analysis.analyzer.status, "skipped");
    assert!(!stale_analysis
        .edges
        .iter()
        .any(|edge| edge.certainty == "resolved_semantic"));
}

#[test]
fn python_impact_uses_bounded_ast_references_and_test_paths() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("src/api.py"),
        "async def ChangedAPI(value):\n    return 1\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/consumer.py"),
        "# ChangedAPI in a comment\nlabel = 'ChangedAPI'\nresult = ChangedAPI(1)\n",
    )
    .unwrap();
    std::fs::write(
        root.join("tests/test_api.py"),
        "from src.api import ChangedAPI\n\ndef test_api():\n    assert ChangedAPI(1) == 1\n",
    )
    .unwrap();
    std::fs::write(root.join("src/broken.py"), "result = ChangedAPI(\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "python baseline"]);
    std::fs::write(
        root.join("src/api.py"),
        "async def ChangedAPI(value):\n    return 2\n",
    )
    .unwrap();

    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let impact = analyze_impact(root, &change_set).unwrap();

    assert!(impact.changed_symbols.contains(&"ChangedAPI".to_owned()));
    let python_analyzer = impact
        .analyzers
        .iter()
        .find(|analyzer| analyzer.id == "python-ast")
        .unwrap();
    if find_python_interpreter().is_some() {
        assert_eq!(python_analyzer.status, "partial");
    }
    if python_analyzer.status == "partial" {
        assert!(python_analyzer.version.is_some());
        assert!(!impact.coverage_complete);
        assert!(impact.paths.iter().any(|edge| {
            edge.affected_path == "src/consumer.py"
                && edge.relationship == "syntactic_symbol_reference"
                && edge.certainty == "inferred_syntax"
                && edge.evidence_line == 3
        }));
        assert!(impact.paths.iter().any(|edge| {
            edge.affected_path == "src/broken.py"
                && edge.relationship == "textual_symbol_reference"
                && edge.certainty == "inferred_heuristic"
                && edge.evidence_line == 1
        }));
        assert!(impact
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("Python AST parsing failed") }));
    } else {
        assert!(impact.paths.iter().any(|edge| {
            edge.affected_path == "src/consumer.py"
                && edge.relationship == "textual_symbol_reference"
                && edge.certainty == "inferred_heuristic"
                && edge.evidence_line == 3
        }));
    }
    assert!(!impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "src/consumer.py" && edge.evidence_line < 3));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "tests/test_api.py"
            && edge.relationship == "likely_test_reference"
            && matches!(
                edge.certainty.as_str(),
                "inferred_syntax" | "inferred_heuristic"
            )
    }));
    assert!(impact.limitations.iter().any(|limitation| limitation
        .contains("Python AST references are syntax-derived")
        || limitation.contains("Python interpreter was not found")));
}

#[test]
fn java_impact_reports_heuristic_references_and_ignores_comments_and_strings() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src/main/java/demo")).unwrap();
    std::fs::create_dir_all(root.join("src/test/java/demo")).unwrap();
    std::fs::write(
        root.join("src/main/java/demo/ChangedApi.java"),
        "package demo;\npublic class ChangedApi { public int value() { return 1; } }\n",
    )
    .unwrap();
    std::fs::write(
            root.join("src/main/java/demo/Consumer.java"),
            "package demo;\n// ChangedApi is mentioned in a comment\nclass Consumer {\n    String label = \"ChangedApi\";\n    ChangedApi api;\n    int result = api.value();\n}\n",
        )
        .unwrap();
    std::fs::write(
        root.join("src/test/java/demo/ChangedApiTest.java"),
        "package demo;\nclass ChangedApiTest { ChangedApi api; }\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "Java baseline"]);
    std::fs::write(
        root.join("src/main/java/demo/ChangedApi.java"),
        "package demo;\npublic class ChangedApi { public int value() { return 2; } }\n",
    )
    .unwrap();

    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let impact = analyze_impact(root, &change_set).unwrap();

    assert!(impact.changed_symbols.contains(&"ChangedApi".to_owned()));
    assert!(impact.changed_symbols.contains(&"value".to_owned()));
    assert!(impact
        .analyzers
        .iter()
        .any(|analyzer| { analyzer.id == "lexical-java" && analyzer.status == "partial" }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "src/main/java/demo/Consumer.java"
            && edge.relationship == "textual_symbol_reference"
            && edge.certainty == "inferred_heuristic"
            && edge.symbol == "ChangedApi"
            && edge.evidence_line == 5
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "src/main/java/demo/Consumer.java"
            && edge.relationship == "textual_symbol_reference"
            && edge.certainty == "inferred_heuristic"
            && edge.symbol == "value"
            && edge.evidence_line == 6
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.affected_path == "src/test/java/demo/ChangedApiTest.java"
            && edge.relationship == "likely_test_reference"
            && edge.certainty == "inferred_heuristic"
    }));
    assert!(!impact.paths.iter().any(|edge| {
        edge.affected_path == "src/main/java/demo/Consumer.java" && edge.evidence_line == 2
    }));
    assert!(impact
        .limitations
        .iter()
        .any(|limitation| limitation.contains("Java references are lexical heuristics")));
}

#[test]
fn java_symbol_extraction_keeps_declarations_and_ignores_method_calls() {
    let symbols = super::java_declared_symbols(
            "class Sample {\n    public int value() { return 1; }\n    void execute() {\n        if (ready()) invoke();\n        service.run();\n    }\n}\n",
        );

    assert!(symbols.contains("Sample"));
    assert!(symbols.contains("value"));
    assert!(symbols.contains("execute"));
    assert!(!symbols.contains("ready"));
    assert!(!symbols.contains("invoke"));
    assert!(!symbols.contains("run"));
}

#[test]
fn changed_test_files_remain_candidates_for_impact_references() {
    let changed = std::collections::BTreeSet::from([
        "go/pkg/api.go".to_string(),
        "go/pkg/api_test.go".to_string(),
        "go/pkg/consumer.go".to_string(),
        "src/lib.rs".to_string(),
        "tests/api_test.rs".to_string(),
    ]);
    assert!(should_scan_impact_candidate(
        &changed,
        "go/pkg/api.go",
        "go/pkg/api_test.go"
    ));
    assert!(should_scan_impact_candidate(
        &changed,
        "src/lib.rs",
        "tests/api_test.rs"
    ));
    assert!(should_scan_impact_candidate(
        &changed,
        "src/lib.rs",
        "src/consumer.rs"
    ));
    assert!(should_scan_impact_candidate(
        &changed,
        "src/lib.rs",
        "src/lib.rs"
    ));
    assert!(!should_scan_impact_candidate(
        &changed,
        "go/pkg/api.go",
        "go/pkg/consumer.go"
    ));
}

#[test]
fn impact_reports_evidenced_rust_and_go_references_with_uncertainty() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::create_dir_all(root.join("go/pkg")).unwrap();
    std::fs::write(root.join(".gitignore"), "/target/\n/Cargo.lock\n").unwrap();
    std::fs::write(
        root.join("go.mod"),
        "module example.invalid/impact-fixture\n\ngo 1.20\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"impact-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
            root.join("src/lib.rs"),
            "pub fn changed_api() {}\n#[cfg(test)]\npub(crate) fn test_helper_for_consumer() { changed_api(); }\nmod consumer;\n#[cfg(test)]\nmod external_tests;\n#[cfg(test)]\nmod other_tests;\n",
        )
        .unwrap();
    std::fs::write(
        root.join("src/external_tests.rs"),
        "#[test]\nfn check() { crate::changed_api(); }\nmod unrelated { #[test] fn check() {} }\n",
    )
    .unwrap();
    std::fs::write(root.join("src/other_tests.rs"), "#[test]\nfn check() {}\n").unwrap();
    std::fs::write(root.join("src/other_tests.rs"), "#[test]\nfn check() {}\n").unwrap();
    std::fs::write(
            root.join("src/consumer.rs"),
            "// changed_api() is only a comment\nconst LABEL: &str = \"changed_api\";\nfn call() { changed_api(); }\n",
        )
        .unwrap();
    std::fs::write(
        root.join("tests/api_test.rs"),
        "use impact_fixture::changed_api;\n#[test]\nfn api() { changed_api(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("go/pkg/api.go"),
        "package fixture\nfunc ChangedAPI() {}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("go/pkg/consumer.go"),
        "package fixture\nfunc call() { ChangedAPI() }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("go/pkg/api_test.go"),
        "package fixture\nimport \"testing\"\nfunc TestAPI(t *testing.T) { ChangedAPI() }\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "fixture"]);
    std::fs::write(
            root.join("src/lib.rs"),
            "pub fn changed_api() { assert!(true); }\n#[cfg(test)]\npub(crate) fn test_helper_for_consumer() { changed_api(); }\n#[cfg(test)]\nmod tests {\n    #[cfg(test)]\n    fn test_helper() { let _ = stringify!(super::changed_api()); }\n    #[test]\n    fn uses_api() { test_helper(); assert_eq!(stringify!(super::changed_api()), \"super::changed_api()\"); }\n    #[test]\n    fn helper_dependent() { test_helper(); }\n}\nmod consumer;\n#[cfg(test)]\nmod external_tests;\n#[cfg(test)]\nmod other_tests;\n",
        )
        .unwrap();
    std::fs::write(
            root.join("src/consumer.rs"),
            "// changed_api() is only a comment\nconst LABEL: &str = \"changed_api\";\nfn call() { crate::changed_api(); }\n#[cfg(test)]\nmod inline_tests {\n    #[test]\n    fn consumer_api() { crate::test_helper_for_consumer(); }\n}\n",
        )
        .unwrap();
    std::fs::write(
        root.join("go/pkg/api.go"),
        "package fixture\nfunc ChangedAPI() { _ = true }\n",
    )
    .unwrap();
    std::fs::write(
            root.join("go/pkg/api_test.go"),
            "package fixture\nimport \"testing\"\nfunc TestAPI(t *testing.T) { t.Helper(); ChangedAPI() }\n",
        )
        .unwrap();
    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();

    let impact = analyze_impact(root, &change_set).unwrap();

    assert_eq!(impact.snapshot_id, change_set.digest);
    assert_eq!(impact.schema_version, 3);
    assert!(impact.changed_symbols.contains(&"changed_api".to_string()));
    assert!(impact.changed_symbols.contains(&"ChangedAPI".to_string()));
    assert!(impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "src/consumer.rs"
            && edge.evidence_line == 3
            && edge.certainty == "inferred_syntax"
            && edge.relationship == "syntactic_symbol_reference"));
    assert!(!impact
        .paths
        .iter()
        .any(|edge| { edge.affected_path == "src/consumer.rs" && edge.evidence_line < 3 }));
    assert!(impact.paths.iter().any(|edge| {
        edge.source_path == "src/lib.rs"
            && edge.affected_path == "src/lib.rs"
            && edge.relationship == "likely_test_reference"
            && edge.evidence_line == 3
    }));
    assert!(impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "tests/api_test.rs"
            && edge.relationship == "likely_test_reference"));
    assert!(impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "go/pkg/consumer.go"));
    assert!(impact
        .paths
        .iter()
        .any(|edge| edge.affected_path == "go/pkg/api_test.go"
            && edge.relationship == "likely_test_reference"));
    assert!(impact
        .groups
        .iter()
        .any(|group| group.package_id == "rust:.:impact-fixture"
            && group.member_paths.contains(&"src/consumer.rs".to_string())));
    assert!(impact
        .groups
        .iter()
        .any(|group| group.package_id == "go:go/pkg:fixture"
            && group
                .member_paths
                .contains(&"go/pkg/consumer.go".to_string())));
    assert!(!impact.limitations.is_empty());
    let mut expected_test_paths = std::collections::BTreeSet::from([
        ("src/lib.rs".to_string(), "src/lib.rs".to_string()),
        ("src/lib.rs".to_string(), "src/consumer.rs".to_string()),
        (
            "src/lib.rs".to_string(),
            "src/external_tests.rs".to_string(),
        ),
        ("src/lib.rs".to_string(), "tests/api_test.rs".to_string()),
        (
            "go/pkg/api.go".to_string(),
            "go/pkg/api_test.go".to_string(),
        ),
    ]);
    let predicted_test_paths: std::collections::BTreeSet<_> = impact
        .paths
        .iter()
        .filter(|edge| edge.relationship == "likely_test_reference")
        .map(|edge| (edge.source_path.clone(), edge.affected_path.clone()))
        .collect();
    if predicted_test_paths.contains(&(
        "go/pkg/api_test.go".to_string(),
        "go/pkg/api_test.go".to_string(),
    )) {
        // Textual fallback sees the changed test file itself as a likely test target;
        // semantic gopls results do not emit that self-reference edge.
        expected_test_paths.insert((
            "go/pkg/api_test.go".to_string(),
            "go/pkg/api_test.go".to_string(),
        ));
    }
    let true_positives = predicted_test_paths
        .intersection(&expected_test_paths)
        .count();
    let precision = true_positives as f64 / predicted_test_paths.len() as f64;
    let recall = true_positives as f64 / expected_test_paths.len() as f64;
    assert_eq!(predicted_test_paths, expected_test_paths);
    assert_eq!(precision, 1.0, "seeded test-path precision");
    assert_eq!(recall, 1.0, "seeded test-path recall");

    let struct_references = rust_references(
        "struct ChangedStruct { field: u8 }\nfn test() { let _ = ChangedStruct { field: 1 }; }",
        &["ChangedStruct".to_string()],
    )
    .unwrap();
    assert!(struct_references
        .iter()
        .any(|(symbol, line, _)| { symbol == "ChangedStruct" && *line == 2 }));

    std::fs::write(
            root.join(".vee.yaml"),
            "version: 1\nverification:\n  impacted_go:\n    executable: go\n    args: [test, -json, \"{impacted_test_packages}\"]\n    env_allowlist: [PATH, HOME]\n    timeout_seconds: 120\n  impacted_rust:\n    executable: cargo\n    args: [test, --manifest-path, Cargo.toml, \"{impacted_rust_test_filters}\"]\n    env_allowlist: [PATH, HOME, CARGO_HOME, RUSTUP_HOME]\n    timeout_seconds: 120\n",
        )
        .unwrap();
    let config = RepositoryConfig::load(&root.join(".vee.yaml")).unwrap();
    std::fs::create_dir_all(root.join(".vee")).unwrap();
    let go_plan =
        plan_impacted_test_verification(root, &change_set, "impacted_go", &config).unwrap();
    assert_eq!(go_plan.snapshot_id, change_set.digest);
    assert_eq!(go_plan.targets, vec!["./go/pkg"]);
    assert_eq!(go_plan.invocations, vec![vec!["test", "-json", "./go/pkg"]]);
    assert!(!go_plan.execution_performed);
    let protected_policy = root.join(".vee/policy.yaml");
    std::fs::write(&protected_policy, "required_verifications: [impacted_go]\n").unwrap();
    let mut effective_plan_config = config.clone();
    apply_protected_policy(root, &mut effective_plan_config).unwrap();
    let protected_plan =
        plan_impacted_test_verification(root, &change_set, "impacted_go", &effective_plan_config)
            .unwrap();
    assert_eq!(protected_plan.profile_digest, go_plan.profile_digest);
    std::fs::remove_file(protected_policy).unwrap();
    let mut changed_profile_config = config.clone();
    changed_profile_config
        .verification
        .get_mut("impacted_go")
        .unwrap()
        .timeout_seconds += 1;
    let changed_go_plan =
        plan_impacted_test_verification(root, &change_set, "impacted_go", &changed_profile_config)
            .unwrap();
    assert_ne!(go_plan.profile_digest, changed_go_plan.profile_digest);
    let rust_plan =
        plan_impacted_test_verification(root, &change_set, "impacted_rust", &config).unwrap();
    assert_eq!(
        rust_plan.targets,
        vec![
            "impact-fixture::api",
            "impact-fixture::external_tests::check",
            "impact-fixture::external_tests::unrelated::check",
            "impact-fixture::inline_tests::consumer_api",
            "impact-fixture::other_tests::check",
            "impact-fixture::tests::helper_dependent",
            "impact-fixture::tests::uses_api"
        ]
    );
    assert!(rust_plan
        .targets
        .iter()
        .all(|target| target != "impact-fixture::check"));
    assert!(rust_plan
        .invocations
        .iter()
        .all(|args| args.iter().any(|arg| arg == "--format=pretty")));
    let mut store = ReviewStore::open(&root.join(".vee/vee.sqlite")).unwrap();
    let verification =
        run_impacted_test_verification(root, &change_set, "impacted_go", &config, &mut store)
            .unwrap();
    assert_eq!(verification.targets, vec!["./go/pkg"]);
    assert_eq!(verification.snapshot_id, change_set.digest);
    assert_eq!(
        verification.status,
        vee_core::VerificationStatus::Passed,
        "stdout={} stderr={}",
        verification
            .stdout_artifact
            .as_ref()
            .and_then(|artifact| std::fs::read(root.join(&artifact.path)).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default(),
        verification
            .stderr_artifact
            .as_ref()
            .and_then(|artifact| std::fs::read(root.join(&artifact.path)).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    );
    let go_output = std::fs::read(
        root.join(
            verification
                .stdout_artifact
                .as_ref()
                .expect("Go test stdout artifact")
                .path
                .as_str(),
        ),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&go_output).lines().any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .is_ok_and(|event| event["Action"] == "pass" && event["Test"].is_string())
    }));
    assert_eq!(
        store.verification(&verification.run_id).unwrap(),
        Some(verification)
    );
    let rust_verification =
        run_impacted_test_verification(root, &change_set, "impacted_rust", &config, &mut store)
            .unwrap();
    assert_eq!(rust_verification.targets, rust_plan.targets);
    assert_eq!(
        rust_verification.status,
        vee_core::VerificationStatus::Passed,
        "stdout={} stderr={}",
        rust_verification
            .stdout_artifact
            .as_ref()
            .and_then(|artifact| std::fs::read(root.join(&artifact.path)).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default(),
        rust_verification
            .stderr_artifact
            .as_ref()
            .and_then(|artifact| std::fs::read(root.join(&artifact.path)).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    );
    let rust_output = std::fs::read(
        root.join(
            rust_verification
                .stdout_artifact
                .as_ref()
                .expect("Rust test stdout artifact")
                .path
                .as_str(),
        ),
    )
    .unwrap();
    let rust_output = String::from_utf8_lossy(&rust_output);
    assert!(rust_output.contains("test api ... ok"));
    assert!(rust_output.contains("test tests::uses_api ... ok"));
    assert!(rust_output.contains("test tests::helper_dependent ... ok"));
    assert!(rust_output.contains("test external_tests::check ... ok"));
    assert!(rust_output.contains("test external_tests::unrelated::check ... ok"));
    assert!(rust_output.contains("test other_tests::check ... ok"));
    assert!(
        rust_output.contains("test consumer::inline_tests::consumer_api ... ok"),
        "Rust targeted output: {rust_output}"
    );
    let mut no_tests_config = config.clone();
    let fake_cargo_directory = tempfile::tempdir().unwrap();
    // Windows runs only executables with a PATHEXT extension, so the fake
    // there is a batch file rather than a shell script.
    #[cfg(windows)]
    let (fake_cargo_name, fake_cargo_script) =
        ("fake-cargo.cmd", "@echo no tests matched\r\n@exit /b 0\r\n");
    #[cfg(not(windows))]
    let (fake_cargo_name, fake_cargo_script) =
        ("fake-cargo", "#!/bin/sh\necho 'no tests matched'\nexit 0\n");
    let fake_cargo = fake_cargo_directory.path().join(fake_cargo_name);
    let fake_cargo_source = fake_cargo_directory.path().join("fake-cargo-source");
    std::fs::write(&fake_cargo_source, fake_cargo_script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_cargo_source, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    std::fs::copy(&fake_cargo_source, &fake_cargo).unwrap();
    let profile = no_tests_config
        .verification
        .get_mut("impacted_rust")
        .unwrap();
    profile.executable = fake_cargo.to_string_lossy().into_owned();
    profile.args = vec![
        "test".into(),
        "--manifest-path".into(),
        "Cargo.toml".into(),
        "{impacted_rust_test_filters}".into(),
    ];
    profile.env_allowlist = vec!["PATH".into(), "HOME".into()];
    let no_tests = run_impacted_test_verification(
        root,
        &change_set,
        "impacted_rust",
        &no_tests_config,
        &mut store,
    )
    .unwrap();
    assert_eq!(
        no_tests.status,
        vee_core::VerificationStatus::Incomplete,
        "a successful command that reports no executed tests is inconclusive"
    );
    let stderr_artifact = no_tests
        .stderr_artifact
        .as_ref()
        .expect("diagnostic artifact");
    let diagnostic = std::fs::read(root.join(&stderr_artifact.path)).unwrap();
    assert!(String::from_utf8_lossy(&diagnostic).contains("without reporting any executed tests"));
    assert_eq!(digest(&diagnostic), no_tests.stderr_digest);
}

#[test]
fn rust_test_module_context_includes_external_cfg_test_modules() {
    let source = std::collections::BTreeMap::from([
            (
                "src/lib.rs".to_string(),
                "pub fn changed() {}\n#[cfg(test)] mod checks;\n#[cfg(test)] mod nested;\n#[cfg(test)] #[path = \"custom_test.rs\"] mod custom;\n#[cfg(test)] #[cfg(feature = \"extra\")] mod conditional;\n#[cfg(test)] #[path = \"lib.rs\"] mod cycle;\n".to_string(),
            ),
            (
                "src/checks.rs".to_string(),
                "#[test] fn calls_changed() { crate::changed(); }\n".to_string(),
            ),
            (
                "src/consumer.rs".to_string(),
                "fn calls_changed() { crate::changed(); }\n".to_string(),
            ),
            (
                "src/nested/mod.rs".to_string(),
                "#[test] fn nested_test() {}\n".to_string(),
            ),
            (
                "src/custom_test.rs".to_string(),
                "#[test] fn custom_test() {}\n".to_string(),
            ),
            (
                "src/conditional.rs".to_string(),
                "#[test] fn conditional_test() {}\n".to_string(),
            ),
        ]);

    let modules = rust_test_module_paths(&source);
    assert!(!modules["src/checks.rs"].conditional);
    assert_eq!(modules["src/checks.rs"].module_path, ["checks"]);
    assert!(!modules["src/custom_test.rs"].conditional);
    assert_eq!(modules["src/custom_test.rs"].module_path, ["custom"]);
    assert!(!modules["src/nested/mod.rs"].conditional);
    assert_eq!(modules["src/nested/mod.rs"].module_path, ["nested"]);
    assert!(modules["src/conditional.rs"].conditional);
    assert!(modules.len() < source.len());
}

#[test]
fn impact_uses_baseline_symbols_for_deleted_rust_declarations() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='deleted_fixture'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn removed_api() {}\n").unwrap();
    std::fs::write(
        root.join("tests/api.rs"),
        "#[test]\nfn still_calls_removed_api() { deleted_fixture::removed_api(); }\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    std::fs::remove_file(root.join("src/lib.rs")).unwrap();
    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();

    let impact = analyze_impact(root, &change_set).unwrap();

    assert!(impact.changed_symbols.contains(&"removed_api".to_string()));
    assert!(impact.paths.iter().any(|edge| {
        edge.source_path == "src/lib.rs"
            && edge.affected_path == "tests/api.rs"
            && edge.relationship == "likely_test_reference"
            && edge.symbol == "removed_api"
    }));
}

#[test]
fn non_source_changes_do_not_mark_impact_coverage_incomplete() {
    let mut coverage_complete = true;
    let symbols = changed_file_symbols(
        "assets/logo.png",
        None,
        Some(vec![0xff, 0xfe]),
        &mut coverage_complete,
    );
    assert!(symbols.is_empty());
    assert!(coverage_complete);
}

#[test]
fn rust_package_id_parses_toml_spacing_and_quoting() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join("src")).unwrap();
    std::fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname=\"my-crate\"\nversion = '0.1.0'\n",
    )
    .unwrap();
    assert_eq!(
        package_id(directory.path(), "src/lib.rs", ""),
        Some("rust:.:my-crate".into())
    );
}

#[test]
fn go_impact_uses_semantic_references_when_gopls_is_available() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "vee@example.invalid"]);
    git(&["config", "user.name", "Vee test"]);
    std::fs::write(
        root.join("go.mod"),
        "module example.invalid/impact\n\ngo 1.24\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("api")).unwrap();
    std::fs::create_dir_all(root.join("consumer")).unwrap();
    std::fs::create_dir_all(root.join("shared")).unwrap();
    std::fs::create_dir_all(root.join("neighbor")).unwrap();
    std::fs::create_dir_all(root.join("unrelated")).unwrap();
    std::fs::write(
            root.join("api/api.go"),
            "package api\nimport \"example.invalid/impact/shared\"\nfunc Changed() { shared.Helper() }\n",
        )
        .unwrap();
    std::fs::write(
        root.join("shared/shared.go"),
        "package shared\nfunc Helper() {}\n",
    )
    .unwrap();
    std::fs::write(
            root.join("neighbor/neighbor.go"),
            "package neighbor\nimport \"example.invalid/impact/shared\"\nfunc Use() { shared.Helper() }\n",
        )
        .unwrap();
    std::fs::write(
            root.join("consumer/consumer.go"),
            "package consumer\nimport alias \"example.invalid/impact/api\"\nfunc Call() { alias.Changed() }\n",
        )
        .unwrap();
    std::fs::write(
            root.join("consumer/consumer_test.go"),
            "package consumer\nimport (\n    \"testing\"\n    alias \"example.invalid/impact/api\"\n)\nfunc TestCall(t *testing.T) { alias.Changed() }\n",
        )
        .unwrap();
    std::fs::write(
        root.join("unrelated/unrelated.go"),
        "package unrelated\n// Changed() is text only\nconst label = \"Changed\"\n",
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    std::fs::write(
            root.join("api/api.go"),
            "package api\nimport \"example.invalid/impact/shared\"\nfunc Changed() { shared.Helper(); _ = true }\n",
        )
        .unwrap();
    let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();

    let impact = analyze_impact(root, &change_set).unwrap();

    assert_eq!(impact.schema_version, 3);
    let analyzer = impact
        .analyzers
        .iter()
        .find(|analyzer| analyzer.id == "gopls")
        .unwrap();
    if find_executable("gopls").is_some() {
        assert!(
            matches!(analyzer.status.as_str(), "used" | "partial"),
            "{:#?}",
            impact.limitations
        );
        assert!(analyzer
            .version
            .as_deref()
            .is_some_and(|version| version != "unknown"));
        assert!(
            impact.paths.iter().any(|edge| {
                edge.affected_path == "consumer/consumer.go"
                    && edge.relationship == "resolved_symbol_reference"
                    && edge.certainty == "resolved_semantic"
            }),
            "{:#?}",
            impact.paths
        );
        assert!(
            impact.paths.iter().any(|edge| {
                edge.affected_path == "consumer/consumer_test.go"
                    && edge.relationship == "likely_test_reference"
                    && edge.certainty == "resolved_semantic"
            }),
            "{:#?}",
            impact.paths
        );
    } else {
        assert_eq!(analyzer.status, "unavailable");
        assert!(impact.paths.iter().any(|edge| {
            edge.affected_path == "consumer/consumer.go"
                && edge.relationship == "textual_symbol_reference"
                && edge.certainty == "inferred_heuristic"
        }));
        assert!(impact.paths.iter().any(|edge| {
            edge.affected_path == "consumer/consumer_test.go"
                && edge.relationship == "likely_test_reference"
                && edge.certainty == "inferred_heuristic"
        }));
    }
    assert!(!impact.paths.iter().any(|edge| {
        edge.affected_path == "unrelated/unrelated.go" && edge.certainty != "inferred_heuristic"
    }));
    assert!(impact.paths.iter().any(|edge| {
        edge.source_path == "api/api.go"
            && edge.affected_path == "neighbor/neighbor.go"
            && edge.relationship == "shared_local_dependency"
            && edge.symbol == "example.invalid/impact/shared"
            && edge.certainty == "inferred_import"
            && edge.evidence_line == 2
    }));
}

#[test]
fn go_impact_links_changed_packages_to_local_packages_sharing_dependencies() {
    let changed = std::collections::BTreeSet::from(["retry/retry.go".to_string()]);
    let source = std::collections::BTreeMap::from([
            (
                "retry/retry.go".to_string(),
                "package retry\nimport (\n  ferrors \"example.invalid/fortify/errors\"\n  \"time\"\n)\n".to_string(),
            ),
            (
                "errors/errors.go".to_string(),
                "package errors\n".to_string(),
            ),
            (
                "circuitbreaker/breaker.go".to_string(),
                "package circuitbreaker\nimport (\n  ferrors \"example.invalid/fortify/errors\"\n)\n".to_string(),
            ),
            (
                "metrics/metrics.go".to_string(),
                "package metrics\nimport \"example.invalid/fortify/errors\"\n".to_string(),
            ),
        ]);

    let edges = go_local_dependency_edges("example.invalid/fortify", &changed, &source);

    let breaker = edges
        .iter()
        .find(|edge| edge.affected_path == "circuitbreaker/breaker.go")
        .unwrap();
    assert_eq!(breaker.source_path, "retry/retry.go");
    assert_eq!(breaker.relationship, "shared_local_dependency");
    assert_eq!(breaker.symbol, "example.invalid/fortify/errors");
    assert_eq!(breaker.certainty, "inferred_import");
    assert_eq!(breaker.evidence_line, 3);
    assert!(edges
        .iter()
        .any(|edge| edge.affected_path == "metrics/metrics.go"));
    assert!(!edges
        .iter()
        .any(|edge| edge.affected_path == "errors/errors.go"));
    assert_eq!(
        go_import_paths(
            "package p\nimport (\n // \"example.invalid/ignored\"\n `example.invalid/real`\n)\n"
        ),
        vec![("example.invalid/real".into(), 4)]
    );
}

#[test]
fn tsserver_messages_are_read_with_unix_and_windows_newlines() {
    // Content-Length counts the JSON plus one newline byte.
    let unix = b"Content-Length: 3\r\n\r\n{}\nContent-Length: 8\r\n\r\n{\"a\":1}\n".to_vec();
    let windows = b"Content-Length: 3\r\n\r\n{}\r\nContent-Length: 8\r\n\r\n{\"a\":1}\r\n".to_vec();
    for stream in [unix, windows] {
        let mut reader = std::io::BufReader::new(stream.as_slice());
        let first = crate::impact::read_tsserver_message(&mut reader, 1024)
            .unwrap()
            .unwrap();
        let second = crate::impact::read_tsserver_message(&mut reader, 1024)
            .unwrap()
            .unwrap();
        let parse = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap();
        assert_eq!(parse(&first), serde_json::json!({}));
        assert_eq!(parse(&second), serde_json::json!({"a": 1}));
        assert_eq!(
            crate::impact::read_tsserver_message(&mut reader, 1024).unwrap(),
            None
        );
    }
}

#[test]
fn tsserver_messages_without_content_length_or_over_the_limit_are_rejected() {
    let mut missing = std::io::BufReader::new(&b"X-Other: 1\r\n\r\n{}\n"[..]);
    assert!(crate::impact::read_tsserver_message(&mut missing, 1024)
        .unwrap_err()
        .contains("omitted Content-Length"));
    let mut large = std::io::BufReader::new(&b"Content-Length: 4096\r\n\r\n"[..]);
    assert!(crate::impact::read_tsserver_message(&mut large, 1024).is_err());
}

#[test]
fn only_files_naming_a_changed_symbol_need_parsing() {
    let symbols = ["parse_config".to_owned(), "r#type".to_owned()];
    let filter = ChangedSymbolFilter::new(symbols.iter().map(String::as_str));
    assert!(filter.may_mention("fn main() { parse_config(); }"));
    assert!(filter.may_mention("let value = r#type;"));
    // Substrings of a longer identifier are not mentions.
    assert!(!filter.may_mention("fn main() { parse_config_file(); }"));
    assert!(!filter.may_mention("fn unrelated() {}"));
    assert!(!ChangedSymbolFilter::new(std::iter::empty()).may_mention("parse_config"));
}
