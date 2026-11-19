use super::*;

fn findings_schema() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../schemas/provider-findings-v1.schema.json"
    ))
    .unwrap()
}

fn review_input(files: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "instructions": "Review for correctness.",
        "output_schema": findings_schema(),
        "context_files": files,
    })
}

const LOCKOUT: &str = "package domain\n\n// RecordFailure counts a failure.\nfunc RecordFailure(key string) error {\n\tsnap, err := store.Get(key)\n\tif err != nil {\n\t\treturn err\n\t}\n\tsnap.FailureCount++\n\treturn store.Save(snap)\n}\n";

#[test]
fn numbered_source_marks_changed_lines_with_exact_one_based_numbers() {
    let rendered = numbered_source("first\nsecond\nthird\n", &[(2, 2)]);
    assert_eq!(rendered, "  1 | first\n+ 2 | second\n  3 | third");
}

#[test]
fn numbered_source_pads_line_numbers_to_the_widest_line() {
    let text = (1..=10).map(|n| format!("l{n}\n")).collect::<String>();
    let rendered = numbered_source(&text, &[(10, 10)]);
    assert!(rendered.starts_with("   1 | l1\n"));
    assert!(rendered.ends_with("+ 10 | l10"));
}

#[test]
fn fence_is_longer_than_any_backtick_run_in_the_content() {
    assert_eq!(fence_for("plain"), "```");
    assert_eq!(fence_for("has ``` inside"), "````");
    assert_eq!(fence_for("has ````` inside"), "``````");
}

#[test]
fn quoted_statement_resolves_to_its_changed_line() {
    let ranges = [(4, 11)];
    assert_eq!(
        locate_quoted_line(LOCKOUT, &ranges, "snap.FailureCount++"),
        Some(9)
    );
    assert_eq!(
        locate_quoted_line(LOCKOUT, &ranges, "  return store.Save(snap)  "),
        Some(10)
    );
}

#[test]
fn quote_on_an_unchanged_line_or_an_unknown_quote_has_no_line() {
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(9, 9)], "return store.Save(snap)"),
        None
    );
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(1, 11)], "mutex.Lock()"),
        None
    );
    assert_eq!(locate_quoted_line(LOCKOUT, &[(1, 11)], "   "), None);
}

#[test]
fn ambiguous_quote_resolves_only_when_it_matches_one_changed_line() {
    let text = "a := 1\nreturn err\nb := 2\nreturn err\n";
    assert_eq!(locate_quoted_line(text, &[(1, 4)], "return err"), None);
    assert_eq!(locate_quoted_line(text, &[(3, 4)], "return err"), Some(4));
}

#[test]
fn partial_quote_matches_a_unique_changed_line_containing_it() {
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(4, 11)], "snap, err := store.Get"),
        Some(5)
    );
}

#[test]
fn structure_schema_requires_a_quote_without_changing_the_provider_schema() {
    let original = findings_schema();
    let schema = structure_schema(&original);
    let item = &schema["properties"]["findings"]["items"];
    assert_eq!(item["properties"]["quote"]["type"], "string");
    assert!(item["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("quote")));
    assert!(original["properties"]["findings"]["items"]["properties"]
        .get("quote")
        .is_none());
}

#[test]
fn focused_targets_are_changed_files_with_text_in_stable_order() {
    let input = review_input(serde_json::json!([
        {"path":"b_test.go","content":"package b\n","changed_line_ranges":[[1,1]]},
        {"path":"b.go","content":"package b\n","changed_line_ranges":[[1,1]]},
        {"path":"ref.go","content":"package r\n","changed_line_ranges":[],"context_role":"snapshot_impact_reference"},
        {"path":"doc.md","content":"notes","changed_line_ranges":[],"context_role":"reviewer_configured_supplemental"},
        {"path":"big.go","content":null,"diff":"@@ -1 +1 @@\n-a\n+b\n","changed_line_ranges":[[1,1]]},
        {"path":"gone.go","content":null,"changed_line_ranges":[]},
    ]));
    let targets = focused_targets(&input).unwrap();
    let paths: Vec<_> = targets.iter().map(|target| target.path.as_str()).collect();
    assert_eq!(paths, ["b.go", "big.go", "b_test.go"]);
    assert!(targets[1].diff_only);
}

#[test]
fn focused_review_reasons_per_file_then_structures_located_findings() {
    let input = review_input(serde_json::json!([
        {"path":"domain/lockout.go","content":LOCKOUT,"changed_line_ranges":[[4,11]]},
        {"path":"domain/lockout_test.go","content":"package domain\n","changed_line_ranges":[[1,1]]},
    ]));
    let mut calls = Vec::new();
    let output = run_focused_review(&input, 32_768, 2_048, &mut |messages, format| {
        calls.push((messages.clone(), format.cloned()));
        let user = messages.last().unwrap()["content"].as_str().unwrap().to_owned();
        let content = match (format.is_some(), user.contains("domain/lockout_test.go")) {
            (false, false) => "RecordFailure reads, increments and saves without atomicity; concurrent failures lose increments at snap.FailureCount++.".to_owned(),
            (true, false) => serde_json::json!({"schema_version":1,"findings":[
                {"category":"concurrency","severity":"high","rationale":"Lost increment under concurrent failures.","confidence":70,"path":"other.go","line":1,"quote":"snap.FailureCount++"},
                {"category":"correctness","severity":"low","rationale":"Unlocatable.","confidence":null,"path":null,"line":null,"quote":"not in the file"}
            ]}).to_string(),
            (false, true) => "No defects.".to_owned(),
            (true, true) => r#"{"schema_version":1,"findings":[]}"#.to_owned(),
        };
        Ok((content, Some(vee_core::ProviderUsage { input_tokens: Some(100), output_tokens: Some(10), total_tokens: None })))
    })
    .unwrap();

    assert_eq!(calls.len(), 4, "two requests per changed file");
    let (first_messages, first_format) = &calls[0];
    assert!(first_format.is_none(), "reasoning runs without a schema");
    let first_user = first_messages[1]["content"].as_str().unwrap();
    assert!(first_user.contains("+  9 | \tsnap.FailureCount++"));
    assert!(first_user.contains("File under review: domain/lockout.go"));
    assert!(
        !first_user.contains("Related changed file: domain/lockout_test.go"),
        "test files are not related context"
    );
    assert!(first_messages[0]["content"]
        .as_str()
        .unwrap()
        .starts_with("Review for correctness."));
    let (second_messages, second_format) = &calls[1];
    assert!(
        second_format.as_ref().unwrap()["properties"]["findings"]["items"]["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("quote"))
    );
    assert!(second_messages[0]["content"]
        .as_str()
        .unwrap()
        .contains("lose increments"));

    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    crate::providers::validate_provider_task_output(&findings, &findings_schema()).unwrap();
    let findings = findings["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(
        findings[0]["path"], "domain/lockout.go",
        "path is the file under review"
    );
    assert_eq!(
        findings[0]["line"], 9,
        "line comes from the quoted statement"
    );
    assert!(findings[0].get("quote").is_none());
    assert_eq!(findings[1]["path"], "domain/lockout.go");
    assert_eq!(findings[1]["line"], serde_json::Value::Null);
    let usage = output.usage.unwrap();
    assert_eq!(usage.input_tokens, Some(400));
    assert_eq!(usage.output_tokens, Some(40));
}

#[test]
fn focused_review_omits_related_files_beyond_the_context_budget() {
    let large = "x := 1\n".repeat(4_000);
    let input = review_input(serde_json::json!([
        {"path":"a.go","content":"package a\n","changed_line_ranges":[[1,1]]},
        {"path":"b.go","content":large,"changed_line_ranges":[[1,1]]},
    ]));
    let mut first_user = None;
    run_focused_review(&input, 8_192, 1_024, &mut |messages, format| {
        if first_user.is_none() {
            first_user = Some(messages[1]["content"].as_str().unwrap().to_owned());
        }
        Ok((
            if format.is_some() {
                r#"{"schema_version":1,"findings":[]}"#
            } else {
                "No defects."
            }
            .to_owned(),
            None,
        ))
    })
    .unwrap();
    let first_user = first_user.unwrap();
    assert!(!first_user.contains("Related changed file: b.go\n"));
    assert!(first_user.contains("b.go (omitted to fit the context budget)"));
}

#[test]
fn focused_review_propagates_provider_failure_and_rejects_invalid_structure() {
    let input = review_input(serde_json::json!([
        {"path":"a.go","content":"package a\n","changed_line_ranges":[[1,1]]},
    ]));
    let error = run_focused_review(&input, 8_192, 1_024, &mut |_, _| {
        Err("Ollama provider request timed out".into())
    })
    .unwrap_err();
    assert_eq!(error, "Ollama provider request timed out");
    let error = run_focused_review(&input, 8_192, 1_024, &mut |_, format| {
        Ok((
            if format.is_some() {
                "not json"
            } else {
                "notes"
            }
            .to_owned(),
            None,
        ))
    })
    .unwrap_err();
    assert!(error.contains("structured findings"), "{error}");
}

#[test]
fn focused_review_with_no_changed_text_returns_no_findings_without_calls() {
    let input = review_input(serde_json::json!([]));
    let output = run_focused_review(&input, 8_192, 1_024, &mut |_, _| {
        panic!("no provider call expected")
    })
    .unwrap();
    assert_eq!(output.stdout, br#"{"schema_version":1,"findings":[]}"#);
    assert!(output.usage.is_none());
}

#[test]
fn quote_copied_with_its_rendered_marker_and_number_still_resolves() {
    let ranges = [(4, 11)];
    assert_eq!(
        locate_quoted_line(LOCKOUT, &ranges, "+  9 | \tsnap.FailureCount++"),
        Some(9)
    );
    assert_eq!(
        locate_quoted_line(LOCKOUT, &ranges, "9 | snap.FailureCount++"),
        Some(9)
    );
}

#[test]
fn multi_line_quote_resolves_to_its_first_matching_changed_line() {
    assert_eq!(
        locate_quoted_line(
            LOCKOUT,
            &[(4, 11)],
            "snap.FailureCount++\nreturn store.Save(snap)"
        ),
        Some(9)
    );
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(4, 11)], "```go\n\tsnap.FailureCount++\n```"),
        Some(9)
    );
}

#[test]
fn quote_with_different_internal_spacing_still_resolves() {
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(4, 11)], "snap, err  :=  store.Get( key )"),
        None,
        "spacing inside tokens is not normalized"
    );
    assert_eq!(
        locate_quoted_line(LOCKOUT, &[(4, 11)], "snap,   err := store.Get(key)"),
        Some(5)
    );
}
