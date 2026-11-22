use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use vee_application::analytics::QualityAnalytics;
use vee_application::ProviderTaskResult;
use vee_present::{ansi, markdown, ToView};

/// Serializing, deserializing and serializing again yields the same JSON.
fn assert_round_trip<T: Serialize + DeserializeOwned>(document: &T) {
    let first = serde_json::to_value(document).unwrap();
    let rebuilt: T = serde_json::from_value(first.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rebuilt).unwrap(), first);
}

fn text<T: ToView>(document: &T) -> String {
    ansi::render(&document.to_view(), false)
}

fn md<T: ToView>(document: &T) -> String {
    markdown::render(&document.to_view())
}

fn rate(positive: usize, denominator: usize, observed: Option<f64>) -> serde_json::Value {
    json!({
        "positive_occurrences": positive,
        "negative_occurrences": denominator - positive,
        "disputed_occurrences": 1,
        "denominator": denominator,
        "observed_rate": observed
    })
}

fn analytics() -> QualityAnalytics {
    serde_json::from_value(json!({
        "schema_version": 9,
        "review_count": 12,
        "latest_gate_decisions": {"block": 3, "pass": 8},
        "reviews_without_gate_decision": 1,
        "findings_by_status": {"open": 5, "resolved": 9, "waived": 1},
        "findings_by_severity": {"high": 4, "low": 7, "medium": 4},
        "verification_runs_by_profile": {
            "unit": {"failed": 1, "incomplete": 0, "passed": 6, "timed_out": 0}
        },
        "test_diagnostics_by_profile": {"unit": {"test_failed": 2}},
        "test_diagnostics_limitations": ["Logs over 256 MiB were skipped."],
        "reviewed_feedback_by_label": {"confirmed": 6, "false_positive": 2},
        "reviewed_feedback_metrics": {
            "finding_accuracy": rate(6, 8, Some(0.75)),
            "actionability": rate(0, 0, None)
        },
        "provider_latency": {
            "local": {
                "measured_runs": 10,
                "unmeasured_runs": 1,
                "failed_runs": 0,
                "median_duration_ms": 6500,
                "p95_duration_ms": null
            }
        },
        "provider_latency_history_complete": true,
        "provider_latency_note": "Adapter wall-clock time, not model latency.",
        "provider_usage": {
            "local": {
                "reported_runs": 10,
                "unreported_runs": 1,
                "input_tokens": 120000,
                "output_tokens": 8000,
                "total_tokens": 128000,
                "estimated_cost_usd": 0.5,
                "priced_runs": 10,
                "unpriced_runs": 1
            }
        },
        "provider_usage_note": "Only provider-reported tokens are counted."
    }))
    .unwrap()
}

#[test]
fn analytics_view_shows_every_metric_the_cli_prints() {
    let report = analytics();
    let text = text(&report);
    assert!(
        text.starts_with("Local quality analytics (12 reviews)\n"),
        "{text}"
    );
    assert!(
        text.contains("  Finding accuracy       75.0% (6/8 labeled occurrences; 1 disputed)\n"),
        "{text}"
    );
    assert!(
        text.contains("  Actionability          unavailable (no unambiguous labels; 1 disputed)\n"),
        "{text}"
    );
    // Gate decisions and severities follow domain order, not alphabetical order.
    let block = text.find("✖ block").unwrap();
    let pass = text.find("✔ pass").unwrap();
    assert!(block < pass, "{text}");
    let high = text.find("✖ high").unwrap();
    let low = text.find("● low").unwrap();
    assert!(high < low, "{text}");
    assert!(
        text.contains("  unit     6       1       0          0"),
        "{text}"
    );
    assert!(text.contains("  unit     test_failed  2"), "{text}");
    assert!(text.contains("▲ Logs over 256 MiB were skipped."), "{text}");
    assert!(
        text.contains("  local     10       6500ms  n/a  1           0"),
        "{text}"
    );
    assert!(
        text.contains(
            "  local     10/1                      120000/8000/128000   0.500000 USD    10/1"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("Only provider-reported tokens are counted.\n"),
        "{text}"
    );
    assert!(
        md(&report).contains("| 🔴 **block** | 3 |"),
        "{}",
        md(&report)
    );
    assert_round_trip(&report);
}

#[test]
fn analytics_view_states_empty_history() {
    let mut value = serde_json::to_value(analytics()).unwrap();
    for key in [
        "latest_gate_decisions",
        "findings_by_status",
        "findings_by_severity",
        "verification_runs_by_profile",
        "test_diagnostics_by_profile",
        "reviewed_feedback_by_label",
        "provider_latency",
        "provider_usage",
    ] {
        value[key] = json!({});
    }
    value["test_diagnostics_limitations"] = json!([]);
    value["review_count"] = json!(0);
    let report: QualityAnalytics = serde_json::from_value(value).unwrap();
    let text = text(&report);
    for empty in [
        "No gate decisions recorded.",
        "No findings recorded.",
        "No verification runs recorded.",
        "No recognized test log events.",
        "No reviewed feedback recorded.",
        "No provider runs recorded.",
        "No provider usage recorded.",
    ] {
        assert!(text.contains(empty), "{empty}: {text}");
    }
    assert_round_trip(&report);
}

fn draft(output: serde_json::Value) -> ProviderTaskResult {
    serde_json::from_value(json!({
        "schema_version": 1,
        "snapshot_id": "sha256:snap",
        "reviewer_id": "correctness",
        "provider_id": "local",
        "provider_kind": "ollama_native",
        "model": "gemma3:12b",
        "output_digest": "sha256:out",
        "output": output
    }))
    .unwrap()
}

#[test]
fn pr_draft_view_shows_title_body_and_provenance() {
    let report = draft(json!({
        "title": "Fix lockout counter race",
        "body": "## Summary\nMake failed-login counting atomic.\n\n## Changes\n- Use a single UPDATE\n- Add a regression test\n\nSee [docs](https://example.com) <b>now</b>."
    }));
    let text = text(&report);
    assert!(text.starts_with("Pull request draft  · draft\n"), "{text}");
    assert!(
        text.contains("  Provider       local · ollama_native · gemma3:12b\n"),
        "{text}"
    );
    assert!(text.contains("  Output digest  sha256:out\n"), "{text}");
    assert!(
        text.contains("Title\n\nFix lockout counter race\n"),
        "{text}"
    );
    assert!(
        text.contains("Summary\n\nMake failed-login counting atomic.\n"),
        "{text}"
    );
    assert!(
        text.contains("  • Use a single UPDATE\n  • Add a regression test\n"),
        "{text}"
    );
    assert!(
        text.ends_with("● Draft only; it was not published or used in a gate.\n"),
        "{text}"
    );
    let md = md(&report);
    assert!(
        md.contains("See \\[docs\\]\\(https://example\\.com\\) \\<b\\>now\\</b\\>\\."),
        "model-authored Markdown is escaped: {md}"
    );
    assert!(!md.contains("\n## Summary"), "{md}");
    assert_round_trip(&report);
}

#[test]
fn pr_draft_view_says_when_the_body_is_empty() {
    let report = draft(json!({"title": "Tidy imports", "body": "  \n\n"}));
    let text = text(&report);
    assert!(text.contains("The draft has no body."), "{text}");
    assert_round_trip(&report);
}
