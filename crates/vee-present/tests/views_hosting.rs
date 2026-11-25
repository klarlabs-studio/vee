use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use vee_application::hosting::{
    PublicationDestination, PullRequestIssues, ReviewPublication, WebhookRetention,
};
use vee_application::repository_map::{ChangePackage, CrossRepositoryImpact, RepositoryMap};
use vee_hosting::{PullRequestContextReport, WorkItemSnapshot};
use vee_present::{ansi, markdown, ToView};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OID_BASE: &str = "1111111111111111111111111111111111111111";
const OID_HEAD: &str = "2222222222222222222222222222222222222222";

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

fn pull_request(number: u64) -> serde_json::Value {
    json!({"repository": {"host": "github.com", "full_name": "acme/widgets"}, "number": number})
}

fn pull_request_issues(archive: bool) -> PullRequestIssues {
    let mut value = json!({
        "schema_version": 1,
        "provider": "github",
        "pull_request": pull_request(42),
        "revision": "etag-7",
        "complete": true,
        "gate_eligible": false,
        "issues": [
            {
                "external_id": "comment-101",
                "author": "maintainer",
                "body": "Handle the empty list case.\nOtherwise the loop panics.",
                "path": "src/lib.rs",
                "line": 12,
                "side": "new",
                "source_url": "https://github.com/acme/widgets/pull/42#discussion_r101",
                "created_at": "2026-11-01T10:00:00Z",
                "updated_at": null,
                "classification": "untrusted_external_review"
            },
            {
                "external_id": "comment-102",
                "author": null,
                "body": "Please add a changelog entry | and *docs*",
                "path": null,
                "line": null,
                "side": null,
                "source_url": null,
                "created_at": null,
                "updated_at": null,
                "classification": "untrusted_external_review"
            }
        ]
    });
    if archive {
        value["archive_digest"] = json!(DIGEST_A);
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn pull_request_issues_view_lists_untrusted_discussions() {
    let issues = pull_request_issues(true);
    let text = text(&issues);
    assert!(
        text.starts_with("Review discussions on acme/widgets #42  ✔ complete\n"),
        "{text}"
    );
    assert!(text.contains(&format!("Archive   {DIGEST_A}")), "{text}");
    assert!(text.contains("Discussions (2)\n"), "{text}");
    assert!(
        text.contains("comment-101  src/lib.rs:12    maintainer  Handle the empty list case."),
        "{text}"
    );
    assert!(
        text.contains("comment-102  general comment  unknown"),
        "{text}"
    );
    assert!(
        text.contains(&format!("→ vee reviews imported show {DIGEST_A}")),
        "{text}"
    );
    let md = md(&issues);
    assert!(
        md.contains("and \\*docs\\*"),
        "untrusted text is escaped: {md}"
    );
    assert!(md.contains("\\|"), "table separators are escaped: {md}");
    assert_round_trip(&issues);
}

#[test]
fn pull_request_issues_view_offers_archiving_and_flags_incomplete_pagination() {
    let mut issues = pull_request_issues(false);
    issues.report.complete = false;
    let text = text(&issues);
    assert!(text.contains("▲ incomplete"), "{text}");
    assert!(text.contains("Pagination did not complete"), "{text}");
    assert!(
        text.contains(
            "→ vee hosting pr-issues --repository acme/widgets --number 42 --provider github --archive"
        ),
        "{text}"
    );
    assert!(!text.contains("Archive "), "{text}");
    assert_round_trip(&issues);
    assert!(serde_json::to_value(&issues)
        .unwrap()
        .get("archive_digest")
        .is_none());
}

#[test]
fn pull_request_issues_view_says_when_there_are_no_discussions() {
    let mut issues = pull_request_issues(false);
    issues.report.issues.clear();
    let text = text(&issues);
    assert!(text.contains("Discussions (0)\n"), "{text}");
    assert!(
        text.contains("No review discussions on this pull request."),
        "{text}"
    );
    assert!(!text.contains('→'), "nothing to archive: {text}");
    assert!(md(&issues).contains("_No review discussions on this pull request._"));
}

fn pull_request_context() -> PullRequestContextReport {
    serde_json::from_value(json!({
        "schema_version": 1,
        "provider": "azure-devops",
        "snapshot": {
            "pull_request": {"repository": {"host": "dev.azure.com", "full_name": "org/project/repo"}, "number": 7},
            "base_oid": OID_BASE,
            "head_oid": OID_HEAD,
            "title": "Retry *flaky* uploads",
            "body": "Adds a bounded retry.",
            "state": "open",
            "revision": "rev-3"
        },
        "changed_files": [
            {"path": "src/upload.rs", "change": "modified", "previous_path": null, "patch": null, "additions": 12, "deletions": 3},
            {"path": "src/retry.rs", "change": "renamed", "previous_path": "src/backoff.rs", "patch": null, "additions": 0, "deletions": 0}
        ],
        "limitations": ["Azure DevOps diff metadata does not include line-level patches; file records are context only, not line evidence."]
    }))
    .unwrap()
}

#[test]
fn pull_request_context_view_shows_metadata_files_and_limitations() {
    let report = pull_request_context();
    let text = text(&report);
    assert!(
        text.starts_with("Pull request org/project/repo #7  ● open\n"),
        "{text}"
    );
    assert!(text.contains("Title     Retry *flaky* uploads"), "{text}");
    assert!(text.contains(&format!("Head      {OID_HEAD}")), "{text}");
    assert!(text.contains("Revision  rev-3"), "{text}");
    assert!(text.contains("Changed files (2)\n"), "{text}");
    assert!(text.contains("modified  src/upload.rs"), "{text}");
    assert!(text.contains("+12 −3"), "{text}");
    assert!(text.contains("src/backoff.rs → src/retry.rs"), "{text}");
    assert!(text.contains("Limitations\n"), "{text}");
    let md = md(&report);
    assert!(md.contains("Retry \\*flaky\\* uploads"), "{md}");
    assert_round_trip(&report);
}

#[test]
fn pull_request_context_view_says_when_no_files_changed() {
    let mut report = pull_request_context();
    report.changed_files.clear();
    report.limitations.clear();
    let text = text(&report);
    assert!(
        text.contains("The provider reported no changed files."),
        "{text}"
    );
    assert!(!text.contains("Limitations"), "{text}");
    assert_round_trip(&report);
}

fn work_item() -> WorkItemSnapshot {
    serde_json::from_value(json!({
        "schema_version": 1,
        "reference": {"repository": {"host": "github.com", "full_name": "acme/widgets"}, "number": 9},
        "provider": "github",
        "api_base": "https://api.github.com/",
        "title": "Uploads fail on slow links",
        "body": "Steps:\n1. Throttle the network",
        "acceptance_criteria": "Uploads retry three times",
        "url": "https://github.com/acme/widgets/issues/9",
        "state": "open",
        "updated_at": "2026-11-02T08:00:00Z",
        "labels": ["bug", "network"],
        "content_digest": DIGEST_B
    }))
    .unwrap()
}

#[test]
fn issue_context_view_shows_the_attributed_issue() {
    let item = work_item();
    let text = text(&item);
    assert!(
        text.starts_with("Issue acme/widgets #9  ● open\n"),
        "{text}"
    );
    assert!(
        text.contains("Title                Uploads fail on slow links"),
        "{text}"
    );
    assert!(
        text.contains("URL                  https://github.com/acme/widgets/issues/9"),
        "{text}"
    );
    assert!(text.contains("Labels               bug, network"), "{text}");
    assert!(text.contains("Description          Steps:"), "{text}");
    assert!(
        text.contains("Acceptance criteria  Uploads retry three times"),
        "{text}"
    );
    assert!(
        text.contains(&format!("Content digest       {DIGEST_B}")),
        "{text}"
    );
    assert_round_trip(&item);
}

#[test]
fn issue_context_view_marks_a_missing_description() {
    let mut item = work_item();
    item.body = None;
    item.acceptance_criteria = None;
    item.labels.clear();
    let text = text(&item);
    assert!(text.contains("Description     none"), "{text}");
    assert!(!text.contains("Acceptance criteria"), "{text}");
    assert!(!text.contains("Labels"), "{text}");
    assert_round_trip(&item);
}

fn publication() -> ReviewPublication {
    let mut publication: ReviewPublication = serde_json::from_value(json!({
        "schema_version": 1,
        "review_id": "rev_1",
        "snapshot_id": DIGEST_A,
        "provider_check_id": "check-55",
        "thread_ids": {"fp-auth": "thread-1", "fp-race": "thread-2"},
        "revision": "etag-8"
    }))
    .unwrap();
    publication.destination = Some(PublicationDestination {
        provider: "github".into(),
        pull_request: serde_json::from_value(pull_request(42)).unwrap(),
    });
    publication
}

#[test]
fn publication_view_shows_destination_check_and_threads() {
    let publication = publication();
    let text = text(&publication);
    assert!(
        text.starts_with("Published review rev_1  ✔ published\n"),
        "{text}"
    );
    assert!(
        text.contains("Pull request    github.com/acme/widgets#42"),
        "{text}"
    );
    assert!(text.contains("Provider        github"), "{text}");
    assert!(text.contains("Provider check  check-55"), "{text}");
    assert!(text.contains("Finding threads (2)\n"), "{text}");
    assert!(text.contains("fp-auth      thread-1"), "{text}");
    assert_round_trip(&publication);
}

#[test]
fn publication_json_keeps_only_the_published_fields() {
    let value = serde_json::to_value(publication()).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "provider_check_id",
            "review_id",
            "revision",
            "schema_version",
            "snapshot_id",
            "thread_ids"
        ]
    );
}

#[test]
fn publication_view_says_when_no_threads_were_published() {
    let mut publication = publication();
    publication.thread_ids.clear();
    publication.destination = None;
    let text = text(&publication);
    assert!(text.contains("Finding threads (0)\n"), "{text}");
    assert!(
        text.contains("No finding threads were published."),
        "{text}"
    );
    assert!(!text.contains("Pull request"), "{text}");
}

fn retention(eligible: u64, apply: bool) -> WebhookRetention {
    WebhookRetention {
        schema_version: 1,
        retention_days: 30,
        eligible_receipts: eligible,
        deleted_receipts: if apply { eligible } else { 0 },
        dry_run: !apply,
    }
}

#[test]
fn webhook_retention_view_offers_to_apply_a_dry_run() {
    let preview = retention(4, false);
    let text = text(&preview);
    assert!(
        text.starts_with("Webhook receipt retention  · dry run\n"),
        "{text}"
    );
    assert!(text.contains("Eligible receipts  4"), "{text}");
    assert!(
        text.contains("4 completed webhook receipts are eligible for deletion."),
        "{text}"
    );
    assert!(
        text.contains("→ vee hosting prune-webhooks --older-than-days 30 --apply"),
        "{text}"
    );
    assert_round_trip(&preview);
}

#[test]
fn webhook_retention_view_reports_deletions_and_empty_runs() {
    let applied = text(&retention(4, true));
    assert!(applied.contains("✔ pruned"), "{applied}");
    assert!(
        applied.contains("Deleted 4 completed webhook receipts older than 30 days."),
        "{applied}"
    );
    assert!(!applied.contains('→'), "{applied}");
    let empty = text(&retention(0, false));
    assert!(
        empty.contains("No completed webhook receipts are older than 30 days."),
        "{empty}"
    );
    assert!(!empty.contains('→'), "{empty}");
    assert_round_trip(&retention(4, true));
}

fn repository_map() -> RepositoryMap {
    serde_json::from_value(json!({
        "schema_version": 2,
        "repositories": [
            {"id": "consumer", "root": "/work/consumer", "ecosystem": "cargo", "manifest": "Cargo.toml", "manifest_digest": DIGEST_A},
            {"id": "provider", "root": "/work/provider", "ecosystem": "cargo", "manifest": "Cargo.toml", "manifest_digest": DIGEST_B}
        ],
        "dependencies": [
            {
                "from": "consumer", "to": "provider", "package": "provider", "declared_alias": null,
                "kind": "normal", "declared_requirement": "0.1", "version_compatibility": "satisfied",
                "declared_path": "../provider", "match_basis": "resolved_path",
                "evidence_path": "Cargo.toml", "evidence_digest": DIGEST_A,
                "constraint_source_path": null, "constraint_source_digest": null
            }
        ],
        "limitations": ["Only direct manifest dependencies are mapped."],
        "digest": DIGEST_B
    }))
    .unwrap()
}

#[test]
fn repository_map_view_lists_repositories_and_edges() {
    let map = repository_map();
    let text = text(&map);
    assert!(
        text.starts_with("Repository map (2 repositories, 1 direct edge)\n"),
        "{text}"
    );
    assert!(text.contains(&format!("Digest  {DIGEST_B}")), "{text}");
    assert!(
        text.contains("consumer    cargo      Cargo.toml  /work/consumer"),
        "{text}"
    );
    assert!(text.contains("Dependencies (1)\n"), "{text}");
    assert!(
        text.contains(&format!(
            "consumer  provider  provider  normal  ✔ satisfied  {DIGEST_A}"
        )),
        "{text}"
    );
    assert!(text.contains("Only direct manifest dependencies are mapped."));
    assert_round_trip(&map);
}

#[test]
fn repository_map_view_says_when_nothing_was_mapped() {
    let mut map = repository_map();
    map.repositories.clear();
    map.dependencies.clear();
    map.limitations.clear();
    let text = text(&map);
    assert!(text.contains("No repositories were mapped."), "{text}");
    assert!(
        text.contains("No direct dependencies between these repositories."),
        "{text}"
    );
    assert_round_trip(&map);
}

fn change_package() -> ChangePackage {
    serde_json::from_value(json!({
        "schema_version": 2,
        "package_id": DIGEST_A,
        "dependency_map_digest": DIGEST_B,
        "readiness": "incomplete",
        "priority_order": ["provider", "consumer"],
        "remote_state_refreshed": true,
        "pull_request_lifecycle": {
            "status": "local_head_mismatch", "linked_count": 2, "refreshed_count": 1,
            "open_count": 1, "closed_count": 0, "merged_count": 0, "local_head_mismatch_count": 1
        },
        "repositories": [
            {
                "repository_id": "provider",
                "pull_requests": [pull_request(42)],
                "remote_pull_requests": [{
                    "pull_request": pull_request(42), "provider": "github", "state": "open",
                    "base_oid": OID_BASE, "head_oid": OID_HEAD, "revision": "etag-9",
                    "local_head_matches": false
                }],
                "root": "/work/provider", "head_oid": OID_HEAD, "base_oid": OID_BASE,
                "branch": "feat/retry", "snapshot_id": DIGEST_A, "review_id": "rev_1",
                "saved_gate_status": "pass", "gate_validity": "current",
                "downstream_repository_count": 1, "priority_factors": ["upstream"],
                "gate_decision_id": null, "effective_config_digest": null, "policy_digest": null,
                "changed_files": [{"path": "src/lib.rs", "mode": 33188, "content_digest": DIGEST_B, "status": "modified"}],
                "source_digest": DIGEST_B, "has_changes": true
            },
            {
                "repository_id": "consumer",
                "pull_requests": [pull_request(43)],
                "discovered_pull_requests": [pull_request(43)],
                "root": "/work/consumer", "head_oid": OID_HEAD, "base_oid": null,
                "branch": null, "snapshot_id": DIGEST_B, "review_id": null,
                "saved_gate_status": "not_reviewed", "gate_validity": "not_available",
                "downstream_repository_count": 0, "priority_factors": [],
                "gate_decision_id": null, "effective_config_digest": null, "policy_digest": null,
                "changed_files": [], "source_digest": DIGEST_A, "has_changes": false
            }
        ],
        "dependency_edges": [],
        "limitations": ["Remote CI state is not included."]
    }))
    .unwrap()
}

#[test]
fn change_package_view_shows_repositories_files_and_pull_requests() {
    let package = change_package();
    let text = text(&package);
    assert!(
        text.starts_with(&format!("Change package {DIGEST_A}  ▲ incomplete\n")),
        "{text}"
    );
    assert!(
        text.contains("Priority order          provider → consumer"),
        "{text}"
    );
    assert!(
        text.contains("Pull requests           local head mismatch (2 linked, 1 refreshed)"),
        "{text}"
    );
    assert!(
        text.contains("provider    feat/retry  /work/provider  1              ✔ pass"),
        "{text}"
    );
    assert!(text.contains("consumer    detached"), "{text}");
    assert!(text.contains("Changed files (1)\n"), "{text}");
    assert!(
        text.contains("provider    ▲ modified  src/lib.rs"),
        "{text}"
    );
    assert!(text.contains("Pull requests (2)\n"), "{text}");
    assert!(
        text.contains("github.com/acme/widgets#42  linked      ● open"),
        "{text}"
    );
    assert!(text.contains("▲ differs"), "{text}");
    assert!(
        text.contains("github.com/acme/widgets#43  discovered  not refreshed"),
        "{text}"
    );
    assert_round_trip(&package);
}

#[test]
fn change_package_view_says_when_nothing_changed() {
    let mut package = change_package();
    for repository in &mut package.repositories {
        repository.changed_files.clear();
        repository.pull_requests.clear();
        repository.discovered_pull_requests.clear();
        repository.remote_pull_requests.clear();
    }
    let text = text(&package);
    assert!(
        text.contains("No changed files in these repositories."),
        "{text}"
    );
    assert!(!text.contains("Pull requests ("), "{text}");
    package.repositories.clear();
    let text = self::text(&package);
    assert!(text.contains("No repositories in this package."), "{text}");
    assert_round_trip(&package);
}

fn cross_impact() -> CrossRepositoryImpact {
    serde_json::from_value(json!({
        "schema_version": 16,
        "producer_snapshot_id": DIGEST_A,
        "changed_symbols": ["parse_config", "Config"],
        "api_contract_changes": [
            {"producer_path": "openapi.yaml", "producer_digest": DIGEST_B, "method": "GET", "route": "/widgets", "operation_id": "listWidgets"}
        ],
        "api_contract_compatibility": [
            {"producer_path": "openapi.yaml", "issue": "operation_removed", "component_path": null, "method": "DELETE", "route": "/widgets/{id}", "previous_operation_id": "deleteWidget", "current_operation_id": null}
        ],
        "api_contract_coverage": [],
        "dependency_paths": [
            {"producer_package": "provider", "consumer_package": "consumer", "packages": ["consumer", "provider"], "manifest_digests": [DIGEST_A, DIGEST_B]}
        ],
        "references": [
            {
                "consumer_repository": "consumer", "path": "src/main.rs", "line": 14, "symbol": "parse_config",
                "certainty": "inferred_syntax", "match_context": "function_call", "source_digest": DIGEST_B,
                "consumer_package_id": "consumer", "dependency_status": "declared_downstream", "dependency_paths": []
            }
        ],
        "coverage_complete": false,
        "limitations": ["Macro-generated calls are not analyzed."],
        "digest": DIGEST_B
    }))
    .unwrap()
}

#[test]
fn cross_impact_view_shows_references_paths_and_contracts() {
    let impact = cross_impact();
    let text = text(&impact);
    assert!(
        text.starts_with("Cross-repository impact  ▲ incomplete\n"),
        "{text}"
    );
    assert!(
        text.contains("Changed symbols    parse_config, Config"),
        "{text}"
    );
    assert!(text.contains("Coverage is incomplete"), "{text}");
    assert!(text.contains("References (1)\n"), "{text}");
    assert!(
        text.contains("consumer:src/main.rs:14  parse_config  inferred syntax"),
        "{text}"
    );
    assert!(text.contains("consumer → provider"), "{text}");
    assert!(text.contains("GET /widgets"), "{text}");
    assert!(text.contains("✖ operation removed"), "{text}");
    assert!(
        text.contains("Macro-generated calls are not analyzed."),
        "{text}"
    );
    assert_round_trip(&impact);
}

#[test]
fn cross_impact_view_says_when_no_consumer_references_the_change() {
    let mut impact = cross_impact();
    impact.references.clear();
    impact.dependency_paths.clear();
    impact.api_contract_changes.clear();
    impact.api_contract_compatibility.clear();
    impact.changed_symbols.clear();
    impact.coverage_complete = true;
    let text = text(&impact);
    assert!(text.contains("✔ complete"), "{text}");
    assert!(text.contains("Changed symbols    none"), "{text}");
    assert!(
        text.contains("No consumer references to the changed symbols."),
        "{text}"
    );
    assert!(!text.contains("Dependency paths"), "{text}");
    assert_round_trip(&impact);
}
