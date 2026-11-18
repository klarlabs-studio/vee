use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use vero_application::ReviewResult;
use vero_core::ports::*;
use vero_core::{FindingRecord, FindingStatus, RepositoryConfig, ReviewSummary, Severity};
use vero_store_sqlite::ReviewStore;

const INDEX_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/index.html"));
const APP_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/app.js"));
const APP_CSS: &str = include_str!(concat!(env!("OUT_DIR"), "/app.css"));
const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    root: Arc<PathBuf>,
    origin: String,
    auth_token: Option<Arc<str>>,
    webhook: Option<Arc<WebhookState>>,
}

struct WebhookState {
    provider: Arc<dyn vero_hosting::GitHostingProvider>,
    handler: Arc<dyn WebhookEventHandler>,
}

/// Application-owned action for a successfully verified hosting event. The
/// HTTP layer handles signature checks, durable delivery leases, retries, and
/// acknowledgements; product-specific event actions stay outside transport.
/// Implementations must tolerate retry and overlapping execution of the same
/// delivery: a lease can expire during a long-running synchronous handler, and
/// only the current lease token can commit the durable receipt.
pub trait WebhookEventHandler: Send + Sync + 'static {
    fn handle(&self, event: &vero_hosting::WebhookEnvelope) -> Result<(), String>;
}

impl<F> WebhookEventHandler for F
where
    F: Fn(&vero_hosting::WebhookEnvelope) -> Result<(), String> + Send + Sync + 'static,
{
    fn handle(&self, event: &vero_hosting::WebhookEnvelope) -> Result<(), String> {
        self(event)
    }
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = if self.error == "authentication required" {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        (
            status,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"Vero UI\"")],
            Json(self),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    repository: String,
}

#[derive(Serialize)]
struct ReviewDetail {
    review: ReviewResult,
    findings: Vec<FindingRecord>,
    impact: vero_application::ImpactAssessment,
}

#[derive(Serialize)]
struct ConfigSummary {
    config: RepositoryConfig,
    provider_ids: Vec<String>,
    reviewer_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewRequest {
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    reviewer_ids: Vec<String>,
    #[serde(default)]
    policy_profile: Option<String>,
}

#[derive(Deserialize)]
struct FindingQuery {
    review_id: Option<String>,
    severity: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigUpdate {
    config: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusUpdate {
    status: String,
    reason: String,
}

#[derive(Serialize)]
struct FindingStatusUpdated {
    schema_version: u32,
    finding_id: String,
    status: String,
    reason: String,
    note: String,
}

fn default_scope() -> String {
    "base".into()
}

fn open_store(root: &Path) -> Result<ReviewStore, String> {
    ReviewStore::open(&root.join(".vero/vero.sqlite"))
}

fn check_origin(
    headers: &HeaderMap,
    expected: &str,
    auth_token: Option<&str>,
) -> Result<(), ApiError> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError {
            error: "request host is missing or invalid".into(),
        })?;
    let expected_authority = expected.strip_prefix("http://").unwrap_or(expected);
    if !authority_matches(host, expected_authority) {
        return Err(ApiError {
            error: "request host does not match the local UI origin".into(),
        });
    }
    if let Some(expected_token) = auth_token {
        let authorized = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|candidate| {
                constant_time_token_eq(candidate.as_bytes(), expected_token.as_bytes())
            });
        if !authorized {
            return Err(ApiError {
                error: "authentication required".into(),
            });
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let origin_uri = origin.parse::<axum::http::Uri>().ok();
        let expected_uri = expected.parse::<axum::http::Uri>().ok();
        if !origin_uri
            .zip(expected_uri)
            .is_some_and(|(origin, expected)| {
                origin.scheme_str() == expected.scheme_str()
                    && origin.authority().zip(expected.authority()).is_some_and(
                        |(origin, expected)| authority_matches(origin.as_str(), expected.as_str()),
                    )
            })
        {
            return Err(ApiError {
                error: "cross-origin requests are not accepted".into(),
            });
        }
    }
    Ok(())
}

fn constant_time_token_eq(candidate: &[u8], expected: &[u8]) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .iter()
        .zip(expected)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn authority_matches(candidate: &str, expected: &str) -> bool {
    let Ok(candidate) = candidate.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let Ok(expected) = expected.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    candidate.host().eq_ignore_ascii_case(expected.host())
        && candidate.port_u16().unwrap_or(80) == expected.port_u16().unwrap_or(80)
}

fn api_error(error: impl ToString) -> ApiError {
    ApiError {
        error: error.to_string(),
    }
}

async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Health>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    Ok(Json(Health {
        status: "ok",
        repository: state.root.display().to_string(),
    }))
}

async fn list_reviews(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ReviewSummary>>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    open_store(&state.root)
        .map_err(api_error)?
        .list_reviews()
        .map(Json)
        .map_err(api_error)
}

#[derive(Serialize)]
struct AnalyticsDay {
    day: String,
    pass: usize,
    block: usize,
    incomplete: usize,
    ungated: usize,
}

#[derive(Serialize)]
struct AnalyticsReviewDimension {
    review_id: String,
    day: String,
    status: String,
    summary_status: String,
    reviewer_ids: Vec<String>,
    provider_ids: Vec<String>,
    finding_categories: Vec<String>,
    finding_rule_ids: Vec<String>,
}

const MAX_ANALYTICS_FINDING_DRILLDOWN: usize = 200;
const MAX_ANALYTICS_VERIFICATION_RUNS: usize = 500;
const MAX_ANALYTICS_PROVIDER_REVIEWS: usize = 2_000;

#[derive(Serialize)]
struct AnalyticsVerificationRun {
    run_id: String,
    snapshot_id: String,
    profile_id: String,
    status: String,
    created_at: String,
}

#[derive(Serialize)]
struct AnalyticsProviderLatency {
    provider_id: String,
    measured_runs: usize,
    unmeasured_runs: usize,
    failed_runs: usize,
    median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct AnalyticsProviderLatencyDay {
    day: String,
    provider_id: String,
    measured_runs: usize,
    median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct AnalyticsProviderCost {
    provider_id: String,
    estimated_usd: Option<f64>,
    priced_runs: usize,
    unpriced_runs: usize,
}

#[derive(Serialize)]
struct AnalyticsProviderCostDay {
    day: String,
    provider_id: String,
    estimated_usd: f64,
    priced_runs: usize,
    unpriced_runs: usize,
}

#[derive(Serialize)]
struct AnalyticsFinding {
    finding_id: String,
    category: String,
    severity: String,
    rationale: String,
    path: Option<String>,
    line: Option<u32>,
    status: String,
    last_review_id: Option<String>,
    last_seen: String,
    rule_attributions: Vec<vero_core::RuleAttribution>,
}

#[derive(Serialize)]
struct LocalAnalytics {
    schema_version: u32,
    review_count: usize,
    history_complete: bool,
    dimensions_complete: bool,
    reviews_by_day: Vec<AnalyticsDay>,
    review_dimensions: Vec<AnalyticsReviewDimension>,
    findings_by_severity: std::collections::BTreeMap<String, usize>,
    findings_by_rule: std::collections::BTreeMap<String, usize>,
    findings_by_rule_complete: bool,
    finding_drilldown: Vec<AnalyticsFinding>,
    finding_drilldown_total: usize,
    finding_drilldown_complete: bool,
    explicit_feedback_by_label: std::collections::BTreeMap<String, usize>,
    feedback_note: &'static str,
    verification_run_count: usize,
    verification_history_complete: bool,
    verification_runs: Vec<AnalyticsVerificationRun>,
    provider_latency: Vec<AnalyticsProviderLatency>,
    provider_latency_history_complete: bool,
    provider_latency_note: &'static str,
    provider_latency_reviews: usize,
    provider_latency_history: Vec<AnalyticsProviderLatencyDay>,
    provider_costs: Vec<AnalyticsProviderCost>,
    provider_cost_history_complete: bool,
    provider_cost_note: &'static str,
    provider_cost_reviews: usize,
    provider_cost_history: Vec<AnalyticsProviderCostDay>,
}

async fn get_analytics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<LocalAnalytics>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let root = (*state.root).clone();
    let report = tokio::task::spawn_blocking(move || build_analytics(&root))
        .await
        .map_err(|error| api_error(format!("analytics worker failed: {error}")))??;
    Ok(Json(report))
}

fn build_analytics(root: &std::path::Path) -> Result<LocalAnalytics, ApiError> {
    let store = open_store(root).map_err(api_error)?;
    let reviews = store.list_reviews().map_err(api_error)?;
    let history_complete = reviews.len() <= 500;
    let mut dimensions_complete = history_complete;
    let mut provider_latency_history_complete = reviews.len() <= MAX_ANALYTICS_PROVIDER_REVIEWS;
    // Analytics remain readable while a user edits a temporarily invalid config.
    // In that state, usage is counted as unpriced until a valid rate is available.
    let config = vero_application::load_repository_config(root).ok();
    let mut provider_cost_history_complete = reviews.len() <= MAX_ANALYTICS_PROVIDER_REVIEWS;
    let mut provider_cost_totals: std::collections::BTreeMap<String, (f64, usize, usize)> =
        std::collections::BTreeMap::new();
    let mut provider_costs_by_day: std::collections::BTreeMap<
        (String, String),
        (f64, usize, usize),
    > = std::collections::BTreeMap::new();
    let mut provider_samples: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    let mut provider_unmeasured: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut provider_failures: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut provider_samples_by_day: std::collections::BTreeMap<(String, String), Vec<u64>> =
        std::collections::BTreeMap::new();
    for review in reviews.iter().take(MAX_ANALYTICS_PROVIDER_REVIEWS) {
        let day = review.created_at.get(..10).unwrap_or("unknown").to_owned();
        let Some(payload) = store.get(&review.review_id).map_err(api_error)? else {
            provider_latency_history_complete = false;
            provider_cost_history_complete = false;
            continue;
        };
        let Ok(saved) = vero_application::deserialize_review_result(&payload) else {
            provider_latency_history_complete = false;
            provider_cost_history_complete = false;
            continue;
        };
        for outcome in saved.reviewer_outcomes {
            if outcome.provider_id.is_empty() || outcome.provider_id == "vero" {
                continue;
            }
            let total = provider_cost_totals
                .entry(outcome.provider_id.clone())
                .or_default();
            let daily = provider_costs_by_day
                .entry((day.clone(), outcome.provider_id.clone()))
                .or_default();
            let model = outcome.model.as_deref().or_else(|| {
                config
                    .as_ref()
                    .and_then(|config| config.providers.get(&outcome.provider_id))
                    .and_then(|provider| provider.model.as_deref())
            });
            let pricing = model.and_then(|model| {
                config
                    .as_ref()
                    .and_then(|config| config.providers.get(&outcome.provider_id))
                    .and_then(|provider| provider.pricing.get(model))
            });
            let priced = if let (Some(usage), Some(pricing)) = (&outcome.usage, pricing) {
                if let (Some(input_tokens), Some(output_tokens)) =
                    (usage.input_tokens, usage.output_tokens)
                {
                    let estimate = (input_tokens as f64 * pricing.input_usd_per_million
                        + output_tokens as f64 * pricing.output_usd_per_million)
                        / 1_000_000.0;
                    total.0 += estimate;
                    total.1 += 1;
                    daily.0 += estimate;
                    daily.1 += 1;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !priced {
                total.2 += 1;
                daily.2 += 1;
            }
            if outcome.status == "failed" {
                *provider_failures
                    .entry(outcome.provider_id.clone())
                    .or_default() += 1;
            }
            if let Some(duration_ms) = outcome.duration_ms {
                provider_samples
                    .entry(outcome.provider_id.clone())
                    .or_default()
                    .push(duration_ms);
                provider_samples_by_day
                    .entry((day.clone(), outcome.provider_id))
                    .or_default()
                    .push(duration_ms);
            } else {
                *provider_unmeasured.entry(outcome.provider_id).or_default() += 1;
            }
        }
    }
    let mut by_day: std::collections::BTreeMap<String, AnalyticsDay> =
        std::collections::BTreeMap::new();
    let mut review_dimensions = Vec::new();
    for review in reviews.iter().take(500).rev() {
        let day = review.created_at.get(..10).unwrap_or("unknown").to_owned();
        let entry = by_day.entry(day.clone()).or_insert_with(|| AnalyticsDay {
            day: day.clone(),
            pass: 0,
            block: 0,
            incomplete: 0,
            ungated: 0,
        });
        let latest_decision = store
            .gate_decisions_for_review(&review.review_id)
            .map_err(api_error)?
            .pop();
        let status = latest_decision
            .map(|decision| format!("{:?}", decision.status).to_lowercase())
            .unwrap_or_else(|| "ungated".to_owned());
        match status.as_str() {
            "pass" => entry.pass += 1,
            "block" => entry.block += 1,
            "incomplete" => entry.incomplete += 1,
            _ => entry.ungated += 1,
        }
        let payload = store.get(&review.review_id).map_err(api_error)?;
        let mut reviewer_ids = Vec::new();
        let mut provider_ids = Vec::new();
        let mut finding_categories = Vec::new();
        let mut finding_rule_ids = Vec::new();
        if let Some(payload) = payload {
            if let Ok(saved) = vero_application::deserialize_review_result(&payload) {
                reviewer_ids.extend(
                    saved
                        .reviewer_outcomes
                        .iter()
                        .map(|outcome| outcome.reviewer_id.clone()),
                );
                provider_ids.extend(
                    saved
                        .reviewer_outcomes
                        .iter()
                        .map(|outcome| outcome.provider_id.clone())
                        .filter(|id| !id.is_empty()),
                );
                finding_categories.extend(
                    saved
                        .findings
                        .iter()
                        .map(|finding| finding.category.clone()),
                );
                finding_rule_ids.extend(saved.findings.iter().flat_map(|finding| {
                    finding
                        .rule_attributions
                        .iter()
                        .map(|attribution| attribution.rule_id.clone())
                }));
            } else {
                dimensions_complete = false;
            }
        } else {
            dimensions_complete = false;
        }
        reviewer_ids.sort();
        reviewer_ids.dedup();
        provider_ids.sort();
        provider_ids.dedup();
        finding_categories.sort();
        finding_categories.dedup();
        finding_rule_ids.sort();
        finding_rule_ids.dedup();
        review_dimensions.push(AnalyticsReviewDimension {
            review_id: review.review_id.clone(),
            day,
            status,
            summary_status: review.status.clone(),
            reviewer_ids,
            provider_ids,
            finding_categories,
            finding_rule_ids,
        });
    }
    let (finding_records, finding_drilldown_total) = store
        .list_findings_page(None, None, None, MAX_ANALYTICS_FINDING_DRILLDOWN, 0)
        .map_err(api_error)?;
    let (verification_records, verification_run_count) = store
        .recent_verification_summaries(MAX_ANALYTICS_VERIFICATION_RUNS)
        .map_err(api_error)?;
    let mut findings_by_severity = std::collections::BTreeMap::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let key = format!("{severity:?}").to_lowercase();
        let (_, count) = store
            .list_findings_page(Some(severity), None, None, 1, 0)
            .map_err(api_error)?;
        if count > 0 {
            findings_by_severity.insert(key, count);
        }
    }
    let all_findings = store.list_findings(None, None, None).map_err(api_error)?;
    let mut findings_by_rule = std::collections::BTreeMap::new();
    for record in &all_findings {
        let rule_ids = record
            .finding
            .rule_attributions
            .iter()
            .map(|attribution| attribution.rule_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for rule_id in rule_ids {
            *findings_by_rule.entry(rule_id).or_insert(0) += 1;
        }
    }
    let finding_drilldown = finding_records
        .into_iter()
        .map(|record| {
            let last_review_id = record
                .occurrences
                .iter()
                .max_by(|left, right| left.observed_at.cmp(&right.observed_at))
                .map(|occurrence| occurrence.review_id.clone());
            let mut rule_attributions = record.finding.rule_attributions;
            rule_attributions.sort();
            rule_attributions.dedup();
            AnalyticsFinding {
                finding_id: record.finding.id,
                category: record.finding.category,
                severity: format!("{:?}", record.finding.severity).to_lowercase(),
                rationale: record.finding.rationale,
                path: record.finding.path,
                line: record.finding.line,
                status: record.status.as_str().to_owned(),
                last_review_id,
                last_seen: record.last_seen,
                rule_attributions,
            }
        })
        .collect();
    let mut explicit_feedback_by_label = std::collections::BTreeMap::new();
    for feedback in store.list_finding_feedback().map_err(api_error)? {
        let label = serde_json::to_value(feedback.label)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        *explicit_feedback_by_label.entry(label).or_insert(0) += 1;
    }
    Ok(LocalAnalytics {
        schema_version: 8,
        review_count: reviews.len(),
        history_complete,
        dimensions_complete,
        reviews_by_day: by_day
            .into_values()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(14)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
        review_dimensions,
        findings_by_severity,
        findings_by_rule,
        findings_by_rule_complete: true,
        finding_drilldown,
        finding_drilldown_total,
        finding_drilldown_complete: finding_drilldown_total <= MAX_ANALYTICS_FINDING_DRILLDOWN,
        explicit_feedback_by_label,
        feedback_note: "Counts reflect explicit human labels only; they are not calibrated acceptance or accuracy rates.",
        verification_run_count,
        verification_history_complete: verification_run_count <= MAX_ANALYTICS_VERIFICATION_RUNS,
        verification_runs: verification_records
            .into_iter()
            .map(|run| AnalyticsVerificationRun {
                run_id: run.run_id,
                snapshot_id: run.snapshot_id,
                profile_id: run.profile_id,
                status: run.status,
                created_at: run.created_at,
            })
            .collect(),
        provider_latency: {
            let ids = provider_samples
                .keys()
                .chain(provider_unmeasured.keys())
                .chain(provider_failures.keys())
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            ids.into_iter()
                .map(|provider_id| {
                    let mut samples = provider_samples.remove(&provider_id).unwrap_or_default();
                    samples.sort_unstable();
                    let percentile = |numerator: usize, denominator: usize| {
                        (!samples.is_empty()).then(|| {
                            let rank = samples
                                .len()
                                .saturating_mul(numerator)
                                .div_ceil(denominator)
                                .max(1);
                            samples[rank.saturating_sub(1).min(samples.len() - 1)]
                        })
                    };
                    AnalyticsProviderLatency {
                        provider_id: provider_id.clone(),
                        measured_runs: samples.len(),
                        unmeasured_runs: provider_unmeasured.remove(&provider_id).unwrap_or(0),
                        failed_runs: provider_failures.remove(&provider_id).unwrap_or(0),
                        median_duration_ms: percentile(50, 100),
                        p95_duration_ms: percentile(95, 100),
                    }
                })
                .collect()
        },
        provider_latency_history_complete,
        provider_latency_note: "Provider adapter wall-clock durations over the latest 2,000 saved reviews; p50/p95 exclude cached and unmeasured outcomes and are not model compute time. Review preparation and policy evaluation are excluded.",
        provider_latency_reviews: reviews.len().min(MAX_ANALYTICS_PROVIDER_REVIEWS),
        provider_latency_history: provider_samples_by_day
            .into_iter()
            .map(|((day, provider_id), mut samples)| {
                samples.sort_unstable();
                let percentile = |numerator: usize, denominator: usize| {
                    (!samples.is_empty()).then(|| {
                        let rank = samples
                            .len()
                            .saturating_mul(numerator)
                            .div_ceil(denominator)
                            .max(1);
                        samples[rank.saturating_sub(1).min(samples.len() - 1)]
                    })
                };
                AnalyticsProviderLatencyDay {
                    day,
                    provider_id,
                    measured_runs: samples.len(),
                    median_duration_ms: percentile(50, 100),
                    p95_duration_ms: percentile(95, 100),
                }
            })
            .collect(),
        provider_costs: provider_cost_totals
            .into_iter()
            .map(
                |(provider_id, (estimated_usd, priced_runs, unpriced_runs))| {
                    AnalyticsProviderCost {
                        provider_id,
                        estimated_usd: (priced_runs > 0).then_some(estimated_usd),
                        priced_runs,
                        unpriced_runs,
                    }
                },
            )
            .collect(),
        provider_cost_history_complete,
        provider_cost_note: "Informational estimates apply currently configured exact model rates to retained provider token usage. Historical rates, cached-token discounts, and provider invoices are not available; estimates do not affect gate decisions.",
        provider_cost_reviews: reviews.len().min(MAX_ANALYTICS_PROVIDER_REVIEWS),
        provider_cost_history: provider_costs_by_day
            .into_iter()
            .map(
                |((day, provider_id), (estimated_usd, priced_runs, unpriced_runs))| {
                    AnalyticsProviderCostDay {
                        day,
                        provider_id,
                        estimated_usd,
                        priced_runs,
                        unpriced_runs,
                    }
                },
            )
            .collect(),
    })
}

async fn get_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Result<Json<ReviewDetail>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let store = open_store(&state.root).map_err(api_error)?;
    let payload = store.get(&id).map_err(api_error)?.ok_or_else(|| ApiError {
        error: format!("review {id} was not found"),
    })?;
    let mut review = vero_application::deserialize_review_result(&payload).map_err(api_error)?;
    if let Some(latest_gate) = store
        .gate_decisions_for_review(&id)
        .map_err(api_error)?
        .pop()
    {
        review.status = match latest_gate.status {
            vero_core::GateStatus::Pass => "pass",
            vero_core::GateStatus::Block => "block",
            vero_core::GateStatus::Incomplete => "incomplete",
        }
        .into();
        review.reasons = latest_gate.reasons.clone();
        review.gate = latest_gate;
    }
    let findings = store
        .list_findings(None, None, Some(&id))
        .map_err(api_error)?;
    let impact = match vero_application::capture_current_change_set(&state.root, &review.change_set) {
        Ok(current) if current.digest == review.snapshot_id => {
            vero_application::analyze_impact(&state.root, &review.change_set).unwrap_or_else(|error| {
                vero_application::ImpactAssessment {
                    schema_version: 3,
                    snapshot_id: review.snapshot_id.clone(),
                    coverage_complete: false,
                    analyzers: Vec::new(),
                    changed_paths: review.change_set.files.iter().map(|file| file.path.clone()).collect(),
                    changed_symbols: Vec::new(),
                    groups: Vec::new(),
                    paths: Vec::new(),
                    limitations: vec![format!("saved review is available, but impact analysis failed: {error}")],
                }
            })
        }
        Ok(_) => vero_application::ImpactAssessment {
            schema_version: 3,
            snapshot_id: review.snapshot_id.clone(),
            coverage_complete: false,
            analyzers: Vec::new(),
            changed_paths: review.change_set.files.iter().map(|file| file.path.clone()).collect(),
            changed_symbols: Vec::new(),
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: vec!["current checkout differs from saved review snapshot; impact is unavailable for this historical review".into()],
        },
        Err(error) => vero_application::ImpactAssessment {
            schema_version: 3,
            snapshot_id: review.snapshot_id.clone(),
            coverage_complete: false,
            analyzers: Vec::new(),
            changed_paths: review.change_set.files.iter().map(|file| file.path.clone()).collect(),
            changed_symbols: Vec::new(),
            groups: Vec::new(),
            paths: Vec::new(),
            limitations: vec![format!("saved review is available, but impact could not be recomputed from the current checkout: {error}")],
        },
    };
    Ok(Json(ReviewDetail {
        review,
        findings,
        impact,
    }))
}

async fn list_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FindingQuery>,
) -> Result<Json<Vec<FindingRecord>>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let severity = query
        .severity
        .map(|s| match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            _ => Err(ApiError {
                error: "severity must be critical, high, medium, low, or info".into(),
            }),
        })
        .transpose()?;
    open_store(&state.root)
        .map_err(api_error)?
        .list_findings(severity, None, query.review_id.as_deref())
        .map(Json)
        .map_err(api_error)
}

async fn update_finding_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    RoutePath(finding_id): RoutePath<String>,
    Json(update): Json<FindingStatusUpdate>,
) -> Result<Json<FindingStatusUpdated>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let reason = vero_core::Reason::new(&update.reason).map_err(api_error)?;
    let status = FindingStatus::parse(&update.status).map_err(|_| ApiError {
        error: "status must be open, verified, refuted, or resolved".into(),
    })?;
    let change = vero_core::FindingStatusChange::new(status, reason).map_err(api_error)?;
    open_store(&state.root)
        .map_err(api_error)?
        .set_finding_status(&finding_id, &change)
        .map_err(api_error)?;
    Ok(Json(FindingStatusUpdated {
        schema_version: 1,
        finding_id,
        status: update.status,
        reason: change.reason().as_str().into(),
        note: "Lifecycle status is audit metadata. Use the waiver workflow for a scoped gate exception.".into(),
    }))
}

async fn get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConfigSummary>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let effective = vero_application::load_repository_config(&state.root).map_err(api_error)?;
    // The editor shows repository-owned YAML only. User-level provider defaults may
    // satisfy references in this file, so do not validate this partial view alone.
    let raw = std::fs::read_to_string(state.root.join(".vero.yaml")).map_err(api_error)?;
    let config: RepositoryConfig = serde_yaml::from_str(&raw).map_err(api_error)?;
    Ok(Json(ConfigSummary {
        provider_ids: effective.providers.keys().cloned().collect(),
        reviewer_ids: effective.reviewers.keys().cloned().collect(),
        config,
    }))
}

async fn update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<ConfigUpdate>,
) -> Result<Json<ConfigSummary>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let body = serde_json::to_string(&update.config).map_err(api_error)?;
    if body.len() > 256 * 1024 {
        return Err(ApiError {
            error: "configuration exceeds 256 KiB".into(),
        });
    }
    // Validate all cross-references and protected requirements before touching disk.
    vero_application::validate_repository_config_yaml(&state.root, &body).map_err(api_error)?;
    let destination = state.root.join(".vero.yaml");
    let mut temporary = tempfile::NamedTempFile::new_in(&*state.root).map_err(api_error)?;
    std::io::Write::write_all(temporary.as_file_mut(), body.as_bytes()).map_err(api_error)?;
    temporary.persist(&destination).map_err(api_error)?;
    get_config(State(state), headers).await
}

async fn start_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReviewRequest>,
) -> Result<Json<ReviewResult>, ApiError> {
    check_origin(&headers, &state.origin, state.auth_token.as_deref())?;
    let scope =
        match request.scope.as_str() {
            "base" => vero_git::ChangeScope::BaseAndWorktree {
                base_oid: request
                    .base
                    .as_deref()
                    .map(|base| vero_git::merge_base(&state.root, base))
                    .transpose()
                    .map_err(api_error)?,
            },
            "staged" if request.base.is_none() => vero_git::ChangeScope::Staged,
            "working_tree" if request.base.is_none() => vero_git::ChangeScope::WorkingTree,
            _ => return Err(ApiError {
                error:
                    "scope must be base, staged, or working_tree; base is only valid for base scope"
                        .into(),
            }),
        };
    let root = (*state.root).clone();
    let reviewer_ids = request.reviewer_ids;
    let policy_profile = request.policy_profile;
    let review = tokio::task::spawn_blocking(move || {
        let change_set = vero_application::capture_change_set(&root, scope).map_err(api_error)?;
        let mut config = vero_application::load_repository_config(&root).map_err(api_error)?;
        config
            .select_policy_profile(policy_profile.as_deref())
            .map_err(api_error)?;
        vero_application::apply_protected_policy(&root, &mut config).map_err(api_error)?;
        std::fs::create_dir_all(root.join(".vero")).map_err(api_error)?;
        let mut store = open_store(&root).map_err(api_error)?;
        let selection = (!reviewer_ids.is_empty()).then_some(reviewer_ids.as_slice());
        let review = vero_application::run_review_selecting_reviewers(
            &root, change_set, &config, &mut store, selection,
        )
        .map_err(api_error)?;
        Ok::<_, ApiError>(review)
    })
    .await
    .map_err(|error| api_error(format!("review worker failed: {error}")))??;
    Ok(Json(review))
}

async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    check_origin(&headers, &state.origin, None)?;
    Ok((
        [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )],
        Html(INDEX_HTML),
    ))
}
async fn app_js(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    check_origin(&headers, &state.origin, None)?;
    Ok((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    ))
}
async fn app_css(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    check_origin(&headers, &state.origin, None)?;
    Ok(([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS))
}

pub fn router(root: PathBuf, address: SocketAddr) -> Router {
    build_router(root, address, None, None)
}

/// Build the local application router with a signature-verifying webhook
/// adapter and an application event handler.
pub fn router_with_webhooks(
    root: PathBuf,
    address: SocketAddr,
    provider: Arc<dyn vero_hosting::GitHostingProvider>,
    handler: Arc<dyn WebhookEventHandler>,
) -> Router {
    build_router(
        root,
        address,
        None,
        Some(Arc::new(WebhookState { provider, handler })),
    )
}

fn build_router(
    root: PathBuf,
    address: SocketAddr,
    auth_token: Option<String>,
    webhook: Option<Arc<WebhookState>>,
) -> Router {
    let origin = format!("http://{address}");
    let mut router = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/health", get(health))
        .route("/api/reviews", get(list_reviews).post(start_review))
        .route("/api/analytics", get(get_analytics))
        .route("/api/reviews/{id}", get(get_review))
        .route("/api/findings", get(list_findings))
        .route(
            "/api/findings/{id}/status",
            axum::routing::post(update_finding_status),
        )
        .route("/api/config", get(get_config).put(update_config));
    if let Some(webhook) = webhook.as_ref() {
        let path = format!("/api/webhooks/{}", webhook.provider.provider_id());
        router = router.route(
            &path,
            axum::routing::post(receive_hosting_webhook)
                .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY_BYTES)),
        );
    }
    router.with_state(AppState {
        root: Arc::new(root),
        origin,
        auth_token: auth_token.map(Arc::from),
        webhook,
    })
}

#[derive(Serialize)]
struct WebhookReceipt {
    event_id: String,
    status: &'static str,
}

struct WebhookApiError {
    status: StatusCode,
    error: String,
}

impl IntoResponse for WebhookApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ApiError { error: self.error })).into_response()
    }
}

async fn receive_hosting_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookApiError> {
    let webhook = state.webhook.as_ref().ok_or_else(|| WebhookApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error: "webhook receiver is not configured".into(),
    })?;
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let database = state.root.join(".vero/vero.sqlite");
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(|error| WebhookApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: format!("create Vero storage directory: {error}"),
        })?;
    }
    let mut store = ReviewStore::open(&database).map_err(|error| WebhookApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: format!("open Vero storage: {error}"),
    })?;
    let dispatch = vero_application::verify_and_claim_webhook_delivery(
        webhook.provider.as_ref(),
        &mut store,
        &headers,
        &body,
        60,
    )
    .map_err(|error| WebhookApiError {
        status: if error.contains("signature") {
            StatusCode::UNAUTHORIZED
        } else if error.contains("different payload digest") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        },
        error,
    })?;
    match dispatch.claim {
        vero_core::WebhookClaim::AlreadyProcessed => Ok((
            StatusCode::OK,
            Json(WebhookReceipt {
                event_id: dispatch.envelope.event_id,
                status: "duplicate",
            }),
        )),
        vero_core::WebhookClaim::InProgress => Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(WebhookReceipt {
                event_id: dispatch.envelope.event_id,
                status: "in_progress",
            }),
        )),
        vero_core::WebhookClaim::Acquired { lease_token } => {
            let handler = webhook.handler.clone();
            let event = dispatch.envelope.clone();
            let provider = dispatch.envelope.provider.clone();
            let event_id = dispatch.envelope.event_id.clone();
            // Own the handler and lease lifecycle outside the request future. If the
            // client disconnects, this task keeps renewing and records completion.
            let mut processing = tokio::spawn(async move {
                let mut handler_task = tokio::task::spawn_blocking(move || handler.handle(&event));
                let mut lease_failure: Option<String> = None;
                let handled = loop {
                    tokio::select! {
                        result = &mut handler_task => {
                            break result.map_err(|error| format!("webhook handler task failed: {error}"))?;
                        }
                        () = tokio::time::sleep(std::time::Duration::from_secs(if lease_failure.is_some() { 2 } else { 20 })) => {
                            let database = database.clone();
                            let provider = provider.clone();
                            let event_id = event_id.clone();
                            let token = lease_token.clone();
                            let renewal = tokio::task::spawn_blocking(move || {
                                let mut lease_store = ReviewStore::open(&database)?;
                                lease_store.renew_webhook_delivery(&provider, &event_id, &token, unix_time(), 60)
                            }).await;
                            match renewal {
                                Ok(Ok(())) => lease_failure = None,
                                Ok(Err(error)) => lease_failure = Some(format!("webhook lease renewal failed: {error}")),
                                Err(error) => lease_failure = Some(format!("webhook lease renewal task failed: {error}")),
                            }
                        }
                    }
                };
                if let Some(error) = lease_failure {
                    // spawn_blocking cannot be cancelled. Drain the handler before
                    // returning so this worker never detaches an unobserved side effect.
                    return Err(format!(
                        "{error}; handler completed with {}",
                        if handled.is_ok() {
                            "success"
                        } else {
                            "failure"
                        }
                    ));
                }
                let mut completion_store = ReviewStore::open(&database)?;
                match handled {
                    Ok(()) => completion_store.complete_webhook_delivery(
                        &provider,
                        &event_id,
                        &lease_token,
                        unix_time(),
                    ),
                    Err(error) => {
                        completion_store.release_webhook_delivery(
                            &provider,
                            &event_id,
                            &lease_token,
                        )?;
                        Err(error)
                    }
                }
            });
            let handled = (&mut processing).await.map_err(|error| WebhookApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: format!("webhook processing task failed: {error}"),
            })?;
            match handled {
                Ok(()) => Ok((
                    StatusCode::ACCEPTED,
                    Json(WebhookReceipt {
                        event_id: dispatch.envelope.event_id,
                        status: "processed",
                    }),
                )),
                Err(error) => Err(WebhookApiError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error: format!("webhook event handler failed: {error}"),
                }),
            }
        }
    }
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

pub async fn serve(
    root: PathBuf,
    address: SocketAddr,
    allow_network: bool,
    auth_token: Option<String>,
) -> anyhow::Result<()> {
    if address.ip().is_unspecified() {
        anyhow::bail!(
            "wildcard UI binding cannot enforce the Host/Origin guard; bind to a specific interface address"
        );
    }
    if !address.ip().is_loopback() {
        anyhow::bail!(
            "non-loopback UI binding is disabled until Vero can serve TLS directly; use a secure local tunnel"
        );
    }
    let _ = allow_network;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let actual_address = listener.local_addr()?;
    axum::serve(
        listener,
        build_router(root, actual_address, auth_token, None),
    )
    .await?;
    Ok(())
}

/// Run the application API with a hosting webhook adapter and event handler.
/// Non-loopback binding is disabled until the server can terminate TLS itself.
pub async fn serve_with_webhooks(
    root: PathBuf,
    address: SocketAddr,
    allow_network: bool,
    provider: Arc<dyn vero_hosting::GitHostingProvider>,
    handler: Arc<dyn WebhookEventHandler>,
    auth_token: Option<String>,
) -> anyhow::Result<()> {
    if address.ip().is_unspecified() {
        anyhow::bail!("wildcard binding is not supported; bind to a specific interface address");
    }
    if !address.ip().is_loopback() {
        anyhow::bail!(
            "non-loopback webhook binding is disabled until Vero can serve TLS directly; use a secure local tunnel"
        );
    }
    let _ = allow_network;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let actual_address = listener.local_addr()?;
    axum::serve(
        listener,
        build_router(
            root,
            actual_address,
            auth_token,
            Some(Arc::new(WebhookState { provider, handler })),
        ),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    struct WebhookProvider;
    impl vero_hosting::GitHostingProvider for WebhookProvider {
        fn provider_id(&self) -> &'static str {
            "github"
        }
        fn get_pull_request(
            &self,
            _: &vero_hosting::PullRequestRef,
        ) -> Result<vero_hosting::PullRequestSnapshot, vero_hosting::HostingError> {
            unreachable!()
        }
        fn list_changed_files(
            &self,
            _: &vero_hosting::PullRequestRef,
            _: &str,
        ) -> Result<Vec<vero_hosting::PullRequestFile>, vero_hosting::HostingError> {
            unreachable!()
        }
        fn publish_review(
            &self,
            _: vero_hosting::ReviewPublication,
        ) -> Result<vero_hosting::PublicationReceipt, vero_hosting::HostingError> {
            unreachable!()
        }
        fn verify_webhook(
            &self,
            headers: &std::collections::BTreeMap<String, String>,
            _: &[u8],
        ) -> Result<vero_hosting::WebhookEnvelope, vero_hosting::HostingError> {
            Ok(vero_hosting::WebhookEnvelope {
                provider: "github".into(),
                event_id: "http-delivery-1".into(),
                event_type: "pull_request".into(),
                delivery_attempt: 1,
                pull_request: None,
                action: None,
                base_oid: None,
                head_oid: None,
                signature_verified: headers
                    .get("x-fixture-signature")
                    .is_some_and(|value| value == "valid"),
            })
        }
    }

    #[tokio::test]
    async fn webhook_http_ingress_verifies_claims_dispatches_and_deduplicates() {
        let directory = tempfile::tempdir().unwrap();
        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handled_by_callback = handled.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let app = router_with_webhooks(
            directory.path().to_owned(),
            address,
            Arc::new(WebhookProvider),
            Arc::new(move |_: &vero_hosting::WebhookEnvelope| {
                let attempt = handled_by_callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt == 0 {
                    started_tx.send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                    Err("temporary event handler failure".into())
                } else {
                    Ok(())
                }
            }),
        );
        let request = |signature: &str, body: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/webhooks/github")
                .header(header::HOST, "127.0.0.1:7878")
                .header("x-fixture-signature", signature)
                .body(Body::from(body.to_owned()))
                .unwrap()
        };
        let gitlab_request = Request::builder()
            .method("POST")
            .uri("/api/webhooks/gitlab")
            .header(header::HOST, "127.0.0.1:7878")
            .header("x-fixture-signature", "invalid")
            .body(Body::from("fixture body"))
            .unwrap();
        let azure_request = Request::builder()
            .method("POST")
            .uri("/api/webhooks/azure-devops")
            .header(header::HOST, "127.0.0.1:7878")
            .header("x-fixture-signature", "invalid")
            .body(Body::from("fixture body"))
            .unwrap();
        let oversized_request = Request::builder()
            .method("POST")
            .uri("/api/webhooks/github")
            .header(header::HOST, "127.0.0.1:7878")
            .header("x-fixture-signature", "valid")
            .body(Body::from(vec![b'x'; MAX_WEBHOOK_BODY_BYTES + 1]))
            .unwrap();

        let invalid = app
            .clone()
            .oneshot(request("invalid", "fixture body"))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        let gitlab_route = app.clone().oneshot(gitlab_request).await.unwrap();
        assert_eq!(gitlab_route.status(), StatusCode::NOT_FOUND);
        let azure_route = app.clone().oneshot(azure_request).await.unwrap();
        assert_eq!(azure_route.status(), StatusCode::NOT_FOUND);
        let oversized = app.clone().oneshot(oversized_request).await.unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 0);

        let first_app = app.clone();
        let first_request = request("valid", "fixture body");
        let first_task =
            tokio::spawn(async move { first_app.oneshot(first_request).await.unwrap() });
        tokio::task::spawn_blocking(move || {
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("first webhook should enter its handler")
        })
        .await
        .unwrap();
        let concurrent = app
            .clone()
            .oneshot(request("valid", "fixture body"))
            .await
            .unwrap();
        assert_eq!(concurrent.status(), StatusCode::SERVICE_UNAVAILABLE);
        let concurrent_body = to_bytes(concurrent.into_body(), usize::MAX).await.unwrap();
        let concurrent_receipt: serde_json::Value =
            serde_json::from_slice(&concurrent_body).unwrap();
        assert_eq!(concurrent_receipt["status"], "in_progress");
        release_tx.send(()).unwrap();

        let first = first_task.await.unwrap();
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 1);
        let retry = app
            .clone()
            .oneshot(request("valid", "fixture body"))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::ACCEPTED);
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 2);
        let duplicate = app
            .clone()
            .oneshot(request("valid", "fixture body"))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 2);
        let conflicting_payload = app
            .oneshot(request("valid", "different payload"))
            .await
            .unwrap();
        assert_eq!(conflicting_payload.status(), StatusCode::CONFLICT);
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn webhook_processing_finishes_after_request_future_is_aborted() {
        let directory = tempfile::tempdir().unwrap();
        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handled_by_callback = handled.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let app = router_with_webhooks(
            directory.path().to_owned(),
            address,
            Arc::new(WebhookProvider),
            Arc::new(move |_: &vero_hosting::WebhookEnvelope| {
                handled_by_callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                started_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                Ok(())
            }),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/api/webhooks/github")
            .header(header::HOST, "127.0.0.1:7878")
            .header("x-fixture-signature", "valid")
            .body(Body::from("fixture body"))
            .unwrap();
        let task = tokio::spawn(async move { app.oneshot(request).await });
        tokio::task::spawn_blocking(move || {
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
        })
        .await
        .unwrap();
        task.abort();
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if handled.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                    let mut store =
                        ReviewStore::open(&directory.path().join(".vero/vero.sqlite")).unwrap();
                    if store
                        .claim_webhook_delivery(
                            "github",
                            "http-delivery-1",
                            "pull_request",
                            1,
                            &vero_core::digest(b"fixture body"),
                            unix_time(),
                            60,
                        )
                        .unwrap()
                        == vero_core::WebhookClaim::AlreadyProcessed
                    {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("detached handler should complete and persist its lease");
        assert_eq!(handled.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[test]
    fn origin_check_rejects_cross_origin_and_host_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:7878".parse().unwrap());
        headers.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(check_origin(&headers, "http://127.0.0.1:7878", None).is_err());
        headers.insert(header::ORIGIN, "http://127.0.0.1:7878".parse().unwrap());
        assert!(check_origin(&headers, "http://127.0.0.1:7878", None).is_ok());
        headers.insert(header::HOST, "evil.example".parse().unwrap());
        assert!(check_origin(&headers, "http://127.0.0.1:7878", None).is_err());
    }

    #[test]
    fn network_origin_requires_matching_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "192.0.2.10:7878".parse().unwrap());
        assert!(check_origin(&headers, "http://192.0.2.10:7878", Some("secret")).is_err());
        headers.insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
        assert!(check_origin(&headers, "http://192.0.2.10:7878", Some("secret")).is_err());
        headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(check_origin(&headers, "http://192.0.2.10:7878", Some("secret")).is_ok());
    }

    #[test]
    fn origin_check_accepts_browser_normalized_default_http_port() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1".parse().unwrap());
        headers.insert(header::ORIGIN, "http://127.0.0.1".parse().unwrap());
        assert!(check_origin(&headers, "http://127.0.0.1:80", None).is_ok());
    }

    #[test]
    fn repository_editor_view_can_reference_user_level_providers() {
        let yaml = "version: 1\nproviders: {}\nreviewers:\n  correctness:\n    provider: workstation-codex\n    instructions_file: reviewer.md\n";
        let config: RepositoryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.reviewers["correctness"].provider,
            "workstation-codex"
        );
        assert!(config.providers.is_empty());
    }

    #[tokio::test]
    async fn api_rejects_host_mismatch_on_read_routes() {
        let directory = tempfile::tempdir().unwrap();
        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn network_api_requires_bearer_token_but_serves_login_shell() {
        let directory = tempfile::tempdir().unwrap();
        let address: SocketAddr = "192.0.2.10:7878".parse().unwrap();
        let app = build_router(
            directory.path().to_owned(),
            address,
            Some("secret".into()),
            None,
        );
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header(header::HOST, "192.0.2.10:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let authorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header(header::HOST, "192.0.2.10:7878")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let shell = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "192.0.2.10:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(shell.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn analytics_endpoint_returns_local_versioned_empty_state() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join(".vero")).unwrap();
        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/analytics")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["schema_version"], 8);
        assert_eq!(report["review_count"], 0);
        assert_eq!(report["reviews_by_day"], serde_json::json!([]));
        assert_eq!(report["review_dimensions"], serde_json::json!([]));
        assert_eq!(report["finding_drilldown"], serde_json::json!([]));
        assert_eq!(report["finding_drilldown_total"], 0);
        assert_eq!(report["finding_drilldown_complete"], true);
        assert_eq!(report["findings_by_rule"], serde_json::json!({}));
        assert_eq!(report["findings_by_rule_complete"], true);
        assert_eq!(report["verification_run_count"], 0);
        assert_eq!(report["verification_history_complete"], true);
        assert_eq!(report["verification_runs"], serde_json::json!([]));
        assert_eq!(report["provider_latency"], serde_json::json!([]));
        assert_eq!(report["provider_costs"], serde_json::json!([]));
        assert_eq!(report["provider_cost_history_complete"], true);
        assert_eq!(report["provider_cost_history"], serde_json::json!([]));
        assert_eq!(report["provider_latency_history_complete"], true);
        assert!(report["provider_latency_note"]
            .as_str()
            .unwrap()
            .contains("p50/p95"));
        assert!(report["feedback_note"]
            .as_str()
            .unwrap()
            .contains("not calibrated"));
    }

    #[tokio::test]
    async fn analytics_rule_totals_cover_all_findings_beyond_drilldown_limit() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join(".vero")).unwrap();
        let mut store = open_store(directory.path()).unwrap();
        let findings = (0..205)
            .map(|index| vero_core::Finding {
                id: format!("FIND-{index:03}"),
                fingerprint: format!("sha256:finding-{index:03}"),
                category: "correctness".into(),
                severity: Severity::High,
                confidence: Some(90),
                rationale: "A fixture finding".into(),
                path: Some("src/lib.rs".into()),
                line: Some(index + 1),
                provenance: "model_inference".into(),
                reviewer_ids: vec!["correctness".into()],
                evidence_ids: Vec::new(),
                rule_attributions: vec![vero_core::RuleAttribution {
                    rule_id: "rule_validation".into(),
                    approval_id: "approval_validation_v2".into(),
                    reviewer_id: "correctness".into(),
                }],
            })
            .collect::<Vec<_>>();
        store
            .save_review(
                "review-many-findings",
                "snapshot-many-findings",
                "config",
                "block",
                "{}",
                &findings,
            )
            .unwrap();

        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/analytics")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(report["findings_by_rule"]["rule_validation"], 205);
        assert_eq!(report["findings_by_rule_complete"], true);
        assert_eq!(report["finding_drilldown_total"], 205);
        assert_eq!(report["finding_drilldown"].as_array().unwrap().len(), 200);
        assert_eq!(report["finding_drilldown_complete"], false);
    }

    #[tokio::test]
    async fn analytics_includes_bounded_snapshot_linked_verification_history() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join(".vero")).unwrap();
        let mut store = open_store(directory.path()).unwrap();
        for (run_id, snapshot_id, profile_id, status) in [
            (
                "verify_old",
                "snapshot_old",
                "unit",
                vero_core::VerificationStatus::Passed,
            ),
            (
                "verify_new",
                "snapshot_new",
                "integration",
                vero_core::VerificationStatus::Incomplete,
            ),
        ] {
            store
                .save_verification(&vero_core::VerificationRun {
                    schema_version: 1,
                    run_id: run_id.into(),
                    snapshot_id: snapshot_id.into(),
                    profile_id: profile_id.into(),
                    finding_id: None,
                    targets: Vec::new(),
                    command_digest: "sha256:command".into(),
                    status,
                    exit_code: None,
                    stdout_digest: "sha256:stdout".into(),
                    stderr_digest: "sha256:stderr".into(),
                    stdout_artifact: None,
                    stderr_artifact: None,
                })
                .unwrap();
        }
        let (limited, total) = store.recent_verification_summaries(1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].run_id, "verify_new");

        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/analytics")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["schema_version"], 8);
        assert_eq!(report["verification_run_count"], 2);
        assert_eq!(report["verification_history_complete"], true);
        assert_eq!(report["verification_runs"].as_array().unwrap().len(), 2);
        assert_eq!(report["verification_runs"][0]["run_id"], "verify_new");
        assert_eq!(
            report["verification_runs"][0]["snapshot_id"],
            "snapshot_new"
        );
        assert_eq!(report["verification_runs"][0]["profile_id"], "integration");
        assert_eq!(report["verification_runs"][0]["status"], "incomplete");
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/local-review-analytics-v8.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            validator.validate(&report).is_ok(),
            "local analytics output must match v8 schema"
        );
        assert!(report["verification_runs"][0]["created_at"]
            .as_str()
            .is_some());
    }

    #[tokio::test]
    async fn analytics_uses_latest_gate_per_review_and_counts_ungated_reviews() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join(".vero")).unwrap();
        std::fs::write(
            directory.path().join(".vero.yaml"),
            "version: 1\nproviders:\n  claude:\n    kind: claude_cli\n    executable: claude\n    model: model-a\n    pricing:\n      model-a:\n        input_usd_per_million: 2\n        output_usd_per_million: 10\n",
        )
        .unwrap();
        let mut store = open_store(directory.path()).unwrap();
        let finding = vero_core::Finding {
            id: "FIND-001".into(),
            fingerprint: "sha256:finding".into(),
            category: "correctness".into(),
            severity: Severity::High,
            confidence: Some(90),
            rationale: "Validation is skipped on this branch.".into(),
            path: Some("src/lib.rs".into()),
            line: Some(42),
            provenance: "model_inference".into(),
            reviewer_ids: vec!["correctness".into()],
            evidence_ids: Vec::new(),
            rule_attributions: vec![vero_core::RuleAttribution {
                rule_id: "rule_validation".into(),
                approval_id: "approval_validation_v2".into(),
                reviewer_id: "correctness".into(),
            }],
        };
        store
            .save_review(
                "rev_one",
                "snapshot_one",
                "config",
                "block",
                "{}",
                std::slice::from_ref(&finding),
            )
            .unwrap();
        for (decision_id, status, evidence_digest) in [
            ("decision_old", vero_core::GateStatus::Block, "evidence_old"),
            (
                "decision_latest",
                vero_core::GateStatus::Pass,
                "evidence_latest",
            ),
        ] {
            store
                .save_gate_decision(
                    "rev_one",
                    &vero_core::GateDecision {
                        schema_version: 1,
                        decision_id: decision_id.into(),
                        snapshot_id: "snapshot_one".into(),
                        effective_config_digest: "config".into(),
                        policy_digest: "policy".into(),
                        status,
                        blocking_findings: Vec::new(),
                        verification_run_ids: Vec::new(),
                        evidence_digest: evidence_digest.into(),
                        reasons: Vec::new(),
                        replay_inputs: None,
                    },
                )
                .unwrap();
        }
        let mut dimension_finding = finding.clone();
        dimension_finding.id = "FIND-DIMENSION".into();
        dimension_finding.fingerprint = "sha256:dimension-finding".into();
        let saved_review = vero_application::ReviewResult {
            schema_version: 2,
            review_id: "rev_dimensions".into(),
            snapshot_id: "snapshot_dimensions".into(),
            status: "pass".into(),
            findings: vec![dimension_finding],
            policy_findings: None,
            evidence: Vec::new(),
            verification_runs: Vec::new(),
            reviewer_outcomes: vec![
                vero_application::ReviewerOutcome {
                    reviewer_id: "security".into(),
                    provider_id: "claude".into(),
                    provider_kind: vero_core::ProviderKind::ClaudeCli,
                    model: Some("model-a".into()),
                    provider_version: None,
                    status: "completed".into(),
                    duration_ms: Some(137),
                    usage: Some(vero_core::ProviderUsage {
                        input_tokens: Some(120),
                        output_tokens: Some(45),
                        total_tokens: Some(165),
                    }),
                },
                vero_application::ReviewerOutcome {
                    reviewer_id: "security_unpriced".into(),
                    provider_id: "unknown_provider".into(),
                    provider_kind: vero_core::ProviderKind::Cli,
                    model: Some("unknown-model".into()),
                    provider_version: None,
                    status: "completed".into(),
                    duration_ms: None,
                    usage: None,
                },
            ],
            reviewer_arbitration: Vec::new(),
            analysis_complete: true,
            reasons: Vec::new(),
            gate: vero_core::GateDecision {
                schema_version: 1,
                decision_id: "decision_latest".into(),
                snapshot_id: "snapshot_dimensions".into(),
                effective_config_digest: "config".into(),
                policy_digest: "policy".into(),
                status: vero_core::GateStatus::Pass,
                blocking_findings: Vec::new(),
                verification_run_ids: Vec::new(),
                evidence_digest: "evidence_latest".into(),
                reasons: Vec::new(),
                replay_inputs: None,
            },
            change_set: vero_core::ChangeSet::from_entries(None, None, "working_tree", Vec::new()),
            effective_config_digest: "config".into(),
            selected_reviewers: vec!["security".into()],
            reviewer_context: Vec::new(),
            policy_profile: None,
            work_item: None,
            work_item_token_env: None,
        };
        let saved_payload = serde_json::to_string(&saved_review).unwrap();
        vero_application::deserialize_review_result(&saved_payload).unwrap();
        store
            .save_review(
                "rev_dimensions",
                "snapshot_dimensions",
                "config",
                "pass",
                &saved_payload,
                &saved_review.findings,
            )
            .unwrap();
        store
            .save_gate_decision(
                "rev_dimensions",
                &vero_core::GateDecision {
                    schema_version: 1,
                    decision_id: "decision_latest_block".into(),
                    snapshot_id: "snapshot_dimensions".into(),
                    effective_config_digest: "config".into(),
                    policy_digest: "policy".into(),
                    status: vero_core::GateStatus::Block,
                    blocking_findings: vec!["FIND-DIMENSION".into()],
                    verification_run_ids: Vec::new(),
                    evidence_digest: "evidence_latest_block".into(),
                    reasons: vec!["latest policy check blocked".into()],
                    replay_inputs: None,
                },
            )
            .unwrap();
        store
            .save_review("rev_two", "snapshot_two", "config", "incomplete", "{}", &[])
            .unwrap();

        let address: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        let response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/analytics")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["review_count"], 3);
        assert_eq!(report["reviews_by_day"].as_array().unwrap().len(), 1);
        let day = &report["reviews_by_day"][0];
        assert_eq!(day["pass"], 1);
        assert_eq!(day["block"], 1);
        assert_eq!(day["incomplete"], 0);
        assert_eq!(day["ungated"], 1);
        let dimensions = report["review_dimensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["review_id"] == "rev_dimensions")
            .unwrap();
        assert_eq!(
            dimensions["reviewer_ids"],
            serde_json::json!(["security", "security_unpriced"])
        );
        assert_eq!(
            dimensions["provider_ids"],
            serde_json::json!(["claude", "unknown_provider"])
        );
        assert_eq!(
            report["provider_latency"],
            serde_json::json!([
                {
                    "provider_id":"claude", "measured_runs":1, "unmeasured_runs":0,
                    "failed_runs":0, "median_duration_ms":137, "p95_duration_ms":137
                },
                {
                    "provider_id":"unknown_provider", "measured_runs":0, "unmeasured_runs":1,
                    "failed_runs":0, "median_duration_ms":null, "p95_duration_ms":null
                }
            ])
        );
        assert_eq!(
            report["provider_costs"],
            serde_json::json!([
                {
                    "provider_id":"claude", "estimated_usd":0.00069,
                    "priced_runs":1, "unpriced_runs":0
                },
                {
                    "provider_id":"unknown_provider", "estimated_usd":null,
                    "priced_runs":0, "unpriced_runs":1
                }
            ])
        );
        let expected_day = store
            .list_reviews()
            .unwrap()
            .into_iter()
            .find(|review| review.review_id == "rev_dimensions")
            .unwrap()
            .created_at
            .chars()
            .take(10)
            .collect::<String>();
        assert_eq!(
            report["provider_cost_history"],
            serde_json::json!([
                {
                    "day": expected_day.clone(), "provider_id":"claude", "estimated_usd":0.00069,
                    "priced_runs":1, "unpriced_runs":0
                },
                {
                    "day": expected_day, "provider_id":"unknown_provider", "estimated_usd":0.0,
                    "priced_runs":0, "unpriced_runs":1
                }
            ])
        );
        assert_eq!(
            dimensions["finding_categories"],
            serde_json::json!(["correctness"])
        );
        assert_eq!(
            dimensions["finding_rule_ids"],
            serde_json::json!(["rule_validation"])
        );
        assert_eq!(report["findings_by_severity"]["high"], 2);
        assert_eq!(report["findings_by_rule"]["rule_validation"], 2);
        assert_eq!(report["findings_by_rule_complete"], true);
        assert_eq!(report["finding_drilldown_total"], 2);
        assert_eq!(report["finding_drilldown_complete"], true);
        let drilldown = report["finding_drilldown"].as_array().unwrap();
        let finding = drilldown
            .iter()
            .find(|item| item["finding_id"] == "FIND-001")
            .expect("the first review's finding should appear in the drilldown");
        assert_eq!(finding["last_review_id"], "rev_one");
        assert_eq!(finding["path"], "src/lib.rs");
        assert_eq!(
            finding["rule_attributions"][0]["approval_id"],
            "approval_validation_v2"
        );

        let detail_response = router(directory.path().to_owned(), address)
            .oneshot(
                Request::builder()
                    .uri("/api/reviews/rev_dimensions")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let detail_bytes = axum::body::to_bytes(detail_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let detail: serde_json::Value = serde_json::from_slice(&detail_bytes).unwrap();
        assert_eq!(detail["review"]["status"], "block");
        assert_eq!(
            detail["review"]["gate"]["decision_id"],
            "decision_latest_block"
        );
        assert_eq!(
            detail["review"]["reasons"][0],
            "latest policy check blocked"
        );
    }

    #[tokio::test]
    async fn finding_disposition_requires_reason_and_never_creates_waiver() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join(".vero")).unwrap();
        let mut store = open_store(root).unwrap();
        store
            .save_review(
                "review-disposition",
                "snapshot-disposition",
                "config",
                "block",
                "{}",
                &[vero_core::Finding {
                    id: "finding-disposition".into(),
                    fingerprint: "fingerprint-disposition".into(),
                    category: "correctness".into(),
                    severity: Severity::High,
                    confidence: Some(90),
                    rationale: "fixture finding".into(),
                    path: Some("src.rs".into()),
                    line: Some(1),
                    provenance: "model_inference".into(),
                    reviewer_ids: Vec::new(),
                    evidence_ids: vec![],
                    rule_attributions: Vec::new(),
                }],
            )
            .unwrap();
        drop(store);
        let app = router(root.to_owned(), "127.0.0.1:7878".parse().unwrap());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/findings/finding-disposition/status")
                    .header(header::HOST, "127.0.0.1:7878")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"status":"refuted","reason":"Confirmed false positive"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "refuted");
        assert!(value["note"].as_str().unwrap().contains("waiver"));
        let stored = open_store(root)
            .unwrap()
            .finding("finding-disposition")
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, FindingStatus::Refuted);
        assert_eq!(
            stored.status_reason.as_deref(),
            Some("Confirmed false positive")
        );

        for invalid in [
            r#"{"status":"resolved","reason":"   "}"#,
            r#"{"status":"waived","reason":"approved"}"#,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/findings/finding-disposition/status")
                        .header(header::HOST, "127.0.0.1:7878")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(invalid))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn saved_review_survives_impact_recomputation_failure() {
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
        git(&["config", "user.email", "vero@example.invalid"]);
        git(&["config", "user.name", "Vero test"]);
        std::fs::write(root.join("src.rs"), "pub fn stable() {}\n").unwrap();
        std::fs::create_dir_all(root.join(".vero")).unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "baseline"]);
        let change_set =
            vero_application::capture_change_set(root, vero_git::ChangeScope::WorkingTree).unwrap();
        let review = ReviewResult {
            schema_version: 2,
            review_id: "rev_saved".into(),
            snapshot_id: change_set.digest.clone(),
            status: "pass".into(),
            findings: Vec::new(),
            policy_findings: None,
            evidence: Vec::new(),
            verification_runs: Vec::new(),
            reviewer_outcomes: Vec::new(),
            reviewer_arbitration: Vec::new(),
            analysis_complete: true,
            reasons: Vec::new(),
            gate: vero_core::GateDecision {
                schema_version: 1,
                decision_id: "gate_saved".into(),
                snapshot_id: change_set.digest.clone(),
                effective_config_digest: "config".into(),
                policy_digest: "policy".into(),
                status: vero_core::GateStatus::Pass,
                blocking_findings: Vec::new(),
                verification_run_ids: Vec::new(),
                evidence_digest: "evidence".into(),
                reasons: Vec::new(),
                replay_inputs: None,
            },
            change_set,
            effective_config_digest: "config".into(),
            selected_reviewers: Vec::new(),
            reviewer_context: Vec::new(),
            policy_profile: None,
            work_item: None,
            work_item_token_env: None,
        };
        let mut store = open_store(root).unwrap();
        store
            .save(
                &review.review_id,
                &review.snapshot_id,
                &review.effective_config_digest,
                &review.status,
                &serde_json::to_string(&review).unwrap(),
            )
            .unwrap();
        drop(store);

        // Keep the source bytes and snapshot identity intact, but remove Git metadata
        // so the capture check succeeds while semantic impact analysis fails.
        std::fs::rename(root.join(".git"), root.join(".git-hidden")).unwrap();

        let response = router(root.to_owned(), "127.0.0.1:7878".parse().unwrap())
            .oneshot(
                Request::builder()
                    .uri("/api/reviews/rev_saved")
                    .header(header::HOST, "127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["review"]["review_id"], "rev_saved");
        assert_eq!(value["impact"]["coverage_complete"], false);
        assert!(value["impact"]["limitations"][0]
            .as_str()
            .unwrap()
            .contains("impact could not be recomputed"));
    }

    #[tokio::test]
    async fn non_loopback_ui_binding_is_rejected_even_with_opt_in() {
        let error = serve(
            PathBuf::from("."),
            "192.0.2.1:7878".parse().unwrap(),
            true,
            Some("test-token".into()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("serve TLS directly"));
    }

    #[tokio::test]
    async fn wildcard_network_bind_is_rejected() {
        let error = serve(
            PathBuf::from("."),
            "0.0.0.0:7878".parse().unwrap(),
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("specific interface address"));
    }

    #[test]
    fn non_loopback_webhook_ui_binding_is_rejected_even_with_opt_in() {
        let provider = Arc::new(
            vero_hosting::github::GitHubAdapter::new(
                vero_hosting::github::GitHubConfig::new(
                    "https://api.github.com",
                    "token".into(),
                    "secret".into(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(serve_with_webhooks(
                PathBuf::from("."),
                "192.0.2.1:7878".parse().unwrap(),
                true,
                provider,
                Arc::new(|_: &vero_hosting::WebhookEnvelope| Ok(())),
                Some("test-token".into()),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("serve TLS directly"));
    }
}
