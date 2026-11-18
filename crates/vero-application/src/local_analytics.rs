//! Local review analytics for the dashboard (`local-review-analytics-v8`):
//! gate outcomes by day, finding drill-down, explicit feedback, verification
//! history, and provider latency and cost. Reads only the local review store.

use serde::Serialize;
use std::path::Path;
use vero_core::ports::*;
use vero_core::Severity;

#[derive(Debug, Serialize)]
pub struct AnalyticsDay {
    pub day: String,
    pub pass: usize,
    pub block: usize,
    pub incomplete: usize,
    pub ungated: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsReviewDimension {
    pub review_id: String,
    pub day: String,
    pub status: String,
    pub summary_status: String,
    pub reviewer_ids: Vec<String>,
    pub provider_ids: Vec<String>,
    pub finding_categories: Vec<String>,
    pub finding_rule_ids: Vec<String>,
}

pub const MAX_ANALYTICS_FINDING_DRILLDOWN: usize = 200;
pub const MAX_ANALYTICS_VERIFICATION_RUNS: usize = 500;
pub const MAX_ANALYTICS_PROVIDER_REVIEWS: usize = 2_000;

#[derive(Debug, Serialize)]
pub struct AnalyticsVerificationRun {
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsProviderLatency {
    pub provider_id: String,
    pub measured_runs: usize,
    pub unmeasured_runs: usize,
    pub failed_runs: usize,
    pub median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsProviderLatencyDay {
    pub day: String,
    pub provider_id: String,
    pub measured_runs: usize,
    pub median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsProviderCost {
    pub provider_id: String,
    pub estimated_usd: Option<f64>,
    pub priced_runs: usize,
    pub unpriced_runs: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsProviderCostDay {
    pub day: String,
    pub provider_id: String,
    pub estimated_usd: f64,
    pub priced_runs: usize,
    pub unpriced_runs: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsFinding {
    pub finding_id: String,
    pub category: String,
    pub severity: String,
    pub rationale: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub status: String,
    pub last_review_id: Option<String>,
    pub last_seen: String,
    pub rule_attributions: Vec<vero_core::RuleAttribution>,
}

#[derive(Debug, Serialize)]
pub struct LocalAnalytics {
    pub schema_version: u32,
    pub review_count: usize,
    pub history_complete: bool,
    pub dimensions_complete: bool,
    pub reviews_by_day: Vec<AnalyticsDay>,
    pub review_dimensions: Vec<AnalyticsReviewDimension>,
    pub findings_by_severity: std::collections::BTreeMap<String, usize>,
    pub findings_by_rule: std::collections::BTreeMap<String, usize>,
    pub findings_by_rule_complete: bool,
    pub finding_drilldown: Vec<AnalyticsFinding>,
    pub finding_drilldown_total: usize,
    pub finding_drilldown_complete: bool,
    pub explicit_feedback_by_label: std::collections::BTreeMap<String, usize>,
    pub feedback_note: &'static str,
    pub verification_run_count: usize,
    pub verification_history_complete: bool,
    pub verification_runs: Vec<AnalyticsVerificationRun>,
    pub provider_latency: Vec<AnalyticsProviderLatency>,
    pub provider_latency_history_complete: bool,
    pub provider_latency_note: &'static str,
    pub provider_latency_reviews: usize,
    pub provider_latency_history: Vec<AnalyticsProviderLatencyDay>,
    pub provider_costs: Vec<AnalyticsProviderCost>,
    pub provider_cost_history_complete: bool,
    pub provider_cost_note: &'static str,
    pub provider_cost_reviews: usize,
    pub provider_cost_history: Vec<AnalyticsProviderCostDay>,
}

pub fn build(root: &Path, store: &dyn Repositories) -> Result<LocalAnalytics, String> {
    let reviews = store.list_reviews()?;
    let history_complete = reviews.len() <= 500;
    let mut dimensions_complete = history_complete;
    let mut provider_latency_history_complete = reviews.len() <= MAX_ANALYTICS_PROVIDER_REVIEWS;
    // Analytics remain readable while a user edits a temporarily invalid config.
    // In that state, usage is counted as unpriced until a valid rate is available.
    let config = crate::load_repository_config(root).ok();
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
        let Some(payload) = store.get(&review.review_id)? else {
            provider_latency_history_complete = false;
            provider_cost_history_complete = false;
            continue;
        };
        let Ok(saved) = crate::deserialize_review_result(&payload) else {
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
        let latest_decision = store.gate_decisions_for_review(&review.review_id)?.pop();
        let status = latest_decision
            .map(|decision| format!("{:?}", decision.status).to_lowercase())
            .unwrap_or_else(|| "ungated".to_owned());
        match status.as_str() {
            "pass" => entry.pass += 1,
            "block" => entry.block += 1,
            "incomplete" => entry.incomplete += 1,
            _ => entry.ungated += 1,
        }
        let payload = store.get(&review.review_id)?;
        let mut reviewer_ids = Vec::new();
        let mut provider_ids = Vec::new();
        let mut finding_categories = Vec::new();
        let mut finding_rule_ids = Vec::new();
        if let Some(payload) = payload {
            if let Ok(saved) = crate::deserialize_review_result(&payload) {
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
    let (finding_records, finding_drilldown_total) =
        store.list_findings_page(None, None, None, MAX_ANALYTICS_FINDING_DRILLDOWN, 0)?;
    let (verification_records, verification_run_count) =
        store.recent_verification_summaries(MAX_ANALYTICS_VERIFICATION_RUNS)?;
    let mut findings_by_severity = std::collections::BTreeMap::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let key = format!("{severity:?}").to_lowercase();
        let (_, count) = store.list_findings_page(Some(severity), None, None, 1, 0)?;
        if count > 0 {
            findings_by_severity.insert(key, count);
        }
    }
    let all_findings = store.list_findings(None, None, None)?;
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
    for feedback in store.list_finding_feedback()? {
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
