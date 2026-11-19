use crate::{ImpactAnalyzer, ImpactAssessment, ReviewResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vee_core::VerificationStatus;
use vee_hosting::WorkItemSnapshot;

#[derive(Clone, Debug, Serialize)]
pub struct AcceptanceReport {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub work_item: Option<WorkItemReference>,
    pub criteria: Vec<AcceptanceCriterion>,
    pub changed_paths: Vec<String>,
    pub impact_snapshot_id: Option<String>,
    pub impact_coverage_complete: Option<bool>,
    pub impact_analyzers: Vec<ImpactAnalyzer>,
    pub verification_runs: Vec<VerificationSummary>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkItemReference {
    pub url: String,
    pub content_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceptanceCriterion {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub source_line: usize,
    pub text: String,
    /// Lexical/path candidates only; this is not a coverage or satisfaction claim.
    pub candidate_changed_paths: Vec<String>,
    /// Analyzer-derived changed-source -> likely-test links; these remain inferred candidates.
    pub candidate_test_references: Vec<TestReferenceCandidate>,
    pub status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct TestReferenceCandidate {
    pub changed_path: String,
    pub test_path: String,
    pub symbol: String,
    pub evidence_line: u32,
    pub certainty: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationSummary {
    pub run_id: String,
    pub profile_id: String,
    pub status: VerificationStatus,
    pub targets: Vec<String>,
}

/// Local, human-authored traceability assertions. These are never policy evidence.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceMapping {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub work_item_digest: String,
    pub author: String,
    pub recorded_at: String,
    pub assessments: Vec<CriterionAssessment>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriterionAssessment {
    pub criterion_id: String,
    /// One of `met`, `not_met`, or `uncertain`.
    pub assessment: String,
    pub rationale: String,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub verification_run_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceptanceValidation {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub work_item_digest: String,
    pub policy_digest: String,
    pub gate_status: String,
    pub author: String,
    pub recorded_at: String,
    /// `all_attested_met`, `attention_required`, or `incomplete`.
    pub result: String,
    pub assessment_complete: bool,
    pub criteria: Vec<ValidatedCriterion>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedCriterion {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub text: String,
    pub assessment: Option<String>,
    pub rationale: Option<String>,
    pub changed_paths: Vec<String>,
    pub verification_runs: Vec<VerificationSummary>,
    pub evidence_satisfied: bool,
    pub evidence_reasons: Vec<String>,
}

pub fn validate_mapping(
    review: &ReviewResult,
    mapping: &AcceptanceMapping,
    policy: &vee_core::AcceptancePolicyConfig,
) -> Result<AcceptanceValidation, String> {
    let work_item = review
        .work_item
        .as_ref()
        .ok_or_else(|| "review has no attached work item".to_owned())?;
    if mapping.schema_version != 1
        || mapping.review_id != review.review_id
        || mapping.snapshot_id != review.snapshot_id
        || mapping.work_item_digest != work_item.content_digest
    {
        return Err(
            "acceptance mapping is stale or bound to a different review, snapshot, or work item"
                .into(),
        );
    }
    if mapping.author.trim().is_empty() || mapping.recorded_at.trim().is_empty() {
        return Err("acceptance mapping requires author and recorded_at provenance".into());
    }
    let report = report(review);
    if report.criteria.is_empty() {
        return Err("work item contains no supported acceptance criteria".into());
    }
    let known_criteria = report
        .criteria
        .iter()
        .map(|criterion| criterion.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let changed_paths = review
        .change_set
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let runs = review
        .verification_runs
        .iter()
        .filter(|run| run.snapshot_id == review.snapshot_id)
        .map(|run| (run.run_id.as_str(), run))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut assessments = std::collections::BTreeMap::new();
    for assessment in &mapping.assessments {
        if !known_criteria.contains(assessment.criterion_id.as_str()) {
            return Err(format!(
                "mapping references unknown criterion {}",
                assessment.criterion_id
            ));
        }
        if assessments
            .insert(assessment.criterion_id.as_str(), assessment)
            .is_some()
        {
            return Err(format!(
                "mapping repeats criterion {}",
                assessment.criterion_id
            ));
        }
        if !["met", "not_met", "uncertain"].contains(&assessment.assessment.as_str())
            || assessment.rationale.trim().is_empty()
        {
            return Err(format!(
                "criterion {} has an invalid assessment or empty rationale",
                assessment.criterion_id
            ));
        }
        let mut referenced_paths = std::collections::BTreeSet::new();
        for path in &assessment.changed_paths {
            if !referenced_paths.insert(path.as_str()) {
                return Err(format!(
                    "criterion {} repeats changed path {path}",
                    assessment.criterion_id
                ));
            }
            if !changed_paths.contains(path.as_str()) {
                return Err(format!(
                    "criterion {} references path outside the reviewed snapshot: {path}",
                    assessment.criterion_id
                ));
            }
        }
        let mut referenced_runs = std::collections::BTreeSet::new();
        for run_id in &assessment.verification_run_ids {
            if !referenced_runs.insert(run_id.as_str()) {
                return Err(format!(
                    "criterion {} repeats verification run {run_id}",
                    assessment.criterion_id
                ));
            }
            let run = runs.get(run_id.as_str()).ok_or_else(|| {
                format!(
                "criterion {} references verification run outside the reviewed snapshot: {run_id}",
                assessment.criterion_id
            )
            })?;
            if assessment.assessment == "met" && run.status != VerificationStatus::Passed {
                return Err(format!(
                    "criterion {} is marked met but references non-passing verification run {run_id}",
                    assessment.criterion_id
                ));
            }
        }
        if assessment.assessment == "met"
            && assessment.changed_paths.is_empty()
            && assessment.verification_run_ids.is_empty()
        {
            return Err(format!("criterion {} marked met must reference a changed path or snapshot-bound verification run", assessment.criterion_id));
        }
    }
    let mut any_not_met = false;
    let mut all_met = true;
    let mut any_evidence_incomplete = false;
    let criteria = report
        .criteria
        .into_iter()
        .map(|criterion| {
            let assessment = assessments.get(criterion.id.as_str()).copied();
            if let Some(assessment) = assessment {
                any_not_met |= assessment.assessment == "not_met";
                all_met &= assessment.assessment == "met";
            } else {
                all_met = false;
            }
            let verification_runs: Vec<VerificationSummary> = assessment
                .map(|assessment| {
                    assessment
                        .verification_run_ids
                        .iter()
                        .filter_map(|id| runs.get(id.as_str()))
                        .map(|run| VerificationSummary {
                            run_id: run.run_id.clone(),
                            profile_id: run.profile_id.clone(),
                            status: run.status,
                            targets: run.targets.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut evidence_reasons = Vec::new();
            if assessment.is_some_and(|assessment| assessment.assessment == "met") {
                let passed_profiles = verification_runs
                    .iter()
                    .filter(|run| run.status == VerificationStatus::Passed)
                    .map(|run| run.profile_id.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                if policy.require_passing_verification && passed_profiles.is_empty() {
                    evidence_reasons
                        .push("a passing snapshot-bound verification run is required".into());
                }
                for profile in &policy.required_verification_profiles {
                    if !passed_profiles.contains(profile.as_str()) {
                        evidence_reasons.push(format!(
                            "required verification profile {profile} has no passing run attached"
                        ));
                    }
                }
            }
            any_evidence_incomplete |= !evidence_reasons.is_empty();
            ValidatedCriterion {
                id: criterion.id,
                source_id: criterion.source_id,
                text: criterion.text,
                assessment: assessment.map(|item| item.assessment.clone()),
                rationale: assessment.map(|item| item.rationale.clone()),
                changed_paths: assessment
                    .map(|item| item.changed_paths.clone())
                    .unwrap_or_default(),
                verification_runs,
                evidence_satisfied: evidence_reasons.is_empty(),
                evidence_reasons,
            }
        })
        .collect::<Vec<_>>();
    let assessment_complete = criteria
        .iter()
        .all(|criterion| criterion.assessment.is_some());
    let result = if any_not_met {
        "attention_required"
    } else if any_evidence_incomplete {
        "evidence_incomplete"
    } else if all_met {
        "all_attested_met"
    } else {
        "incomplete"
    };
    let gate_status = if any_not_met {
        "block"
    } else if all_met && !any_evidence_incomplete {
        "pass"
    } else {
        "incomplete"
    };
    let policy_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(policy).map_err(|error| error.to_string())?)
    );
    Ok(AcceptanceValidation {
        schema_version: 1,
        review_id: review.review_id.clone(),
        snapshot_id: review.snapshot_id.clone(),
        work_item_digest: work_item.content_digest.clone(),
        policy_digest,
        gate_status: gate_status.into(),
        author: mapping.author.clone(),
        recorded_at: mapping.recorded_at.clone(),
        result: result.into(),
        assessment_complete,
        criteria,
        limitations: vec![
            "Assessments are human-authored local attestations; Vee does not verify that the stated behavior is correct.".into(),
            "This result does not modify or replace the deterministic Vee quality gate.".into(),
            "Referenced paths and verification runs are bound to the saved review snapshot; changing the review or work item requires a new mapping.".into(),
        ],
    })
}

pub fn report(review: &ReviewResult) -> AcceptanceReport {
    report_with_impact(review, None, None)
}

/// Keep traceability reporting available when impact analysis fails or returns a
/// result for another snapshot. The report must never expose mismatched edges.
pub fn matching_impact(
    expected_snapshot_id: &str,
    result: Result<ImpactAssessment, String>,
) -> (Option<ImpactAssessment>, Option<String>) {
    match result {
        Ok(impact) if impact.snapshot_id == expected_snapshot_id => (Some(impact), None),
        Ok(_) => (
            None,
            Some("impact analyzer returned a different snapshot identity".to_owned()),
        ),
        Err(error) => (None, Some(error)),
    }
}

pub fn report_with_impact(
    review: &ReviewResult,
    impact: Option<&ImpactAssessment>,
    impact_problem: Option<&str>,
) -> AcceptanceReport {
    let impact = impact.filter(|assessment| assessment.snapshot_id == review.snapshot_id);
    let work_item = review.work_item.as_ref();
    let criteria = work_item
        .map(parse_criteria)
        .unwrap_or_default()
        .into_iter()
        .map(|(line, source_id, text)| {
            let tokens = words(&text);
            let candidates = review
                .change_set
                .files
                .iter()
                .filter(|file| {
                    let path_tokens = words(&file.path);
                    !tokens.is_disjoint(&path_tokens)
                })
                .map(|file| file.path.clone())
                .collect::<Vec<_>>();
            let criterion_tokens = words(&text);
            let candidate_test_references = impact
                .into_iter()
                .flat_map(|assessment| assessment.paths.iter())
                .filter(|edge| {
                    edge.relationship == "likely_test_reference"
                        && (candidates.contains(&edge.source_path)
                            || !criterion_tokens.is_disjoint(&words(&edge.symbol))
                            || !criterion_tokens.is_disjoint(&words(&edge.source_path)))
                })
                .map(|edge| TestReferenceCandidate {
                    changed_path: edge.source_path.clone(),
                    test_path: edge.affected_path.clone(),
                    symbol: edge.symbol.clone(),
                    evidence_line: edge.evidence_line,
                    certainty: edge.certainty.clone(),
                })
                .collect();
            AcceptanceCriterion {
                id: criterion_id_with_source(
                    work_item
                        .map(|item| item.content_digest.as_str())
                        .unwrap_or(""),
                    line,
                    source_id.as_deref(),
                    &text,
                ),
                source_id,
                source_line: line,
                text,
                candidate_changed_paths: candidates,
                candidate_test_references,
                status: "needs_human_review",
            }
        })
        .collect();
    let mut limitations = vec![
        "Criteria are extracted from explicit Markdown checkboxes/lists or schema-versioned structured JSON/YAML; unsupported specification formats may be missed.".into(),
        "Path matches are lexical candidates only and do not establish implementation coverage or criterion satisfaction.".into(),
        "Verification runs are shown only when bound to this exact reviewed snapshot; a successful command does not prove every criterion.".into(),
        "No criterion is automatically marked satisfied. Human traceability assessments are not yet supported.".into(),
    ];
    if let Some(problem) = impact_problem {
        limitations.push(format!(
            "Snapshot-bound test-impact analysis was unavailable: {problem}"
        ));
    }
    if impact.is_none() && impact_problem.is_none() {
        limitations.push("No matching snapshot-bound impact assessment was supplied; test-reference candidates are unavailable.".into());
    }
    if let Some(impact) = impact {
        limitations.extend(impact.limitations.iter().cloned());
    }
    if work_item.is_none() {
        limitations.insert(0, "This review has no attached work item; no acceptance criteria were available to parse.".into());
    }
    AcceptanceReport {
        schema_version: 1,
        review_id: review.review_id.clone(),
        snapshot_id: review.snapshot_id.clone(),
        work_item: work_item.map(|item| WorkItemReference {
            url: item.url.clone(),
            content_digest: item.content_digest.clone(),
        }),
        criteria,
        changed_paths: review
            .change_set
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        impact_snapshot_id: impact.map(|assessment| assessment.snapshot_id.clone()),
        impact_coverage_complete: impact.map(|assessment| assessment.coverage_complete),
        impact_analyzers: impact
            .map(|assessment| assessment.analyzers.clone())
            .unwrap_or_default(),
        verification_runs: review
            .verification_runs
            .iter()
            .filter(|run| run.snapshot_id == review.snapshot_id)
            .map(|run| VerificationSummary {
                run_id: run.run_id.clone(),
                profile_id: run.profile_id.clone(),
                status: run.status,
                targets: run.targets.clone(),
            })
            .collect(),
        limitations,
    }
}

fn parse_criteria(item: &WorkItemSnapshot) -> Vec<(usize, Option<String>, String)> {
    let (source, native_field) = match item
        .acceptance_criteria
        .as_deref()
        .filter(|criteria| !criteria.trim().is_empty())
    {
        Some(criteria) => (criteria, true),
        None => match item.body.as_deref() {
            Some(body) => (body, false),
            None => return Vec::new(),
        },
    };
    let normalized;
    let source = if native_field && source.contains('<') {
        normalized = html_to_lines(source);
        normalized.as_str()
    } else {
        source
    };
    if let Some(criteria) = parse_structured_criteria(source) {
        return criteria;
    }
    if source.trim_start().starts_with("{") || source.trim_start().starts_with("schema_version:") {
        return Vec::new();
    }
    let mut in_section = native_field;
    let mut criteria = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = raw.trim();
        if let Some(heading) = trimmed.strip_prefix('#') {
            let heading = heading
                .trim()
                .trim_start_matches('#')
                .trim()
                .to_ascii_lowercase();
            in_section = [
                "acceptance",
                "acceptance criteria",
                "definition of done",
                "requirements",
                "done when",
                "expected behavior",
            ]
            .iter()
            .any(|recognized| {
                heading == *recognized || heading.starts_with(&format!("{recognized}:"))
            });
            continue;
        }
        let text = list_text(trimmed).or_else(|| {
            (native_field && !trimmed.is_empty() && !trimmed.starts_with('#')).then_some(trimmed)
        });
        let Some(text) = text else { continue };
        if text.is_empty() || (!in_section && !is_checkbox(trimmed)) {
            continue;
        }
        criteria.push((line_number, None, text.to_owned()));
    }
    criteria
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredCriteria {
    schema_version: u32,
    requirements: Vec<StructuredRequirement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredRequirement {
    id: String,
    text: String,
}

fn parse_structured_criteria(source: &str) -> Option<Vec<(usize, Option<String>, String)>> {
    let parsed = serde_json::from_str::<StructuredCriteria>(source)
        .or_else(|_| serde_yaml::from_str::<StructuredCriteria>(source))
        .ok()?;
    if parsed.schema_version != 1
        || parsed.requirements.is_empty()
        || parsed.requirements.len() > 500
    {
        return None;
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut criteria = Vec::with_capacity(parsed.requirements.len());
    for (index, requirement) in parsed.requirements.into_iter().enumerate() {
        let id = requirement.id.trim();
        let text = requirement.text.trim();
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            || text.is_empty()
            || text.len() > 16_384
            || !ids.insert(id.to_ascii_lowercase())
        {
            return None;
        }
        criteria.push((index + 1, Some(id.to_owned()), text.to_owned()));
    }
    Some(criteria)
}

fn html_to_lines(input: &str) -> String {
    let mut output = String::with_capacity(input.len().min(131_072));
    let mut in_tag = false;
    let mut tag = String::new();
    for character in input.chars() {
        match character {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let trimmed_tag = tag.trim();
                let closing = trimmed_tag.starts_with('/');
                let name = trimmed_tag
                    .trim_start_matches('/')
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
                if (closing && matches!(name, "li" | "p" | "div")) || name == "br" {
                    output.push('\n');
                }
            }
            _ if in_tag => tag.push(character),
            _ => output.push(character),
        }
    }
    output
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn list_text(line: &str) -> Option<&str> {
    let line = if let Some(line) = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))
    {
        line
    } else {
        let split = line.find(['.', ')'])?;
        if !line[..split]
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return None;
        }
        line[split + 1..].strip_prefix(' ')?
    };
    let line = line
        .strip_prefix("[ ] ")
        .or_else(|| line.strip_prefix("[x] "))
        .or_else(|| line.strip_prefix("[X] "))
        .unwrap_or(line);
    Some(line.trim())
}

fn is_checkbox(line: &str) -> bool {
    [
        "- [ ] ", "- [x] ", "- [X] ", "* [ ] ", "* [x] ", "* [X] ", "+ [ ] ", "+ [x] ", "+ [X] ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

fn words(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| word.len() > 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
fn criterion_id(digest: &str, line: usize, text: &str) -> String {
    criterion_id_with_source(digest, line, None, text)
}

fn criterion_id_with_source(
    digest: &str,
    line: usize,
    source_id: Option<&str>,
    text: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(digest.as_bytes());
    hash.update([0]);
    hash.update(line.to_be_bytes());
    hash.update([0]);
    if let Some(source_id) = source_id {
        hash.update(source_id.as_bytes());
        hash.update([0]);
    }
    hash.update(text.trim().as_bytes());
    let encoded = format!("{:x}", hash.finalize());
    format!("AC-{}", &encoded[..12])
}

pub fn render_text(report: &AcceptanceReport) {
    println!("Acceptance traceability for review {}", report.review_id);
    println!("Snapshot: {}", report.snapshot_id);
    if let Some(work_item) = &report.work_item {
        println!(
            "Work item: {} ({})",
            work_item.url, work_item.content_digest
        );
    } else {
        println!("Work item: none");
    }
    if report.criteria.is_empty() {
        println!("No supported acceptance criteria were extracted.");
    }
    for criterion in &report.criteria {
        println!(
            "{} [line {}] {}",
            criterion.id, criterion.source_line, criterion.text
        );
        println!("  Status: {}", criterion.status);
        if criterion.candidate_changed_paths.is_empty() {
            println!("  Candidate changed paths: none");
        } else {
            println!(
                "  Candidate changed paths: {}",
                criterion.candidate_changed_paths.join(", ")
            );
        }
    }
    println!(
        "Snapshot-bound verification runs: {}",
        report.verification_runs.len()
    );
    for run in &report.verification_runs {
        let result = match run.status {
            VerificationStatus::Passed => "passed",
            VerificationStatus::Failed => "failed",
            VerificationStatus::TimedOut => "timed_out",
            VerificationStatus::Incomplete => "incomplete",
        };
        println!(
            "  {} [{}] {} targets={}",
            run.run_id,
            run.profile_id,
            result,
            run.targets.join(",")
        );
    }
    for limitation in &report.limitations {
        println!("Limitation: {limitation}");
    }
}

pub fn render_validation_text(report: &AcceptanceValidation) {
    println!("Acceptance assessment for review {}", report.review_id);
    println!("Snapshot: {}", report.snapshot_id);
    println!("Result: {} (human attestation)", report.result);
    println!("Gate: {}", report.gate_status);
    println!("Policy: {}", report.policy_digest);
    for criterion in &report.criteria {
        println!(
            "{}: {}",
            criterion.id,
            criterion.assessment.as_deref().unwrap_or("unassessed")
        );
        println!("  {}", criterion.text);
        if let Some(rationale) = &criterion.rationale {
            println!("  Rationale: {rationale}");
        }
        if !criterion.changed_paths.is_empty() {
            println!("  Paths: {}", criterion.changed_paths.join(", "));
        }
        if !criterion.verification_runs.is_empty() {
            println!(
                "  Verification runs: {}",
                criterion
                    .verification_runs
                    .iter()
                    .map(|run| run.run_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !criterion.evidence_satisfied {
            for reason in &criterion.evidence_reasons {
                println!("  Evidence required: {reason}");
            }
        }
    }
    for limitation in &report.limitations {
        println!("Limitation: {limitation}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_impact_keeps_analyzer_failures_in_report_and_rejects_stale_results() {
        let (impact, problem) = matching_impact("snapshot-1", Err("analyzer unavailable".into()));
        assert!(impact.is_none());
        assert_eq!(problem.as_deref(), Some("analyzer unavailable"));

        let stale = ImpactAssessment {
            schema_version: 3,
            snapshot_id: "snapshot-2".into(),
            coverage_complete: true,
            analyzers: vec![],
            changed_paths: vec![],
            changed_symbols: vec![],
            groups: vec![],
            paths: vec![],
            limitations: vec![],
        };
        let (impact, problem) = matching_impact("snapshot-1", Ok(stale));
        assert!(impact.is_none());
        assert_eq!(
            problem.as_deref(),
            Some("impact analyzer returned a different snapshot identity")
        );
    }

    #[test]
    fn extracts_markdown_criteria_and_keeps_unmapped_status_explicit() {
        let parsed = parse_body("Context\n- ignored\n## Acceptance Criteria\n- [ ] Add secure token parser\n- Keep stable API\n## Notes\n- ignored");
        assert_eq!(
            parsed,
            vec![
                (4, None, "Add secure token parser".into()),
                (5, None, "Keep stable API".into())
            ]
        );
        assert_eq!(
            list_text("2. Retain backward compatibility"),
            Some("Retain backward compatibility")
        );
        assert!(is_checkbox("- [x] done"));
        assert_eq!(
            criterion_id("digest", 4, "one"),
            criterion_id("digest", 4, "one")
        );
        assert_ne!(
            criterion_id("digest", 4, "one"),
            criterion_id("digest", 5, "one")
        );
    }

    #[test]
    fn prefers_provider_acceptance_field_and_extracts_html_list_items() {
        let mut item = test_work_item();
        item.body = Some("## Acceptance Criteria\n- description fallback".into());
        item.acceptance_criteria = Some(
            "<ul><li>Reject unsafe input</li><li>Keep API stable &amp; documented</li></ul>".into(),
        );
        assert_eq!(
            parse_criteria(&item),
            vec![
                (1, None, "Reject unsafe input".into()),
                (2, None, "Keep API stable & documented".into())
            ]
        );
    }

    #[test]
    fn structured_requirements_preserve_source_ids_and_reject_duplicate_ids() {
        let mut item = test_work_item();
        item.acceptance_criteria = Some("schema_version: 1\nrequirements:\n  - id: AUTH-1\n    text: Reject expired tokens\n  - id: AUTH-2\n    text: Record denial events\n".into());
        let parsed = parse_criteria(&item);
        assert_eq!(
            parsed[0],
            (1, Some("AUTH-1".into()), "Reject expired tokens".into())
        );
        assert_eq!(parsed[1].1.as_deref(), Some("AUTH-2"));
        assert_ne!(
            criterion_id_with_source("digest", 1, Some("AUTH-1"), "same"),
            criterion_id_with_source("digest", 1, Some("AUTH-2"), "same")
        );

        item.acceptance_criteria = Some("schema_version: 1\nrequirements:\n  - id: R1\n    text: First\n  - id: r1\n    text: Duplicate\n".into());
        assert!(parse_criteria(&item).is_empty());
    }

    fn test_work_item() -> WorkItemSnapshot {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "reference": {"repository": {"host":"example.com", "full_name":"org/repo"}, "number": 1},
            "provider":"test", "api_base":"https://example.com/api", "title":"test",
            "body":null, "url":"https://example.com/issue/1", "state":"open", "updated_at":"now",
            "labels":[], "content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })).unwrap()
    }

    #[test]
    fn a_met_attestation_cannot_reference_a_failed_verification_run() {
        let review: ReviewResult = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "review_id": "review-1",
            "snapshot_id": "snapshot-1",
            "status": "pass",
            "findings": [],
            "evidence": [],
            "verification_runs": [{
                "schema_version": 1,
                "run_id": "run-failed",
                "snapshot_id": "snapshot-1",
                "profile_id": "tests",
                "finding_id": null,
                "targets": [],
                "command_digest": "sha256:command",
                "status": "failed",
                "exit_code": 1,
                "stdout_digest": "sha256:stdout",
                "stderr_digest": "sha256:stderr"
            }],
            "reviewer_outcomes": [],
            "analysis_complete": true,
            "reasons": [],
            "gate": {
                "schema_version": 1,
                "decision_id": "decision-1",
                "snapshot_id": "snapshot-1",
                "effective_config_digest": "sha256:config",
                "policy_digest": "sha256:policy",
                "status": "pass",
                "blocking_findings": [],
                "verification_run_ids": [],
                "evidence_digest": "sha256:evidence",
                "reasons": []
            },
            "change_set": {
                "schema_version": 1,
                "base_oid": null,
                "head_oid": null,
                "scope": "working_tree",
                "files": [{"path": "src/lib.rs", "mode": 33188, "content_digest": "sha256:file", "status": "modified"}],
                "warnings": [],
                "digest": "snapshot-1"
            },
            "effective_config_digest": "sha256:config",
            "selected_reviewers": [],
            "policy_profile": null,
            "work_item": {
                "schema_version": 1,
                "reference": {"repository": {"host": "example.com", "full_name": "org/repo"}, "number": 1},
                "provider": "test",
                "api_base": "https://example.com/api",
                "title": "Feature",
                "body": "## Acceptance Criteria\n- [ ] Keep format stable",
                "url": "https://example.com/issues/1",
                "state": "open",
                "updated_at": "2026-11-14T12:00:00Z",
                "labels": [],
                "content_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })).unwrap();
        let criterion_id = report(&review).criteria[0].id.clone();
        let impact = ImpactAssessment {
            schema_version: 3,
            snapshot_id: review.snapshot_id.clone(),
            coverage_complete: true,
            analyzers: vec![ImpactAnalyzer {
                id: "syntax-rust".into(),
                version: Some("test".into()),
                status: "used".into(),
            }],
            changed_paths: vec!["src/lib.rs".into()],
            changed_symbols: vec!["format".into()],
            groups: vec![],
            paths: vec![
                crate::ImpactEdge {
                    source_path: "src/lib.rs".into(),
                    affected_path: "tests/api_test.rs".into(),
                    relationship: "likely_test_reference".into(),
                    symbol: "format".into(),
                    certainty: "inferred_syntax".into(),
                    evidence_line: 12,
                },
                crate::ImpactEdge {
                    source_path: "src/lib.rs".into(),
                    affected_path: "src/other.rs".into(),
                    relationship: "syntactic_symbol_reference".into(),
                    symbol: "format".into(),
                    certainty: "inferred_syntax".into(),
                    evidence_line: 8,
                },
            ],
            limitations: vec!["fixture analyzer limitation".into()],
        };
        let trace = report_with_impact(&review, Some(&impact), None);
        assert_eq!(trace.impact_snapshot_id.as_deref(), Some("snapshot-1"));
        assert_eq!(trace.impact_analyzers[0].id, "syntax-rust");
        assert_eq!(trace.criteria[0].candidate_test_references.len(), 1);
        assert_eq!(
            trace.criteria[0].candidate_test_references[0].test_path,
            "tests/api_test.rs"
        );
        assert!(trace
            .limitations
            .iter()
            .any(|item| item == "fixture analyzer limitation"));

        let mapping = AcceptanceMapping {
            schema_version: 1,
            review_id: review.review_id.clone(),
            snapshot_id: review.snapshot_id.clone(),
            work_item_digest: review.work_item.as_ref().unwrap().content_digest.clone(),
            author: "maintainer@example.invalid".into(),
            recorded_at: "2026-11-14T12:10:00Z".into(),
            assessments: vec![CriterionAssessment {
                criterion_id: criterion_id.clone(),
                assessment: "met".into(),
                rationale: "Reviewed implementation".into(),
                changed_paths: vec!["src/lib.rs".into()],
                verification_run_ids: vec!["run-failed".into()],
            }],
        };
        assert!(validate_mapping(
            &review,
            &mapping,
            &vee_core::AcceptancePolicyConfig::default()
        )
        .unwrap_err()
        .contains("non-passing verification"));

        let uncertain = AcceptanceMapping {
            assessments: vec![CriterionAssessment {
                assessment: "uncertain".into(),
                ..mapping.assessments[0].clone()
            }],
            ..mapping.clone()
        };
        let result = validate_mapping(
            &review,
            &uncertain,
            &vee_core::AcceptancePolicyConfig::default(),
        )
        .unwrap();
        assert_eq!(result.result, "incomplete");
        assert_eq!(
            result.criteria[0].verification_runs[0].status,
            VerificationStatus::Failed
        );

        let met_without_run = AcceptanceMapping {
            assessments: vec![CriterionAssessment {
                verification_run_ids: vec![],
                ..mapping.assessments[0].clone()
            }],
            ..mapping
        };
        let strict_policy = vee_core::AcceptancePolicyConfig {
            require_passing_verification: true,
            required_verification_profiles: vec!["tests".into()],
        };
        let strict = validate_mapping(&review, &met_without_run, &strict_policy).unwrap();
        assert_eq!(strict.gate_status, "incomplete");
        assert_eq!(strict.result, "evidence_incomplete");
        assert!(!strict.criteria[0].evidence_satisfied);
        assert_eq!(strict.criteria[0].evidence_reasons.len(), 2);
    }

    fn parse_body(body: &str) -> Vec<(usize, Option<String>, String)> {
        let mut item: WorkItemSnapshot = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "reference": {"repository": {"host":"example.com", "full_name":"org/repo"}, "number": 1},
            "provider":"test", "api_base":"https://example.com/api", "title":"test", "body":body,
            "url":"https://example.com/issue/1", "state":"open", "updated_at":"now",
            "labels":[], "content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })).unwrap();
        item.body = Some(body.into());
        parse_criteria(&item)
    }
}
