use crate::quorum::{calibrate, MIN_LABELED_FINDINGS};
use vee_core::{FindingFeedbackLabel, SampleAgreement};

fn record(index: usize, reviewer: &str, reported: u32, samples: u32) -> vee_core::FindingRecord {
    vee_core::FindingRecord {
        finding: vee_core::Finding {
            suggestion: None,
            id: format!("find_{index:012x}"),
            fingerprint: format!("fp-{index}"),
            category: "correctness".into(),
            severity: vee_core::Severity::High,
            confidence: Some(80),
            rationale: "A defect".into(),
            path: Some("src/lib.rs".into()),
            line: Some(index as u32 + 1),
            provenance: "model_inference".into(),
            reviewer_ids: vec![reviewer.into()],
            evidence_ids: vec![],
            rule_attributions: vec![],
            sample_agreement: Some(SampleAgreement {
                reported,
                samples,
                quorum: samples / 2 + 1,
            }),
            advisory: false,
        },
        assessments: vec![],
        status: vee_core::FindingStatus::Open,
        status_reason: None,
        occurrence_count: 1,
        first_seen: String::new(),
        last_seen: String::new(),
        occurrences: vec![],
    }
}

fn label(index: usize, label: FindingFeedbackLabel, at: &str) -> vee_core::FindingFeedback {
    vee_core::FindingFeedback {
        schema_version: 1,
        feedback_id: format!("feedback-{index}-{at}"),
        finding_id: format!("find_{index:012x}"),
        snapshot_id: "s".into(),
        label,
        reason: "checked".into(),
        reviewer: "dev".into(),
        created_at: at.into(),
    }
}

fn config(samples: u32, quorum: Option<u32>) -> vee_core::RepositoryConfig {
    let quorum = quorum.map_or(String::new(), |quorum| format!(", sample_quorum: {quorum}"));
    let yaml = format!(
        "version: 1\nproviders:\n  p: {{ kind: cli, executable: reviewer }}\nreviewers:\n  correctness: {{ provider: p, instructions_file: r.md, samples: {samples}{quorum} }}\n  single: {{ provider: p, instructions_file: r.md }}\n"
    );
    serde_yaml::from_str(&yaml).unwrap()
}

#[test]
fn recommends_the_quorum_that_keeps_most_confirmed_findings_net_of_rejected() {
    // Five samples, configured quorum 4. Confirmed findings were reported by
    // 3 to 5 runs and rejected ones by 1 or 2, so quorum 3 keeps every
    // confirmed finding and no rejected one, while 4 drops three confirmed.
    let mut records = Vec::new();
    let mut feedback = Vec::new();
    let confirmed = [3, 3, 4, 5, 5, 3, 4];
    let rejected = [1, 1, 2, 2, 1];
    for (index, reported) in confirmed.iter().chain(rejected.iter()).enumerate() {
        records.push(record(index, "correctness", *reported, 5));
        let kind = if index < confirmed.len() {
            FindingFeedbackLabel::Confirmed
        } else {
            FindingFeedbackLabel::FalsePositive
        };
        feedback.push(label(index, kind, "2026-11-20 10:00:00"));
    }
    let calibration = calibrate(&config(5, Some(4)), &records, &feedback);
    assert_eq!(
        calibration.reviewers.len(),
        1,
        "the unsampled reviewer is left out"
    );
    let reviewer = &calibration.reviewers[0];
    assert_eq!(reviewer.labeled, 12);
    assert_eq!(reviewer.configured_quorum, 4);
    assert_eq!(reviewer.recommended_quorum, Some(3));
    let at_three = &reviewer.outcomes[2];
    assert_eq!((at_three.kept_confirmed, at_three.kept_rejected), (7, 0));
    let at_four = &reviewer.outcomes[3];
    assert_eq!((at_four.kept_confirmed, at_four.dropped_confirmed), (4, 3));
    assert!(reviewer.reason.contains("quorum 3 keeps 7 confirmed"));
}

#[test]
fn too_few_labels_and_other_sample_counts_give_no_recommendation() {
    let records: Vec<_> = (0..MIN_LABELED_FINDINGS)
        .map(|index| record(index, "correctness", 3, if index == 0 { 5 } else { 3 }))
        .collect();
    let feedback: Vec<_> = (0..MIN_LABELED_FINDINGS)
        .map(|index| {
            label(
                index,
                FindingFeedbackLabel::Confirmed,
                "2026-11-20 10:00:00",
            )
        })
        .collect();
    // One finding comes from a five-sample run, which no longer applies.
    let reviewer = &calibrate(&config(3, None), &records, &feedback).reviewers[0];
    assert_eq!(reviewer.labeled, MIN_LABELED_FINDINGS - 1);
    assert_eq!(reviewer.recommended_quorum, None);
    assert!(reviewer.reason.contains("at least 10"));
}

#[test]
fn the_latest_label_counts_and_ties_keep_the_configured_quorum() {
    let records: Vec<_> = (0..10)
        .map(|index| record(index, "correctness", 3, 3))
        .collect();
    let mut feedback: Vec<_> = (0..10)
        .map(|index| {
            label(
                index,
                FindingFeedbackLabel::FalsePositive,
                "2026-11-20 10:00:00",
            )
        })
        .collect();
    // A later label replaces the earlier rejection.
    feedback.extend((0..10).map(|index| {
        label(
            index,
            FindingFeedbackLabel::Actionable,
            "2026-11-21 10:00:00",
        )
    }));
    let reviewer = &calibrate(&config(3, None), &records, &feedback).reviewers[0];
    // Every finding has full agreement, so every quorum keeps all ten.
    assert!(reviewer
        .outcomes
        .iter()
        .all(|outcome| outcome.kept_confirmed == 10));
    assert_eq!(reviewer.recommended_quorum, Some(2));
    assert!(reviewer.reason.contains("already keeps"));
}
