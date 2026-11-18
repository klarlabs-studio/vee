use super::*;

#[test]
fn protected_policy_can_only_strengthen_repository_policy() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join(".vero")).unwrap();
    std::fs::write(
        directory.path().join(".vero.yaml"),
        r#"
version: 1
providers:
  p: { kind: cli, executable: fake }
reviewers:
  correctness: { provider: p, instructions_file: review.md, enabled: true }
verification:
  unit: { executable: true }
policy:
  required_reviewers: []
  required_verifications: []
  block_severities: [high]
  minimum_confidence: 40
  on_incomplete: allow
  acceptance:
    require_passing_verification: false
    required_verification_profiles: []
policy_profiles:
  relaxed:
    required_reviewers: []
    required_verifications: []
    block_severities: []
    minimum_confidence: 0
    on_incomplete: allow
"#,
    )
    .unwrap();
    let mut config = RepositoryConfig::load(&directory.path().join(".vero.yaml")).unwrap();
    config.select_policy_profile(Some("relaxed")).unwrap();
    std::fs::write(
        directory.path().join(".vero/policy.yaml"),
        r#"
required_reviewers: [correctness]
required_verifications: [unit]
block_severities: [critical]
minimum_confidence: 90
on_incomplete: block
acceptance:
  require_passing_verification: true
  required_verification_profiles: [unit]
"#,
    )
    .unwrap();
    apply_protected_policy(directory.path(), &mut config).unwrap();
    assert_eq!(config.policy.required_reviewers, vec!["correctness"]);
    assert_eq!(config.policy.required_verifications, vec!["unit"]);
    assert_eq!(config.policy.block_severities, vec!["critical"]);
    assert_eq!(config.policy.minimum_confidence, 90);
    assert_eq!(config.policy.on_incomplete, "block");
    assert!(config.policy.acceptance.require_passing_verification);
    assert_eq!(
        config.policy.acceptance.required_verification_profiles,
        vec!["unit"]
    );
}

#[test]
fn protected_policy_rejects_unknown_requirements() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join(".vero")).unwrap();
    std::fs::write(directory.path().join(".vero.yaml"), "version: 1\n").unwrap();
    std::fs::write(
        directory.path().join(".vero/policy.yaml"),
        "required_reviewers: [missing]\n",
    )
    .unwrap();
    let mut config = RepositoryConfig::load(&directory.path().join(".vero.yaml")).unwrap();
    assert!(apply_protected_policy(directory.path(), &mut config)
        .unwrap_err()
        .contains("unknown reviewer"));
}
