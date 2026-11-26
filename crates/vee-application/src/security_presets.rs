//! Security scanners `vee init` can set up as trusted analyzers (ADR 0029).
//!
//! Vee ships no scanner. It knows how to run a few common ones so that their
//! SARIF reaches the gate: results on changed lines block the gate at the
//! levels listed for each scanner.

use crate::setup::SystemProbe;
use serde::{Deserialize, Serialize};

/// A scanner Vee knows how to run.
struct Preset {
    id: &'static str,
    egress: &'static str,
    args: &'static [&'static str],
    block_levels: &'static [&'static str],
    /// What it finds.
    covers: &'static str,
    /// Why Vee does not set it up, when it cannot gate a change.
    unsupported: Option<&'static str>,
}

const PRESETS: [Preset; 5] = [
    Preset {
        id: "nox",
        egress: "network",
        // nox exits non-zero when it reports results; with valid SARIF that
        // is a complete run. Add `--offline` to skip the OSV advisories and
        // run without the network (then set `egress: local`).
        args: &["scan", ".", "--format", "sarif", "--output", "-", "-q"],
        block_levels: &["error"],
        covers: "secrets, insecure code and vulnerable dependencies",
        unsupported: None,
    },
    Preset {
        id: "gitleaks",
        egress: "local",
        args: &[
            "dir", ".", "--report-format", "sarif", "--report-path", "-", "--no-banner",
            "--redact", "--exit-code", "0",
        ],
        // gitleaks gives its results no level, which SARIF reads as `warning`.
        block_levels: &["error", "warning"],
        covers: "committed secrets",
        unsupported: None,
    },
    Preset {
        id: "semgrep",
        egress: "network",
        args: &["scan", "--sarif", "--quiet", "--metrics", "off", "--config", "p/default"],
        block_levels: &["error"],
        covers: "insecure code patterns",
        unsupported: None,
    },
    Preset {
        id: "trivy",
        egress: "network",
        args: &[
            "fs", "--format", "sarif", "--quiet", "--scanners", "vuln,secret,misconfig", ".",
        ],
        block_levels: &["error"],
        covers: "vulnerable dependencies, secrets and misconfiguration",
        unsupported: None,
    },
    Preset {
        id: "osv-scanner",
        egress: "network",
        args: &[],
        block_levels: &[],
        covers: "vulnerable dependencies",
        unsupported: Some(
            "its SARIF gives no line for a result, and Vee only counts results on changed lines; use trivy for dependencies",
        ),
    },
];

/// A scanner found on this machine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityScanner {
    pub id: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub covers: String,
    /// `configured` when Vee can run it as a gate analyzer, else `unsupported`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SecurityScanner {
    pub fn configurable(&self) -> bool {
        self.status == "configured"
    }
}

/// The known scanners on `PATH`.
pub fn detect(probe: &dyn SystemProbe) -> Vec<SecurityScanner> {
    PRESETS
        .iter()
        .filter_map(|preset| {
            let path = probe.find_executable(preset.id)?;
            Some(SecurityScanner {
                id: preset.id.to_owned(),
                version: probe.command_version(&path),
                path: path.display().to_string(),
                covers: preset.covers.to_owned(),
                status: if preset.unsupported.is_some() {
                    "unsupported"
                } else {
                    "configured"
                }
                .to_owned(),
                reason: preset.unsupported.map(str::to_owned),
            })
        })
        .collect()
}

fn yaml_list(items: &[&str]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|item| serde_json::to_string(item).expect("strings serialize"))
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// The `verification` entries for `scanners`, indented under `verification:`.
pub fn verification_yaml(scanners: &[SecurityScanner]) -> String {
    let mut yaml = String::new();
    for scanner in scanners.iter().filter(|scanner| scanner.configurable()) {
        let preset = PRESETS
            .iter()
            .find(|preset| preset.id == scanner.id)
            .expect("detected scanners have presets");
        yaml.push_str(&format!(
            "  # {covers}; results on changed lines at {levels} block the gate.\n{extra}  {id}:\n    executable: {id}\n    egress: {egress}\n    args: {args}\n    env_allowlist: [PATH, HOME]\n    timeout_seconds: 600\n    sarif:\n      block_levels: {levels}\n",
            covers = preset.covers,
            extra = if preset.id == "nox" {
                "  # Add --offline to args and set egress: local to scan without OSV advisories.\n"
            } else {
                ""
            },
            id = preset.id,
            egress = preset.egress,
            args = yaml_list(preset.args),
            levels = yaml_list(preset.block_levels),
        ));
    }
    yaml
}

/// The `security` and `regulated` policy profiles, indented under
/// `policy_profiles:`. `reviewer` is the required reviewer.
pub fn policy_profiles_yaml(scanners: &[SecurityScanner], reviewer: &str) -> String {
    let ids: Vec<&str> = scanners
        .iter()
        .filter(|scanner| scanner.configurable())
        .map(|scanner| scanner.id.as_str())
        .collect();
    let verifications = yaml_list(&ids);
    format!(
        "  # `--policy-profile security`: the default policy, and the security scanners must run.\n  security:\n    required_reviewers: [{reviewer}]\n    required_verifications: {verifications}\n    block_severities: [critical, high]\n    minimum_confidence: 80\n    on_incomplete: block\n    severity_floors:\n      - categories: [security]\n        minimum: high\n  # `--policy-profile regulated`: stricter, and a person approves every change.\n  regulated:\n    required_reviewers: [{reviewer}]\n    required_verifications: {verifications}\n    block_severities: [critical, high, medium]\n    minimum_confidence: 70\n    on_incomplete: block\n    on_unreviewed: block\n    automatic_approval: false\n    severity_floors:\n      - categories: [security]\n        minimum: high\n      - paths: [\"**/auth/**\", \"**/crypto/**\", \"**/payments/**\", \"**/migrations/**\", \".github/workflows/**\"]\n        minimum: high\n"
    )
}

/// What to add to an existing `.vee.yaml` to use the scanners.
pub fn snippet(scanners: &[SecurityScanner], reviewer: &str) -> Option<String> {
    scanners.iter().any(SecurityScanner::configurable).then(|| {
        format!(
            "verification:\n{}policy_profiles:\n{}",
            verification_yaml(scanners),
            policy_profiles_yaml(scanners, reviewer)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(id: &str, status: &str) -> SecurityScanner {
        SecurityScanner {
            id: id.into(),
            path: format!("/usr/bin/{id}"),
            version: None,
            covers: String::new(),
            status: status.into(),
            reason: None,
        }
    }

    #[test]
    fn the_presets_are_valid_configuration_that_requires_each_usable_scanner() {
        let scanners = [
            scanner("nox", "configured"),
            scanner("gitleaks", "configured"),
            scanner("trivy", "configured"),
            scanner("osv-scanner", "unsupported"),
        ];
        let yaml = format!(
            "version: 1\nreviewers:\n  correctness: {{ provider: default, instructions_file: r.md }}\n{}",
            snippet(&scanners, "correctness").unwrap()
        );
        let mut config: vee_core::RepositoryConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            config.verification.keys().collect::<Vec<_>>(),
            ["gitleaks", "nox", "trivy"]
        );
        assert_eq!(config.verification["nox"].args[0], "scan");
        assert!(config.verification["gitleaks"].sarif.is_some());
        config.select_policy_profile(Some("regulated")).unwrap();
        assert_eq!(
            config.policy.required_verifications,
            ["nox", "gitleaks", "trivy"]
        );
        assert!(!config.policy.allows_automatic_approval());
        assert_eq!(config.policy.severity_floors.len(), 2);
        config.select_policy_profile(Some("security")).unwrap();
        assert!(config.policy.allows_automatic_approval());

        assert_eq!(snippet(&[scanner("osv-scanner", "unsupported")], "c"), None);
    }
}
