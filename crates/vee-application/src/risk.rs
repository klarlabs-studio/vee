//! Change risk: a transparent, rule-based tier over measured change metrics.
//!
//! The factors are the change metrics that predict defect-inducing changes in
//! just-in-time defect prediction (diffusion and size; Mockus & Weiss 2000,
//! Kamei et al. 2013) plus review-size limits (Czerwonka et al. 2015) and the
//! impact analysis' blast radius. Without a repository's own labelled defect
//! history a model cannot be trained or calibrated, so Vee reports an ordinal
//! tier with every contributing factor named, never a probability (see
//! `docs/research/review-literature.md`, section 2). Risk is informational: it
//! routes attention and never changes the gate.

use super::*;

/// Version of the change risk document (`change-risk-v1`).
pub const CHANGE_RISK_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Elevated,
    High,
}

impl RiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskTier::Low => "low",
            RiskTier::Elevated => "elevated",
            RiskTier::High => "high",
        }
    }
}

/// One measured factor. A factor is flagged when `value >= threshold`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskFactor {
    pub id: String,
    pub label: String,
    pub value: u64,
    pub threshold: u64,
    pub flagged: bool,
    /// What was counted, such as the subsystems or files involved.
    pub detail: String,
    /// The research the factor and its threshold come from.
    pub basis: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeRisk {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub tier: RiskTier,
    pub factors: Vec<RiskFactor>,
    pub limitations: Vec<String>,
}

/// Flagged factors at or above which a change is high risk; one or more
/// flags make it elevated. Two cut-offs over named flags follow the deployed
/// tool in Mockus & Weiss (2000).
const HIGH_RISK_FLAGS: usize = 3;
/// Subsystems touched (the strongest single predictor in Mockus & Weiss).
const SUBSYSTEMS_THRESHOLD: u64 = 3;
/// Files changed; comment usefulness drops past about 20 files.
const FILES_THRESHOLD: u64 = 20;
/// Lines added plus deleted; review effectiveness drops past 200-400 lines.
const LINES_THRESHOLD: u64 = 400;
/// Production files outside the change that reference changed code.
const BLAST_RADIUS_THRESHOLD: u64 = 10;
/// Directories that hold one subsystem per child, such as `crates/vee-git`.
const CONTAINER_DIRECTORIES: &[&str] = &[
    "apps", "cmd", "crates", "internal", "libs", "modules", "packages", "pkg", "plugins",
    "services",
];

/// The subsystem a path belongs to: its top-level directory, or the first
/// two levels under a container directory. Root files form the `(root)`
/// subsystem.
pub(crate) fn subsystem(path: &str) -> String {
    let mut parts = path.split('/');
    let first = parts.next().unwrap_or_default();
    let Some(second) = parts.next() else {
        return "(root)".into();
    };
    if CONTAINER_DIRECTORIES.contains(&first) && parts.next().is_some() {
        format!("{first}/{second}")
    } else {
        first.to_owned()
    }
}

/// Lines added and deleted between two texts, counted as a multiset
/// difference of lines. Moved lines count as unchanged, so this is a lower
/// bound on a diff's counts; it is exact for edits that do not reorder.
pub(crate) fn changed_line_counts(base: &str, current: &str) -> (u64, u64) {
    let mut remaining = std::collections::HashMap::<&str, i64>::new();
    for line in base.lines() {
        *remaining.entry(line).or_default() += 1;
    }
    let mut added = 0u64;
    for line in current.lines() {
        match remaining.get_mut(line) {
            Some(count) if *count > 0 => *count -= 1,
            _ => added += 1,
        }
    }
    let deleted = remaining.values().filter(|count| **count > 0).sum::<i64>() as u64;
    (added, deleted)
}

/// Assess the risk of `change_set` from its files and `impact`.
pub fn assess_change_risk(
    root: &Path,
    change_set: &ChangeSet,
    impact: &ImpactAssessment,
) -> Result<ChangeRisk, String> {
    let filter = crate::impact::impact_review_filter(root);
    let paths: Vec<String> = change_set
        .files
        .iter()
        .map(|file| file.path.clone())
        .filter(|path| {
            filter
                .as_ref()
                .is_none_or(|filter| crate::review::review_path_is_included(path, filter))
        })
        .collect();
    let mut limitations = Vec::new();
    if paths.len() < change_set.files.len() {
        limitations.push(format!(
            "{} changed path(s) outside the repository review filter are not counted.",
            change_set.files.len() - paths.len()
        ));
    }

    // Diffusion is measured over code: documentation changes alongside
    // features without spreading the change's behavior.
    let subsystems: std::collections::BTreeSet<String> = paths
        .iter()
        .filter(|path| !crate::impact::is_documentation_path(path))
        .map(|path| subsystem(path))
        .collect();

    let path_bufs: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let current = vee_git::read_snapshot_files(root, change_set, &path_bufs)?;
    let base = vee_git::read_snapshot_base_files(root, change_set, &path_bufs)?;
    let (mut added, mut deleted, mut binary) = (0u64, 0u64, 0usize);
    for (current, base) in current.into_iter().zip(base) {
        let text = |bytes: Option<Vec<u8>>| match bytes {
            None => Some(String::new()),
            Some(bytes) => String::from_utf8(bytes).ok(),
        };
        match (text(base), text(current)) {
            (Some(base), Some(current)) => {
                let (file_added, file_deleted) = changed_line_counts(&base, &current);
                added += file_added;
                deleted += file_deleted;
            }
            _ => binary += 1,
        }
    }
    if binary > 0 {
        limitations.push(format!(
            "{binary} binary or non-UTF-8 file(s) are counted as changed files but not as lines."
        ));
    }

    let changed: std::collections::BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    let affected: std::collections::BTreeSet<&str> = impact
        .paths
        .iter()
        .filter(|edge| {
            edge.co_change.is_none()
                && edge.relationship != "likely_test_reference"
                && !crate::impact::is_test_path(&edge.affected_path)
                && !changed.contains(edge.affected_path.as_str())
        })
        .map(|edge| edge.affected_path.as_str())
        .collect();
    if !impact.coverage_complete {
        limitations
            .push("Impact coverage is incomplete, so the blast radius may be undercounted.".into());
    }

    let tested: std::collections::BTreeSet<&str> = impact
        .paths
        .iter()
        .filter(|edge| edge.relationship == "likely_test_reference")
        .map(|edge| edge.source_path.as_str())
        .collect();
    let any_test_changed = paths.iter().any(|path| crate::impact::is_test_path(path));
    let untested: Vec<&str> = paths
        .iter()
        .map(String::as_str)
        .filter(|path| {
            crate::impact::declares_symbols(path)
                && !crate::impact::is_test_path(path)
                && !tested.contains(path)
        })
        .collect();
    let untested: Vec<&str> = if any_test_changed {
        Vec::new()
    } else {
        untested
    };

    let factor =
        |id: &str, label: &str, value: u64, threshold: u64, detail: String, basis: &str| {
            RiskFactor {
                id: id.into(),
                label: label.into(),
                value,
                threshold,
                flagged: value >= threshold,
                detail,
                basis: basis.into(),
            }
        };
    let list = |items: &mut dyn Iterator<Item = &str>| {
        const SHOWN: usize = 5;
        let items: Vec<&str> = items.collect();
        let mut text = items
            .iter()
            .take(SHOWN)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if items.len() > SHOWN {
            text.push_str(&format!(" and {} more", items.len() - SHOWN));
        }
        text
    };
    let factors = vec![
        factor(
            "subsystems",
            "Code subsystems touched",
            subsystems.len() as u64,
            SUBSYSTEMS_THRESHOLD,
            list(&mut subsystems.iter().map(String::as_str)),
            "Mockus & Weiss 2000; Kamei et al. 2013 (diffusion)",
        ),
        factor(
            "files",
            "Files changed",
            paths.len() as u64,
            FILES_THRESHOLD,
            format!("{} file(s)", paths.len()),
            "Kamei et al. 2013 (diffusion); Czerwonka et al. 2015 (review size)",
        ),
        factor(
            "lines",
            "Lines added and deleted",
            added + deleted,
            LINES_THRESHOLD,
            format!("+{added} −{deleted}"),
            "Kamei et al. 2013 (size); 200-400 line review limit (Cisco case study, not peer reviewed)",
        ),
        factor(
            "blast_radius",
            "Production files referencing changed code",
            affected.len() as u64,
            BLAST_RADIUS_THRESHOLD,
            list(&mut affected.iter().copied()),
            "Hattori et al. 2008 (direct dependents); impact analysis",
        ),
        factor(
            "untested_source",
            "Changed source files with no test changed or referencing them",
            untested.len() as u64,
            1,
            list(&mut untested.iter().copied()),
            "McIntosh & Kamei 2018; agent-change failure studies (missing tests and CI)",
        ),
    ];
    let flagged = factors.iter().filter(|factor| factor.flagged).count();
    let tier = match flagged {
        0 => RiskTier::Low,
        count if count >= HIGH_RISK_FLAGS => RiskTier::High,
        _ => RiskTier::Elevated,
    };
    limitations.push("The tier is a rule over the flagged factors, not a calibrated defect probability; history factors (author experience, prior changes) are not yet included.".into());
    Ok(ChangeRisk {
        schema_version: CHANGE_RISK_SCHEMA_VERSION,
        snapshot_id: change_set.digest.clone(),
        tier,
        factors,
        limitations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystems_split_container_directories_one_level_deeper() {
        assert_eq!(subsystem("README.md"), "(root)");
        assert_eq!(subsystem("web/src/App.vue"), "web");
        assert_eq!(subsystem("crates/vee-git/src/lib.rs"), "crates/vee-git");
        assert_eq!(subsystem("crates/README.md"), "crates");
    }

    #[test]
    fn line_counts_are_a_multiset_difference() {
        assert_eq!(changed_line_counts("a\nb\nc\n", "a\nB\nc\nd\n"), (2, 1));
        assert_eq!(changed_line_counts("", "x\ny\n"), (2, 0));
        assert_eq!(changed_line_counts("x\nx\n", "x\n"), (0, 1));
        assert_eq!(changed_line_counts("a\nb\n", "b\na\n"), (0, 0));
    }

    #[test]
    fn a_change_across_subsystems_without_tests_is_elevated_with_named_flags() {
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
        for (path, contents) in [
            (
                "api/handler.go",
                "package api\n\nfunc Handle() int { return 1 }\n",
            ),
            (
                "store/db.go",
                "package store\n\nfunc Save() int { return 1 }\n",
            ),
            ("docs/guide.md", "guide\n"),
        ] {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        git(&["add", "."]);
        git(&["commit", "-qm", "baseline"]);
        std::fs::write(
            root.join("api/handler.go"),
            "package api\n\nfunc Handle() int { return 2 }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("store/db.go"),
            "package store\n\nfunc Save() int {\n\treturn 2\n}\n",
        )
        .unwrap();
        std::fs::write(root.join("docs/guide.md"), "guide\nmore\n").unwrap();
        let change_set = capture_change_set(root, vee_git::ChangeScope::WorkingTree).unwrap();
        let impact = analyze_impact(root, &change_set).unwrap();

        let risk = assess_change_risk(root, &change_set, &impact).unwrap();

        let factor = |id: &str| risk.factors.iter().find(|factor| factor.id == id).unwrap();
        assert_eq!(risk.tier, RiskTier::Elevated, "{risk:#?}");
        assert_eq!(
            factor("subsystems").value,
            2,
            "documentation is not a subsystem"
        );
        assert!(!factor("subsystems").flagged);
        assert_eq!(factor("subsystems").detail, "api, store");
        assert_eq!(factor("files").value, 3);
        assert!(!factor("files").flagged);
        assert_eq!(factor("lines").value, 7, "{risk:#?}");
        assert_eq!(factor("untested_source").value, 2);
        assert!(factor("untested_source").flagged);
        assert_eq!(
            factor("untested_source").detail,
            "api/handler.go, store/db.go"
        );
        assert_eq!(risk.snapshot_id, change_set.digest);
    }
}
