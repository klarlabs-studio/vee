//! Snapshot source access: reading files at a snapshot, code anchors, and changed-line diffs.

use super::*;

/// Read a bounded regular file confined to the repository root.
pub fn read_repository_file(root: &Path, relative: &Path) -> Result<Vec<u8>, String> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "path escapes repository root: {}",
            relative.display()
        ));
    }
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let path = root.join(relative);
    let canonical_path = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
    if !canonical_path.starts_with(canonical_root) {
        return Err(format!(
            "path escapes repository root through a symlink: {}",
            relative.display()
        ));
    }
    std::fs::read(canonical_path).map_err(|error| error.to_string())
}

pub(crate) fn snapshot_code_anchor(
    root: &Path,
    change_set: &ChangeSet,
    finding: &vero_core::Finding,
) -> Result<Option<String>, String> {
    let (Some(path), Some(line)) = (finding.path.as_deref(), finding.line) else {
        return Ok(None);
    };
    let Some(bytes) = vero_git::read_snapshot_file(root, change_set, Path::new(path))? else {
        return Ok(None);
    };
    let Ok(source) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Some(source_line) = source.lines().nth(line.saturating_sub(1) as usize) else {
        return Ok(None);
    };
    let normalized = source_line.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        Ok(None)
    } else {
        Ok(Some(normalized))
    }
}

/// Build a bounded unified diff for a text file whose complete baseline and current
/// contents would exceed a reviewer's context budget.
pub fn bounded_text_diff(
    baseline: Option<&[u8]>,
    current: Option<&[u8]>,
    max_output_bytes: usize,
) -> Result<Option<String>, String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut old_file = tempfile::NamedTempFile::new()
        .map_err(|error| format!("creating temporary diff baseline: {error}"))?;
    let mut new_file = tempfile::NamedTempFile::new()
        .map_err(|error| format!("creating temporary diff source: {error}"))?;
    if let Some(bytes) = baseline {
        old_file
            .write_all(bytes)
            .map_err(|error| format!("writing temporary diff baseline: {error}"))?;
    }
    if let Some(bytes) = current {
        new_file
            .write_all(bytes)
            .map_err(|error| format!("writing temporary diff source: {error}"))?;
    }

    let mut child = Command::new("git")
        .args([
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-color",
            "--unified=40",
            "--",
        ])
        .arg(old_file.path())
        .arg(new_file.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("starting bounded text diff: {error}"))?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| "bounded text diff stdout was unavailable".to_string())?
        .take(max_output_bytes.saturating_add(1) as u64)
        .read_to_end(&mut output)
        .map_err(|error| format!("reading bounded text diff: {error}"))?;
    if output.len() > max_output_bytes {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(None);
    }
    let status = child
        .wait()
        .map_err(|error| format!("waiting for bounded text diff: {error}"))?;
    if !status.success() && status.code() != Some(1) {
        return Err(format!(
            "bounded text diff exited with {}",
            status
                .code()
                .map_or("signal".into(), |code| code.to_string())
        ));
    }
    let diff = String::from_utf8(output)
        .map_err(|error| format!("bounded text diff was not UTF-8: {error}"))?;
    if diff.is_empty() {
        return Ok(Some("No textual line changes were present.".into()));
    }
    if !diff.lines().any(|line| line.starts_with("@@ ")) {
        return Ok(None);
    }
    let hunks = diff
        .lines()
        .skip_while(|line| !line.starts_with("@@ "))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Some(hunks))
}

/// Return one-based line numbers added by a bounded unified diff. `None` means
/// the diff was not textual or exceeded the caller's output bound.
pub fn changed_line_numbers(
    baseline: Option<&[u8]>,
    current: Option<&[u8]>,
    max_output_bytes: usize,
) -> Result<Option<std::collections::BTreeSet<u64>>, String> {
    let Some(diff) = bounded_text_diff(baseline, current, max_output_bytes)? else {
        return Ok(None);
    };
    if diff == "No textual line changes were present." {
        return Ok(Some(std::collections::BTreeSet::new()));
    }
    let mut added = std::collections::BTreeSet::new();
    let mut new_line = None;
    for row in diff.lines() {
        if row.starts_with("@@ ") {
            let header = row
                .strip_prefix("@@ ")
                .and_then(|value| value.split_once(" @@"))
                .map(|(ranges, _)| ranges)
                .ok_or("malformed unified diff hunk header")?;
            let new_range = header
                .split_whitespace()
                .find(|range| range.starts_with('+'))
                .ok_or("unified diff hunk is missing its new range")?
                .trim_start_matches('+');
            let start = new_range
                .split_once(',')
                .map_or(new_range, |(start, _)| start)
                .parse::<u64>()
                .map_err(|_| "invalid unified diff line number")?;
            new_line = Some(start);
            continue;
        }
        let Some(line) = new_line.as_mut() else {
            continue;
        };
        match row.as_bytes().first().copied() {
            Some(b'+') => {
                added.insert(*line);
                *line += 1;
            }
            Some(b'-') => {}
            Some(b' ') => *line += 1,
            Some(b'\\') => {}
            _ => return Err("malformed unified diff hunk row".into()),
        }
    }
    Ok(Some(added))
}

/// Return compact inclusive changed-line ranges for the captured current file.
/// `None` means the bounded text diff was unavailable or exceeded its limit.
pub fn changed_line_ranges(
    baseline: Option<&[u8]>,
    current: Option<&[u8]>,
    max_output_bytes: usize,
) -> Result<Option<Vec<(u64, u64)>>, String> {
    let Some(lines) = changed_line_numbers(baseline, current, max_output_bytes)? else {
        return Ok(None);
    };
    let mut ranges = Vec::<(u64, u64)>::new();
    for line in lines {
        match ranges.last_mut() {
            Some((_, end)) if end.saturating_add(1) == line => *end = line,
            _ => ranges.push((line, line)),
        }
    }
    Ok(Some(ranges))
}

#[cfg(test)]
mod changed_line_range_tests {
    use super::changed_line_ranges;

    #[test]
    fn changed_line_ranges_compress_contiguous_added_and_replaced_lines() {
        let baseline = b"one\ntwo\nthree\nfour\n";
        let current = b"one\nTWO\nTHREE\nfour\nfive\n";
        let ranges = changed_line_ranges(Some(baseline), Some(current), 4096).unwrap();
        assert_eq!(ranges, Some(vec![(2, 3), (5, 5)]));
    }

    #[test]
    fn changed_line_ranges_marks_new_files_and_empty_changes() {
        assert_eq!(
            changed_line_ranges(None, Some(b"one\ntwo\n"), 4096).unwrap(),
            Some(vec![(1, 2)])
        );
        assert_eq!(
            changed_line_ranges(Some(b"same\n"), Some(b"same\n"), 4096).unwrap(),
            Some(vec![])
        );
    }
}
