#!/usr/bin/env python3
"""Prepare local, untrusted location candidates for a historical review case.

This helper never creates accepted labels. A curator must verify every candidate
against the buggy source, fix, and independent defect evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def git_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return env


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, env=git_environment(), text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def verify_oid(repo: Path, value: str, label: str) -> str:
    if not OID.fullmatch(value):
        raise ValueError(f"{label} must be a full lowercase Git object ID")
    resolved = git(repo, "rev-parse", "--verify", f"{value}^{{commit}}").strip()
    if resolved != value:
        raise ValueError(f"{label} must resolve to its full object ID")
    return value


def line_ranges(diff: str) -> list[tuple[int, int]]:
    ranges = []
    for match in HUNK.finditer(diff):
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count:
            ranges.append((start, start + count - 1))
    return merge_ranges(ranges)


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def intersect(left: list[tuple[int, int]], right: list[tuple[int, int]]) -> list[tuple[int, int]]:
    overlaps = []
    for left_start, left_end in left:
        for right_start, right_end in right:
            start, end = max(left_start, right_start), min(left_end, right_end)
            if start <= end:
                overlaps.append((start, end))
    return merge_ranges(overlaps)


def safe_output_path(repo: Path, output: Path) -> Path:
    repo_root = Path(git(repo, "rev-parse", "--show-toplevel").strip()).resolve(strict=True)
    requested = output.expanduser().absolute()
    if requested.is_symlink():
        raise ValueError("candidate output must not be a symlink")
    target = requested.parent.resolve() / requested.name
    if target == repo_root or target.is_relative_to(repo_root):
        raise ValueError("candidate output must be outside the subject repository")
    if target.exists() and not target.is_file():
        raise ValueError("candidate output must be a regular file")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def prepare(args: argparse.Namespace) -> dict:
    repo = args.repository.expanduser().resolve(strict=True)
    if not repo.is_dir() or not (repo / ".git").exists():
        raise ValueError("repository must be an existing local Git checkout")
    root = Path(git(repo, "rev-parse", "--show-toplevel").strip()).resolve(strict=True)
    commit = verify_oid(root, args.commit, "--commit")
    parents = git(root, "rev-list", "--parents", "-n", "1", commit).split()
    if len(parents) != 2:
        raise ValueError("buggy commit must have exactly one parent")
    parent = parents[1]
    fix = verify_oid(root, args.fix_commit, "--fix-commit") if args.fix_commit else None
    if fix:
        result = subprocess.run(["git", "merge-base", "--is-ancestor", commit, fix], cwd=root,
                                env=git_environment(), text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError("--fix-commit must be a descendant of --commit")

    raw_paths = git(root, "diff", "--name-only", "-z", parent, commit)
    try:
        paths = sorted(set(path for path in raw_paths.split("\0") if path))
        for path in paths:
            path.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ValueError("changed paths must be UTF-8 to write a JSON curation worksheet") from error

    changed_files = []
    candidates = []
    for path in paths:
        intro_diff = git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", parent, commit, "--", path)
        introduced = line_ranges(intro_diff)
        fix_touched: list[tuple[int, int]] = []
        if fix:
            # Reverse the fix diff so its new-side coordinates refer to buggy source.
            fix_diff = git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", fix, commit, "--", path)
            fix_touched = line_ranges(fix_diff)
        overlaps = intersect(introduced, fix_touched)
        changed_files.append({
            "path": path,
            "buggy_commit_changed_ranges": [{"start_line": start, "end_line": end} for start, end in introduced],
            "fix_touched_buggy_ranges": [{"start_line": start, "end_line": end} for start, end in fix_touched],
            "candidate_overlap_ranges": [{"start_line": start, "end_line": end} for start, end in overlaps],
            "line_ranges_available": bool(introduced),
        })
        for index, (start, end) in enumerate(overlaps, 1):
            seed = f"{commit}\0{path}\0{start}\0{end}".encode()
            candidates.append({
                "candidate_id": "candidate-" + hashlib.sha256(seed).hexdigest()[:12],
                "path": path,
                "start_line": start,
                "end_line": end,
                "category": None,
                "rationale": None,
                "source": "overlap_between_buggy_change_and_fix_diff",
                "review_required": True,
            })

    return {
        "schema_version": 1,
        "artifact": "historical_review_curation_candidates",
        "candidate_only": True,
        "case_id": args.case_id,
        "project": args.project,
        "project_license_reference": args.project_license,
        "defect_reference": args.defect_reference,
        "repository_name": root.name,
        "buggy_commit": commit,
        "buggy_parent_commit": parent,
        "fix_commit": fix,
        "changed_files": changed_files,
        "candidate_locations": candidates,
        "curation_requirements": [
            "Candidates are derived only from textual diff overlap and are not defect ground truth.",
            "Inspect buggy source, fix, issue context, and reproduction evidence before writing labels.",
            "Assign a category and rationale independently; omit candidates that are not defensible.",
            "Convert only curator-approved labels to historical-review-labels-v1 and hash the final bytes.",
        ],
        "limitations": [
            "Binary files, deleted-line locations, renames, and fix edits outside the introduced diff may need manual analysis.",
            "A fix can touch unrelated code or only indirectly address the defect; overlap does not prove causality.",
            "No project build, test, network, or model command is run by this helper.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="existing local Git checkout")
    parser.add_argument("--commit", required=True, help="full buggy commit object ID")
    parser.add_argument("--fix-commit", help="optional full descendant fix commit object ID")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--project", required=True, help="human-readable upstream project identifier")
    parser.add_argument("--project-license", help="curator-supplied subject project license reference")
    parser.add_argument("--defect-reference", help="optional issue or dataset bug identifier")
    parser.add_argument("--output", type=Path, required=True, help="JSON worksheet path outside the subject checkout")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.case_id):
        print("prepare-historical-review-case: invalid --case-id", file=sys.stderr)
        return 2
    try:
        output = safe_output_path(args.repository.expanduser().resolve(strict=True), args.output)
        report = prepare(args)
        data = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".vero-candidate-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
        print(json.dumps({"artifact": report["artifact"], "candidate_only": True,
                          "candidate_count": len(report["candidate_locations"]), "output": str(output)}))
        return 0
    except Exception as error:  # noqa: BLE001 - CLI boundary emits a concise diagnostic.
        print(f"prepare-historical-review-case: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
