#!/usr/bin/env python3
"""Run a curated historical-defect review benchmark using local Git checkouts.

The runner never fetches repositories or uploads reports. It does not execute
project verification commands unless the operator explicitly selects trusted
profiles with --verify-profile; those commands run locally in disposable
checkouts. --verification-only compares those profiles on pinned buggy/fix
revisions and does not invoke review providers. Configured Vee providers retain
their own network/egress behavior in ordinary review mode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_LABEL_BYTES = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_TRUSTED_FILE_BYTES = 1024 * 1024
MAX_VERIFICATION_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_CASES = 500
OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
EXTENSION_LANGUAGE = {
    ".go": "go",
    ".rs": "rust",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".java": "java",
    ".rb": "ruby",
}


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def ensure_real_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"output path is not a directory: {path}")


def review_input_key(args: argparse.Namespace, case_commit: str, config_bytes: bytes, trusted_files: list[tuple[PurePosixPath, Path]]) -> str:
    """Digest of every input that shapes one case's Vee review, for --resume."""
    executable = shutil.which(args.vee)
    if executable is None:
        raise ValueError(f"Vee executable not found: {args.vee}")
    material = {
        "vee": sha256(Path(executable).read_bytes()),
        "commit": case_commit,
        "config": sha256(config_bytes),
        "trusted_files": sorted((str(target), sha256(source.read_bytes())) for target, source in trusted_files),
        "reviewers": list(args.reviewers),
        "timeout": args.timeout,
    }
    return sha256(json.dumps(material, sort_keys=True).encode())


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        path.unlink()
    elif path.exists() and not path.is_file():
        raise ValueError(f"refusing non-regular output file: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=".vee-write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_trusted_files(values: list[str]) -> list[tuple[PurePosixPath, Path]]:
    """Validate explicit trusted-file overlays for disposable review worktrees."""
    result: list[tuple[PurePosixPath, Path]] = []
    seen: set[PurePosixPath] = set()
    for value in values:
        target_text, separator, source_text = value.partition("=")
        target = PurePosixPath(target_text)
        source_input = Path(source_text).expanduser()
        if not separator or not source_text or target.is_absolute() or not target.parts or any(part in {"", ".", ".."} for part in target.parts):
            raise ValueError("--trusted-file must be TARGET=SOURCE with a safe relative target")
        if target in seen:
            raise ValueError(f"duplicate --trusted-file target: {target}")
        seen.add(target)
        if source_input.is_symlink():
            raise ValueError(f"refusing symlink trusted-file source: {source_input}")
        source = source_input.resolve(strict=True)
        if not source.is_file() or source.stat().st_size > MAX_TRUSTED_FILE_BYTES:
            raise ValueError(f"trusted-file source must be a regular file no larger than 1 MiB: {source}")
        result.append((target, source))
    return result


def install_trusted_files(worktree: Path, files: list[tuple[PurePosixPath, Path]]) -> None:
    """Overlay explicit trusted files without following repository symlinks."""
    for relative, source in files:
        target = worktree.joinpath(*relative.parts)
        parent = worktree
        for part in relative.parts[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise ValueError(f"refusing symlink in trusted-file target: {relative}")
            if parent.exists() and not parent.is_dir():
                raise ValueError(f"trusted-file target parent is not a directory: {relative}")
            parent.mkdir(exist_ok=True)
        if target.is_symlink():
            raise ValueError(f"refusing symlink trusted-file target: {relative}")
        if target.exists() and not target.is_file():
            raise ValueError(f"trusted-file target is not a regular file: {relative}")
        target.write_bytes(source.read_bytes())


def install_trusted_config(worktree: Path, config_bytes: bytes, trusted_files: list[tuple[PurePosixPath, Path]]) -> None:
    """Replace untrusted repository config and apply explicit trusted overlays."""
    config_target = worktree / ".vee.yaml"
    if config_target.is_symlink():
        config_target.unlink()
    elif config_target.exists():
        if not config_target.is_file():
            raise ValueError("checked-out .vee.yaml is not a regular file")
        config_target.unlink()
    descriptor = os.open(config_target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as trusted_config:
        trusted_config.write(config_bytes)
    install_trusted_files(worktree, trusted_files)


def run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("RIPGREP_CONFIG_PATH", None)
    env.pop("GIT_EXTERNAL_DIFF", None)
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True,
                          timeout=timeout, check=False)


def git(repo: Path, *args: str, timeout: int = 60) -> str:
    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    for key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_EXTERNAL_DIFF"):
        env.pop(key, None)
    result = subprocess.run(["git", *args], cwd=repo, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def safe_relative(root: Path, value: str, label: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError(f"{label} must be relative to the corpus root")
    resolved = (root / candidate).resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} escapes the corpus root")
    return resolved


def load_corpus(manifest_path: Path, corpus_root: Path) -> dict[str, Any]:
    raw = manifest_path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds 4 MiB")
    doc = json.loads(raw)
    if not isinstance(doc, dict) or type(doc.get("schema_version")) is not int or doc.get("schema_version") != 1:
        raise ValueError("manifest schema_version must be 1")
    allowed_manifest_keys = {"schema_version", "corpus_id", "source", "source_revision", "license_reference", "cases"}
    if set(doc) - allowed_manifest_keys:
        raise ValueError("manifest contains unknown fields")
    for key in ("source_revision", "license_reference"):
        if key in doc and (not isinstance(doc[key], str) or len(doc[key]) > 2048):
            raise ValueError(f"{key} must be a bounded string")
    if not TOKEN.fullmatch(str(doc.get("corpus_id", ""))):
        raise ValueError("corpus_id must use 1-128 ASCII letters, digits, '.', '_' or '-'")
    if not isinstance(doc.get("source"), str) or not doc["source"].strip():
        raise ValueError("source must identify the dataset/project source")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("cases must contain 1..=500 entries")
    seen: set[str] = set()
    normalized = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each case must be an object")
        if set(case) - {"id", "repository", "commit", "labels", "labels_digest", "category_aliases", "defect_reference", "fix_commit", "fix_reference", "project_license"}:
            raise ValueError("case contains unknown fields")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not TOKEN.fullmatch(case_id) or case_id in seen:
            raise ValueError("case IDs must be unique bounded ASCII tokens")
        seen.add(case_id)
        oid = case.get("commit")
        if not isinstance(oid, str) or not OID.fullmatch(oid):
            raise ValueError(f"{case_id}: commit must be a full lowercase Git object ID")
        if not isinstance(case.get("repository"), str) or not isinstance(case.get("labels"), str):
            raise ValueError(f"{case_id}: repository and labels paths must be strings")
        if not isinstance(case.get("labels_digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", case["labels_digest"]):
            raise ValueError(f"{case_id}: labels_digest must be a SHA-256 digest")
        for key in ("defect_reference", "fix_reference", "project_license"):
            if key in case and (not isinstance(case[key], str) or len(case[key]) > 2048):
                raise ValueError(f"{case_id}: {key} must be a bounded string")
        if "fix_commit" in case and (not isinstance(case["fix_commit"], str) or not OID.fullmatch(case["fix_commit"])):
            raise ValueError(f"{case_id}: fix_commit must be a full lowercase Git object ID")
        repo_path = safe_relative(corpus_root, case["repository"], f"{case_id} repository")
        labels_path = safe_relative(corpus_root, case["labels"], f"{case_id} labels")
        if not repo_path.is_dir() or not (repo_path / ".git").exists():
            raise ValueError(f"{case_id}: repository must be an existing local Git checkout")
        if not labels_path.is_file() or labels_path.stat().st_size > MAX_LABEL_BYTES:
            raise ValueError(f"{case_id}: labels must be a regular file no larger than 16 MiB")
        label_bytes = labels_path.read_bytes()
        expected_digest = case.get("labels_digest")
        if expected_digest != sha256(label_bytes):
            raise ValueError(f"{case_id}: labels_digest does not match labels file")
        labels_doc = json.loads(label_bytes)
        if not isinstance(labels_doc, dict) or type(labels_doc.get("schema_version")) is not int or labels_doc.get("schema_version") != 1 or set(labels_doc) != {"schema_version", "labels"}:
            raise ValueError(f"{case_id}: labels schema_version must be 1 with no unknown fields")
        labels = labels_doc.get("labels")
        if not isinstance(labels, list) or not labels:
            raise ValueError(f"{case_id}: labels file must contain a non-empty labels array")
        label_ids = set()
        for label in labels:
            if not isinstance(label, dict) or set(label) != {"id", "path", "start_line", "end_line", "category", "rationale"} or not isinstance(label.get("id"), str) or not TOKEN.fullmatch(label["id"]):
                raise ValueError(f"{case_id}: each label needs a bounded unique id")
            if label["id"] in label_ids:
                raise ValueError(f"{case_id}: duplicate label id {label['id']}")
            label_ids.add(label["id"])
            path = label.get("path")
            start, end = label.get("start_line"), label.get("end_line")
            if not isinstance(path, str) or not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
                raise ValueError(f"{case_id}/{label['id']}: path must be repository-relative")
            if not isinstance(start, int) or isinstance(start, bool) or start < 1 or not isinstance(end, int) or isinstance(end, bool) or end < start:
                raise ValueError(f"{case_id}/{label['id']}: invalid line range")
            if not isinstance(label.get("category"), str) or not label["category"].strip():
                raise ValueError(f"{case_id}/{label['id']}: category is required")
            if not isinstance(label.get("rationale"), str) or not label["rationale"].strip():
                raise ValueError(f"{case_id}/{label['id']}: curator rationale is required")
        aliases = case.get("category_aliases", {})
        if not isinstance(aliases, dict) or any(not isinstance(k, str) or not k or not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v) for k, v in aliases.items()):
            raise ValueError(f"{case_id}: category_aliases must map strings to string arrays")
        normalized.append((case, repo_path, labels_path, label_bytes, labels, aliases))
    return {"document": doc, "manifest_digest": sha256(raw), "cases": normalized}


def match_findings(labels: list[dict[str, Any]], findings: list[dict[str, Any]], aliases: dict[str, list[str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    remaining = set(range(len(findings)))
    matched = []
    missed = []
    localization_candidates = []
    for label in labels:
        acceptable = {label["category"], *aliases.get(label["category"], [])}
        candidates = []
        for idx in remaining:
            finding = findings[idx]
            if finding.get("path") != label["path"] or not isinstance(finding.get("line"), int):
                continue
            if not label["start_line"] <= finding["line"] <= label["end_line"]:
                continue
            if finding.get("category") not in acceptable:
                continue
            candidates.append(idx)
        if candidates:
            idx = min(candidates, key=lambda i: (str(findings[i].get("fingerprint", "")), i))
            remaining.remove(idx)
            matched.append({"label_id": label["id"], "finding_id": findings[idx].get("id"), "category": findings[idx].get("category"), "path": findings[idx].get("path"), "line": findings[idx].get("line")})
        else:
            missed.append({"label_id": label["id"], "path": label["path"], "start_line": label["start_line"], "end_line": label["end_line"], "category": label["category"]})
    # Keep strict recall tied to the labeled location. Separately surface findings
    # in the same file and category that may have recognized the defect but missed
    # its location. These candidates are diagnostic only and never count as matches.
    candidate_remaining = set(remaining)
    for label in missed:
        acceptable = {label["category"], *aliases.get(label["category"], [])}
        candidates = []
        for idx in candidate_remaining:
            finding = findings[idx]
            if finding.get("path") != label["path"] or finding.get("category") not in acceptable:
                continue
            line = finding.get("line")
            if isinstance(line, int) and not label["start_line"] <= line <= label["end_line"]:
                distance = min(abs(line - label["start_line"]), abs(line - label["end_line"]))
                candidates.append((distance, str(finding.get("fingerprint", "")), idx, "wrong_line"))
            elif line is None:
                candidates.append((2**63 - 1, str(finding.get("fingerprint", "")), idx, "missing_line"))
        if candidates:
            _distance, _fingerprint, idx, candidate_type = min(candidates)
            candidate_remaining.remove(idx)
            finding = findings[idx]
            localization_candidates.append({"label_id": label["label_id"], "finding_id": finding.get("id"), "candidate_type": candidate_type, "path": finding.get("path"), "line": finding.get("line"), "target_start_line": label["start_line"], "target_end_line": label["end_line"], "category": finding.get("category")})
    unmatched = [{"finding_id": findings[i].get("id"), "category": findings[i].get("category"), "path": findings[i].get("path"), "line": findings[i].get("line"), "severity": findings[i].get("severity")} for i in sorted(remaining)]
    return matched, missed, unmatched, localization_candidates


def archive_verification_artifact(worktree: Path, artifact: Any, artifacts: Path,
                                  case_id: str, revision_role: str,
                                  profile_id: str, stream: str) -> dict[str, Any] | None:
    """Retain bounded, digest-verified verification output outside the disposable checkout."""
    if artifact is None:
        return None
    if not isinstance(artifact, dict) or set(artifact) != {"digest", "path", "size_bytes"}:
        raise ValueError(f"{revision_role}/{profile_id}: malformed {stream} artifact reference")
    digest = artifact.get("digest")
    expected_path = f".vee/artifacts/sha256/{digest.removeprefix('sha256:')}" if isinstance(digest, str) else ""
    if (not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or artifact.get("path") != expected_path
            or not isinstance(artifact.get("size_bytes"), int)
            or isinstance(artifact.get("size_bytes"), bool)
            or not 0 <= artifact["size_bytes"] <= MAX_VERIFICATION_ARTIFACT_BYTES):
        raise ValueError(f"{revision_role}/{profile_id}: invalid {stream} artifact metadata")
    source = worktree / ".vee" / "artifacts" / "sha256" / digest.removeprefix("sha256:")
    current = worktree
    for component in (".vee", "artifacts", "sha256", digest.removeprefix("sha256:")):
        current = current / component
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise ValueError(f"{revision_role}/{profile_id}: missing {stream} artifact") from error
        if stat.S_ISLNK(mode) or (current == source and not stat.S_ISREG(mode)):
            raise ValueError(f"{revision_role}/{profile_id}: unsafe {stream} artifact path")
    data = source.read_bytes()
    if len(data) != artifact["size_bytes"] or len(data) > MAX_VERIFICATION_ARTIFACT_BYTES or sha256(data) != digest:
        raise ValueError(f"{revision_role}/{profile_id}: {stream} artifact digest or size mismatch")
    relative = Path("cases") / case_id / "verification" / revision_role / profile_id / f"{stream}-{digest.removeprefix('sha256:')}.bin"
    destination_dir = artifacts / "verification" / revision_role / profile_id
    ensure_real_directory(destination_dir)
    atomic_write(destination_dir / f"{stream}-{digest.removeprefix('sha256:')}.bin", data)
    return {"digest": digest, "size_bytes": len(data), "path": relative.as_posix()}


def verification_overlay_manifest(files: list[tuple[PurePosixPath, Path]]) -> tuple[list[dict[str, Any]], str | None]:
    entries = [
        {"path": relative.as_posix(), "digest": sha256(source.read_bytes()), "size_bytes": source.stat().st_size}
        for relative, source in files
    ]
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return entries, sha256(encoded) if entries else None


def install_verification_files(worktree: Path, files: list[tuple[PurePosixPath, Path]]) -> None:
    """Install explicit test overlays and refuse to replace different committed content."""
    for relative, source in files:
        parent = worktree
        for component in relative.parts[:-1]:
            parent = parent / component
            if parent.is_symlink():
                raise ValueError(f"refusing symlink in verification overlay target: {relative}")
            if parent.exists() and not parent.is_dir():
                raise ValueError(f"verification overlay target parent is not a directory: {relative}")
        target = worktree.joinpath(*relative.parts)
        if target.is_symlink():
            raise ValueError(f"refusing symlink verification overlay target: {relative}")
        if target.exists():
            if not target.is_file():
                raise ValueError(f"verification overlay target is not a regular file: {relative}")
            if target.read_bytes() != source.read_bytes():
                raise ValueError(f"verification overlay conflicts with checked-out content: {relative}")
    install_trusted_files(worktree, files)


def run_verification_profiles(args: argparse.Namespace, worktree: Path, commit_oid: str, expected_snapshot_id: str | None, revision_role: str, artifacts: Path, case_id: str) -> list[dict[str, Any]]:
    """Run only explicitly selected profiles from the trusted config."""
    results = []
    overlay_manifest, overlay_digest = verification_overlay_manifest(args.verification_files)
    for profile_id in args.verify_profiles:
        entry: dict[str, Any] = {
            "profile_id": profile_id,
            "revision_role": revision_role,
            "source_commit": commit_oid,
            "state": "incomplete",
        }
        if overlay_manifest:
            entry["verification_overlay"] = overlay_manifest
            entry["verification_overlay_digest"] = overlay_digest
        started = time.monotonic()
        try:
            if args.verification_files:
                install_verification_files(worktree, args.verification_files)
                scope_args = ["--working-tree"]
            else:
                scope_args = ["--commit", commit_oid]
            completed = run(
                [args.vee, "verify", "--profile", profile_id, *scope_args, "--output", "json"],
                worktree,
                args.verification_timeout,
            )
        except subprocess.TimeoutExpired:
            entry.update({"state": "timeout", "elapsed_seconds": round(time.monotonic() - started, 3)})
            results.append(entry)
            continue
        entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError:
            entry.update({"state": "invalid_output", "exit_code": completed.returncode})
            results.append(entry)
            continue
        if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("profile_id") != profile_id:
            entry.update({"state": "invalid_output", "exit_code": completed.returncode})
            results.append(entry)
            continue
        snapshot_id = report.get("snapshot_id")
        status = report.get("status")
        if report.get("stdout_digest") != (report.get("stdout_artifact") or {}).get("digest"):
            entry.update({"state": "invalid_output", "exit_code": completed.returncode})
            results.append(entry)
            continue
        if report.get("stderr_digest") != (report.get("stderr_artifact") or {}).get("digest"):
            entry.update({"state": "invalid_output", "exit_code": completed.returncode})
            results.append(entry)
            continue
        entry["stdout_artifact"] = archive_verification_artifact(
            worktree, report.get("stdout_artifact"), artifacts, case_id,
            revision_role, profile_id, "stdout",
        )
        entry["stderr_artifact"] = archive_verification_artifact(
            worktree, report.get("stderr_artifact"), artifacts, case_id,
            revision_role, profile_id, "stderr",
        )
        entry.update({
            "run_id": report.get("run_id"),
            "snapshot_id": snapshot_id,
            "status": status,
            "exit_code": completed.returncode,
            "command_digest": report.get("command_digest"),
        })
        if not args.verification_files and expected_snapshot_id is not None and snapshot_id != expected_snapshot_id:
            entry["state"] = "snapshot_mismatch"
        elif status == "passed" and completed.returncode == 0:
            entry["state"] = "passed"
        elif status in {"failed", "timed_out"}:
            entry["state"] = status
        else:
            entry["state"] = "incomplete"
        results.append(entry)
    return results


def compare_verification_profiles(buggy_runs: list[dict[str, Any]], fix_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pair same-profile outcomes without claiming that a test proves a label."""
    fixes_by_profile = {run["profile_id"]: run for run in fix_runs}
    comparisons = []
    for buggy in buggy_runs:
        fixed = fixes_by_profile.get(buggy["profile_id"])
        entry: dict[str, Any] = {
            "profile_id": buggy["profile_id"],
            "buggy_state": buggy["state"],
            "buggy_run_id": buggy.get("run_id"),
            "buggy_command_digest": buggy.get("command_digest"),
            "fix_state": fixed.get("state") if fixed else None,
            "fix_run_id": fixed.get("run_id") if fixed else None,
            "fix_command_digest": fixed.get("command_digest") if fixed else None,
            "same_command": None,
            "same_verification_overlay": None,
            "comparison": "missing_fix_run",
        }
        if fixed is None:
            comparisons.append(entry)
            continue
        buggy_digest = buggy.get("command_digest")
        fix_digest = fixed.get("command_digest")
        buggy_overlay = buggy.get("verification_overlay_digest")
        fix_overlay = fixed.get("verification_overlay_digest")
        if buggy_overlay != fix_overlay:
            entry["same_verification_overlay"] = False
            entry["comparison"] = "verification_overlay_mismatch"
            comparisons.append(entry)
            continue
        entry["same_verification_overlay"] = True
        if not isinstance(buggy_digest, str) or not isinstance(fix_digest, str):
            entry["comparison"] = "incomplete"
        elif buggy_digest != fix_digest:
            entry["same_command"] = False
            entry["comparison"] = "command_mismatch"
        else:
            entry["same_command"] = True
            outcome_pair = (buggy["state"], fixed["state"])
            entry["comparison"] = {
                ("failed", "passed"): "buggy_failed_fix_passed",
                ("passed", "passed"): "passed_both",
                ("failed", "failed"): "failed_both",
                ("passed", "failed"): "buggy_passed_fix_failed",
            }.get(outcome_pair, "incomplete")
        comparisons.append(entry)
    return comparisons


def load_resumable_review(case_artifacts: Path, input_key: str) -> dict[str, Any] | None:
    """A saved review usable for --resume: same inputs, intact review.json."""
    try:
        key = json.loads((case_artifacts / "review-input-key.json").read_text(encoding="utf-8"))
        review_bytes = (case_artifacts / "review.json").read_bytes()
    except (OSError, json.JSONDecodeError):
        return None
    if (not isinstance(key, dict) or key.get("input_key") != input_key
            or key.get("review_json_digest") != sha256(review_bytes)
            or not isinstance(key.get("vee_exit_code"), int)
            or not isinstance(key.get("elapsed_seconds"), (int, float))):
        return None
    return {"stdout": review_bytes.decode("utf-8"), "vee_exit_code": key["vee_exit_code"], "elapsed_seconds": key["elapsed_seconds"]}


def assess_case(args: argparse.Namespace, case: dict[str, Any], repo: Path, label_bytes: bytes, labels: list[dict[str, Any]], aliases: dict[str, list[str]], config_bytes: bytes, trusted_files: list[tuple[PurePosixPath, Path]], artifacts: Path) -> dict[str, Any]:
    case_id, oid = case["id"], case["commit"]
    item: dict[str, Any] = {"case_id": case_id, "repository": case["repository"], "commit": oid, "labels_digest": sha256(label_bytes), "state": "incomplete", "defect_reference": case.get("defect_reference"), "fix_commit": case.get("fix_commit"), "fix_reference": case.get("fix_reference"), "project_license": case.get("project_license")}
    temp_parent = Path(tempfile.mkdtemp(prefix="vee-historical-"))
    worktree = temp_parent / "checkout"
    fix_worktree: Path | None = None
    hook_dir = temp_parent / "empty-hooks"
    hook_dir.mkdir()
    try:
        resolved = git(repo, "rev-parse", "--verify", f"{oid}^{{commit}}")
        if resolved != oid:
            raise ValueError("commit did not resolve to the pinned full object ID")
        ancestry = git(repo, "rev-list", "--parents", "-n", "1", oid).split()
        if case.get("fix_commit") and git(repo, "rev-parse", "--verify", f"{case['fix_commit']}^{{commit}}") != case["fix_commit"]:
            raise ValueError("fix_commit did not resolve to the pinned full object ID")
        if case.get("fix_commit"):
            ancestry_check = run(["git", "merge-base", "--is-ancestor", oid, case["fix_commit"]], repo, 60)
            if ancestry_check.returncode != 0:
                raise ValueError("fix_commit is not a descendant of the defect-introducing commit")
        if len(ancestry) != 2:
            raise ValueError("historical-review cases must be non-merge commits with one parent")
        parent_oid = ancestry[1]
        changed_paths = set(git(repo, "diff-tree", "--first-parent", "--no-commit-id", "--name-only", "-r", oid).splitlines())
        for label in labels:
            if label["path"] not in changed_paths:
                raise ValueError(f"label {label['id']} does not target a file changed by the pinned commit")
            source = git(repo, "show", f"{oid}:{label['path']}")
            if label["end_line"] > len(source.splitlines()):
                raise ValueError(f"label {label['id']} line range exceeds the pinned source file")
        if args.scope_languages:
            case_languages = sorted({EXTENSION_LANGUAGE.get(PurePosixPath(label["path"]).suffix.lower(), "unknown") for label in labels})
            unsupported = sorted(set(case_languages) - set(args.scope_languages))
            if unsupported:
                item.update({"state": "out_of_scope", "languages": case_languages, "unsupported_languages": unsupported, "scope_languages": sorted(set(args.scope_languages))})
                return item
        filter_result = run(["git", "config", "--local", "--name-only", "--get-regexp", r"^filter\..*\.(smudge|process)$"], repo, 60)
        if filter_result.returncode not in (0, 1):
            raise RuntimeError("could not inspect local Git filter settings")
        filter_keys = filter_result.stdout if filter_result.returncode == 0 else ""
        filter_overrides = []
        for key in filter_keys.splitlines():
            filter_overrides.extend(["-c", f"{key}="])
        git(repo, *filter_overrides, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "add", "--detach", str(worktree), oid, timeout=180)
        # Historical source is untrusted. Never follow a committed .vee.yaml symlink.
        install_trusted_config(worktree, config_bytes, trusted_files)
        started = time.monotonic()
        input_key = review_input_key(args, oid, config_bytes, trusted_files)
        saved = load_resumable_review(artifacts / case_id, input_key) if args.resume else None
        try:
            if saved is not None:
                result = subprocess.CompletedProcess([], saved["vee_exit_code"], saved["stdout"], "")
                item["resumed"] = True
            else:
                command = [args.vee, "review", "--commit", oid, "--output", "json"]
                for reviewer in args.reviewers:
                    command.extend(["--reviewer", reviewer])
                result = run(command, worktree, args.timeout)
        except subprocess.TimeoutExpired as error:
            elapsed = round(time.monotonic() - started, 3)
            item.update({"state": "timeout", "error": f"Vee review exceeded {args.timeout}s", "elapsed_seconds": elapsed})
            # Keep any bounded JSON emitted before the timeout for diagnosis.
            # Provider output and stderr are deliberately excluded.
            partial = error.stdout
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            if isinstance(partial, str) and len(partial.encode("utf-8")) <= MAX_LABEL_BYTES:
                try:
                    partial_report = json.loads(partial)
                    if isinstance(partial_report, dict) and partial_report.get("schema_version") == 2:
                        case_artifacts = artifacts / case_id
                        ensure_real_directory(case_artifacts)
                        data = (json.dumps(partial_report, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
                        atomic_write(case_artifacts / "partial-review.json", data)
                        item["partial_review_json_path"] = f"cases/{case_id}/partial-review.json"
                        item["partial_review_json_digest"] = sha256(data)
                except (json.JSONDecodeError, OSError, ValueError):
                    pass
            return item
        item["elapsed_seconds"] = saved["elapsed_seconds"] if saved is not None else round(time.monotonic() - started, 3)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            item["error"] = f"Vee exited with code {result.returncode} without one JSON review document"
            return item
        if (not isinstance(report, dict) or report.get("schema_version") != 2
                or report.get("status") not in {"pass", "block", "incomplete"}
                or not isinstance(report.get("analysis_complete"), bool)
                or not isinstance(report.get("findings"), list)
                or not isinstance(report.get("reviewer_outcomes"), list)
                or not isinstance(report.get("review_id"), str)
                or not isinstance(report.get("snapshot_id"), str)
                or not isinstance(report.get("effective_config_digest"), str)):
            contract_fields = {
                "analysis_complete": isinstance(report.get("analysis_complete"), bool),
                "findings": isinstance(report.get("findings"), list),
                "reviewer_outcomes": isinstance(report.get("reviewer_outcomes"), list),
                "review_id": isinstance(report.get("review_id"), str),
                "snapshot_id": isinstance(report.get("snapshot_id"), str),
                "effective_config_digest": isinstance(report.get("effective_config_digest"), str),
            }
            invalid_fields = [key for key, valid in contract_fields.items() if not valid]
            item["error"] = (
                "Vee output does not satisfy the supported review-output-v2 contract "
                f"(schema_version={report.get('schema_version')!r}, "
                f"status={report.get('status')!r}, "
                f"keys={sorted(report) if isinstance(report, dict) else type(report).__name__!r}, "
                f"error={report.get('error')!r}, "
                f"missing_or_invalid={invalid_fields!r})"
            )
            return item
        # Review commands use 1 for a completed block and 2 for an incomplete
        # review. Preserve their valid structured reports; only unexpected
        # process failures make an otherwise parseable result unusable.
        if result.returncode not in (0, 1, 2):
            item["error"] = f"Vee exited with unexpected code {result.returncode}"
            return item
        for finding in report["findings"]:
            if (not isinstance(finding, dict) or not isinstance(finding.get("id"), str)
                    or not isinstance(finding.get("category"), str)
                    or finding.get("path") is not None and not isinstance(finding.get("path"), str)
                    or finding.get("line") is not None and (not isinstance(finding.get("line"), int) or isinstance(finding.get("line"), bool))):
                item["error"] = "Vee output contains a malformed finding"
                return item
        case_artifacts = artifacts / case_id
        ensure_real_directory(case_artifacts)
        report_bytes = (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
        atomic_write(case_artifacts / "review.json", report_bytes)
        atomic_write(case_artifacts / "review-input-key.json", (json.dumps({"input_key": input_key, "review_json_digest": sha256(report_bytes), "vee_exit_code": result.returncode, "elapsed_seconds": item["elapsed_seconds"]}, sort_keys=True) + "\n").encode())
        outcomes = report.get("reviewer_outcomes", [])
        manifests = report.get("reviewer_context", [])
        completed_reviewers = {
            outcome.get("reviewer_id") for outcome in outcomes
            if isinstance(outcome, dict) and outcome.get("status") in {"completed", "cached"}
        }
        manifests_by_reviewer = {
            manifest.get("reviewer_id"): manifest
            for manifest in manifests
            if isinstance(manifest, dict) and isinstance(manifest.get("reviewer_id"), str)
        } if isinstance(manifests, list) else {}
        label_coverage = []
        for label in labels:
            received_by = []
            for reviewer_id in completed_reviewers:
                manifest = manifests_by_reviewer.get(reviewer_id, {})
                context_files = manifest.get("files", []) if isinstance(manifest, dict) else []
                if any(
                    isinstance(entry, dict)
                    and entry.get("path") == label["path"]
                    and entry.get("status") == "full_source"
                    for entry in context_files
                ):
                    received_by.append(reviewer_id)
            label_coverage.append({"label_id": label["id"], "path": label["path"], "full_source_reviewer_ids": sorted(received_by)})
        item.update({"state": "complete" if report.get("analysis_complete") is True and report.get("status") != "incomplete" else "incomplete", "vee_exit_code": result.returncode, "review_id": report.get("review_id"), "snapshot_id": report.get("snapshot_id"), "effective_config_digest": report.get("effective_config_digest"), "selected_reviewers": report.get("selected_reviewers", []), "reviewer_outcomes": outcomes, "review_json_digest": sha256(report_bytes), "review_json_path": f"cases/{case_id}/review.json", "finding_count": len(report["findings"]), "provider_egress_mode": "declared_in_trusted_config; CLI_adapter_egress_not_independently_verified", "label_context_coverage": label_coverage})
        if args.verify_profiles:
            item["verification_runs"] = run_verification_profiles(args, worktree, oid, report["snapshot_id"], "buggy_commit", case_artifacts, case_id)
            item["verification_profiles_requested"] = list(args.verify_profiles)
            if args.verify_fix and case.get("fix_commit"):
                fix_worktree = temp_parent / "fix-checkout"
                git(repo, *filter_overrides, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "add", "--detach", str(fix_worktree), case["fix_commit"], timeout=180)
                install_trusted_config(fix_worktree, config_bytes, trusted_files)
                item["fix_verification_runs"] = run_verification_profiles(args, fix_worktree, case["fix_commit"], None, "fix_commit", case_artifacts, case_id)
        if not isinstance(manifests, list) or not manifests:
            item["state"] = "incomplete"
            item["incomplete_reason"] = "reviewer_context_manifest_unavailable"
            item["error"] = "Vee output does not include per-reviewer context provenance"
            return item
        uncovered_labels = [entry for entry in label_coverage if not entry["full_source_reviewer_ids"]]
        if uncovered_labels:
            item["state"] = "incomplete"
            item["incomplete_reason"] = "labeled_paths_not_fully_supplied_to_completed_reviewer"
            item["uncovered_labels"] = uncovered_labels
            item["error"] = "one or more labeled paths were not supplied in full to a completed reviewer"
            return item
        matched, missed, unmatched, localization_candidates = match_findings(labels, report["findings"], aliases)
        item.update({"label_count": len(labels), "matched_labels": matched, "missed_labels": missed, "localization_candidates": localization_candidates, "unmatched_findings": unmatched})
        if args.verify_profiles:
            buggy_runs = item.get("verification_runs", [])
            fix_runs = item.get("fix_verification_runs", [])
            item["analysis_evidence_comparison"] = {
                "ai_review": {
                    "matched_label_ids": [entry["label_id"] for entry in matched],
                    "missed_label_ids": [entry["label_id"] for entry in missed],
                },
                "trusted_verification": compare_verification_profiles(buggy_runs, fix_runs),
                "interpretation": "AI label matches and trusted verification outcomes are independent evidence. Verification overlays are explicit, digest-recorded local test inputs and use a working-tree snapshot. Same-command, same-overlay buggy/fix differences are differential signals only; they do not prove that a profile failure was caused by a labeled defect.",
            }
        return item
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        if item.get("state") not in {"out_of_scope", "interrupted"}:
            item["state"] = "incomplete"
            item["incomplete_reason"] = "benchmark_execution_error"
        item["error"] = str(error)
        return item
    finally:
        if worktree.exists():
            try:
                git(repo, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "remove", "--force", str(worktree), timeout=180)
            except (OSError, RuntimeError):
                shutil.rmtree(worktree, ignore_errors=True)
        if fix_worktree is not None and fix_worktree.exists():
            try:
                git(repo, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "remove", "--force", str(fix_worktree), timeout=180)
            except (OSError, RuntimeError):
                shutil.rmtree(fix_worktree, ignore_errors=True)
        shutil.rmtree(temp_parent, ignore_errors=True)


def build_report(corpus: dict[str, Any], config_bytes: bytes, version: str, executable: str, cases: list[dict[str, Any]], report_path: Path, scope_languages: list[str], interrupted: bool = False) -> dict[str, Any]:
    complete = [case for case in cases if case["state"] == "complete"]
    out_of_scope = [case for case in cases if case["state"] == "out_of_scope"]
    total_labels = sum(case.get("label_count", 0) for case in complete)
    matched_labels = sum(len(case.get("matched_labels", [])) for case in complete)
    localization_candidates = sum(len(case.get("localization_candidates", [])) for case in complete)
    return {"schema_version": 1, "benchmark": "historical_review", "corpus_id": corpus["document"]["corpus_id"], "source": corpus["document"]["source"], "source_revision": corpus["document"].get("source_revision"), "license_reference": corpus["document"].get("license_reference"), "manifest_digest": corpus["manifest_digest"], "benchmark_config_digest": sha256(config_bytes), "vee_version": version, "verifier_digest": sha256(Path(executable).read_bytes()), "provider_egress_mode": "declared_in_trusted_config; CLI_adapter_egress_not_independently_verified", "case_count": len(cases), "completed_cases": len(complete), "incomplete_cases": len(cases) - len(complete) - len(out_of_scope), "out_of_scope_cases": len(out_of_scope), "scope_languages": sorted(set(scope_languages)), "label_count_completed_cases": total_labels, "matched_labels": matched_labels, "missed_labels": total_labels - matched_labels, "finding_recall": matched_labels / total_labels if total_labels else None, "labels_with_localization_candidates": localization_candidates, "interrupted": interrupted, "cases": cases, "report_path": str(report_path), "limitations": ["Labels and license references are curator-supplied and are not authenticated by Vee.", "Strict matches require exact repository-relative file and overlapping line range plus category or a curator-defined alias. Same-file/category localization candidates are diagnostic only and do not increase recall.", "The configured provider may use a network; local CLI execution does not imply local inference.", "Completed cases require every labeled path to be supplied in full to at least one completed reviewer, based on Vee's local context manifest.", "Recall is specific to this corpus, Vee/provider versions, reviewer configuration, and matching policy."]}


def assess_verification_case(args: argparse.Namespace, case: dict[str, Any], repo: Path, config_bytes: bytes, trusted_files: list[tuple[PurePosixPath, Path]], artifacts: Path) -> dict[str, Any]:
    item: dict[str, Any] = {"case_id": case["id"], "repository": case["repository"], "buggy_commit": case["commit"], "fix_commit": case.get("fix_commit"), "state": "incomplete"}
    if not case.get("fix_commit"):
        item["error"] = "case has no pinned fix_commit"
        return item
    temp_parent = Path(tempfile.mkdtemp(prefix="vee-historical-verification-"))
    hook_dir = temp_parent / "empty-hooks"
    hook_dir.mkdir()
    outcomes: dict[str, list[dict[str, Any]]] = {}
    try:
        for role, oid in (("buggy_commit", case["commit"]), ("fix_commit", case["fix_commit"])):
            if git(repo, "rev-parse", "--verify", f"{oid}^{{commit}}") != oid:
                raise ValueError(f"{role} did not resolve to its pinned full object ID")
            checkout = temp_parent / role
            filter_result = run(["git", "config", "--local", "--name-only", "--get-regexp", r"^filter\..*\.(smudge|process)$"], repo, 60)
            if filter_result.returncode not in (0, 1):
                raise RuntimeError("could not inspect local Git filter settings")
            overrides = []
            for key in (filter_result.stdout if filter_result.returncode == 0 else "").splitlines():
                overrides.extend(["-c", f"{key}="])
            git(repo, *overrides, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "add", "--detach", str(checkout), oid, timeout=180)
            install_trusted_config(checkout, config_bytes, trusted_files)
            case_artifacts = artifacts / case["id"]
            ensure_real_directory(case_artifacts)
            outcomes[role] = run_verification_profiles(args, checkout, oid, None, role, case_artifacts, case["id"])
        comparisons = compare_verification_profiles(outcomes["buggy_commit"], outcomes["fix_commit"])
        complete = all(c["comparison"] in {"buggy_failed_fix_passed", "passed_both", "failed_both", "buggy_passed_fix_failed"} for c in comparisons) and len(comparisons) == len(args.verify_profiles)
        item.update({"state": "complete" if complete else "incomplete", "buggy_runs": outcomes["buggy_commit"], "fix_runs": outcomes["fix_commit"], "comparisons": comparisons})
        return item
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        item["error"] = str(error)
        return item
    finally:
        for role in ("buggy_commit", "fix_commit"):
            checkout = temp_parent / role
            if checkout.exists():
                try:
                    git(repo, "-c", f"core.hooksPath={hook_dir}", "-c", "core.fsmonitor=false", "worktree", "remove", "--force", str(checkout), timeout=180)
                except (OSError, RuntimeError):
                    shutil.rmtree(checkout, ignore_errors=True)
        shutil.rmtree(temp_parent, ignore_errors=True)


def build_verification_report(corpus: dict[str, Any], config_bytes: bytes, version: str, executable: str, cases: list[dict[str, Any]], report_path: Path) -> dict[str, Any]:
    completed = sum(case["state"] == "complete" for case in cases)
    return {"schema_version": 1, "benchmark": "historical_verification", "corpus_id": corpus["document"]["corpus_id"], "manifest_digest": corpus["manifest_digest"], "benchmark_config_digest": sha256(config_bytes), "vee_version": version, "verifier_digest": sha256(Path(executable).read_bytes()), "case_count": len(cases), "completed_cases": completed, "incomplete_cases": len(cases) - completed, "cases": cases, "report_path": str(report_path), "limitations": ["This report records trusted local verification outcomes only; it contains no AI review findings, recall, or quality claim.", "A matching failed-on-buggy/passed-on-fix result is evidence for that configured check, not proof of defect causality or program correctness.", "Selected verification profiles are explicit operator-authorized local commands; Vee does not independently provide OS-level isolation."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True, help="all repository and label paths must resolve beneath this directory")
    parser.add_argument("--vee", default="vee", help="Vee executable")
    parser.add_argument("--config", type=Path, required=True, help="trusted Vee repository configuration copied into each temporary worktree")
    parser.add_argument("--trusted-file", action="append", default=[], metavar="TARGET=SOURCE", help="overlay a trusted local file at a relative path in each disposable worktree; repeatable")
    parser.add_argument("--verification-file", dest="verification_files", action="append", default=[], metavar="TARGET=SOURCE", help="overlay a trusted local test/fixture only for explicitly selected verification profiles; repeatable")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reviewer", dest="reviewers", action="append", default=[], help="select a configured reviewer; repeatable (defaults to repository configuration)")
    parser.add_argument("--scope-language", dest="scope_languages", action="append", default=[], choices=sorted(set(EXTENSION_LANGUAGE.values())), help="declare a language supported by the trusted review configuration; repeatable; labeled cases in other languages are reported out of scope")
    parser.add_argument("--verify-profile", dest="verify_profiles", action="append", default=[], help="explicitly execute a named trusted local verification profile on the exact reviewed commit in a disposable checkout; repeatable")
    parser.add_argument("--verify-fix", action="store_true", help="also execute selected local profiles on each case's pinned fix commit in a disposable checkout")
    parser.add_argument("--verification-only", action="store_true", help="compare selected trusted local verification profiles on each pinned buggy/fix commit without invoking review providers")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--resume", action="store_true", help="reuse a case's saved review when the Vee binary, commit, trusted config and files, reviewers, and timeout are unchanged")
    parser.add_argument("--verification-timeout", type=int, default=900, help="maximum seconds per explicitly selected verification profile")
    args = parser.parse_args()
    if args.timeout < 1 or args.verification_timeout < 1:
        parser.error("timeouts must be positive")
    if any(not TOKEN.fullmatch(profile) for profile in args.verify_profiles):
        parser.error("--verify-profile values must use 1-128 ASCII letters, digits, '.', '_' or '-'")
    if args.verify_fix and not args.verify_profiles:
        parser.error("--verify-fix requires at least one --verify-profile")
    if args.verification_files and not args.verify_profiles:
        parser.error("--verification-file requires at least one --verify-profile")
    if args.verification_only and not args.verify_profiles:
        parser.error("--verification-only requires at least one --verify-profile")
    if args.verification_only and (args.verify_fix or args.scope_languages or args.reviewers or args.trusted_file):
        parser.error("--verification-only cannot be combined with --verify-fix, review scope/reviewer options, or --trusted-file")
    try:
        root = args.corpus_root.resolve(strict=True)
        manifest_path = args.manifest.resolve(strict=True)
        if not manifest_path.is_relative_to(root):
            raise ValueError("manifest must be beneath corpus root")
        args.vee = str(Path(shutil.which(args.vee) or args.vee).resolve(strict=True))
        version = run([args.vee, "--version"], Path.cwd(), 30)
        if version.returncode:
            raise RuntimeError("could not read Vee version")
        corpus = load_corpus(manifest_path, root)
        config_path = args.config.resolve(strict=True)
        if not config_path.is_file() or config_path.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError("trusted --config must be a regular file no larger than 1 MiB")
        config_bytes = config_path.read_bytes()
        trusted_files = parse_trusted_files(args.trusted_file)
        args.verification_files = parse_trusted_files(args.verification_files)
        trusted_targets = {relative for relative, _ in trusted_files}
        verification_targets = {relative for relative, _ in args.verification_files}
        if trusted_targets & verification_targets:
            raise ValueError("--trusted-file and --verification-file targets must be distinct")
        output = args.output_dir.resolve()
        if any(output == repo or output.is_relative_to(repo) for _, repo, *_ in corpus["cases"]):
            raise ValueError("output directory must be outside every benchmark repository")
        ensure_real_directory(output)
        artifacts = output / "cases"
        ensure_real_directory(artifacts)
        report_path = output / "historical-review-report-v1.json"
        if args.verification_only:
            report_path = output / "historical-verification-report-v1.json"
            cases = []
            for case, repo, _labels_path, _label_bytes, _labels, _aliases in corpus["cases"]:
                cases.append(assess_verification_case(args, case, repo, config_bytes, [], artifacts))
            report = build_verification_report(corpus, config_bytes, version.stdout.strip(), args.vee, cases, report_path)
            atomic_write(report_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            print(json.dumps({k: report[k] for k in ("benchmark", "corpus_id", "case_count", "completed_cases", "incomplete_cases", "report_path")}, indent=2))
            return 0 if report["incomplete_cases"] == 0 else 2
        cases = []
        try:
            for case, repo, _labels_path, label_bytes, labels, aliases in corpus["cases"]:
                cases.append(assess_case(args, case, repo, label_bytes, labels, aliases, config_bytes, trusted_files, artifacts))
        except KeyboardInterrupt:
            cases.append({"case_id": case["id"], "repository": case["repository"], "commit": case["commit"], "state": "interrupted", "error": "Benchmark interrupted by operator"})
            report = build_report(corpus, config_bytes, version.stdout.strip(), args.vee, cases, report_path, args.scope_languages, interrupted=True)
            atomic_write(report_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            print(f"historical-review-benchmark: interrupted; partial report saved to {report_path}", file=sys.stderr)
            return 130
        report = build_report(corpus, config_bytes, version.stdout.strip(), args.vee, cases, report_path, args.scope_languages)
        atomic_write(report_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        print(json.dumps({k: report[k] for k in ("benchmark", "corpus_id", "case_count", "completed_cases", "incomplete_cases", "out_of_scope_cases", "label_count_completed_cases", "matched_labels", "missed_labels", "finding_recall", "labels_with_localization_candidates", "interrupted", "report_path")}, indent=2))
        return 0 if not report["incomplete_cases"] and not report["out_of_scope_cases"] else 2
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"historical-review-benchmark: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
