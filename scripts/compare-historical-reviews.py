#!/usr/bin/env python3
"""Compare local historical-review reports without combining unlike cases.

The comparator reads saved JSON only. It never opens repositories, labels, or
provider endpoints, and emits per-case results rather than a pooled score.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 64 * 1024 * 1024
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def read_report(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink():
        raise ValueError(f"refusing symlink report: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"report must be a regular file no larger than 64 MiB: {path}")
    raw = resolved.read_bytes()
    report = json.loads(raw)
    required = {
        "schema_version", "benchmark", "corpus_id", "manifest_digest",
        "benchmark_config_digest", "vee_version", "verifier_digest",
        "cases", "finding_recall", "completed_cases", "incomplete_cases",
        "out_of_scope_cases",
    }
    if not isinstance(report, dict) or not required.issubset(report):
        raise ValueError(f"not a supported historical-review report: {path}")
    if report["schema_version"] != 1 or report["benchmark"] != "historical_review":
        raise ValueError(f"unsupported report version: {path}")
    for key in ("manifest_digest", "benchmark_config_digest", "verifier_digest"):
        if not isinstance(report[key], str) or not DIGEST.fullmatch(report[key]):
            raise ValueError(f"{path}: invalid {key}")
    if not isinstance(report["cases"], list):
        raise ValueError(f"{path}: cases must be an array")
    for key in ("completed_cases", "incomplete_cases", "out_of_scope_cases"):
        if not isinstance(report[key], int) or isinstance(report[key], bool) or report[key] < 0:
            raise ValueError(f"{path}: {key} must be a non-negative integer")
    if report["finding_recall"] is not None and (
        not isinstance(report["finding_recall"], (int, float))
        or isinstance(report["finding_recall"], bool)
        or not 0 <= report["finding_recall"] <= 1
    ):
        raise ValueError(f"{path}: finding_recall must be null or between 0 and 1")
    seen: set[str] = set()
    for case in report["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str) or case.get("state") not in {
            "complete", "incomplete", "out_of_scope", "timeout", "interrupted",
        }:
            raise ValueError(f"{path}: malformed case record")
        if case["case_id"] in seen:
            raise ValueError(f"{path}: duplicate case_id {case['case_id']}")
        seen.add(case["case_id"])
        if case.get("state") == "complete":
            for key in ("label_count", "matched_labels", "missed_labels", "unmatched_findings", "localization_candidates", "reviewer_outcomes"):
                if key not in case:
                    raise ValueError(f"{path}/{case['case_id']}: missing {key}")
            if not isinstance(case["matched_labels"], list) or not isinstance(case["missed_labels"], list):
                raise ValueError(f"{path}/{case['case_id']}: matched/missed labels must be arrays")
            if not isinstance(case["label_count"], int) or isinstance(case["label_count"], bool) or case["label_count"] < 1:
                raise ValueError(f"{path}/{case['case_id']}: label_count must be positive")
            label_ids = [
                item.get("label_id")
                for key in ("matched_labels", "missed_labels")
                for item in case[key]
                if isinstance(item, dict)
            ]
            if len(label_ids) != len(case["matched_labels"]) + len(case["missed_labels"]) or any(not isinstance(value, str) for value in label_ids):
                raise ValueError(f"{path}/{case['case_id']}: malformed label identity")
            if len(label_ids) != case["label_count"] or len(set(label_ids)) != len(label_ids):
                raise ValueError(f"{path}/{case['case_id']}: label identities do not match label_count")
    return report, "sha256:" + hashlib.sha256(raw).hexdigest()


def identity(report: dict[str, Any]) -> dict[str, Any]:
    outcomes = [
        outcome for case in report["cases"]
        for outcome in case.get("reviewer_outcomes", [])
        if isinstance(outcome, dict)
    ]
    providers = sorted({
        "/".join(str(outcome.get(key) or "unknown") for key in ("provider_kind", "provider_id", "model"))
        for outcome in outcomes
    })
    reviewers = sorted({str(outcome.get("reviewer_id")) for outcome in outcomes if outcome.get("reviewer_id")})
    return {
        "corpus_id": report["corpus_id"],
        "manifest_digest": report["manifest_digest"],
        "config_digest": report["benchmark_config_digest"],
        "providers_models": providers,
        "reviewers": reviewers,
        "vee_version": report["vee_version"],
        "verifier_digest": report["verifier_digest"],
    }


def case_summary(case: dict[str, Any]) -> dict[str, Any]:
    outcomes = case.get("reviewer_outcomes", [])
    return {
        "state": case["state"],
        "commit": case.get("commit"),
        "labels_digest": case.get("labels_digest"),
        "defect_reference": case.get("defect_reference"),
        "label_count": case.get("label_count"),
        "label_ids": sorted(
            str(item["label_id"])
            for key in ("matched_labels", "missed_labels")
            for item in case.get(key, [])
            if isinstance(item, dict) and isinstance(item.get("label_id"), str)
        ),
        "matched_labels": len(case.get("matched_labels", [])),
        "missed_labels": len(case.get("missed_labels", [])),
        "finding_count": case.get("finding_count"),
        "unmatched_findings": len(case.get("unmatched_findings", [])),
        "localization_candidates": len(case.get("localization_candidates", [])),
        "reviewers": sorted({str(o.get("reviewer_id")) for o in outcomes if o.get("reviewer_id")}),
        "provider_models": sorted({
            "/".join(str(o.get(key) or "unknown") for key in ("provider_kind", "provider_id", "model"))
            for o in outcomes
        }),
        "effective_config_digest": case.get("effective_config_digest"),
        "snapshot_id": case.get("snapshot_id"),
    }


def compare(reports: list[tuple[Path, dict[str, Any], str]]) -> dict[str, Any]:
    shared_ids = set.intersection(*[
        {c["case_id"] for c in report["cases"]}
        for _, report, _ in reports
    ]) if reports else set()
    cases = []
    for case_id in sorted(shared_ids):
        entries = []
        for path, report, digest in reports:
            record = next(c for c in report["cases"] if c["case_id"] == case_id)
            entries.append({"report_digest": digest, "report_path": str(path), **case_summary(record)})
        comparable = all(entry["state"] == "complete" for entry in entries)
        same_labels = len({(entry.get("label_count"), tuple(entry.get("label_ids", [])), entry.get("labels_digest")) for entry in entries}) == 1
        same_snapshot = len({entry.get("commit") for entry in entries}) == 1
        same_corpus = len({report["manifest_digest"] for _, report, _ in reports}) == 1
        is_comparable = comparable and same_labels and same_snapshot and same_corpus
        if is_comparable:
            note = None
        elif not comparable:
            note = "incomplete_or_out_of_scope"
        elif not same_corpus:
            note = "corpus_manifest_differs"
        elif not same_snapshot:
            note = "case_commit_differs"
        elif not same_labels:
            note = "label_identity_differs"
        else:
            note = "incomparable"
        cases.append({"case_id": case_id, "comparable": is_comparable,
                      "comparison_note": note,
                      "runs": entries})
    return {
        "schema_version": 1,
        "comparison": "historical_review_runs",
        "local_only": True,
        "reports": [
            {"path": str(path), "report_digest": digest,
             "identity": identity(report), "completed_cases": report["completed_cases"],
             "incomplete_cases": report["incomplete_cases"],
             "out_of_scope_cases": report["out_of_scope_cases"],
             "finding_recall": report["finding_recall"]}
            for path, report, digest in reports
        ],
        "shared_case_count": len(shared_ids),
        "cases": cases,
        "limitations": [
            "Only case IDs present in every input report are compared.",
            "Every run must be complete and use the same corpus manifest, pinned commit, and label identities; otherwise the case is shown but marked incomparable.",
            "The comparator trusts the saved reports and does not authenticate labels, source licenses, provider identity, or local egress.",
            "Finding recall is reported per run and is not a pooled or calibrated quality score.",
        ],
    }


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".vee-compare-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="saved historical-review-report-v1.json files")
    parser.add_argument("--output", type=Path, help="write the comparison JSON locally; stdout is used by default")
    args = parser.parse_args()
    if len(args.reports) < 2:
        parser.error("provide at least two report files")
    try:
        loaded = [(path.resolve(strict=True), *read_report(path)) for path in args.reports]
        if args.output and args.output.resolve() in {path for path, _, _ in loaded}:
            raise ValueError("output must not replace an input report")
        result = compare(loaded)
        data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        if args.output:
            atomic_write(args.output, data)
        else:
            sys.stdout.buffer.write(data)
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(f"compare-historical-reviews: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
