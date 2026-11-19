#!/usr/bin/env python3
"""Synthetic acceptance for local historical-review report comparison."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile


def report(case_id: str, *, state: str = "complete", model: str = "local-model", matched: int = 1,
           label_id: str = "defect", commit: str = "f" * 40) -> dict:
    case = {
        "case_id": case_id,
        "state": state,
        "reviewer_outcomes": [{
            "reviewer_id": "correctness", "provider_kind": "ollama_native",
            "provider_id": "local", "model": model,
        }],
    }
    if state == "complete":
        case.update({
            "label_count": 1,
            "matched_labels": [{"label_id": label_id}] if matched else [],
            "missed_labels": [] if matched else [{"label_id": label_id}],
            "unmatched_findings": [], "localization_candidates": [],
            "finding_count": matched, "effective_config_digest": "sha256:" + "c" * 64,
            "snapshot_id": "sha256:" + "d" * 64,
            "commit": commit, "labels_digest": "sha256:" + "9" * 64,
        })
    return {
        "schema_version": 1, "benchmark": "historical_review", "corpus_id": "private-corpus",
        "manifest_digest": "sha256:" + "a" * 64,
        "benchmark_config_digest": "sha256:" + "b" * 64,
        "vero_version": "vero 0.1.0", "verifier_digest": "sha256:" + "e" * 64,
        "completed_cases": int(state == "complete"), "incomplete_cases": int(state != "complete"),
        "out_of_scope_cases": 0, "finding_recall": float(matched) if state == "complete" else None,
        "cases": [case],
    }


def main() -> int:
    script = pathlib.Path(__file__).resolve().parents[1] / "compare-historical-reviews.py"
    with tempfile.TemporaryDirectory(prefix="vero-compare-acceptance-") as temporary:
        root = pathlib.Path(temporary)
        first, second, third = root / "first.json", root / "second.json", root / "third.json"
        first.write_text(json.dumps(report("same", model="model-a")), encoding="utf-8")
        second.write_text(json.dumps(report("same", model="model-b", matched=0)), encoding="utf-8")
        third.write_text(json.dumps(report("same", state="incomplete", model="model-c")), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(first), str(second)], text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        comparison = json.loads(result.stdout)
        assert comparison["shared_case_count"] == 1
        assert comparison["cases"][0]["comparable"] is True
        assert [r["provider_models"][0] for r in comparison["cases"][0]["runs"]] == [
            "ollama_native/local/model-a", "ollama_native/local/model-b",
        ]
        assert comparison["reports"][0]["identity"]["manifest_digest"] == comparison["reports"][1]["identity"]["manifest_digest"]
        assert "pooled" in comparison["limitations"][-1]

        incomplete = subprocess.run([sys.executable, str(script), str(first), str(third)], text=True, capture_output=True)
        assert incomplete.returncode == 0, incomplete.stderr
        assert json.loads(incomplete.stdout)["cases"][0]["comparable"] is False

        unrelated = root / "unrelated.json"
        unrelated.write_text(json.dumps(report("different")), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(first), str(unrelated)], text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["shared_case_count"] == 0

        changed_labels = root / "changed-labels.json"
        changed_labels.write_text(json.dumps(report("same", label_id="different")), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(first), str(changed_labels)], text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        compared = json.loads(result.stdout)["cases"][0]
        assert compared["comparable"] is False and compared["comparison_note"] == "label_identity_differs"

        changed_commit = root / "changed-commit.json"
        changed_commit.write_text(json.dumps(report("same", commit="1" * 40)), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(first), str(changed_commit)], text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        compared = json.loads(result.stdout)["cases"][0]
        assert compared["comparable"] is False and compared["comparison_note"] == "case_commit_differs"

        link = root / "symlink.json"
        try:
            link.symlink_to(first)
        except (NotImplementedError, OSError):
            pass
        else:
            result = subprocess.run([sys.executable, str(script), str(link), str(second)], text=True, capture_output=True)
            assert result.returncode == 2 and "symlink" in result.stderr

        malformed = root / "malformed.json"
        invalid = report("same")
        invalid["cases"][0]["label_count"] = 4
        malformed.write_text(json.dumps(invalid), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(malformed), str(second)], text=True, capture_output=True)
        assert result.returncode == 2 and "label identities" in result.stderr

        result = subprocess.run([sys.executable, str(script), str(first), str(second), "--output", str(first)], text=True, capture_output=True)
        assert result.returncode == 2 and "must not replace" in result.stderr
    print("local historical-review comparison acceptance passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
