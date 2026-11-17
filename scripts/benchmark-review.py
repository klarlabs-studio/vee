#!/usr/bin/env python3
"""Measure local Vero review overhead with a deterministic no-network provider.

This is a plumbing baseline, not an AI quality or provider-cost benchmark. It
creates an isolated Git repository, varies one working-tree snapshot per run,
and reports whole-process latency for configurable repository/change sizes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


PROVIDER_SOURCE = """import json, sys
json.load(sys.stdin)
print(json.dumps({"schema_version": 1, "findings": []}))
"""


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("RIPGREP_CONFIG_PATH", None)
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


def git(repo: Path, *args: str) -> None:
    result = run(["git", *args], repo)
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")


def rust_source(file_index: int, lines: int, revision: int) -> str:
    body = [f"// file {file_index}, revision {revision}"]
    body.extend(
        f"pub fn item_{file_index}_{line}() -> usize {{ {file_index + line + revision} }}"
        for line in range(max(1, lines - 1))
    )
    return "\n".join(body) + "\n"


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * pct) - 1))
    return ordered[index]


def benchmark_case(args: argparse.Namespace, repo_files: int, changed_files: int) -> dict[str, Any]:
    if changed_files > repo_files:
        raise ValueError("--changed-files must be less than or equal to --repo-files")

    with tempfile.TemporaryDirectory(prefix="vero-bench-") as temporary:
        repo = Path(temporary)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "vero-benchmark@example.invalid")
        git(repo, "config", "user.name", "Vero benchmark")

        provider = repo / "fake-provider.py"
        provider.write_text(PROVIDER_SOURCE, encoding="utf-8")
        (repo / "reviewer.md").write_text(
            "Return no findings for this benchmark fixture.\n", encoding="utf-8"
        )
        (repo / ".vero.yaml").write_text(
            "version: 1\n"
            "review:\n  include: [\"**/*.rs\"]\n"
            "  max_context_files: 512\n"
            "  max_context_file_bytes: 4194304\n"
            "  max_context_bytes: 16777216\n"
            "providers:\n  baseline:\n"
            "    kind: cli\n"
            f"    executable: {json.dumps(sys.executable)}\n"
            f"    args: [{json.dumps(str(provider))}]\n"
            "reviewers:\n  correctness:\n"
            "    provider: baseline\n"
            "    instructions_file: reviewer.md\n"
            "policy:\n"
            "  required_reviewers: [correctness]\n"
            "  block_severities: [critical, high]\n"
            "  minimum_confidence: 80\n"
            "  on_incomplete: block\n",
            encoding="utf-8",
        )

        paths = [repo / "src" / f"module_{index:05}.rs" for index in range(repo_files)]
        for index, path in enumerate(paths):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rust_source(index, args.lines_per_file, 0), encoding="utf-8")

        git(repo, "add", ".")
        git(repo, "commit", "-qm", "benchmark baseline")

        durations: list[float] = []
        observed_changed_files: int | None = None
        observed_lines: int | None = None
        total_runs = args.warmups + args.iterations
        for iteration in range(1, total_runs + 1):
            for file_index, path in enumerate(paths[:changed_files]):
                path.write_text(
                    rust_source(file_index, args.lines_per_file, iteration), encoding="utf-8"
                )

            started = time.perf_counter()
            result = run(
                [args.vero, "review", "--base", "HEAD", "--output", "json"], repo
            )
            elapsed = time.perf_counter() - started
            if result.returncode != 0:
                raise RuntimeError(
                    f"vero review failed with exit {result.returncode}: "
                    f"{result.stderr.strip()}\n{result.stdout.strip()}"
                )
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError("vero did not emit one JSON review document") from error
            if report.get("status") not in {"pass", "block"}:
                raise RuntimeError(f"benchmark review was not complete: {report.get('status')}")
            if observed_changed_files is None:
                observed_changed_files = len(report["change_set"]["files"])
                observed_lines = sum(
                    len(rust_source(index, args.lines_per_file, iteration).splitlines())
                    for index in range(changed_files)
                )
            if iteration > args.warmups:
                durations.append(elapsed)

    return {
        "repository": {
            "tracked_files": repo_files + 3,
            "changed_files_requested": changed_files,
            "changed_files_observed": observed_changed_files,
            "changed_lines_estimated": observed_lines,
            "lines_per_changed_file": args.lines_per_file,
        },
        "runs": {
            "warmups": args.warmups,
            "measured": len(durations),
            "latency_seconds": {
                "min": min(durations),
                "median": statistics.median(durations),
                "p95_nearest_rank": percentile(durations, 0.95),
                "max": max(durations),
                "samples": durations,
            },
        },
    }


def benchmark(args: argparse.Namespace) -> dict[str, Any]:
    cases = args.matrix or [(args.repo_files, args.changed_files)]
    stratified = {
        f"{repo_files}_repo_files_{changed_files}_changed": benchmark_case(
            args, repo_files, changed_files
        )
        for repo_files, changed_files in cases
    }
    binary = Path(args.vero)
    version = subprocess.run(
        [args.vero, "--version"], text=True, capture_output=True, check=False
    )
    if version.returncode:
        raise RuntimeError(f"could not read Vero version: {version.stderr.strip()}")
    return {
        "schema_version": 1,
        "benchmark": "local_review_plumbing",
        "provider_mode": "deterministic_local_fake_no_network",
        "vero": {
            "version": version.stdout.strip(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "environment": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "rustc": subprocess.run(
                ["rustc", "--version"], text=True, capture_output=True, check=False
            ).stdout.strip(),
        },
        "strata": stratified,
        "matrix": [
            {"repo_files": repo_files, "changed_files": changed_files}
            for repo_files, changed_files in cases
        ],
        "limitations": [
            "Measures local CLI, Git, storage, and fake-provider process overhead only.",
            "Does not measure AI quality, network latency, token use, or provider cost.",
            "Compare results only on equivalent hardware and tool versions.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vero", default="target/debug/vero", help="path to the Vero binary")
    parser.add_argument("--repo-files", type=int, default=100)
    parser.add_argument("--changed-files", type=int, default=5)
    parser.add_argument("--lines-per-file", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument(
        "--matrix",
        action="append",
        metavar="REPO_FILES:CHANGED_FILES",
        help="run a size stratum; repeatable (defaults to 100:5, 1000:25, 5000:100)",
    )
    parser.add_argument("--output", type=Path, help="write JSON to a file instead of stdout")
    args = parser.parse_args()
    if args.matrix:
        try:
            args.matrix = [tuple(map(int, item.split(":"))) for item in args.matrix]
            if any(len(case) != 2 or min(case) < 1 or case[1] > case[0] for case in args.matrix):
                raise ValueError
        except ValueError:
            parser.error("each --matrix must be REPO_FILES:CHANGED_FILES with 1 <= changed <= repo")
    else:
        args.matrix = [(100, 5), (1000, 25), (5000, 100)]
    resolved_vero = shutil.which(args.vero) or args.vero
    args.vero = str(Path(resolved_vero).resolve())
    if min(args.repo_files, args.changed_files, args.lines_per_file, args.iterations) < 1:
        parser.error("repo-files, changed-files, lines-per-file, and iterations must be positive")
    if args.warmups < 0:
        parser.error("warmups must be non-negative")

    try:
        result = benchmark(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"benchmark-review: {error}", file=sys.stderr)
        return 2
    document = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(document, encoding="utf-8")
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
