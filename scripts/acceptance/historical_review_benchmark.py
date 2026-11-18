#!/usr/bin/env python3
"""Exercise the local historical-review runner with hostile repository metadata."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import PurePosixPath

import jsonschema


def execute(command: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def git(repo: pathlib.Path, *args: str) -> str:
    result = execute(["git", *args], repo)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def resolve_executable(name: str) -> pathlib.Path:
    """Resolve a path, or a bare command name through PATH, to an absolute path."""
    if os.sep not in name and (os.altsep is None or os.altsep not in name):
        found = shutil.which(name)
        if found is None:
            raise SystemExit(f"{name} was not found on PATH")
        name = found
    return pathlib.Path(name).resolve(strict=True)


def main() -> int:
    vee = resolve_executable(sys.argv[1] if len(sys.argv) > 1 else "target/debug/vee")
    runner = pathlib.Path(__file__).resolve().parents[1] / "historical-review-benchmark.py"
    with tempfile.TemporaryDirectory(prefix="vee-historical-acceptance-") as temporary:
        root = pathlib.Path(temporary)
        repo = root / "subject"
        repo.mkdir()
        external_config = root / "outside-config"
        external_config.write_text("preserve me", encoding="utf-8")
        hook_marker = root / "hook-ran"
        filter_marker = root / "filter-ran"
        provider = root / "fake-provider.py"
        trusted_instructions = root / "trusted-reviewer.md"
        trusted_instructions.write_text(
            "Only report the seeded division-by-zero defect when b can be zero.\n",
            encoding="utf-8",
        )
        trusted_verification = root / "trusted-regression.py"
        trusted_verification.write_text(
            "import subprocess\nfrom pathlib import Path\n"
            "root = Path(__file__).resolve().parents[1]\n"
            "source = subprocess.check_output(['git', '-C', str(root), 'show', 'HEAD:src/bug.rs'], text=True)\n"
            "assert 'b == 0' in source, 'division-by-zero regression is present'\n",
            encoding="utf-8",
        )
        provider.write_text(
            "import json,sys\n"
            f"from pathlib import Path; Path({str(root / 'provider-ran')!r}).touch()\n"
            "request=json.load(sys.stdin)\n"
            "assert 'Only report' in request['instructions']\n"
            "print(json.dumps({'schema_version':1,'findings':["
            "{'category':'correctness','severity':'high','confidence':95,"
            "'rationale':'Division by zero panics for b = 0.',"
            "'path':'src/bug.rs','line':1}]}))\n",
            encoding="utf-8",
        )

        git(repo, "init", "-q")
        git(repo, "config", "user.email", "acceptance@example.invalid")
        git(repo, "config", "user.name", "Vee acceptance")
        (repo / "src").mkdir()
        baseline_source = "pub fn divide(a: i32, b: i32) -> i32 { a }\n// stable context line\n"
        (repo / "src/bug.rs").write_text(baseline_source, encoding="utf-8")
        (repo / "reviewer.md").write_text(
            "Review changed code for concrete defects.\n", encoding="utf-8"
        )
        (repo / ".vee.yaml").symlink_to(external_config)
        (repo / ".gitattributes").write_text("*.rs filter=evil\n", encoding="utf-8")
        git(
            repo,
            "config",
            "filter.evil.smudge",
            f"{sys.executable} -c \"open({str(filter_marker)!r}, 'w').write('ran')\"",
        )
        git(repo, "config", "filter.evil.clean", "cat")
        hook = repo / ".git" / "hooks" / "post-checkout"
        hook.parent.mkdir(exist_ok=True)
        hook.write_text(f"#!/bin/sh\nprintf ran > {hook_marker}\n", encoding="utf-8")
        hook.chmod(0o755)
        git(repo, "add", "-f", ".")
        git(repo, "commit", "-qm", "baseline")
        (repo / "src/bug.rs").write_text(
            "pub fn divide(a: i32, b: i32) -> i32 { a / b }\n// stable context line\n", encoding="utf-8"
        )
        git(repo, "add", "src/bug.rs")
        git(repo, "commit", "-qm", "introduce defect")
        defect_commit = git(repo, "rev-parse", "HEAD")
        (repo / "src/bug.rs").write_text(
            "pub fn divide(a: i32, b: i32) -> i32 { if b == 0 { 0 } else { a / b } }\n// stable context line\n",
            encoding="utf-8",
        )
        git(repo, "add", "src/bug.rs")
        git(repo, "commit", "-qm", "fix defect")
        fix_commit = git(repo, "rev-parse", "HEAD")
        (repo / "src/bug.ts").write_text("export function divide(a: number, b: number) { return a / b; }\n", encoding="utf-8")
        git(repo, "add", "src/bug.ts")
        git(repo, "commit", "-qm", "introduce TypeScript defect")
        typescript_commit = git(repo, "rev-parse", "HEAD")
        (repo / "src/unreviewed.rs").write_text(
            "pub fn unreviewed(value: i32) -> i32 { value / value }\n", encoding="utf-8"
        )
        git(repo, "add", "src/unreviewed.rs")
        git(repo, "commit", "-qm", "introduce excluded Rust fixture")
        excluded_rust_commit = git(repo, "rev-parse", "HEAD")


        out_of_scope_commits = {}
        out_of_scope_sources = {
            "python": ("src/bug.py", "def divide(a, b):\n    return a / b\n"),
            "java": ("src/Bug.java", "final class Bug { int divide(int a, int b) { return a / b; } }\n"),
            "ruby": ("src/bug.rb", "def divide(a, b)\n  a / b\nend\n"),
        }
        out_of_scope_label_bytes = {}
        for language, (relative_path, source) in out_of_scope_sources.items():
            target = repo / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            git(repo, "add", relative_path)
            git(repo, "commit", "-qm", f"introduce {language} fixture")
            out_of_scope_commits[language] = git(repo, "rev-parse", "HEAD")
            label_id = f"{language}-out-of-scope"
            path = relative_path
            label_bytes = (json.dumps({"schema_version": 1, "labels": [{"id": label_id, "path": path, "start_line": 1, "end_line": 1, "category": "correctness", "rationale": f"Fixture for {language} scope handling."}]}) + "\n").encode()
            label_filename = f"{language}-labels.json"
            (root / label_filename).write_bytes(label_bytes)
            out_of_scope_label_bytes[language] = (label_filename, label_bytes)

        config = root / "benchmark.vee.yaml"
        config.write_text(
            "version: 1\noffline: true\nreview:\n  include: [\"**/*.rs\"]\n"
            "  exclude: [\"src/unreviewed.rs\"]\n"
            "providers:\n  local_fixture:\n    kind: cli\n    egress: local\n"
            f"    executable: {json.dumps(sys.executable)}\n"
            f"    args: [{json.dumps(str(provider))}]\n"
            "reviewers:\n  correctness:\n    provider: local_fixture\n"
            "    instructions_file: reviewer.md\n"
            "verification:\n  unit:\n"
            f"    executable: {json.dumps(sys.executable)}\n"
            "    egress: local\n    args: [\"tests/local_regression.py\"]\n"
            "    timeout_seconds: 30\n"
            "policy:\n  required_reviewers: [correctness]\n"
            "  block_severities: [critical, high]\n  minimum_confidence: 80\n"
            "  on_incomplete: block\n",
            encoding="utf-8",
        )
        labels = root / "labels.json"
        label_bytes = (
            json.dumps(
                {
                    "schema_version": 1,
                    "labels": [
                        {
                            "id": "division-by-zero",
                            "path": "src/bug.rs",
                            "start_line": 1,
                            "end_line": 1,
                            "category": "correctness",
                            "rationale": "The new division panics when b is zero.",
                        }
                    ],
                }
            )
            + "\n"
        ).encode()
        labels.write_bytes(label_bytes)
        wrong_location_labels = root / "wrong-location-labels.json"
        wrong_location_bytes = (
            json.dumps(
                {
                    "schema_version": 1,
                    "labels": [
                        {
                            "id": "division-by-zero-location",
                            "path": "src/bug.rs",
                            "start_line": 2,
                            "end_line": 2,
                            "category": "correctness",
                            "rationale": "The same defect is intentionally labeled on another line to exercise localization diagnostics.",
                        }
                    ],
                }
            )
            + "\n"
        ).encode()
        wrong_location_labels.write_bytes(wrong_location_bytes)
        typescript_labels = root / "typescript-labels.json"
        typescript_label_bytes = (json.dumps({"schema_version": 1, "labels": [{"id": "typescript-divide", "path": "src/bug.ts", "start_line": 1, "end_line": 1, "category": "correctness", "rationale": "Fixture for language scope handling."}]}) + "\n").encode()
        typescript_labels.write_bytes(typescript_label_bytes)
        excluded_rust_labels = root / "excluded-rust-labels.json"
        excluded_rust_label_bytes = (json.dumps({"schema_version": 1, "labels": [{"id": "excluded-rust", "path": "src/unreviewed.rs", "start_line": 1, "end_line": 1, "category": "correctness", "rationale": "The configured review excludes this changed Rust path."}]}) + "\n").encode()
        excluded_rust_labels.write_bytes(excluded_rust_label_bytes)
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "corpus_id": "local-adversarial-acceptance",
                    "source": "synthetic local acceptance fixture",
                    "cases": [
                        {
                            "id": "division-by-zero",
                            "repository": "subject",
                            "commit": defect_commit,
                            "labels": "labels.json",
                            "labels_digest": "sha256:" + hashlib.sha256(label_bytes).hexdigest(),
                            "fix_commit": fix_commit,
                            "project_license": "MIT test fixture",
                        },
                        {
                            "id": "division-by-zero-wrong-location",
                            "repository": "subject",
                            "commit": defect_commit,
                            "labels": "wrong-location-labels.json",
                            "labels_digest": "sha256:" + hashlib.sha256(wrong_location_bytes).hexdigest(),
                            "fix_commit": fix_commit,
                            "project_license": "MIT test fixture",
                        },
                        {
                            "id": "typescript-out-of-scope",
                            "repository": "subject",
                            "commit": typescript_commit,
                            "labels": "typescript-labels.json",
                            "labels_digest": "sha256:" + hashlib.sha256(typescript_label_bytes).hexdigest(),
                            "project_license": "MIT test fixture",
                        },
                        {
                            "id": "rust-excluded-by-config",
                            "repository": "subject",
                            "commit": excluded_rust_commit,
                            "labels": "excluded-rust-labels.json",
                            "labels_digest": "sha256:" + hashlib.sha256(excluded_rust_label_bytes).hexdigest(),
                            "project_license": "MIT test fixture",
                        },
                        *[
                            {
                                "id": f"{language}-out-of-scope",
                                "repository": "subject",
                                "commit": out_of_scope_commits[language],
                                "labels": out_of_scope_label_bytes[language][0],
                                "labels_digest": "sha256:" + hashlib.sha256(out_of_scope_label_bytes[language][1]).hexdigest(),
                                "project_license": "MIT test fixture",
                            }
                            for language in ("python", "java", "ruby")
                        ],
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        output = root / "results"
        benchmark_command = [
                sys.executable,
                str(runner),
                "--manifest",
                str(manifest),
                "--corpus-root",
                str(root),
                "--config",
                str(config),
                "--trusted-file",
                f"reviewer.md={trusted_instructions}",
                "--verification-file",
                f"tests/local_regression.py={trusted_verification}",
                "--vee",
                str(vee),
                "--output-dir",
                str(output),
                "--reviewer",
                "correctness",
                "--scope-language",
                "rust",
                "--verify-profile",
                "unit",
                "--verify-fix",
            ]
        result = execute(benchmark_command, pathlib.Path.cwd())
        if result.returncode not in (0, 2):
            detail = ""
            report_path = output / "historical-review-report-v1.json"
            if report_path.exists():
                detail += "\n" + json.dumps(json.loads(report_path.read_text()).get("cases", []), indent=2)
            raise RuntimeError(f"benchmark failed ({result.returncode}): {result.stdout}\n{result.stderr}{detail}")
        report = json.loads((output / "historical-review-report-v1.json").read_text())
        assert report["verifier_digest"].startswith("sha256:")
        case = report["cases"][0]
        assert result.returncode == 2
        assert report["case_count"] == 7
        assert report["completed_cases"] == 2
        assert report["incomplete_cases"] == 1
        assert report["out_of_scope_cases"] == 4
        assert report["matched_labels"] == 1 and report["missed_labels"] == 1
        assert report["finding_recall"] == 0.5
        assert report["labels_with_localization_candidates"] == 1
        verification_manifest = root / "verification-manifest.json"
        verification_manifest.write_text(json.dumps({
            "schema_version": 1,
            "corpus_id": "local-verification-only-acceptance",
            "source": "synthetic local acceptance fixture",
            "cases": [json.loads(manifest.read_text())["cases"][0]],
        }), encoding="utf-8")
        verification_output = root / "verification-only-results"
        verification_command = [
            sys.executable, str(runner), "--manifest", str(verification_manifest),
            "--corpus-root", str(root), "--config", str(config), "--vee", str(vee),
            "--output-dir", str(verification_output), "--verification-only",
            "--verify-profile", "unit", "--verification-file", f"tests/local_regression.py={trusted_verification}",
        ]
        (root / "provider-ran").unlink(missing_ok=True)
        verification_result = execute(verification_command, pathlib.Path.cwd())
        verification_report_path = verification_output / "historical-verification-report-v1.json"
        assert verification_result.returncode == 0, verification_result.stdout + verification_result.stderr
        verification_report = json.loads(verification_report_path.read_text())
        assert verification_report["benchmark"] == "historical_verification"
        assert "finding_recall" not in verification_report and "matched_labels" not in verification_report
        assert verification_report["completed_cases"] == 1 and verification_report["incomplete_cases"] == 0
        verification_case = verification_report["cases"][0]
        assert verification_case["comparisons"][0]["comparison"] == "buggy_failed_fix_passed", json.dumps(verification_case, indent=2) + "\nfix stderr: " + (verification_output / verification_case["fix_runs"][0]["stderr_artifact"]["path"]).read_text(errors="replace")
        assert verification_case["comparisons"][0]["same_command"] is True
        assert not (root / "provider-ran").exists(), "verification-only must not invoke the review provider"
        schema = json.loads((pathlib.Path(__file__).resolve().parents[2] / "schemas/historical-verification-report-v1.schema.json").read_text())
        assert schema["properties"]["benchmark"]["const"] == verification_report["benchmark"]
        jsonschema.validate(verification_report, schema)
        for revision_runs in (verification_case["buggy_runs"], verification_case["fix_runs"]):
            run_record = revision_runs[0]
            assert run_record["command_digest"].startswith("sha256:")
            for stream in ("stdout", "stderr"):
                artifact = run_record[f"{stream}_artifact"]
                saved = verification_output / artifact["path"]
                assert saved.is_file() and hashlib.sha256(saved.read_bytes()).hexdigest() == artifact["digest"].removeprefix("sha256:")
        excluded_case = next(case for case in report["cases"] if case["case_id"] == "rust-excluded-by-config")
        assert excluded_case["state"] == "incomplete"
        assert excluded_case["incomplete_reason"] == "labeled_paths_not_fully_supplied_to_completed_reviewer"
        assert excluded_case["label_context_coverage"][0]["full_source_reviewer_ids"] == []
        excluded_review = json.loads((output / excluded_case["review_json_path"]).read_text())
        excluded_manifest = excluded_review["reviewer_context"][0]
        excluded_entry = next(entry for entry in excluded_manifest["files"] if entry["path"] == "src/unreviewed.rs")
        assert excluded_entry["status"] == "excluded_by_review_filter"
        location_case = next(case for case in report["cases"] if case["case_id"] == "division-by-zero-wrong-location")
        assert len(location_case["localization_candidates"]) == 1
        localization = location_case["localization_candidates"][0]
        assert localization == {
            "label_id": "division-by-zero-location",
            "finding_id": localization["finding_id"],
            "candidate_type": "wrong_line",
            "path": "src/bug.rs",
            "line": 1,
            "target_start_line": 2,
            "target_end_line": 2,
            "category": "correctness",
        }
        assert isinstance(localization["finding_id"], str)
        assert case["fix_commit"] == fix_commit and case["state"] == "complete"
        for rust_case in (case for case in report["cases"] if case["state"] == "complete"):
            verification = rust_case["verification_runs"][0]
            assert verification["profile_id"] == "unit"
            expected_state = "failed" if rust_case["case_id"] in {"division-by-zero", "division-by-zero-wrong-location"} else "passed"
            assert verification["state"] == expected_state, json.dumps(verification, indent=2)
            assert verification["snapshot_id"] != rust_case["snapshot_id"]
            assert verification["source_commit"] == rust_case["commit"]
            assert verification["verification_overlay"] == [{
                "path": "tests/local_regression.py",
                "digest": "sha256:" + hashlib.sha256(trusted_verification.read_bytes()).hexdigest(),
                "size_bytes": trusted_verification.stat().st_size,
            }]
            assert verification["verification_overlay_digest"].startswith("sha256:")
            assert verification["command_digest"].startswith("sha256:")
            for stream in ("stdout", "stderr"):
                artifact = verification[f"{stream}_artifact"]
                assert artifact["digest"].startswith("sha256:")
                saved_artifact = output / artifact["path"]
                assert saved_artifact.is_file() and not saved_artifact.is_symlink()
                assert saved_artifact.stat().st_size == artifact["size_bytes"]
                assert hashlib.sha256(saved_artifact.read_bytes()).hexdigest() == artifact["digest"].removeprefix("sha256:")
            comparison = rust_case["analysis_evidence_comparison"]
            if rust_case["case_id"] == "division-by-zero":
                assert comparison["ai_review"]["matched_label_ids"] == ["division-by-zero"]
                assert comparison["ai_review"]["missed_label_ids"] == []
            else:
                assert comparison["ai_review"]["matched_label_ids"] == []
                assert comparison["ai_review"]["missed_label_ids"] == ["division-by-zero-location"]
            assert comparison["trusted_verification"][0]["comparison"] == "buggy_failed_fix_passed"
            assert comparison["trusted_verification"][0]["same_command"] is True
            assert comparison["trusted_verification"][0]["same_verification_overlay"] is True
            assert "do not prove" in comparison["interpretation"]
        for fixed_case in (case for case in report["cases"] if case.get("fix_commit")):
            verification = fixed_case["fix_verification_runs"][0]
            assert verification["revision_role"] == "fix_commit"
            assert verification["state"] == "passed", json.dumps(verification, indent=2)
            assert verification["snapshot_id"] != fixed_case["snapshot_id"]
            for stream in ("stdout", "stderr"):
                artifact = verification[f"{stream}_artifact"]
                saved_artifact = output / artifact["path"]
                assert saved_artifact.is_file() and hashlib.sha256(saved_artifact.read_bytes()).hexdigest() == artifact["digest"].removeprefix("sha256:")
        unsupported_case = next(case for case in report["cases"] if case["case_id"] == "typescript-out-of-scope")
        assert unsupported_case["state"] == "out_of_scope"
        assert unsupported_case["unsupported_languages"] == ["typescript"]
        for language in ("python", "java", "ruby"):
            unsupported_case = next(case for case in report["cases"] if case["case_id"] == f"{language}-out-of-scope")
            assert unsupported_case["state"] == "out_of_scope"
            assert unsupported_case["unsupported_languages"] == [language]
        conflicting_file = root / "conflicting-source.py"
        conflicting_file.write_text("this is deliberately different from the checked-out source\n", encoding="utf-8")
        conflict_output = root / "conflict-results"
        conflict_command = list(benchmark_command)
        conflict_command[conflict_command.index("--output-dir") + 1] = str(conflict_output)
        overlay_arg = conflict_command.index("--vee")
        conflict_command[overlay_arg:overlay_arg] = [
            "--verification-file",
            f"src/bug.rs={conflicting_file}",
        ]
        conflict_result = execute(conflict_command, pathlib.Path.cwd())
        conflict_report = json.loads((conflict_output / "historical-review-report-v1.json").read_text())
        conflict_case = next(case for case in conflict_report["cases"] if case["case_id"] == "division-by-zero")
        assert conflict_result.returncode == 2
        assert conflict_case["state"] == "incomplete"
        assert conflict_case["incomplete_reason"] == "benchmark_execution_error"
        assert "verification overlay conflicts" in conflict_case["error"]
        review_path = (output / case["review_json_path"]).resolve(strict=True)
        assert review_path.is_relative_to(output.resolve())
        assert hashlib.sha256(review_path.read_bytes()).hexdigest() == case["review_json_digest"].removeprefix("sha256:")
        saved_review = json.loads(review_path.read_text(encoding="utf-8"))
        assert saved_review["reviewer_context"][0]["reviewer_id"] == "correctness"
        supplied = next(entry for entry in saved_review["reviewer_context"][0]["files"] if entry["path"] == "src/bug.rs")
        assert supplied["status"] == "full_source"
        assert supplied["artifact_digest"].startswith("sha256:")
        assert report["benchmark_config_digest"] == "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest()
        assert external_config.read_text(encoding="utf-8") == "preserve me"
        assert not hook_marker.exists() and not filter_marker.exists()
        assert not (repo / ".vee/vee.sqlite").exists()
        assert not list((repo / ".git" / "worktrees").glob("*"))
        runner_api = runpy.run_path(str(runner))
        try:
            runner_api["parse_trusted_files"]([f"../escaped={trusted_instructions}"])
            raise AssertionError("trusted-file path traversal was accepted")
        except ValueError:
            pass
        unsafe_target_root = root / "unsafe-overlay"
        unsafe_target_root.mkdir()
        (unsafe_target_root / "linked").symlink_to(root, target_is_directory=True)
        try:
            runner_api["install_trusted_files"](
                unsafe_target_root,
                [(PurePosixPath("linked/reviewer.md"), trusted_instructions)],
            )
            raise AssertionError("trusted-file symlink target was accepted")
        except ValueError:
            pass
        try:
            runner_api["install_verification_files"](
                unsafe_target_root,
                [(PurePosixPath("linked/regression.py"), trusted_verification)],
            )
            raise AssertionError("verification-file symlink target was accepted")
        except ValueError:
            pass
        print("historical review benchmark acceptance passed: strict recall preserved, digest-recorded trusted verification overlays distinguished from source snapshots, buggy/fix verification profiles compared, conflicting overlays marked incomplete, wrong-location diagnostics reported, trusted instructions overlaid, and hostile config, hooks, filters, traversal, and symlink targets rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
