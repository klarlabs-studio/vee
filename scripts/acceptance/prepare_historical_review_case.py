#!/usr/bin/env python3
"""Exercise local historical-case candidate preparation without external data."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, check=False)


def git(repo: pathlib.Path, *args: str) -> str:
    result = run(["git", *args], repo)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def main() -> int:
    helper = pathlib.Path(__file__).resolve().parents[1] / "prepare-historical-review-case.py"
    with tempfile.TemporaryDirectory(prefix="vee-local-curation-acceptance-") as temporary:
        root = pathlib.Path(temporary)
        repo = root / "subject"
        repo.mkdir()
        unrelated_repo = root / "unrelated"
        unrelated_repo.mkdir()
        git(unrelated_repo, "init", "-q")
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "fixture@example.invalid")
        git(repo, "config", "user.name", "Vee fixture")
        textconv_marker = root / "textconv-ran"
        textconv = f"{sys.executable} -c \"open({str(textconv_marker)!r}, 'w').write('ran')\""
        git(repo, "config", "diff.evil.textconv", textconv)
        (repo / ".gitattributes").write_text("*.rs diff=evil\n", encoding="utf-8")
        (repo / "src").mkdir()
        source = repo / "src/divide.rs"
        source.write_text("pub fn divide(a: i32, b: i32) -> i32 { a }\n", encoding="utf-8")
        git(repo, "add", ".gitattributes", "src/divide.rs")
        git(repo, "commit", "-qm", "baseline")
        source.write_text("pub fn divide(a: i32, b: i32) -> i32 { a / b }\n", encoding="utf-8")
        git(repo, "commit", "-qam", "introduce defect")
        buggy = git(repo, "rev-parse", "HEAD")
        source.write_text("pub fn divide(a: i32, b: i32) -> i32 { if b == 0 { 0 } else { a / b } }\n", encoding="utf-8")
        git(repo, "commit", "-qam", "fix defect")
        fixed = git(repo, "rev-parse", "HEAD")

        output = root / "candidate.json"
        command = [sys.executable, str(helper), "--repository", str(repo), "--commit", buggy,
                   "--fix-commit", fixed, "--case-id", "fixture-1", "--project", "local-fixture",
                   "--output", str(output)]
        hostile_env = os.environ.copy()
        hostile_env.update({
            "GIT_DIR": str(unrelated_repo / ".git"),
            "GIT_WORK_TREE": str(unrelated_repo),
            "GIT_INDEX_FILE": str(unrelated_repo / ".git/index"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "diff.evil.textconv",
            "GIT_CONFIG_VALUE_0": f"{sys.executable} -c \"open({str(textconv_marker)!r}, 'w').write('ran')\"",
        })
        result = run(command, root, hostile_env)
        if result.returncode:
            raise RuntimeError(f"candidate preparation failed: {result.stdout}\n{result.stderr}")
        document = json.loads(output.read_text(encoding="utf-8"))
        assert document["candidate_only"] is True
        assert document["buggy_commit"] == buggy and document["fix_commit"] == fixed
        assert len(document["candidate_locations"]) == 1
        candidate = document["candidate_locations"][0]
        assert (candidate["path"], candidate["start_line"], candidate["end_line"]) == ("src/divide.rs", 1, 1)
        assert candidate["category"] is None and candidate["rationale"] is None and candidate["review_required"]
        assert not textconv_marker.exists()

        inside = run(command[:-2] + ["--output", str(repo / "candidate.json")], root)
        assert inside.returncode != 0 and not (repo / "candidate.json").exists()
        link = root / "candidate-link.json"
        link.symlink_to(root / "other.json")
        symlink = run(command[:-2] + ["--output", str(link)], root)
        assert symlink.returncode != 0
        unrelated = git(repo, "rev-parse", "HEAD~2")
        bad_command = command.copy()
        bad_command[bad_command.index("--fix-commit") + 1] = unrelated
        bad_fix = run(bad_command, root)
        assert bad_fix.returncode != 0

        labels_schema = json.loads((helper.parents[1] / "schemas/historical-review-labels-v1.schema.json").read_text())
        candidate_schema = json.loads((helper.parents[1] / "schemas/historical-review-candidates-v1.schema.json").read_text())
        assert "candidate_only" not in labels_schema["properties"]
        assert candidate_schema["properties"]["candidate_only"] == {"const": True}
        print("local historical curation acceptance passed: candidates stay untrusted; hostile Git environment, repository textconv, inside-repository, symlink, and unrelated-fix inputs rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
