#!/usr/bin/env python3
"""Validate clean-source UI, Rust, browser, and CLI installation workflows."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


EXCLUDED = {".git", ".vero", "target", "node_modules", "test-results", "playwright-report"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path) -> None:
    print(f"+ ({cwd}) {' '.join(command)}", flush=True)
    environment = os.environ.copy()
    # Git-based fixtures must not inherit host-wide signing, LFS, credential,
    # hook, or branch-default settings from the developer running acceptance.
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = subprocess.run(command, cwd=cwd, env=environment, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {' '.join(command)}")


def main() -> int:
    source = Path(__file__).resolve().parent.parent
    try:
        with tempfile.TemporaryDirectory(prefix="vero-clean-build-") as temporary:
            staging = Path(temporary) / "source"
            shutil.copytree(
                source,
                staging,
                symlinks=True,
                ignore=lambda _directory, names: {name for name in names if name in EXCLUDED},
            )
            assets = [staging / "web" / "dist" / name for name in ("index.html", "app.js", "app.css")]
            missing = [path for path in assets if not path.is_file()]
            if missing:
                raise RuntimeError(f"bundled UI assets are missing: {', '.join(map(str, missing))}")
            before = {path.name: digest(path) for path in assets}

            run(["npm", "ci"], staging / "web")
            run(["npm", "run", "build"], staging / "web")
            after = {path.name: digest(path) for path in assets}
            if before != after:
                raise RuntimeError("web/dist is stale; rebuild it and include the generated assets")
            run(["npm", "run", "test:e2e"], staging / "web")

            run(["cargo", "fmt", "--all", "--", "--check"], staging)
            run(
                ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
                staging,
            )
            run(
                ["cargo", "test", "--workspace", "--locked", "--", "--test-threads=1"],
                staging,
            )
            run(["cargo", "build", "--workspace", "--locked"], staging)
            install_root = Path(temporary) / "install"
            run(
                [
                    "cargo",
                    "install",
                    "--path",
                    "crates/vero-cli",
                    "--locked",
                    "--force",
                    "--root",
                    str(install_root),
                ],
                staging,
            )
            executable = install_root / "bin" / ("vero.exe" if sys.platform == "win32" else "vero")
            run([str(executable), "--version"], staging)
            run(
                [
                    sys.executable,
                    str(staging / "scripts" / "acceptance" / "installed_cli_smoke.py"),
                    str(executable),
                ],
                staging,
            )
            if sys.platform == "win32":
                print(
                    "Skipping POSIX hook/symlink benchmark and report-comparison acceptance on Windows; "
                    "CI runs it on Unix.",
                    flush=True,
                )
            else:
                run(
                    [
                        sys.executable,
                        str(staging / "scripts" / "acceptance" / "compare_historical_reviews.py"),
                    ],
                    staging,
                )
                run(
                    [
                        sys.executable,
                        str(staging / "scripts" / "acceptance" / "historical_review_benchmark.py"),
                        str(executable),
                    ],
                    staging,
                )
    except (OSError, RuntimeError) as error:
        print(f"verify-clean-build: {error}", file=sys.stderr)
        return 1
    print(
        "Clean source-tree build, locked tests, installed local review, "
        "historical benchmark safety, and version check passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
