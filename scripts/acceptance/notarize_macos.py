#!/usr/bin/env python3
"""Check that `scripts/notarize-macos.py` reads codesign's output correctly and
refuses a release whose macOS binary is not signed with a Developer ID.

The signature parsing runs everywhere; the end-to-end refusal needs macOS's
codesign and is skipped elsewhere."""

from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "notarize-macos.py"

DEVELOPER_ID = """Executable=/tmp/vee
Identifier=vee
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=9000 flags=0x10000(runtime) hashes=270+7 location=embedded
Signature size=9000
Authority=Developer ID Application: Example Org (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=27 Nov 2026 at 10:00:00
TeamIdentifier=ABCDE12345
"""

AD_HOC = """Executable=/tmp/vee
Identifier=vee
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=9000 flags=0x20002(adhoc,linker-signed) hashes=270+0 location=embedded
Signature=adhoc
TeamIdentifier=not set
"""


def load_script():
    spec = importlib.util.spec_from_file_location("notarize_macos", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up while the class is created.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check_parsing(module) -> None:
    signed = module.parse_signature(DEVELOPER_ID)
    assert signed.team == "ABCDE12345", signed
    assert signed.timestamped and signed.hardened_runtime, signed
    assert module.signature_problems(signed) == [], module.signature_problems(signed)

    ad_hoc = module.parse_signature(AD_HOC)
    problems = module.signature_problems(ad_hoc)
    assert len(problems) == 4, problems
    assert "Developer ID" in problems[0], problems

    no_runtime = module.parse_signature(DEVELOPER_ID.replace("flags=0x10000(runtime)", "flags=0x0(none)"))
    assert module.signature_problems(no_runtime) == [
        "the hardened runtime is off (CODESIGN_OPTIONS must be 'runtime')"
    ]


def script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, timeout=120
    )


def archive(directory: Path, binary: Path, name: str) -> None:
    with tarfile.open(directory / f"{name}.tar.xz", "w:xz") as tar:
        tar.add(binary, arcname=f"{name}/vee")


def check_refusals(scratch: Path) -> None:
    empty = scratch / "empty"
    empty.mkdir()
    result = script("--check-only", "--directory", str(empty))
    assert result.returncode == 1 and "no macOS archives" in result.stderr, result

    binary = scratch / "vee"
    shutil.copy("/usr/bin/true", binary)
    subprocess.run(["codesign", "--force", "--sign", "-", str(binary)], check=True, timeout=60)
    release = scratch / "release"
    release.mkdir()
    archive(release, binary, "vee-aarch64-apple-darwin")
    result = script("--check-only", "--directory", str(release))
    assert result.returncode == 1, result
    assert "not signed with a Developer ID" in result.stderr, result.stderr

    # Notarizing without the API key is refused before anything is uploaded.
    result = script("--directory", str(release))
    assert result.returncode == 1 and "notarization needs APPLE_NOTARY_KEY" in result.stderr, result


def main() -> int:
    check_parsing(load_script())
    if platform.system() == "Darwin":
        with tempfile.TemporaryDirectory() as scratch:
            check_refusals(Path(scratch))
    else:
        print("skipping the codesign checks: not macOS")
    print("notarize-macos checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
