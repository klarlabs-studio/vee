#!/usr/bin/env python3
"""Sign a disposable release with a throwaway SSH key and check that
`scripts/release-signature.py verify` accepts it and refuses tampering."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "release-signature.py"


def tool(*args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, timeout=60
    )
    if result.returncode != expected:
        raise SystemExit(
            f"{args!r} returned {result.returncode}, expected {expected}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout + result.stderr


def key(directory: Path, name: str) -> tuple[Path, str]:
    path = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(path)],
        check=True,
        timeout=60,
    )
    return path, path.with_suffix(".pub").read_text(encoding="utf-8").strip()


def main() -> int:
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        release = root / "release"
        release.mkdir()
        archives = {
            "vee-x86_64-unknown-linux-gnu.tar.xz": b"linux binary",
            "vee-x86_64-pc-windows-msvc.zip": b"windows binary",
        }
        lines = []
        for name, content in archives.items():
            (release / name).write_bytes(content)
            lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
        (release / "sha256.sum").write_text("\n".join(lines) + "\n", encoding="utf-8")

        maintainer, public = key(root, "maintainer")
        stranger, _ = key(root, "stranger")
        signers = root / "signers"
        signers.write_text(
            f'# comment\nvee-release namespaces="vee-release" {public}\n', encoding="utf-8"
        )
        empty = root / "empty-signers"
        empty.write_text("# no keys yet\n", encoding="utf-8")
        common = ["--directory", str(release), "--signers", str(signers)]

        # Unsigned: verification refuses.
        assert "not signed" in tool("verify", *common, expected=1)
        # A key the signers file does not list cannot sign.
        assert "failed" in tool("sign", *common, "--key", str(stranger), expected=1)
        # The maintainer signs, and every archive verifies.
        tool("sign", *common, "--key", str(maintainer))
        output = tool("verify", *common)
        assert all(name in output for name in archives), output
        # One archive given on the command line, from elsewhere.
        elsewhere = root / "download"
        elsewhere.mkdir()
        linux = elsewhere / "vee-x86_64-unknown-linux-gnu.tar.xz"
        linux.write_bytes(archives[linux.name])
        tool("verify", *common, str(linux))
        # A tampered archive fails its digest.
        linux.write_bytes(b"tampered")
        assert "does not match" in tool("verify", *common, str(linux), expected=1)
        # A tampered checksum file fails the signature.
        sums = release / "sha256.sum"
        original = sums.read_text(encoding="utf-8")
        sums.write_text(original.replace("linux", "linuz"), encoding="utf-8")
        tool("verify", *common, expected=1)
        sums.write_text(original, encoding="utf-8")
        # A signers file without keys verifies nothing.
        assert "lists no release key" in tool(
            "verify", "--directory", str(release), "--signers", str(empty), expected=1
        )
        # A file name that escapes the release directory is refused.
        sums.write_text(f"{'0' * 64}  ../outside\n", encoding="utf-8")
        tool("sign", *common, "--key", str(maintainer), expected=1)
    print("release signature acceptance passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
