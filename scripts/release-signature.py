#!/usr/bin/env python3
"""Sign a Vee release with a maintainer's SSH key, or verify one.

The signature covers the release's `sha256.sum`, which lists the digest of
every archive, so one signature covers every binary (ADR 0039). Signing runs
on the maintainer's machine with their own key, never in CI.

    # Maintainer, after the release workflow has published vX.Y.Z:
    python3 scripts/release-signature.py sign --tag vX.Y.Z --key ~/.ssh/id_ed25519

    # Anyone, to check downloaded archives:
    python3 scripts/release-signature.py verify --tag vX.Y.Z vee-x86_64-unknown-linux-gnu.tar.xz

`--directory DIR` works on release files already downloaded, without `gh`.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = "klarlabs-studio/vee"
SUMS = "sha256.sum"
SIGNATURE = "sha256.sum.sig"
# The principal and namespace in `.github/release-signers`. The namespace keeps
# a release signature from being valid as any other kind of SSH signature.
PRINCIPAL = "vee-release"
NAMESPACE = "vee-release"
DEFAULT_SIGNERS = Path(__file__).resolve().parent.parent / ".github" / "release-signers"


class ReleaseError(Exception):
    pass


def run(command: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    if shutil.which(command[0]) is None:
        raise ReleaseError(f"{command[0]} is not installed")
    result = subprocess.run(command, input=stdin, capture_output=True, timeout=300)
    if result.returncode != 0:
        raise ReleaseError(
            f"{' '.join(command)} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result


def read_sums(directory: Path) -> dict[str, str]:
    """The archive names and digests `sha256.sum` lists."""
    path = directory / SUMS
    if not path.is_file():
        raise ReleaseError(f"{path} is missing")
    sums: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        digest, _, name = line.partition(" ")
        name = name.strip().lstrip("*")
        if len(digest) != 64 or not name or "/" in name or "\\" in name or name in {".", ".."}:
            raise ReleaseError(f"{path}:{number} is not a `<sha256>  <file>` line")
        sums[name] = digest.lower()
    if not sums:
        raise ReleaseError(f"{path} lists no files")
    return sums


def check_digests(sums: dict[str, str], paths: list[Path]) -> None:
    for path in paths:
        if path.name not in sums:
            raise ReleaseError(f"{path.name} is not listed in {SUMS}")
        if not path.is_file():
            raise ReleaseError(f"{path} is missing")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != sums[path.name]:
            raise ReleaseError(f"{path.name} does not match its digest in {SUMS}")
        print(f"ok  {path.name}")


def verify_signature(directory: Path, signers: Path) -> None:
    if not signers.is_file():
        raise ReleaseError(f"signers file {signers} is missing")
    if not any(
        line.strip() and not line.lstrip().startswith("#")
        for line in signers.read_text(encoding="utf-8").splitlines()
    ):
        raise ReleaseError(f"{signers} lists no release key")
    signature = directory / SIGNATURE
    if not signature.is_file():
        raise ReleaseError(f"{signature} is missing: this release is not signed")
    run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", str(signers),
            "-I", PRINCIPAL,
            "-n", NAMESPACE,
            "-s", str(signature),
        ],
        stdin=(directory / SUMS).read_bytes(),
    )
    print(f"ok  {SUMS} is signed by a key in {signers.name}")


def download(tag: str, directory: Path, patterns: list[str]) -> None:
    command = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(directory)]
    for pattern in patterns:
        command += ["--pattern", pattern]
    run(command)


def sign(args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(args.directory) if args.directory else Path(scratch)
        if args.tag:
            # Every listed archive, to check it before vouching for it.
            download(args.tag, directory, [SUMS])
            names = list(read_sums(directory))
            download(args.tag, directory, names)
        sums = read_sums(directory)
        check_digests(sums, [directory / name for name in sums])
        if args.tag:
            for name in sums:
                run(["gh", "attestation", "verify", str(directory / name), "--repo", REPOSITORY])
                print(f"ok  {name} has build provenance")
        signature = directory / SIGNATURE
        signature.unlink(missing_ok=True)
        run(["ssh-keygen", "-Y", "sign", "-f", args.key, "-n", NAMESPACE, str(directory / SUMS)])
        # Refuse a signature that the published signers file would not accept.
        verify_signature(directory, Path(args.signers))
        if args.tag and not args.no_upload:
            run(["gh", "release", "upload", args.tag, str(signature), "--repo", REPOSITORY])
            print(f"uploaded {SIGNATURE} to {args.tag}")
        elif args.tag:
            kept = Path.cwd() / SIGNATURE
            shutil.copyfile(signature, kept)
            print(f"wrote {kept}")


def verify(args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        if args.tag:
            directory = Path(scratch)
            download(args.tag, directory, [SUMS, SIGNATURE])
        else:
            directory = Path(args.directory)
        verify_signature(directory, Path(args.signers))
        sums = read_sums(directory)
        if args.archives:
            check_digests(sums, [Path(archive) for archive in args.archives])
        else:
            present = [directory / name for name in sums if (directory / name).is_file()]
            if not present:
                raise ReleaseError("no listed archive is present to check")
            check_digests(sums, present)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("sign", "verify"):
        command = commands.add_parser(name)
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--tag", help="the release, as vX.Y.Z")
        source.add_argument("--directory", help="release files already downloaded")
        command.add_argument(
            "--signers", default=str(DEFAULT_SIGNERS), help="allowed signers file"
        )
        if name == "sign":
            command.add_argument("--key", required=True, help="the SSH private key to sign with")
            command.add_argument(
                "--no-upload", action="store_true", help="write the signature instead of uploading it"
            )
        else:
            command.add_argument("archives", nargs="*", help="downloaded archives to check")
    args = parser.parse_args()
    try:
        (sign if args.command == "sign" else verify)(args)
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
