#!/usr/bin/env python3
"""Check and notarize the macOS binaries in a release's archives.

dist signs each macOS binary with the Developer ID certificate in the
CODESIGN_* secrets, but skips signing with only a warning when they are
missing, and does not notarize. This script runs after `dist build` on the
macOS runners. It extracts the binary from every macOS archive, refuses one
that is not signed with a Developer ID, the hardened runtime and a secure
timestamp, and submits it to Apple's notary service, failing unless Apple
accepts it. A bare binary cannot carry a stapled ticket, so Gatekeeper looks
the ticket up online; the archives themselves are not changed.

Notarization authenticates with an App Store Connect API key, read from the
environment:

    APPLE_NOTARY_KEY      the .p8 key file, base64-encoded
    APPLE_NOTARY_KEY_ID   the key's ID
    APPLE_NOTARY_ISSUER   the issuer ID of the team

Usage:
    notarize-macos.py [--directory target/distrib] [--binary vee] [--check-only]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

ARCHIVE_SUFFIXES = (".tar.xz", ".tar.gz", ".tar.zst")
NOTARY_TIMEOUT = "30m"
NOTARY_ENV = ("APPLE_NOTARY_KEY", "APPLE_NOTARY_KEY_ID", "APPLE_NOTARY_ISSUER")


class ReleaseError(Exception):
    """A release that must not be published as it is."""


@dataclass(frozen=True)
class Signature:
    authorities: tuple[str, ...]
    team: str | None
    timestamped: bool
    hardened_runtime: bool


def parse_signature(details: str) -> Signature:
    """Read the output of `codesign -d --verbose=4`."""
    authorities = tuple(re.findall(r"^Authority=(.+)$", details, re.MULTILINE))
    team = re.search(r"^TeamIdentifier=(.+)$", details, re.MULTILINE)
    flags = re.search(r"^CodeDirectory .*flags=0x[0-9a-f]+\(([^)]*)\)", details, re.MULTILINE)
    return Signature(
        authorities=authorities,
        team=team.group(1).strip() if team and team.group(1).strip() != "not set" else None,
        timestamped=re.search(r"^Timestamp=", details, re.MULTILINE) is not None,
        hardened_runtime=flags is not None and "runtime" in flags.group(1).split(","),
    )


def signature_problems(signature: Signature) -> list[str]:
    """What keeps a signature from being notarized, empty when nothing does."""
    problems = []
    if not signature.authorities or not signature.authorities[0].startswith(
        "Developer ID Application:"
    ):
        problems.append(
            "not signed with a Developer ID Application certificate"
            " (are the CODESIGN_* secrets set?)"
        )
    if signature.team is None:
        problems.append("no team identifier")
    if not signature.timestamped:
        problems.append("no secure timestamp")
    if not signature.hardened_runtime:
        problems.append("the hardened runtime is off (CODESIGN_OPTIONS must be 'runtime')")
    return problems


def macos_archives(directory: Path) -> list[Path]:
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and "apple-darwin" in path.name and path.name.endswith(ARCHIVE_SUFFIXES)
    )


def extract_binary(archive: Path, binary: str, destination: Path) -> Path:
    """Extract the one file named `binary` from the archive."""
    if archive.name.endswith(".tar.zst"):
        raise ReleaseError(f"{archive.name}: zstd archives are not supported")
    with tarfile.open(archive) as tar:
        members = [
            member
            for member in tar.getmembers()
            if member.isfile() and Path(member.name).name == binary
        ]
        if len(members) != 1:
            raise ReleaseError(f"{archive.name}: expected one file named {binary}, found {len(members)}")
        member = members[0]
        if hasattr(tarfile, "data_filter"):
            tar.extract(member, destination, filter="data")
        else:
            # Pythons before the extraction filters: refuse paths that leave
            # the destination ourselves.
            if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                raise ReleaseError(f"{archive.name}: unsafe path {member.name}")
            tar.extract(member, destination)
        return destination / member.name


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def check_signature(path: Path, label: str) -> None:
    verify = run("codesign", "--verify", "--strict", "--verbose=2", str(path))
    if verify.returncode != 0:
        raise ReleaseError(f"{label}: the signature does not verify: {verify.stderr.strip()}")
    details = run("codesign", "-d", "--verbose=4", str(path))
    if details.returncode != 0:
        raise ReleaseError(f"{label}: codesign could not read the signature: {details.stderr.strip()}")
    problems = signature_problems(parse_signature(details.stderr + details.stdout))
    if problems:
        raise ReleaseError(f"{label}: " + "; ".join(problems))


def notary_key(scratch: Path) -> tuple[Path, str, str]:
    missing = [name for name in NOTARY_ENV if not os.environ.get(name)]
    if missing:
        raise ReleaseError("notarization needs " + ", ".join(missing))
    try:
        key = base64.b64decode(os.environ["APPLE_NOTARY_KEY"], validate=True)
    except binascii.Error as error:
        raise ReleaseError("APPLE_NOTARY_KEY is not base64") from error
    path = scratch / "notary-key.p8"
    path.touch(mode=0o600)
    path.write_bytes(key)
    return path, os.environ["APPLE_NOTARY_KEY_ID"], os.environ["APPLE_NOTARY_ISSUER"]


def notarize(path: Path, label: str, key: tuple[Path, str, str], scratch: Path) -> None:
    upload = scratch / f"{label}.zip"
    zipped = run("ditto", "-c", "-k", "--keepParent", str(path), str(upload))
    if zipped.returncode != 0:
        raise ReleaseError(f"{label}: could not zip the binary: {zipped.stderr.strip()}")
    key_path, key_id, issuer = key
    credentials = ("--key", str(key_path), "--key-id", key_id, "--issuer", issuer)
    submitted = run(
        "xcrun", "notarytool", "submit", str(upload), *credentials,
        "--wait", "--timeout", NOTARY_TIMEOUT, "--output-format", "json",
        timeout=40 * 60,
    )
    try:
        result = json.loads(submitted.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseError(
            f"{label}: notarytool gave no result: {submitted.stderr.strip()}"
        ) from error
    status = result.get("status")
    if status != "Accepted":
        submission = result.get("id")
        log = (
            run("xcrun", "notarytool", "log", submission, *credentials).stdout
            if submission
            else ""
        )
        raise ReleaseError(f"{label}: Apple's notary service answered {status!r}\n{log}")
    print(f"{label}: notarized (submission {result.get('id')})")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--directory", type=Path, default=Path("target/distrib"))
    parser.add_argument("--binary", default="vee")
    parser.add_argument(
        "--check-only", action="store_true", help="check the signatures without notarizing"
    )
    options = parser.parse_args(argv)
    try:
        archives = macos_archives(options.directory)
        if not archives:
            raise ReleaseError(f"no macOS archives in {options.directory}")
        with tempfile.TemporaryDirectory() as scratch_dir:
            scratch = Path(scratch_dir)
            key = None if options.check_only else notary_key(scratch)
            for archive in archives:
                label = archive.name.split(".tar.")[0]
                binary = extract_binary(archive, options.binary, scratch / label)
                check_signature(binary, label)
                print(f"{label}: signed with a Developer ID, hardened runtime and timestamp")
                if key is not None:
                    notarize(binary, label, key, scratch)
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
