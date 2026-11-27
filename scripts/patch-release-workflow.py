#!/usr/bin/env python3
"""Fix dist's generated release workflow.

dist 0.34 renders a local post-announce job with the path "$/.github/..." and
without the permissions the called workflow needs, commits the Homebrew
formula to the shared tap as its own vendor's bot, and neither enables the
hardened runtime nor notarizes macOS binaries. Run after `dist generate`;
running it again changes nothing.
"""
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/release.yml"
PERMISSIONS = """    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
"""
NOTARIZE = """      - name: Notarize macOS binaries
        if: ${{ runner.os == 'macOS' && needs.plan.outputs.publishing == 'true' }}
        env:
          APPLE_NOTARY_KEY: ${{ secrets.APPLE_NOTARY_KEY }}
          APPLE_NOTARY_KEY_ID: ${{ secrets.APPLE_NOTARY_KEY_ID }}
          APPLE_NOTARY_ISSUER: ${{ secrets.APPLE_NOTARY_ISSUER }}
        run: python3 scripts/notarize-macos.py --directory target/distrib
"""

text = WORKFLOW.read_text()
text = text.replace("uses: $/.github/workflows/container.yml", "uses: ./.github/workflows/container.yml")
job = "  custom-container:\n"
start = text.index(job)
uses = text.index("    uses: ./.github/workflows/container.yml", start)
if "    permissions:" not in text[start:uses]:
    text = text[:uses] + PERMISSIONS + text[uses:]
# The tap is shared by the organization's projects; commit as the account the
# token acts for, not as dist's vendor.
text = text.replace('GITHUB_USER: "axo bot"', 'GITHUB_USER: "github-actions[bot]"')
text = text.replace(
    'GITHUB_EMAIL: "admin+bot@axo.dev"',
    'GITHUB_EMAIL: "41898282+github-actions[bot]@users.noreply.github.com"',
)
# Notarization needs the hardened runtime, which dist passes to codesign only
# through CODESIGN_OPTIONS, and a step dist does not have.
identity = "      CODESIGN_IDENTITY: ${{ secrets.CODESIGN_IDENTITY }}\n"
if "CODESIGN_OPTIONS" not in text:
    text = text.replace(identity, identity + '      CODESIGN_OPTIONS: "runtime"\n', 1)
if "name: Notarize macOS binaries" not in text:
    attest = "      - name: Attest\n        uses: actions/attest@v4\n"
    if text.count(attest) != 1:
        raise SystemExit("could not find the Attest step of build-local-artifacts")
    text = text.replace(attest, NOTARIZE + attest)
WORKFLOW.write_text(text)
print(f"patched {WORKFLOW}")
