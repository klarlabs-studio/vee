#!/usr/bin/env python3
"""Fix dist's generated release workflow.

dist 0.34 renders a local post-announce job with the path "$/.github/..." and
without the permissions the called workflow needs, and commits the Homebrew
formula to the shared tap as its own vendor's bot. Run after `dist generate`;
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
WORKFLOW.write_text(text)
print(f"patched {WORKFLOW}")
