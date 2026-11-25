#!/usr/bin/env python3
"""Fix the container job in dist's generated release workflow.

dist 0.34 renders a local post-announce job with the path "$/.github/..." and
without the permissions the called workflow needs. Run after `dist generate`;
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
WORKFLOW.write_text(text)
print(f"patched {WORKFLOW}")
