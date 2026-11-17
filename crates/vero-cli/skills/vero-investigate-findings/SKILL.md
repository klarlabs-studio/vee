---
name: vero-investigate-findings
description: Investigate a structured Vero finding against its source snapshot, evidence, and impact before deciding how to address it.
---

# Investigate Vero findings

1. Retrieve the complete finding using `vero findings show <finding-id>` or MCP `get_finding`.
2. Read the referenced source and evidence from the finding's review snapshot. Confirm the location still corresponds to current files.
3. Use `vero impact` or MCP `analyze_impact` to inspect downstream paths and uncertainty.
4. Classify the claim: reproduced by verification, supported by deterministic analysis, model-inferred, refuted, or inconclusive. Do not upgrade inference to verification based on plausibility.
5. If information is missing or the snapshot is stale, rerun review/verification rather than guessing.

Do not dismiss a finding solely because a model says it is low confidence. Use repository behavior and reproducible evidence; preserve uncertainty in the explanation.
