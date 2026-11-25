---
name: vee-requirement-traceability
description: Trace explicit work-item acceptance criteria to a Vee review snapshot, inspect candidate source and test links, and record bounded human assessments.
---

# Requirement traceability with Vee

Use this workflow when a task has acceptance criteria and you need to show how the reviewed change relates to them.

1. Run or identify a Vee review for the exact change under consideration.
2. Generate the traceability report with `vee acceptance report --review REVIEW_ID --output json` or MCP `acceptance_traceability`.
3. Check the report's snapshot ID, work-item digest, limitations, and criterion text. Candidate changed paths and Go/Rust changed-symbol-to-test links are navigation hints, not proof that a criterion is met or covered.
4. Inspect the referenced source and test evidence yourself. Run only verification profiles configured or explicitly authorized by the user; attach results through Vee's verification workflow.
5. If a human assessment is required, create a mapping bound to the exact review ID, snapshot ID, and work-item digest using `schemas/acceptance-mapping-v1.schema.json`. Include author, timestamp, rationale, relevant changed paths, and only valid verification run IDs.
6. Validate it with `vee acceptance validate --review REVIEW_ID --mapping mapping.json --output json`. Treat the result as a traceability attestation, not as a Vee gate decision or self-approval.
7. Re-review after any source or relevant configuration change. A mapping for an older snapshot is stale and must not be carried forward as current evidence.

Do not claim that an inferred path, likely test reference, model statement, or human mapping proves correctness. Report uncertainty and missing evidence explicitly; the deterministic Vee gate remains the authority for policy acceptance.
