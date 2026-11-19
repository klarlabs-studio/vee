---
name: vee-local-review
description: Run an independent Vee review of local changes and interpret its deterministic gate result.
---

# Vee local review

Use Vee as an independent reviewer after implementation and before declaring the task complete.

0. If this is the first review on this machine, run `vee doctor` (MCP: `check_setup`). It exits 2 with next steps when a reviewer cannot run; `vee init` configures a provider from the local model, agent CLI, or API key it detects.
1. Select the intended scope explicitly: `vee review --base <base> --gate`, `vee review --staged --gate`, or `vee review --working-tree --gate`.
2. Preserve stdout JSON as machine-readable output when using `--output json`; diagnostics belong on stderr.
3. Interpret exit codes: 0 passed, 1 blocked, 2 incomplete or execution failure, 3 invalid invocation/configuration. Incomplete is never a pass.
4. Inspect findings and evidence with `vee findings list --review <id>` (paged; follow `--offset` while `total` exceeds the page) and `vee findings show <id>`; check reviewer outcomes and snapshot identity.
5. A blocking ID starting with `analyzer:` comes from a trusted static analyzer, not a model: inspect it with `vee verification findings <run-id>` (MCP: `get_analyzer_findings`) and fix it like a failing check. Rerun the analyzer (`vee verify --profile <profile>` on the same scope) before re-reviewing.
6. If files or effective policy change after a pass, rerun the review. Do not reuse a prior gate decision for a modified snapshot.

Do not ask Vee or another model to self-approve. The gate is determined by stored evidence and policy, not reviewer prose.
