---
name: vero-local-review
description: Run an independent Vero review of local changes and interpret its deterministic gate result.
---

# Vero local review

Use Vero as an independent reviewer after implementation and before declaring the task complete.

1. Select the intended scope explicitly: `vero review --base <base> --gate`, `vero review --staged --gate`, or `vero review --working-tree --gate`.
2. Preserve stdout JSON as machine-readable output when using `--output json`; diagnostics belong on stderr.
3. Interpret exit codes: 0 passed, 1 blocked, 2 incomplete or execution failure, 3 invalid invocation/configuration. Incomplete is never a pass.
4. Inspect findings and evidence with `vero findings list --review <id>` and `vero findings show <id>`; check reviewer outcomes and snapshot identity.
5. If files or effective policy change after a pass, rerun the review. Do not reuse a prior gate decision for a modified snapshot.

Do not ask Vero or another model to self-approve. The gate is determined by stored evidence and policy, not reviewer prose.
