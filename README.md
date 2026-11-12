# Vero

Vero is a local-first tool for reviewing code changes and evaluating deterministic quality gates. It is independent of any orchestrator and exposes a CLI contract first.

## Status

Early Rust CLI and stdio MCP implementation. `vero review` captures Git changes into a content-addressed snapshot, resolves merge-base for `--base`, invokes configured CLI or OpenAI-compatible API reviewers with bounded execution, evaluates a local deterministic policy, and persists review records in SQLite under `.vero/vero.sqlite`. The configured `review.include` and `review.exclude` globs limit changed-file context sent to reviewers; all captured changes remain in the snapshot used for stale-review checks. Each textual changed file includes its baseline and captured contents so reviewers can reason about the actual change. Binary, non-UTF-8, and LFS pointer content is disclosed as omitted and makes reviewer analysis incomplete. Provider output must match [provider-findings-v1.schema.json](schemas/provider-findings-v1.schema.json). Vero assigns finding identity and model-inference provenance; providers cannot submit those fields. Reviewers with malformed output, nonzero exit, or timeouts make the review incomplete.

## Build

```sh
cargo build --workspace
cargo install --path crates/vero-cli --locked
cargo run -p vero -- init
cargo run -p vero -- review --base main --gate --output json
cargo run -p vero -- review --commit HEAD~1 --gate --output json
cargo run -p vero -- impact --commit HEAD~1 --output json
cargo run -p vero -- gate check --review rev_<id> --output json
```

Add a provider under `providers` and a reviewer under `reviewers` in `.vero.yaml`; reviewer instructions are read from the named file. The repository config follows [repository-config-v1.schema.json](schemas/repository-config-v1.schema.json). `review.max_concurrency` controls bounded parallel reviewer runs (default 4, range 1–32). Per reviewer, Vero sends at most 512 changed files and 512 KiB of combined baseline/source text, with a 128 KiB per-file combined limit. If matching changed files are omitted by these limits, the reviewer outcome is `context_limited` and the gate is incomplete. Repository-wide `review.include` and `review.exclude` globs apply first. Each reviewer can further narrow its context with its own `include` and `exclude` globs; exclusions win and an empty reviewer `include` inherits all repository-included paths. `kind: openai_compatible` selects an HTTP Chat Completions adapter with schema-constrained output, bounded response size, timeout, cancellation, no redirects, and no proxy environment use. Configure an explicit `endpoint`, `model`, and `egress`; `egress: local` accepts only localhost or loopback IPs and can be used with `offline: true`. Hosted endpoints must use `egress: network`. `OPENAI_API_KEY` is sent only when included in `env_allowlist`; it is the only environment variable accepted for this adapter. Credentials are not stored in YAML. Context is sent to the configured endpoint, so local execution alone does not imply offline inference. API responses are not cached yet. `kind: codex_cli` selects Vero's Codex-specific read-only contract. It runs `codex exec` with ephemeral state, ignores user config, uses `--sandbox read-only`, passes a temporary output schema, and sends the review prompt on stdin. `kind: gemini_cli` selects Gemini CLI headless mode (`--prompt`, `--output-format json`); Vero extracts only the envelope's `response` and validates it as findings JSON. `kind: claude_cli` selects Claude Code print mode with restricted mode, no session persistence, no tools, and schema-validated JSON output; Vero extracts only `structured_output`. All provider-specific adapters own their arguments and probe `--version`. Do not configure custom args or version args for them. Their review prompts prohibit edits and command execution; Claude’s restricted mode also disables command tools. These providers may still have network access and use external inference; set `egress: network` and use trusted CLI configuration. `kind: cli` remains available for generic executables that accept Vero's JSON request on stdin and return provider-findings-v1 JSON on stdout. A generic provider can declare `version_args` (for example `[--version]`) so Vero can capture its version with a bounded probe; without this declaration its version is reported as unknown. For example:

```yaml
review:
  max_concurrency: 4 # bounded reviewer parallelism; allowed range 1..=32
  include: ["**/*.rs", "**/*.go"]
  exclude: ["**/generated/**"]
providers:
  codex:
    kind: codex_cli
    egress: network
    executable: codex
    model: gpt-5-codex # optional
    env_allowlist: [PATH, HOME, CODEX_HOME]
reviewers:
  correctness:
    provider: codex
    instructions_file: .vero/reviewers/correctness.md
    include: ["src/**/*.rs"]
  security:
    provider: codex
    instructions_file: .vero/reviewers/security.md
    exclude: ["**/*_test.rs"]
```

Provider defaults can also live in a per-user `config.yaml`: `$XDG_CONFIG_HOME/vero/config.yaml` (or `~/.config/vero/config.yaml` when XDG is unset) on Unix-like systems, and `%APPDATA%/vero/config.yaml` on Windows. Set `VERO_CONFIG` to use a specific file. This file uses [user-config-v1.schema.json](schemas/user-config-v1.schema.json) and may define `version: 1` plus `providers`; repository provider entries override same-ID user entries. This lets a checked-in reviewer refer to a provider configured on the developer's machine. Effective merged provider settings participate in the review digest. Keep credentials outside both config files: use environment variables named by `env_allowlist` or an OS secret store.

Vero reuses a successful reviewer response only when the complete request, provider version, executable content, model, arguments, limits, and allowlisted environment-value digest match. Providers without a declared or probed version are never cached. Failed and invalid responses are not cached. Cached outcomes are reported as `cached` and count as completed reviewers. Allowlisted environment values are hashed into review freshness identity, so changing a credential or endpoint invalidates the previous gate without writing the value to storage.

Use repeated `--reviewer <id>` flags to run only selected enabled reviewers, for example `vero review --base main --reviewer correctness --reviewer security --gate`. Without flags, every enabled reviewer runs. Selection is recorded in the review and included in its effective configuration digest; leaving a policy-required reviewer out makes the analysis incomplete. MCP `review_changes` and `start_review` accept an optional `reviewer_ids` string array with the same semantics. The generic provider receives one JSON document on stdin with snapshot ID, reviewer ID, instructions, and changed paths. Providers run from an empty, disposable working directory, so relative file access does not expose or modify the repository. A configured executable containing a relative path is resolved against the repository before the working directory changes. This is defense in depth, not an OS sandbox: a provider running as the current user can still access absolute paths and use any explicitly allowed environment values. Configure required environment variable names with `env_allowlist`; Vero resolves values from the invoking process, clears other inherited values, and does not persist the values. Vero invokes executables without a shell. Provider `egress` defaults to `network`; set `offline: true` at the configuration root to reject network providers during configuration validation. A generic executable must be declared `egress: local` to be accepted in offline mode. That declaration classifies the adapter but does not provide OS-level network isolation; only use it for a provider you have configured to run locally. The Codex CLI adapter is always classified as network-backed. See the [Codex CLI non-interactive mode documentation](https://learn.chatgpt.com/docs/non-interactive-mode) for its `exec` contract.

Named policy profiles can be defined under `policy_profiles`; each profile uses the same fields as `policy` and is selected with `vero review --policy-profile strict`. The chosen profile is stored in the review and restored by `gate check`. MCP `review_changes` and `start_review` accept the optional `policy_profile` field. The trusted local `.vero/policy.yaml` is applied after profile selection, so a profile cannot weaken protected requirements.

For repositories where policy must not be weakened by checked-in configuration, maintainers can provide a trusted local `.vero/policy.yaml`. It can add required reviewers and verification profiles, add blocking severities, require a higher confidence threshold, and require incomplete analyses to block. Repository config may strengthen these settings, but cannot weaken them. Requirements must name reviewers and verification profiles already declared in `.vero.yaml`; malformed protected policy fails configuration. The merged effective configuration is fingerprinted, so edits invalidate prior gate approvals. Keep this file in the local checkout's `.vero` directory and provision it through the repository owner's trusted setup process.

Exit codes: `0` pass (and top-level help/version), `1` block, `2` incomplete or execution failure, `3` usage/configuration failure. JSON output is one versioned document on stdout; review summaries and diagnostics go to stderr. JSON errors use the versioned `cli-error-v1` schema and identify `usage_error`, `configuration_error`, or `execution_failed`.

Use `vero review --markdown /tmp/review.md` to write a portable Markdown report alongside the normal text or JSON stdout result. It includes the gate decision, reviewer outcomes, findings, locations, provenance, and evidence references. Provider/model text is escaped as Markdown content. If you save the report inside the checkout, Git may treat it as a source change and make a later gate recheck stale; place it outside the checkout or in an ignored path.

`gate check` reloads the stored review, recaptures its recorded Git scope, recomputes the effective config and reviewer-instruction digest, and rejects the decision as incomplete if either source or review inputs changed. `.vero.yaml` is excluded from the source manifest and fingerprinted in effective configuration separately. Gate decisions and gate-check responses expose the effective configuration digest separately from the policy digest, and the decision identity binds both. Gate-check JSON follows [schemas/gate-check-v1.schema.json](schemas/gate-check-v1.schema.json).
`vero gate history --review <review-id> --output json` lists immutable gate decisions recorded for that review, including rechecks after verification evidence changes.
Use `vero reviews list --output json` to find persisted reviews and `vero reviews show <review-id> --output json` to retrieve the full record. The list response follows [schemas/reviews-list-v1.schema.json](schemas/reviews-list-v1.schema.json); review output v2 records reviewer provider ID, adapter kind, configured model, and probed Codex CLI version in addition to status. See [schemas/review-output-v2.schema.json](schemas/review-output-v2.schema.json); v1 remains available for existing consumers.
Export a persisted review as SARIF 2.1.0 with `vero reviews export <review-id> --format sarif`. The document is written to stdout, findings are ordered by stable fingerprint, and source paths are emitted as URI references. Severity maps to SARIF levels (`critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`); Vero fingerprints, confidence, provenance, and evidence IDs are retained as result metadata. The output follows the [OASIS SARIF 2.1.0 specification and schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

## Impact analysis

`vero impact --base main --output json` reports changed Go/Rust declarations, likely textual references, heuristic package membership, likely test references, and source line evidence. Every inferred relationship is labeled, and the response includes known limits and a `coverage_complete` flag. The first adapter is syntax-light and does not model dynamic dispatch, generated code, or runtime interactions. JSON follows [schemas/impact-assessment-v1.schema.json](schemas/impact-assessment-v1.schema.json).

`--commit <ref>` reviews one immutable commit against its first parent (or the empty tree for a root commit). `--commit <from>..<to>` reviews a range against its endpoint tree. Sources come from Git trees, independent of later worktree edits. Commit scopes can be passed to `review` and `impact`; gate rechecks recapture the same commit or range. MCP clients use `scope: "commit"` and pass the ref or range in `commit`.

## Finding lifecycle

Findings persist across reviews by fingerprint. Their status can be inspected and updated with a required rationale:

```sh
vero findings list --severity high --status open
vero findings show find_<id>
vero findings set-status find_<id> --status verified --reason "Confirmed against the source"
```

The show and JSON list outputs include occurrence history with review and snapshot IDs. Reobserving a resolved or waived finding reopens it; verified and refuted statuses remain intact for maintainer review.

Waivers are separate audit records and are bound to one finding fingerprint and one immutable review snapshot. They require a reason and author and expire after 30 days by default:

```sh
vero waivers create find_<id> --review rev_<id> --reason "Accepted until the next release" --author "maintainer" --expires-in-days 7 --output json
vero waivers list --review rev_<id> --output json
vero gate check --review rev_<id> --output json
```

The gate records applied waiver IDs in its evidence digest and explains which finding was waived. An expired waiver no longer suppresses a blocking finding. Any source change that produces a different snapshot makes the old review stale; create a new waiver against the new review if the exception still applies. The author is caller-supplied attribution, and the recorded provenance identifies the local CLI.

## Explicit verification

Verification profiles are repository-defined argument vectors and run only when explicitly selected. Vero invokes the configured executable directly, with no shell expansion, bounded time and output, and a null stdin. Results store the snapshot ID, command digest, exit status, and output digests in SQLite.

```yaml
verification:
  unit:
    executable: cargo
    args: [test, --workspace]
    env_allowlist: [CARGO_TERM_COLOR]
    timeout_seconds: 300
    output_limit_bytes: 1048576
policy:
  required_verifications: [unit]
```

Run a snapshot-wide profile with the same scope as the review, for example `vero verify --profile unit --base main --output json`. To associate a check with a finding, pass its ID: `vero verify find_<id> --profile unit --output json`; Vero verifies the exact latest occurrence snapshot and rejects stale findings. Finding-scoped runs do not satisfy snapshot-wide required verification profiles. Inspect the saved record with `vero verification show <run-id> --output json`. Bounded stdout/stderr are stored as content-addressed files under `.vero/artifacts/sha256/`, referenced by the run and SQLite artifact index. Values from configured environment allowlists are redacted before hashing and storage. A passed command exits `0`, a completed command that reports failure exits `1`, and a timeout exits `2`. Provider and verification configurations use `env_allowlist` variable names; Vero resolves values from the invoking process and clears all other inherited environment variables. Put credentials in the shell or OS secret store, never in `.vero.yaml`. Verification configuration contributes to the effective review configuration digest. Required profiles must have a latest successful result for the exact review snapshot. A newer failed or timed-out run makes the gate incomplete. Vero recaptures the selected source scope before and after each verification command and refuses to persist evidence if the snapshot is stale or changed during the command. Staged-scope verification also requires the checkout to match the index and have no non-ignored untracked files, because commands execute in the checkout. The gate output records the selected verification run IDs and their evidence digest.

The JSON contract is defined in [schemas/verification-run-v1.schema.json](schemas/verification-run-v1.schema.json). Artifact paths are relative to the repository root and content-addressed by their SHA-256 digest.

## MCP stdio server

Run `vero mcp serve --transport stdio` inside a Git checkout to expose review operations to MCP clients. Tools include `review_changes` (`staged`, `working_tree`, `base` with a base ref, or `commit` with a commit ref), `start_review` (task-capable asynchronous review with status polling and cancellation), `list_findings` (filters and SQL-bounded pagination with a filtered `total` count), `get_finding` (including lifecycle and occurrences), `get_review`, `get_repository_context` (bounded path reads from an identified immutable review snapshot, with optional symbol-line matching, repository-root confinement, and untrusted-source labeling), `analyze_impact`, `verify_finding` (runs a configured verification profile only when the finding's source snapshot is still current), and `evaluate_gate` (recaptures the reviewed scope, checks source and effective config freshness, reevaluates policy, and persists the decision). The server is pinned to `klarlabs-mcp` 0.1.0 and uses the 2026-07-28 discovery lifecycle. Its database is confined to the current checkout's `.vero/vero.sqlite`; it does not accept repository paths from the client.

The CLI and MCP review, verification, impact, and gate paths call the same `vero-application` services. Task cancellation is cooperative: Vero terminates the active provider child process; snapshot capture and local database operations complete or fail at their next synchronous boundary.
