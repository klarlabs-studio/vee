# Local historical review benchmark

**Status:** Local runner available; six initial debugging cases plus an independently reproduced lockout case across local MIT repositories; representative corpus remains open  
**Date:** 2026-11-16

### Local Gemma 3 rerun (2026-11-17)

A follow-up run used the installed `gemma3:12b` model through loopback Ollama,
with offline mode enabled and a trusted reviewer-instruction overlay. The
runner completed five of six cases before the final case exceeded the
operator's ~20-minute timeout configuration and was interrupted before that
per-case bound. Five reports were present: three completed Go cases matched
0/3 labels, and two Go cases were incomplete and excluded from recall. A
TypeScript case was not reached; it is outside the Go-only config scope, but
this run did not produce evidence about its behavior. Of the completed Go
cases, one emitted 12 findings and two emitted none. An incomplete Go case
emitted 25 findings; these are machine-produced counts, not human-verified
false-positive labels.

The run confirms a local product-quality gap: the reviewer missed all three
curated defects in completed supported cases, and two additional supported
cases were incomplete. It does not establish comparative model quality or broad-language
performance; this is a six-case corpus, one language was out of scope, and the
last case did not finish. Gemma 4's earlier six-case local run also matched 0/6,
but the two model runs are small diagnostic samples, not a general benchmark.
Raw per-case reviews remain outside the repository at
`/tmp/vee-local-benchmark-2026-11-16/consolidated-six/results-gemma3-local-overlay-2026-11-17/`;
there is no complete aggregate report for this interrupted run.

The runner's scope and interruption reporting gaps have since been addressed
and locally accepted. The next quality step is to expand curated labels and
improve local review signal with evidence that can be independently checked.
Keep all source, inference, and artifacts on the developer machine; local
execution is the product constraint, not a hosted benchmark service.

### Local concurrent-lockout review result (2026-11-17)

A seventh private case was added outside the Vee checkout from the local
MIT-licensed `auth-go` history. It reviews lockout implementation commit
`786b3b22c919032a00e62dd040cd04e5d8866577`; the curator label covers the
non-atomic read/increment/write in `domain/lockout.go:166-172`. The later fix
`de8d98a432e1f17593845eb07abfc55334cffcb5` adds atomic store implementations
and a 20-way concurrency regression test. The label was independently checked
with a temporary barrier-backed test in disposable worktrees: on the buggy
commit, 20 simultaneous failures deterministically left the count at 1 and did
not engage a 5-failure lock; on the fixed commit the same test passed with all
20 increments. Both runs used `go test -race` with `GOPROXY=off` and
`GOSUMDB=off`.

Two full-Go-scope reviews then ran against that exact case through local Ollama
with `offline: true` and the same trusted instructions. Gemma 4 e4b completed
in about 400 seconds, missed the label, and emitted one unmatched critical
finding claiming a duplicate `DeleteByUser` method; inspection of the pinned
source showed no such method at the reported locations. Gemma 3 12B completed
in about 174 seconds, missed the label, and emitted no findings. The initial
Gemma 4 run with a domain-only filter was discarded as a scope comparison
because it excluded the changed storage adapters; expanding the trusted config
to all Go files did not fix the miss. Reports and the digest-pinned private
manifest remain under `/tmp/vee-local-benchmark-2026-11-16/` and are not part
of this repository.

This is one MIT-licensed historical example, not a calibrated metric. It shows
that successful local provider execution still does not establish useful
review quality: both local models missed a reproducible concurrency security
defect, and one produced an unsupported critical claim. The product-quality
work remains open: add independently adjudicated cases across the existing
local checkouts, measure false positives as well as strict recall, then test
review-context and reviewer changes against the same private corpus. The
benchmark report records that egress mode is declared by the trusted config;
strict isolation from network access still requires OS-level controls.

#### Direct Ollama-native rerun (2026-11-17)

After adding the explicit local `ollama_native` adapter, the same pinned buggy
commit was reviewed again through Ollama's native chat API with a 96,000-token
context window. The benchmark completed one of one cases with full source
context for the labeled `domain/lockout.go` path. `gemma3:12b` used 39,939
input tokens and 13 output tokens over 267.9 seconds, returned no findings,
and passed the configured gate. Strict recall remained 0/1; there were no
unmatched findings in this run. This confirms that the large-context request
completed through the native adapter, but it did not improve detection of this
defect.

The local Ollama process reported `gemma3:12b` at context length 96,000 while
the review ran. The trusted config selected `ollama_native`, `offline: true`,
and the loopback endpoint `http://127.0.0.1:11434/api/chat`. The report itself
continues to describe egress as declared rather than independently verified;
no OS-level network restriction was applied. Report and review JSON are under
`/tmp/vee-local-review-2026-11-17/results-gemma3-native-96000/`. The review
JSON digest is
`sha256:ff1e6b038f88845f9754a566b4058db6c30979e9c5f41558cc682a6ea0359cc7`,
the source snapshot is
`sha256:ade20c7927476948faacc5bf9f407e5195a0ff6f55461bbe14a91b5054d8501c`,
and the benchmark config digest is
`sha256:c22751051726a82d8778cf5b926365d58974ba2c73660083c2dff839255bc8eb`.
Validating the aggregate against its published schema exposed a runner defect:
`verifier_digest` lacked the required `sha256:` prefix. The runner now emits the
schema-defined format, its adversarial local acceptance passes, and this
completed report was normalized to that format and validated against the
schema. The source checkout and benchmark corpus remain outside Vee.

### Local reviewer reasoning probe (2026-11-17)

Two additional full-scope Gemma 4 e4b runs used the same pinned lockout case,
snapshot, and context. The first received an instruction overlay asking for a
concrete request interleaving and confirmation across relevant implementations.
It completed in about 249 seconds, missed the lockout label, and reported a
high-severity race in the unchanged PostgreSQL `MarkConsumed` implementation;
because this finding was outside the changed lines, the runner correctly marked
the case incomplete. The second overlay additionally required checking whether
the interleaving crosses an authentication or lockout boundary and confirming
the source location. It completed in about 204 seconds with no findings, again
missing the label. Thus, the stricter prompt removed the unmatched report but
did not recover the defect. This one-case probe does not validate either prompt
as a default or support a recall claim. Full reports remain in local `/tmp`
directories `results-gemma4-lockout-interleaving` and
`results-gemma4-lockout-interleaving-verify`; neither contains repository source
outside the user's machine.

### Local test-proposal generation probe (2026-11-17)

Vee's snapshot-bound `vee tests generate --commit` workflow was tried against
the same disposable buggy auth-go revision with local Gemma 4 e4b. The provider
request timed out at its configured 600-second bound and returned a structured
`execution_failed` response; it did not save a patch proposal or execute a
command. The run used the 2 MiB review context ceiling and included all changed
Go files. This indicates that bounded bytes alone do not ensure a practical
context size for local generation on this machine. A next implementation step
is impact-guided, token-aware context selection for test generation, with
explicit omissions and snapshot provenance, followed by this same local
buggy/fixed acceptance. The experiment and worktree stayed under `/tmp`.

Vee now has a `test_generation.max_context_tokens` ceiling (default
20,000, configurable from 1,024 to 131,072). Test generation prioritizes
changed source/test pairs and then impact-linked tests and source files. Its
request includes context roles, content digests, estimated prompt tokens, and
omitted-path counts; it stops before provider execution when the bounded
context estimate exceeds the configured budget. The estimate is serialized JSON character
count divided by three plus reserved space, so it is deliberately approximate
and is not a guarantee about a provider's tokenizer or model window. Formatting
and workspace compilation passed on macOS arm64. Runtime checks found that
12,000 tokens was too small by about 60 estimated tokens and 16,000 was still
too small by about 80 tokens for this pinned change manifest. At 20,000 the
context guard passed and local Ollama received the request, but Gemma 4 e4b
exceeded the configured 600-second timeout and returned `execution_failed`.
No proposal was saved and no command was run.

Follow-up probes lowered the context budget to 8,000 and the provider timeout
to 180 seconds on the same disposable fixture. They exposed implementation
issues: the estimate had omitted its own budget metadata, the selection order
favored large changed test files before changed implementation files, and
alphabetical source ordering could crowd the changed implementation out of a
tight budget. The estimate now includes budget metadata and reserves the full
possible omission manifest; changed implementations paired with changed tests
are prioritized, then smaller source files, before test files. A local fake-
provider acceptance with twelve oversized changed files and a 2,048-token cap
now completes the proposal/apply/refine lifecycle and asserts both the bounded
estimate and explicit content omissions.
After those fixes, one Gemma 4 e4b request and one Gemma 3 12b request passed
the context guard but timed out at 180 seconds. Earlier 8,000-token runs
returned malformed unified diffs (`corrupt patch at <stdin>:10`); Vee rejected
them and saved no proposal. Stronger unified-diff instructions were added, but
the later runs timed out before producing a validated proposal. After improving
source selection, Gemma 4 e4b returned in about 50 seconds but still produced
no parseable patch; Vee rejected it and saved no proposal. The benchmark
checkout's original configuration was restored after the probes.

The context-budget checks and bounded failure paths are exercised, but
successful local generation is still not accepted for this eight-file change
on this machine. The 20,000-token default remains for this revision; improving
local generation quality and latency requires another successful,
artifact-inspected run rather than treating a smaller prompt or timeout as
evidence of success.

### Offline verification profile comparison (2026-11-17)

The trusted `go-tests` profile ran `go test ./...` through Vee's new
commit-isolated verifier on the pinned auth-go magic-link buggy and fixed
revisions. The machine had Go 1.27.4 on macOS arm64. `GOPROXY=off` and
`GOSUMDB=off` were passed through the explicit environment allowlist, so the
verification could not retrieve missing Go modules. The buggy revision passed
its available suite (snapshot `sha256:1bf85a72625a5f77c74ae96b60cbc2acbb676122efd10f6b29c0da85869a437a`,
run `sha256:968fbcdc2fc5d95664a799d016d13d95c07b32360696326989744d1fdc3da339`).
The fixed revision exited unsuccessfully because `modernc.org/sqlite v1.52.0`
was not in the local module cache (snapshot
`sha256:0a559fd260ae78ca3e51b87f39d1e7f2449e4fba5583cfab7118189ddd7a3cec`,
run `sha256:4f719d4afc12f696b02aeed46a78418f05cddd4baf4b78879bd5b809bdcfd04`).
This is a missing local prerequisite, not evidence that the fix's tests fail,
and it does not reproduce the concurrency defect by itself. Vee now recognizes
this exact Go diagnostic as `incomplete` (exit code 2), preserving the result as
“tests could not start” rather than “tests failed.” A focused local unit check and
the historical review acceptance pass cover this distinction; the offline corpus
itself remains blocked until the module is already present in the local cache. The paired raw
reports and content-addressed output artifacts are under
`/tmp/vee-local-benchmark-2026-11-16/auth-go-magiclink-corpus/results-offline-go-tests-2026-11-17/`.

This dogfood run confirms that commit verification uses the selected revision
even when the current checkout differs. It exposed a usability gap for offline
repositories: dependency resolution could be reported as a test failure even
when tests never started. Vee now classifies the observed Go module-lookup
messages and Cargo's explicit offline HTTP-request diagnostic as `incomplete`,
while preserving raw output and keeping generic nonzero exits as `failed`. The
focused Go and Cargo marker checks pass; the real fixed-revision corpus remains
incomplete until the missing module is already available locally.

#### Reviewer-context coverage integrity (2026-11-17)

The current review JSON records the full change-set manifest, but that is not
the same as the source context delivered to a reviewer: repository and
reviewer include/exclude rules, context budgets, binary files, and truncation
can omit changed files. Vee now emits an additive `reviewer_context` manifest
with per-reviewer changed paths, context roles, full-source/diff/metadata-only
status, filter or budget omissions, and digests of supplied context artifacts.
The benchmark counts a label only when at least one completed reviewer received
its file in full; missing provenance or filtered/partial labeled files make the
case incomplete instead of distorting recall. The manifest contains paths and
digests rather than source text and remains local with the review report.

The runner accepts repeatable `--scope-language` declarations for Go, Rust,
TypeScript, JavaScript, Python, Java, and Ruby, and counts out-of-scope cases
separately. It preserves valid JSON from Vee block/incomplete exit codes and
writes an aggregate report when interrupted. Its local acceptance fixture
covers TypeScript, Python, Java, and Ruby labels under a Rust-only scope. This
is an operator declaration; the runner does not prove that the trusted config's
include globs match it.

The expanded language-scope acceptance passed on macOS with
`python3 scripts/acceptance/historical_review_benchmark.py target/debug/vee`.
Its six synthetic cases included two Rust cases that completed, one TypeScript
case and Python/Java/Ruby cases that were each correctly reported out of scope,
and an unchanged strict-recall result of 1/2 for the completed Rust labels.
The fixture also retained wrong-line localization diagnostics and continued to
reject repository-controlled configuration symlinks, checkout hooks, smudge
filters, trusted-file traversal, and symlinked overlay targets. These are
benchmark-contract checks; the deliberately wrong-line Rust case is not a
review-quality metric for real repositories.

### Generic review-checklist experiment (2026-11-17)

A generic checklist was temporarily added to the local review prompt, then
compared against the prior prompt with Gemma 3 12B through offline loopback
Ollama and the same trusted reviewer config. On three completed Go cases,
strict recall remained 0/3. The circuit-breaker case still emitted no findings
(about 210 seconds versus 208 seconds and 26,594 versus 26,509 input tokens).
The WebAuthn case also remained empty. The concurrent magic-link case grew from
12 to 23 findings and from about 314 to 380 seconds, but still matched none of
the curated label; many added findings were informational maintainability or
reliability notes. The generic checklist was therefore reverted. These results
do not establish that prompting cannot help, but this experiment gave no
evidence to ship that prompt change.

The matched manifests and reports are local under
`/tmp/vee-local-benchmark-2026-11-16/consolidated-six/`. The next useful
quality work is to improve evidence/context selection or add trusted local
verification signals, then evaluate on a broader curated corpus. Do not count
more model-generated comments as progress without adjudicated label matches
and actionable-finding review.

## Purpose

Measure whether configured Vee reviewers identify defects in real historical
changes. This is a reviewer-quality benchmark, separate from
`vee tests effectiveness-corpus`, which measures whether a trusted test profile
catches supplied mutants.

The benchmark runs from a local manifest over repositories already present on
disk. It does not fetch datasets, upload source, require an account, or depend on
a hosted Git service. A configured AI provider may still use its own network;
Vee must report that execution mode clearly, and an offline profile must reject
network-backed providers.

## Case model

Each case must identify an immutable defect-introducing commit and a reviewed
label set. The runner checks out the commit in a disposable local worktree and
asks Vee to review the commit relative to its parent. The case records the
upstream project and revision, applicable source license, optional defect and
fix references, an optional pinned fix commit, and a digest of its label file.
When supplied, the fix commit must exist in the local checkout. Corpus metadata is provenance supplied by the
corpus curator; Vee cannot authenticate a license claim.

Labels should point to the defect-introducing changed lines and include a defect
category plus a short curator rationale. Cases without a defensible location or
whose buggy revision cannot be built/reproduced are excluded or explicitly
marked non-reproducible; they must not silently count as reviewer misses.

The corpus is a local directory containing a versioned manifest and labels.
Repository paths must resolve beneath a user-selected corpus root, and each Git
revision must already exist locally. The runner rejects path escapes,
mutable branch names, duplicate case IDs, oversized manifests, and unpinned
revisions. It must never run project build scripts or tests as part of review
unless the user separately selects an explicit trusted verification profile.
Labels are checked against the defect commit: each labeled file must be changed
by that commit, and the labeled line range must exist in the pinned file.
Merge commits are rejected until their comparison-parent semantics are
explicitly selected.

The runner is available as `scripts/historical-review-benchmark.py`. It creates
a detached temporary Git worktree for each case, invokes Vee's normal review
command, removes the worktree, and writes the complete Vee JSON review next to
the aggregate report. It replaces the checked-out commit's `.vee.yaml` with
the explicitly supplied trusted `--config` for the duration of the review, so
untrusted benchmark source cannot choose a provider executable or egress mode.
Reviewer instruction files may be selected by that config and are read as
untrusted repository text. A case is complete only when Vee
reports `analysis_complete: true` and a non-incomplete review status.

Example corpus layout:

```text
my-corpus/
  manifest.json
  benchmark.vee.yaml   # trusted local config, outside the subject checkout
  labels/
    project-bug-001.json
  checkouts/
    project/             # already cloned locally; commit must exist here
```

The manifest uses `schemas/historical-review-corpus-v1.schema.json`; label
files use `schemas/historical-review-labels-v1.schema.json`. Pin the label file
bytes with `labels_digest` (`sha256:<hex>`). Run the corpus with:

```sh
python3 scripts/historical-review-benchmark.py \
  --manifest /path/to/my-corpus/manifest.json \
  --corpus-root /path/to/my-corpus \
  --config /path/to/my-corpus/benchmark.vee.yaml \
  --vee /path/to/vee \
  --output-dir /path/to/local-results \
  --reviewer correctness
```

The command exits `0` when every case completed, `2` when any case was
incomplete, outside declared language scope, or could not run, and `2` for invalid corpus input. Declare the languages covered by the trusted review config with repeatable `--scope-language` options (for example, `--scope-language go`). Cases whose labeled source language is not declared are reported as `out_of_scope`, excluded from recall, and counted separately. This declaration is operator-supplied; the runner cannot prove that config include patterns actually cover the full language.
A nonzero code
does not discard partial results. Review JSON and the aggregate
`historical-review-report-v1.json` remain in the selected local results folder.
The aggregate is checkpointed when the operator interrupts the run. A timed-out
case is marked `timeout` with elapsed time; a valid partial review document, if
available, is stored separately from a complete review. Valid structured Vee
reports are retained when the review command exits with its documented block or
incomplete status codes.
When `--verify-profile` is explicitly selected, bounded stdout and stderr
artifacts for the buggy and optional fixed revisions are copied into the local
results folder. The runner verifies each declared size and SHA-256 before
copying and records relative paths and digests in the aggregate report.
Verification logs can contain repository or environment details; keep the
results folder local and handle it with the same care as the checkout.
The report preserves strict recall and adds
`labels_with_localization_candidates` plus per-case
`localization_candidates` as separate diagnostics.
The trusted config's content digest is recorded in the report. Set `offline:
true` and local provider egress in that config to reject adapters declared as
network-backed. The report says egress was declared in the trusted config; it
does not independently verify network activity by a generic CLI provider. A
local executable may itself contact a service, so use a local inference adapter
and OS-level network restrictions when strict offline execution is required.

Compare saved runs locally without re-running providers or loading the corpus:

```sh
python3 scripts/compare-historical-reviews.py \
  /path/to/run-a/historical-review-report-v1.json \
  /path/to/run-b/historical-review-report-v1.json \
  --output /path/to/local-comparison.json
```

The comparator reads only the selected report files. It lists provider/model,
reviewer, configuration, corpus-manifest, Vee, and runner identities, then
compares case IDs shared by every report. A case is marked comparable only
when every run completed and label counts agree. It retains per-run matches,
misses, unmatched findings, and localization candidates; it does not pool
different cases into an aggregate quality score. Saved report contents and
curator-supplied identities are trusted inputs, not authenticated attestations.

Historical repositories may not contain Vee reviewer instructions. Supply a
trusted local instruction file without changing the pinned historical commit
using a repeatable overlay argument:

```sh
python3 scripts/historical-review-benchmark.py \
  --manifest /path/to/my-corpus/manifest.json \
  --corpus-root /path/to/my-corpus \
  --config /path/to/my-corpus/benchmark.vee.yaml \
  --trusted-file .vee/reviewers/correctness.md=/path/to/my-corpus/correctness.md \
  --vee /path/to/vee \
  --output-dir /path/to/local-results \
  --reviewer correctness
```

`TARGET` must be a safe repository-relative path; `SOURCE` must be a regular,
non-symlink local file no larger than 1 MiB. Vee copies the explicitly named
file only into each disposable worktree, rejects symlinked target paths, and
removes it with that worktree after the review. The trusted config should point
its `instructions_file` at `TARGET`. The historical repository and commit stay
unchanged, and no instruction file is added to the corpus manifest or Vee's
repository.

## Evaluation

Run the normal `vee review --commit <oid> --output json` path with the selected
reviewers and provider configuration. Preserve the exact CLI and provider
identity, Vee version, selected reviewer IDs, commit, label digest, effective
configuration digest, review JSON digest, and completion state in each result.
Incomplete provider runs remain incomplete and are excluded from recall
denominators while being counted separately.

Report strict finding-level recall against curated labels, unmatched finding
count, per-case completion, and label/finding matching details. Strict matches
require the changed file, overlapping defect-introducing line range, and
compatible category; allow curator-defined aliases where taxonomy differs. The
report also lists same-file/category localization candidates when a finding
misses the labeled line (or omits its line). These candidates are diagnostic
only: they do not count as matches or increase recall. This helps distinguish a
defect a reviewer may have recognized but mislocated from one it did not report,
without weakening the benchmark score. Do not compress the outcome to one
“quality score”: include numerator and denominator, localization candidates,
unmatched findings, incomplete cases, and corpus composition. These metrics are
observational and depend on the selected provider, model, prompt, and corpus.

Human adjudication is required for ambiguous matches and false positives.
Benchmark outputs stay in the chosen local results directory and redact
provider credentials. Reports must distinguish an empty completed review from
an incomplete one.

## Dataset selection and licensing

Start with a small, curated set that has explicit redistribution/use terms and
reproducible revisions. Dataset presence in Vee does not grant rights to
redistribute the subject repositories. Keep downloaded or cloned source outside
the Vee repository unless each project's license permits bundling it. A
corpus entry records both benchmark license and subject-project license
references when they differ. The initial implementation should accept
user-supplied local checkouts and labels rather than bundle third-party source.

Defects4J may be evaluated as an optional Java source: its harness repository
is MIT-licensed, but each subject project's files retain their own licensing
terms. BugsInPy is not suitable for bundling until its missing license status
is resolved. These are candidate sources, not endorsements or included data.

### Curating from an already-installed Defects4J checkout

This is a manual, local-only intake workflow; Vee does not install Defects4J,
download projects, or turn inferred locations into accepted labels. Use the
Defects4J checkout and project repositories that you have already installed
under their applicable terms. Record the harness revision and the subject
project license separately in your private corpus manifest.

For each selected bug, obtain the full buggy and fixed revision IDs from the
local Defects4J metadata/CLI, then resolve them to full Git object IDs in that
project's local repository. Keep only non-merge buggy commits with one parent,
because the benchmark compares the buggy commit to that parent. Confirm that
the fixed revision is a descendant before recording it as `fix_commit`.
Defects4J's triggering test and bug metadata can guide curation, but a test
failure does not by itself establish the defect's source location or category.

To draft labels without granting them authority, inspect the local patch from
the buggy revision to its fixed revision and compare it with the buggy commit's
changed lines. A fix-side hunk is only a location candidate: review it against
the buggy source, the issue description, and reproduction evidence. Write a
curator-reviewed label file using `historical-review-labels-v1`, including a
short rationale and the buggy revision's path and line range. Hash the final
label bytes and put that digest in the manifest. Preserve excluded or ambiguous
cases in curator notes, not as empty-label benchmark cases.

Before running, check that each selected project's license permits the
intended local use and any planned sharing of results. Keep source checkouts,
labels, and results outside Vee's repository unless redistribution has been
reviewed and approved for every included project. The runner itself works from
local paths and never invokes Defects4J build or test commands. Use a trusted
local provider configuration; use a genuinely local inference provider plus
OS-level network restrictions when offline operation is required.

For a local first draft of changed-line locations, use
`scripts/prepare-historical-review-case.py` with the already-present buggy and
fixed commit IDs. It writes a worksheet outside the subject checkout and never
fetches repositories, runs project commands, or invokes a model:

```sh
python3 scripts/prepare-historical-review-case.py \
  --repository /path/to/local/project \
  --commit <full-buggy-commit-oid> \
  --fix-commit <full-descendant-fix-commit-oid> \
  --case-id project-bug-001 \
  --project project-name \
  --project-license 'license reference confirmed by curator' \
  --output /path/to/private-corpus/candidates/project-bug-001.json
```

The output follows `schemas/historical-review-candidates-v1.schema.json` and
is deliberately not accepted by the benchmark runner. Diff overlap only
suggests where to inspect: it does not establish causality, category, or a
valid label. A curator must inspect source, fix, issue context, and reproduction
evidence, then independently create and digest a
`historical-review-labels-v1` file. Keep the worksheet and source checkouts
local and outside the Vee checkout. Validate the local workflow with
`python3 scripts/acceptance/prepare_historical_review_case.py`.

## Acceptance and current limits

1. A local corpus manifest is validated and pins every case to a full
   commit OID and label digest.
2. The runner uses only existing local repositories, creates and removes
   disposable worktrees, and never fetches or uploads data.
3. Each case invokes the same CLI review service users run locally and stores
   versioned JSON output plus provenance.
4. A completed case with no findings counts as a miss when labels exist;
   incomplete cases are reported separately.
5. Scoring is deterministic for identical review output and labels, with
   documented location/category matching and per-label traceability.
6. The report states provider egress mode and does not imply that local CLI
   execution means local inference.
7. Vee's existing mutation corpus remains separately named and scored.
8. Each report's `review_json_path` resolves from the report directory to the
   exact review JSON whose digest is recorded in that case.

The runner currently matches labels by exact repository-relative path,
overlapping line range, and category (or a curator-defined category alias).
Each label matches at most one finding. Completed-case recall counts matched
labels divided by all labels in completed cases; unmatched findings are
reported separately. The summary contains per-case Vee/provider metadata,
source and label digests, exact review JSON digests, and the aggregate report
schema. The corpus file and licenses remain curator-provided and unauthenticated.

## Current limits

### First local case: retry and circuit-breaker interaction (2026-11-16)

A single curator-labeled case from the local MIT-licensed Fortify Git history
was reviewed with Vee's `correctness` reviewer and Ollama `gemma4:e4b` at the
loopback endpoint, with `VEE_OFFLINE=1`. The review completed, but matched
zero of one labeled defect (recall 0/1); it emitted one unmatched finding.
This is a useful missed-defect example, not a meaningful quality estimate:
there is one case, labels were locally curated, and the provider adapter's
network behavior was not independently verified. The corpus and artifacts
remain outside the Vee repository under `/tmp/vee-local-benchmark-2026-11-16`.
The saved review's change manifest and Vee's request-building path show that
the reviewer received changed `retry/*` files but not the pre-existing
circuit-breaker package or the repository's composition guidance.
The later fix describes the defect as an interaction when retry wraps an open
circuit. This makes repository-context selection a concrete follow-up to
investigate; it does not establish that broader context would have made this
model find the defect.

A follow-up run supplied the unchanged `errors/errors.go` and
`circuitbreaker/breaker.go` files through reviewer `context_files`. The same
snapshot and model completed again, but still matched 0/1 labels. Input usage
increased from 9,387 to 12,922 tokens, and the model returned a different,
unmatched assertion about global random jitter. This shows explicit extra
context is delivered and freshness-bound, but did not fix this model's miss;
context selection alone is not a sufficient quality improvement.

### Second local case: concurrent window reset (2026-11-16)

A second MIT-licensed Fortify case uses the `ResetAfter` implementation commit
`aa54f8c4c6e301cafe73e9ca18bd1628e7e98e4f` and fix
`5a14e9b391710648cf2cb28d15c0d755829234ad`. The label covers the reset unlock
and subsequent counter-clearing stores in `budget/budget.go` (lines 224–229).
The fix commit adds a race regression test. Independently, the same
window-consistent counter invariant failed under `go test -race` on the buggy
commit and passed on the fix commit in disposable worktrees. The private label
and manifest identify this as locally adjudicated; Vee does not authenticate
the curator's assessment.

Vee's normal review completed with local Ollama `gemma4:e4b` and reported the
correct lost-charge/torn-reset mechanism, but located it at `budget/budget.go`
line 118, the new comment describing the mutex, rather than the reset unlock
and stores. The strict path/range/category matcher therefore records 0/1
matched labels and one unmatched high-severity finding.
This is a localization miss with a semantically relevant rationale, not a
matched label. The review took 101 seconds and used 13,110 input and 2,443
output tokens. Its snapshot is
`sha256:32a32299dd92ba8361dbab2dd7034384afbdeceb5a89feb95015813058d01f3c`;
the saved review digest is
`sha256:ce0cbb27c6de6d6d424aaa6f3a11bd0815b917965d3dd6d4950137a4c116d13a`.
The run declared local egress and enabled offline mode, but the generic CLI
adapter does not independently prove network isolation. Results and source
remain outside the Vee repository.

### Third local case: PostgreSQL lockout query typing (2026-11-16)

A third case uses the MIT-licensed local `auth-go` history. Commit
`de8d98a432e1f17593845eb07abfc55334cffcb5` introduced the atomic lockout UPSERT;
fix `5a6d3288fbc5ffd71944e05914e5135934172faf` added explicit
`timestamptz` casts to its two `CASE` branches. The curator label targets the
first untyped branch at `adapters/pgstore/pgstore.go:342`. The fix commit's
description documents PostgreSQL SQLSTATE 42804, and its diff applies the same
type correction at lines 342 and 349.

The defect was independently reproduced with the locally cached PostgreSQL 17
image: preparing the buggy expression with inferred parameter types failed
because PostgreSQL resolved the `CASE` as text for a `timestamptz` column. The
fixed statement prepared and successfully performed both an insert and a
conflict update that incremented the failure count to the lockout threshold.
The disposable database container was removed afterward. The local auth-go
checkout was cloned under `/tmp`; no source was added to the Vee repository.

Vee reviewed the pinned commit with loopback Ollama `gemma4:e4b` and completed
in 157 seconds (15,204 input and 4,132 output tokens). Strict recall was 0/1.
The one unmatched medium finding at line 345 used category
`SQL_Logic_Inconsistency` and claimed PostgreSQL cannot reference a column being
updated in the same `ON CONFLICT DO UPDATE` clause. The fixed query's successful
conflict update disproves that claim, so this case records one confirmed miss
and one reproducible false positive. Snapshot:
`sha256:6eb6def648cf4ec6daaf5367230eeb61c1a1c0d0e60e41cc885c36250519a46a`;
review JSON digest:
`sha256:6915a98492fc39b635cb089a34b22201af9704063b3dd250a72d4a51b542a962`.
The corpus, checkout, configuration, and reports are under
`/tmp/vee-local-benchmark-2026-11-16/auth-go-corpus`. Egress is declared as
local and the endpoint is loopback, but the generic adapter does not
independently enforce network isolation.

The benchmark matcher now preserves this as a strict miss and can separately
show it as a localization candidate when the curator maps the provider's
`concurrency` category to the label's `correctness` category. Replaying the
saved finding against that explicit alias reports line 118 against labeled
lines 224–229; it does not increase strict recall. The alias is a curator
choice, and the diagnostic only establishes same-file/category proximity, not
that the model's rationale is correct.

#### Changed-line context follow-up

The review request now includes compact, one-based changed-line ranges for each
captured text file, and the reviewer prompt asks for a finding location on the
smallest relevant changed line or no line when uncertain. This is advisory;
Vee does not silently move, discard, or auto-correct provider findings. Unit
coverage checks inserted/replaced line ranges, new and unchanged files, and
delivery in the provider request. The same Fortify snapshot was reviewed again
with these ranges using local Ollama `gemma4:e4b`. The completed run returned no
findings and still matched 0/1 labels (recall 0/1); it took 145 seconds and used
13,282 input and 4,017 output tokens. The review JSON digest is
`sha256:7f2f19f5b2b30ade6ebdfe4ae8c6d3036a2628d2dbfa8588f1f0db88ef5d1016`.
This single rerun does not establish that the location guidance improved or
reduced recall; reviewer variability remains a limitation. The saved artifact
is under `/tmp/vee-local-benchmark-2026-11-16/results-window-reset-with-ranges`.

### Fourth local case: concurrent magic-link redemption (2026-11-16)

A fourth case uses the local MIT-licensed `auth-go` history. Commit
`1d7147d04d6e6f02115271074c89da6de3efd911` introduced a magic-link `Consume`
flow that reads the unconsumed state, checks it, and then performs an
unconditional repository write. Fix
`9c93053a0a2f71131dae5c58ada7b9ecf59f7025` made consumption an atomic
check-and-set and rejected calls that did not perform the state transition.

The defect was reproduced against the buggy memory-repository path in an
isolated temporary checkout. A barrier released eight callers only after all
eight had read the same unconsumed link; all eight `Consume` calls succeeded.
The fixed commit's 16-caller single-use regression passed under Go's race
detector. No project checkout or source was copied into Vee's repository.

Vee reviewed the pinned buggy commit with local Ollama `gemma4:e4b` in 98
seconds (12,443 input and 2,150 output tokens). Its rationale correctly
described the concurrent read-then-write race, but it placed the finding at
`domain/services.go:86` (the service constructor) instead of line 125, where
the non-atomic mark occurs. Strict recall is 0/1. With a curator-defined
`authentication` category alias, the deterministic matcher reports one
wrong-line localization candidate; it does not increase recall. Snapshot:
`sha256:1bf85a72625a5f77c74ae96b60cbc2acbb676122efd10f6b29c0da85869a437a`;
review JSON digest:
`sha256:4409998800cc0abc23108966dae4a87632ba54510453817b3ab037067fce3f71`;
label digest:
`sha256:0954fbde5bac22e34bd7d89f842cc79fde09addeed64a9a3e60fef5a6de83453`.
The original and alias-scored reports and source checkout remain under
`/tmp/vee-local-benchmark-2026-11-16/auth-go-magiclink-corpus`. The provider
was configured for offline mode and a loopback endpoint; the generic CLI
adapter still does not independently enforce OS network isolation.

For a same-snapshot local-provider comparison, the case was also run with
`gemma3:12b` using the same reviewer instructions, changed-file scope, policy,
and label. That run completed in 97 seconds and returned no findings (0/1
strict recall; 12,443 input and 13 output tokens). The source snapshot remained
`sha256:1bf85a72625a5f77c74ae96b60cbc2acbb676122efd10f6b29c0da85869a437a`;
the effective config and review JSON digests differ because the model differs.
This shows model-dependent behavior on one case, not comparative model quality.
Its report is under the corpus's `results-gemma3` directory.

The benchmark now writes each `review_json_path` relative to the aggregate
report directory (for example, `cases/<case-id>/review.json`). Acceptance
resolves this path and verifies that the referenced bytes match the recorded
review digest. Earlier locally generated reports may contain the former
`cases/`-relative path and need to be opened relative to their `cases` folder.

### Fifth local case: passwordless WebAuthn user verification (2026-11-16)

A fifth case uses the local MIT-licensed `auth-go` history. Feature commit
`0d1e9dbd7ebb64f6c80199ab716727fa0195e99e` added passkey login without asking
the WebAuthn library to require user verification. Fix
`13898e834457648a0cc3de464453e0ea11e7adf9` set the default to required.

The defect was reproduced with the same focused test in disposable source
archives: the feature commit's login options omitted `userVerification`, and
the security fix returned `required`. No files in the source checkout were
changed. The curated label points to the newly added `BeginLogin` call at
`webauthn/webauthn.go:141`, and is pinned by label digest
`sha256:85602bb838020a578304f15168d55c2d72254eff6864d57cab821be3af614b1e`.

Vee reviewed the feature commit using local Ollama `gemma4:e4b` in 44 seconds
(3,815 input and 1,023 output tokens). The review completed with no findings,
so strict recall is 0/1 with no localization candidate. Snapshot:
`sha256:3358d33842bb50361227fa384a2d39a73f315d387f8b7771e14f9a71fea3760a`;
review JSON digest:
`sha256:3a64744cb96c07541e1c52937ec7f9bffd9faa3372685744f99ba46efb9a57a1`.
The corpus, checkout, trusted config, and results remain under
`/tmp/vee-local-benchmark-2026-11-16/auth-go-webauthn-corpus`, outside Vee.
Inference used the loopback Ollama endpoint and the trusted config declared
local egress; the generic CLI adapter does not enforce OS-level network
isolation.

Two follow-up diagnostics used the same pinned snapshot and label. With
`gemma3:12b` and the same narrow reviewer scope, Vee again completed with no
findings (0/1 strict recall; 3,815 input and 12 output tokens). Its review JSON
digest is
`sha256:1d621d5a4390802cc167acb083413a678e7572aa5c6c1ab1756c9ed2d0e706b7`.
The report is in `results-gemma3/` under the local corpus.

A `gemma4:e4b` run then widened the reviewer scope to all changed Go files and
`go.mod`, including the public adapter and tests. It also completed without
findings (0/1 strict recall; 12,114 input and 2,396 output tokens; 89 seconds).
The source snapshot stayed
`sha256:3358d33842bb50361227fa384a2d39a73f315d387f8b7771e14f9a71fea3760a`;
the review JSON digest is
`sha256:bdcfffe8c25d79846942bb14d610a421ba0ec2b0bd045cddb50d06fe1213618b`.
Its report is in `results-full-scope/` under the local corpus. Added changed-
file context alone did not recover this defect for that model. Both runs reuse
the same label, so they do not add benchmark cases or change the strict score.
Inference used the local loopback Ollama endpoint; provider egress was declared
in trusted config, not independently enforced by Vee.

#### Sixth local historical reviewer pilot (2026-11-16)

A sixth case uses the local, MIT-licensed `statekit` repository. The pinned
feature commit `856247f2451253ef83c12c3cedf3fdcaa93314e4` added delayed XState
transition export under `after`; the later fix
`8cbad27dd05c63978ddeb190bdc9641070458fc6` taught the native visualizer parser
to read it. A parser-level acceptance check failed on the feature commit
(`parsed delayed transition count = 0, want 1`) and passed on the fix.

The first correctly scoped Vee run reviewed only `export/xstate.go` with local
Ollama `gemma4:e4b`; it completed in 43 seconds with no findings (0/1 strict
recall; 3,342 input and 1,203 output tokens). A second run added the unchanged
`viz/parser.go` as explicit supplemental context; it completed in 62 seconds
and also returned no findings (0/1; 5,126 input and 2,099 output tokens).
Both runs returned a passing gate despite the reproduced defect. They share
snapshot `sha256:14b92a8bc9f7be1a33d35da303f577617b1fcf54bd4cf04979813488c03329d0`.
The source-only review JSON digest is
`sha256:25d8291332629a2ee45f945a603401efbe41a746ea83bf5d5b353c59af4b0ba4`;
the context review digest is
`sha256:59b94871407dcc74da66f536659dd90abddb6ed1647e536695de3d934adc8f81`. The
same parser-context review with local Ollama `gemma3:12b` also returned no
findings in 45 seconds (0/1; 5,126 input and 13 output tokens); its review JSON
digest is
`sha256:d55a1aef430d537e46afc15fb5f3e20c7075447f5ba0f3c7fa54c049169ab19c`.
This single matched-snapshot comparison is not evidence that one model is
better. The first, broader attempt included the new test file and was stopped
before a result; it is excluded. Checkouts, trusted configs, and reports remain under
`/tmp/vee-local-benchmark-2026-11-16/statekit-delayed-corpus`, outside Vee.
Egress was declared local and used loopback Ollama; the generic CLI adapter
does not independently enforce OS-level network isolation. This is one more
reproduced miss, not representative quality evidence.

These six locally curated cases are debugging evidence only. They do not
establish representative recall, false-positive rates, or general reviewer
quality; further independently reviewed, license-cleared cases are required.

### Consolidated local run (2026-11-17)

The same `correctness` reviewer, trusted configuration, Vee 0.1.0 binary, and
loopback Ollama model (`gemma4:e4b`) were run against all six pinned cases in a
single invocation with `VEE_OFFLINE=1`. All six reviews completed; none was
incomplete. Strict recall was **0/6 labels**, with zero localization
candidates. Three completed reviews emitted one unmatched finding each; the
other three emitted none. These findings have not been manually adjudicated,
so this is not a false-positive rate. The aggregate report records the exact
per-case snapshot, config, label, review, and provider usage digests.

The local report and source corpus remain outside the Vee checkout at
`/tmp/vee-local-benchmark-2026-11-16/consolidated-six/results-gemma4/` and
`/tmp/vee-local-benchmark-2026-11-16/consolidated-six/`. Manifest digest:
`sha256:2e6947f7fe807db4930faf42802e54df9a72d6dff5dccfb45f8b99c9a405fa4c`;
trusted benchmark-config digest:
`sha256:233645d3cd4931ae4072924c16b4e13e37283902833778b2ef2f4446c9b3c4df`.
Inference used a loopback endpoint and the trusted config declared local
egress. The generic CLI provider adapter does not itself prove or enforce
OS-level network isolation. The cases were selected for local debugging and
are not a representative or independently sampled corpus; the score must not
be generalized to overall Vee quality.

The immediate product follow-up is to improve review context and evaluate
local deterministic analyzers alongside the reviewer, then rerun this same
pinned sample as a diagnostic. That comparison must retain the AI-only result
as its baseline and must not turn this small corpus into a product-quality
claim. A broader, independently adjudicated corpus is still needed before
estimating recall or false-positive rates.

### Local reviewer-instruction experiment (2026-11-17)

To test whether stronger evidence demands reduced unsupported reports without
losing useful defect detection, the same six snapshots, model, reviewer ID,
and trusted provider config were rerun with a local instruction overlay. It
asked the reviewer to describe a concrete triggering state and observable
failure, check language/API semantics, challenge each proposed finding, and
omit issues whose failure path could not be established. The overlay and all
outputs remain outside the checkout under
`/tmp/vee-local-benchmark-2026-11-16/consolidated-six/`.

Five cases completed and one large case timed out; among completed cases the
strict score was **0/5 labels**, with no findings and no localization
candidates. The baseline completed all six, matched 0/6, and emitted three
unmatched findings. The experiment therefore did not improve recall, reduced
potentially useful review signal, and incurred one incomplete result. It is
not evidence that the baseline findings are true positives or that the stricter
prompt improves precision; neither set of findings has complete human
adjudication. Do not adopt this stricter wording as Vee's default. Treat the
timeout as a local inference/configuration limit, not a defect miss.

The experiment confirms that prompt conservatism alone is not a substitute for
independent evidence. Next, compare reviewer findings with trusted, explicitly
selected local analyzers/tests and show their results as separate evidence.
Keep tests opt-in through trusted verification profiles; do not execute
repository scripts automatically. Retain the AI-only baseline and incomplete
status in every comparison.

The runner now accepts repeatable `--verify-profile <id>` options to run named
verification profiles from the trusted benchmark config after each in-scope
review. Profiles are opt-in; the runner never discovers or runs repository
scripts automatically. Each run uses `vee verify --commit` on the same pinned
buggy commit as the review. Add `--verify-fix` to run those profiles again in a
separate worktree at each case's pinned fix commit. The report records each
revision's verification status, run ID, command digest, and snapshot ID
separately from AI findings and strict recall. A mismatch between the buggy
verification and review snapshot is surfaced instead of treating verification
as evidence for that review. For each profile, the report also provides an
`analysis_evidence_comparison` beside the matched/missed AI label IDs. It pairs
buggy and fixed results only when their command digests match and records
outcomes such as `buggy_failed_fix_passed` or `passed_both`. These are
differential signals, not proof that a test failure was caused by the labeled
defect; verification results never increase AI recall. Use
`--verification-timeout` to bound each selected profile. This preserves the
review-only baseline while making independently checked local outcomes easier
to inspect.

Example, with a trusted profile called `unit` in the external benchmark config:

```sh
python3 scripts/historical-review-benchmark.py \
  --manifest /path/to/my-corpus/manifest.json \
  --corpus-root /path/to/my-corpus \
  --config /path/to/my-corpus/benchmark.vee.yaml \
  --vee /path/to/vee \
  --output-dir /path/to/local-results \
  --scope-language go \
  --verify-profile unit \
  --verify-fix
```


Vee also accepts locally supplied, digest-pinned mutation corpora for test
effectiveness; that is a separate measurement. Run the repeatable adversarial
local acceptance with `python3 scripts/acceptance/historical_review_benchmark.py
/path/to/vee`. It exercises label and fix-commit provenance, trusted offline
configuration, and proves that a repository config symlink target, checkout
hook, and Git smudge filter are not executed. A local fake provider matches one
curated label and the temporary worktree is removed. This validates runner mechanics,
not reviewer quality. No third-party historical dataset is bundled, and a
license-cleared, independently reviewed sample corpus plus broader matching
validation remain open.

The curation helper has its own synthetic local acceptance at
`python3 scripts/acceptance/prepare_historical_review_case.py`. It checks
candidate-only output, buggy/fix commit provenance, exact changed-line overlap,
and rejection of repository-internal output paths, symlink outputs, and
non-descendant fix commits. Hostile inherited Git repository/config variables
are ignored, and a repository-configured Git textconv command is verified not
to run. This is safety and workflow evidence only; it does not supply real
historical labels.

The benchmark acceptance also exercises an opt-in local differential check:
the synthetic trusted profile fails on the buggy commit and passes on its fix,
while the fake reviewer's matched/missed label result remains independently
reported. This verifies comparison plumbing only, not real-world reviewer
quality or defect causation. CI runs this acceptance against the installed CLI
on Linux and macOS; Windows still runs the installed local-review and stale
snapshot acceptance, while this hostile Git-worktree fixture remains Unix-only.


### Local test-generation patch acceptance fix (2026-11-17)

The full snapshot-bound fake-provider lifecycle exposed a patch parsing defect:
Vee's presentation-wrapper extractor stripped the trailing newline from a
valid unified diff, and local Git rejected it as corrupt. The extractor now
ensures the patch ends with a newline, and the sandbox still validates every
path and applies the patch only in its isolated temporary directory before an
explicit digest approval is offered. The fixture also puts both the changed
implementation and its paired test in the captured working-tree snapshot, with
twelve oversized unrelated files competing for a 2,048-token context budget.
It confirms both relevant files are prioritized, omitted files are reported,
and the approved lifecycle still rejects stale snapshots before application.
The focused CLI acceptance and the full workspace suite passed. This closes a
patch-format and context-selection regression; it does not show that a local
model can reliably produce useful test patches on historical defects.

### Local PostgreSQL lockout regression investigation (2026-11-17)

Using a private checkout and a disposable local PostgreSQL 17.11 instance, the
historical change at buggy commit
`de8d98a432e1f17593845eb07abfc55334cffcb5` was reproduced against its fix at
`5a6d3288fbc5ffd71944e05914e5135934172faf`. The buggy upsert failed on the
first failed-login record with SQLSTATE `42804` because PostgreSQL could not
resolve the `CASE` expression type for the timestamp column. The exact
regression test passed on the fix and failed on the buggy revision. Module
downloads were completed before running the test with Go proxy and checksum
network access disabled. The database and temporary Git worktrees were stopped
after the investigation.

The case was also run through the local Gemma 3 reviewer. Its full-context and
scoped runs were both marked `context_limited`; the later run returned one
unrelated conditional WebAuthn concern and did not identify the PostgreSQL
regression. Because the required review was incomplete and no matching finding
was produced, this example is excluded from strict recall scoring. It does not
support a recall or false-positive-rate claim.

The investigation exposed excessive unrelated impact context for scoped
reviewers. Reviewer context selection now filters impact paths through the
reviewer's effective file scope before adding source text, then orders eligible
paths deterministically by same-directory proximity, relationship type, and
certainty before applying its context budget. The focused regression tests
check out-of-scope exclusion and this priority order. Validation completed
locally: all 78 `vee-application` tests passed, Clippy passed with warnings
denied, and workspace formatting and CLI build passed.

A follow-up offline Gemma 3 run on the same pinned PostgreSQL case remained
`context_limited`, returned unrelated model-inferred findings, and did not
identify the labeled timestamp-type defect. The selected eight impact files
were the same as in the preceding run, so the new ordering did not resolve this
case's incomplete context. The result is excluded from strict recall scoring
and supports no recall or false-positive-rate claim. This local case remains
useful as a regression for correct incomplete status and explicit omissions,
but it is not an accepted quality benchmark until a complete, independently
scored review can be produced.

To make local small-context inference behavior explicit, Vee now supports an
optional `providers.<id>.max_input_tokens` budget. The estimate is deliberately
approximate; Vee first replaces lower-priority impact source excerpts with
path/reason metadata, and skips the provider with an incomplete result if the
changed-source prompt still exceeds the configured limit. A local Gemma 3 run
with a 12,000-token budget correctly skipped the call because required source
context alone exceeded the budget. A 16,000-token run after removing duplicate
instruction/schema text from the OpenAI-compatible user payload still
estimated 16,849 tokens and skipped the call. Both outcomes were incomplete,
with no finding-quality result; neither is counted in recall or false-positive
metrics. These checks support fail-closed budgeting behavior, not model
accuracy. The focused local suites pass: 79 application tests and 72 core
tests.

### Local Rust historical-review probe (2026-11-17)

A locally cloned Keyward checkout (AGPL-3.0-or-later) supplied a Rust case for
the `sync-postgres` group backend. The buggy snapshot is commit
`646e49bf5041540c86b86e12ead770ff91213490`; the pinned repair is
`96d1183319625eb4be1bb71da7f159ba6faaab59`. The repair commit documents two
concrete failures introduced when `signing_key` was added: `load_group` still
reads `added_epoch` from column 5 after the selected columns shifted, and
`insert_member` lists eight columns but retains seven SQL placeholders. The
private labels target those two locations. The source checkout was cloned
locally; the benchmark runner used disposable worktrees, local Ollama, and
temporary reports under `/tmp/vee-local-review-2026-11-17/keyward-rust/`.
No hosted service or repository upload was involved.

The first Gemma 3 12B run used a 48,000-token context ceiling. It returned a
`context_limited` result after about 178 seconds, so the benchmark marked the
case incomplete because it could not prove the labeled file had been supplied
in full. A retry used Ollama's 96,000-token context window, confirmed active on
the local GPU, and a 90,000-token input allowance. The provider exceeded its
600-second timeout; that run also remained incomplete and is excluded from
strict recall. Neither run produced a scored finding or miss. This is evidence
of a local Rust review latency/context limitation on this large source file,
not evidence about Rust defect recall. Full reports remain outside the Vee
repository at `results-gemma3-local-2026-11-17/` and
`results-gemma3-local-96k-2026-11-17/` within the temporary corpus directory.

A bounded follow-up used a 24,000-token input allowance and Ollama's local
32,768-token context window. It completed in 155.83 seconds, supplied the full
changed Rust source file, and omitted 33 lower-priority impact source references.
The report records that omission separately as advisory impact coverage; it no
longer marks the required source review incomplete. The scored result was still
0/2 strict recall, with no matching or unrelated findings. This is a complete
negative result for this specific local model/run, not a general Rust recall
claim. The report and local-only configuration are under
`/tmp/vee-local-review-2026-11-17/keyward-rust/results-gemma3-24k-2026-11-17/`.

The underlying SQL facts were also checked against a disposable local
PostgreSQL 16 instance: the buggy eight-column insert with seven expressions
was rejected, the repaired eight-placeholder statement prepared successfully,
and the selected column types confirm the shifted `role`/`added_epoch` positions.
The repository's Rust contract test itself was not run: offline Cargo could not
find cached `aead 0.5.2` and `async-trait 0.1.89`, and dependencies were not
fetched. So the SQL probe independently confirms the query-shape defect, but
does not replace the Rust integration test or prove the full application-level
fix. The disposable database and worktrees were removed after the probe.

#### Snapshot-bound Vee verification of the Keyward SQL case (2026-11-17)

To keep this case useful without fetching its Rust dependency graph, a trusted
local verification profile was run through Vee against each exact commit. It
read the selected SQL statements and `added_epoch` row index from each pinned
Rust source file, then checked the SQL projection cast and insert column/value
shape against a temporary PostgreSQL 17.11 table. The temporary server listened
only on `127.0.0.1:55439`; Vee's `verify --commit` captured separate
snapshot-bound records and output artifacts for the buggy and fixed revisions.

The buggy commit produced `failed`, exit 1, snapshot
`sha256:2ac03e8184936759d33370f8a6efd1965a680d72661fad16e55b6c383447b8ea`,
and run `sha256:390064b6b64b7c3484123a8caa39e411c8ceb26c8c659b14dacc3a7c1203226d`.
PostgreSQL rejected decoding `role` as `bigint` and rejected the INSERT with
eight target columns and seven expressions; the source also supplied eight
bind arguments. The fixed commit produced `passed`, exit 0, snapshot
`sha256:4cf66ef44fd1567752190d53793c3ac546f4be359e72c7239def0ccd3c092755`,
and run `sha256:fc92c20c9d1112f6e33d1354ec94a0739cfbbd0db11c9cddf77dabccb0b12254`.
It read `added_epoch` from projection index 6 and used eight placeholders for
eight columns and binds. Both records validate against
`verification-run-v1.schema.json`; local reports and digest-checked output
artifacts are under
`/tmp/vee-local-review-2026-11-17/keyward-rust/results-postgres-contract-2026-11-17/`.

This verifier checks source-derived SQL shape and PostgreSQL type behavior; it
does not compile or execute the Rust adapter, exercise the driver's native bind
protocol, or replace the repository's PostgreSQL contract test. The uncached
Cargo dependencies remain unfetched, and the temporary database was stopped
after the runs. This provides useful local evidence through Vee's own
snapshot-bound verification path without overstating application-level proof.

#### Verification-only runner on the Keyward case (2026-11-17)

The new benchmark `--verification-only` path was then run on the same pinned
Keyward buggy/fix commits with the trusted PostgreSQL contract profile. It
completed both local Vee verification runs using the same command digest
`sha256:30d922a57f14fc7677650a784321eed8dbe56d2094078b97cd53e8b60a2a0207`:
the buggy run failed (`sha256:f2088b6f47d26f03832f2ba290384f9f102f16cc22377ae021039e232d5c001c`)
and the fix passed (`sha256:cd10fc8ba52e9cbc3c028afa4a0c4adc501f3dfa41eed30d15032b6b05fa4891`).
Snapshot IDs matched the previous direct Vee runs for each source commit. The
report validated against `historical-verification-report-v1.schema.json`, and
all four archived stdout/stderr artifacts matched their recorded digests and
sizes. The temporary PostgreSQL 17.11 server listened only on loopback and was
stopped after the run; its data directory was removed. No Rust dependencies
were fetched. The retained report and artifacts are under
`/tmp/vee-local-review-2026-11-17/keyward-rust/results-verification-only-2026-11-17/`.

This confirms the repeatable runner works against an existing local historical
case, in addition to the synthetic acceptance fixture. The check still probes
SQL shape and PostgreSQL behavior rather than compiling or exercising the Rust
driver adapter, so it is one targeted validation point rather than a general
review-quality result.

This is the first complete scored local review for the Rust case, and it shows
that bounded execution now finishes while the reviewer misses both labeled
defects. Earlier timeouts/context-limited runs remain excluded from recall
scoring. Vee should preserve this as a diagnostic benchmark and improve its
local context selection and reviewer effectiveness before making broader
quality claims. Local execution remains bounded, and any genuinely required
source/context omission or provider failure must remain explicitly incomplete.

The follow-up also tested the installed local Gemma 4 e4b model with an
8,192-token output allowance. Vee correctly rejected the provider response as
schema-invalid and marked the review incomplete; the captured local diagnostic
showed extra, model-invented fields (first a finding-level `id`, then a
non-schema top-level `finding` key). These runs are excluded from recall
scoring. The output cap is now configurable for `ollama_native` through
`providers.<id>.max_output_tokens` (default 2,048), with validation that input
and output budgets fit the declared local context window. The review prompt
explicitly says Vee owns finding identity, while strict output validation
still rejects unsupported fields. This fixes a local resource-control limit,
not model compliance or defect recall. All inference remained on loopback
Ollama with offline mode enabled.

### Local PostgreSQL lockout persistence case (2026-11-17)

A second independently reproduced Go case was curated from the existing local,
MIT-licensed `auth-go` checkout. The buggy snapshot is
`de8d98a432e1f17593845eb07abfc55334cffcb5`; its new PostgreSQL lockout UPSERT
left timestamp parameters untyped in `CASE` expressions. The pinned repair is
`5a6d3288fbc5ffd71944e05914e5135934172faf`. A disposable PostgreSQL 17.11
instance and the repair's integration test were used against both archived
snapshots with Go 1.27.4, `GOPROXY=off`, and `GOSUMDB=off`: the buggy snapshot
failed on the first write with SQLSTATE 42804 (`locked_until` expected
`timestamp with time zone`, expression resolved as `text`), while the fixed
snapshot passed. No source checkout was modified.

The private manifest and label are under
`/tmp/vee-local-review-2026-11-17/authgo-lockout-postgres/`; the source,
reports, and labels remain outside the Vee repository. Gemma 3 12B completed a
scoped local review in 130.5 seconds with the entire labeled PostgreSQL source
file supplied (15,938 reported input tokens). It returned no findings and
missed the label: strict recall **0/1**, with no unmatched findings. A broader
Gemma 3 request estimated 75,044 input tokens, exceeded its 600-second provider
bound, and is incomplete, so it is excluded from recall. Scoped Gemma 4 e4b
returned schema-invalid output after 87.4 seconds and is also incomplete.
These are diagnostic runs on one selected defect, not general recall or
false-positive estimates.

The saved-report comparator was run on the broad and scoped Gemma 3 reports. It
retained both provider/config outcomes and marked the pair incomparable because
one run was incomplete. The completed scoped run remains the only scored result.

#### Corrected local acceptance run with verifier no-test guard

The current Vee build was rerun against the exact buggy commit
`de8d98a432e1f17593845eb07abfc55334cffcb5`, with the trusted reviewer
instructions and the same scoped local Gemma 3 12B provider. The review
completed in 93.2 seconds, supplied the full labeled file, returned no
findings, and therefore missed the curated label (0/1 strict recall). The
provider used 15,938 input tokens and returned 13 output tokens. This remains a
negative local review result, not evidence of broad reviewer quality.

The selected `pg-lockout` verifier was also run with the same command against
the buggy and fixed snapshots. On the buggy snapshot, Go exited zero but
reported `[no tests to run]`; Vee now records that result as **incomplete**
(exit 2), so it cannot be mistaken for successful evidence. On the fixed
snapshot, the committed regression test ran and passed. A separate disposable
worktree reproduction that overlaid the trusted regression test on both source
revisions had already confirmed the actual differential: SQLSTATE 42804 on the
buggy implementation and success on the fix. These are distinct facts: Vee's
snapshot-bound verifier does not silently import a test file absent from the
reviewed commit, while the independent overlay reproduction supplies that
missing test explicitly.

The run used loopback Ollama with offline mode enabled, `GOPROXY=off`, and
`GOSUMDB=off`; the local PostgreSQL instance listened only on `127.0.0.1`.
Egress is still declared by trusted configuration rather than independently
enforced by Vee. The report, JSON review, and bounded verification logs are
under `/tmp/vee-local-review-2026-11-17/authgo-lockout-postgres/results-gemma3-verified-correct-2026-11-17e/`.

#### Explicit trusted test overlay (2026-11-17)

The historical runner now accepts `--verification-file TARGET=SOURCE` for
explicitly selected local verification profiles. It installs the trusted file
only in disposable checkouts used for verification, runs Vee against the
working-tree snapshot containing that file, and records its repository path,
SHA-256, byte length, aggregate overlay digest, and source commit separately.
Existing checked-out files may be overlaid only when their bytes already match;
symlinked parents and conflicting files are rejected. A provider review still
runs against the untouched historical commit. This makes an externally
supplied regression test usable without pretending it was present in the
reviewed source snapshot.

The PostgreSQL lockout case was rerun with a distinct
`vee_lockout_regression_test.go` overlay. The same local Gemma 3 12B review
completed with full labeled-file context and again missed the defect (0/1
strict recall). The explicit Go/PostgreSQL test failed on the buggy commit with
SQLSTATE 42804 (`locked_until` timestamp-with-time-zone versus text) and passed
on the fix. Both runs used the same command digest and overlay digest; their
verification snapshot IDs differ and each report retains its pinned source
commit. The output artifacts and report are under
`/tmp/vee-local-review-2026-11-17/authgo-lockout-postgres/results-gemma3-overlay-verification-2026-11-17b/`;
the aggregate report validated against `historical-review-report-v1.schema.json`.

This gives Vee a reproducible local evidence path alongside AI review, but it
does not improve the model's defect recall. The evidence types remain separate:
the curated label scores review localization, and a trusted test's differential
result is independent verification evidence. The next quality milestone is a
larger independently adjudicated local corpus with both signal types retained.

#### Verification-only corpus mode

The local runner also supports `--verification-only` with one or more
`--verify-profile` selections. This compares each explicitly trusted profile on
the case's pinned buggy and fix commits in disposable local worktrees, without
running configured review providers. For example:

```sh
python3 scripts/historical-review-benchmark.py \
  --manifest /path/to/local-corpus/manifest.json \
  --corpus-root /path/to/local-corpus \
  --config /path/to/trusted-local-config.vee.yaml \
  --verify-profile regression \
  --verification-file tests/regression_test.py=/path/to/trusted-regression-test.py \
  --verification-only \
  --vee target/debug/vee \
  --output-dir /path/to/local-results
```

The output is `historical-verification-report-v1.json`, validated by
`historical-verification-report-v1.schema.json`. It records paired states,
source commits, snapshot/run IDs, same-command comparisons, trusted overlay
digests, and digest-checked output artifacts. The report deliberately contains
no review findings or recall metrics. A complete run means the requested
profiles returned usable results on both revisions; it does not require the
buggy revision to fail or the fix to pass. The comparison describes those
observed outcomes and does not claim that a test proves the labeled defect.

This path reads only the caller's local corpus and trusted profile/config,
creates temporary local Git worktrees, and writes local output artifacts. It
does not fetch repositories or upload reports. Selected verification commands
are explicit local executions and may have their own egress behavior; use
trusted profiles and an offline local environment when no network access is
desired. The synthetic acceptance fixture confirmed failed-on-buggy,
passed-on-fix with an identical command and overlay, verified artifact hashes,
and confirmed that the fake review provider was not invoked.

#### Local checklist prompt comparison (2026-11-17)

On the pinned auth-go lockout case described above, two offline Gemma 3 12B
reviews used the same source snapshot, model, provider settings, and full-file
context. The baseline review completed in about 356 seconds, returned no
findings, and missed the single concurrency label. The comparison arm added a
general read-modify-write/concurrency checklist and completed in about 456
seconds. It still missed the label and returned two unsupported medium-severity
findings about `UpdateSignCount`: one in the mutex-protected in-memory adapter
and one in the PostgreSQL adapter's direct SQL update. Both cited line numbers
beyond the actual files. The defect remained independently reproduced on the
pinned buggy/fix revisions; neither review found it. These runs are a diagnostic
prompt comparison for one local case, not a representative recall or
false-positive estimate. The checklist was not adopted as a default.

The malformed locations exposed a Vee robustness issue: a single invalid line
previously discarded the entire batch of source evidence. Vee now retains
evidence for valid findings, leaves evidence absent for each invalid location,
records `vee.source_evidence` as `invalid_finding_location`, and marks the
analysis incomplete. This keeps the gate fail-closed without erasing unrelated
valid evidence. The focused regression and all 83 `vee-application` tests
passed locally; formatting validation passed. The raw A/B reports remain in
the machine-local `/tmp/vee-local-review-2026-11-17/authgo-lockout-postgres/`
directory and are not committed with repository source.
