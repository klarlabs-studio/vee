# ADR 0017: Reviewers explore the review snapshot through Vee

- **Status:** Proposed
- **Date:** 2026-11-24

## Context

A reviewer request carries the change and a bounded set of related files:
- the changed files: full contents or a bounded diff;
- up to eight impact references, such as callers of a changed symbol;
- the reviewer's configured context files.

The model cannot ask for anything else. A defect whose evidence lives in
unchanged code is invisible unless that code happens to be in the bundle.
Examples: a caller that now passes the wrong unit, or a sibling migration
that the change contradicts.

**Benchmark evidence.** We scored Vee on a public offline code-review
benchmark: 50 pull requests from five open-source projects, with expected
findings written by humans. The judge was the benchmark's own LLM judge,
applied identically to every tool.

On the 45 pull requests not used to tune instructions:

| | Vee | Leading hosted reviewers |
|---|---|---|
| Precision | 42% | 32% to 52% |
| Recall | 44% | 45% to 62% |

- **Precision is already in range; recall is the gap.** On precision,
  Vee is ahead of the best-recall hosted reviewers.
- **The reviewers that close the gap can look beyond the diff.** In the
  published results, a general-purpose coding agent with repository
  access outscores the same family of models reviewing a bundle.
- **Instructions alone do not close it.** Broader instructions raised
  Vee's recall by about 13 points, but precision fell by about 7 and F1
  did not improve. That points to missing evidence, not missing
  instructions.

A first measurement of this decision did not raise F1 (see Rollout), so
the default stays off.

**The CLIs' own file tools cannot be confined.** Reviewer CLIs such as the
Claude CLI and the Codex CLI ship file tools. Their reads are not confined
to the change under review:
- they see the live working tree, which can change during a review;
- they see untracked and ignored files, such as `.env`;
- they see paths outside the repository.

Vee's guarantees depend on reviewing an immutable, digest-checked
snapshot, so the CLIs' tools are not acceptable.

## Decision

Reviewers may read more of the **review snapshot**, through tools that
Vee serves itself. Nothing else is reachable.

### Tools

`vee review-context serve` is an internal stdio MCP server, started by the
reviewer CLI. It is given the repository root and the captured change set,
and it offers three read-only tools:

| Tool | Returns |
|---|---|
| `list_files(glob?, limit?)` | Tracked paths of the snapshot, sorted |
| `read_file(path, start_line?, end_line?)` | Text of one snapshot file, with line numbers |
| `search(pattern, glob?, limit?)` | Matching lines (`path:line: text`) across snapshot files |

### Confinement

1. **Reads go through the snapshot readers.**
   - Changed files are read from the captured bytes and checked against
     their manifest digest.
   - Unchanged files are read from the captured head tree, from git
     objects.
   - The working tree, untracked files and paths outside the repository
     are never read.
2. **Paths are validated as finding paths are.** A path must be relative
   and resolve inside the repository, and it may not use `..` to escape.
   Review `include`/`exclude` apply.
3. **A deny list always applies.** It covers environment files, private
   keys and credential stores (`.env*`, `*.pem`, `*.key`, `id_rsa*`,
   `.npmrc`, `.netrc` and similar). `review.exploration.deny` can extend
   it but cannot remove entries.
4. **Budgets bound every request.**
   - Per reviewer request: `max_tool_calls` (default 24) and
     `max_read_bytes` (default 256 KiB).
   - Per tool result: the existing per-file limit.
   - When a budget runs out, the tool returns an explicit "budget
     exhausted" result rather than an error, so the review still finishes.
5. **Results are untrusted data.** Tool output is labelled
   `untrusted_repository_source`, like bundled context. The reviewer
   prompt already forbids following instructions found in repository
   text.
6. **The reviewer gets no other tools.** For example, the Claude CLI runs
   with `--restricted --tools "" --strict-mcp-config`, and only the
   server's three tools are allowed.

### Evidence and the review record

- Every tool call is logged with its tool, arguments, outcome, the files
  whose text it returned and its size. The reviewer context manifest
  records the totals and the files read, so what a reviewer saw is
  auditable.
- Findings may cite explored files, as they may already cite any path
  inside the repository; anchoring is unchanged.

### Providers and rollout

- **Opt-in.** `review.exploration.enabled` defaults to `false`.
- **First provider.** The Claude CLI gets the server as its only MCP
  server, with only the three tools allowed. The Codex CLI accepts MCP
  servers through configuration overrides, but its sandbox still lets its
  own shell read the filesystem, so it follows once that read access can
  be confined.
- **Other providers.** API providers (`openai_compatible`,
  `ollama_native`) can later use the same tool service through function
  calling. Until then they review the bundle alone, and the review records
  `exploration: unsupported` rather than failing.
- **Default.** It changes to `true` only after the held-out benchmark set
  shows higher F1 with exploration than without. On the first
  measurement (36 correctly built held-out pull requests), exploring
  reviewers scored lower: 40 F1 against 45 without exploration. They
  used the tools on about half of the requests.

## Consequences

**Benefits:**
- Reviewers can follow a change into callers, schemas and configuration,
  where most of the missed defects' evidence lies.
- The snapshot guarantee is unchanged: exploration cannot see anything a
  bundled review could not have sent.
- One confined implementation serves every provider, instead of relying on
  each CLI's sandbox.

**Costs and risks:**
- **Latency and cost.** Tool turns add both. The budgets cap them, and
  they are reported per review.
- **Less determinism.** Tool use varies between runs. Reviewer sampling
  ([ADR 0008](0008-reviewer-sampling.md)) gives more stable results when
  needed.
- **Prompt injection.** Repository text can ask the model to read other
  files. The worst case is reading more tracked, non-denied snapshot
  code, within budget, which a bundled review could already have sent.
- **Committed secrets.** A secret committed under an unlisted path can
  reach the provider, as it can today when such a file is changed. The
  deny list narrows this but does not replace secret scanning.
