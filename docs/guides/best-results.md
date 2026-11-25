# Getting the best reviews from Vee

Vee reviews on the AI backend you already have. Three choices decide most of
the quality you get: the model, the review effort, and what the reviewers are
told to look for. `vee init` asks for the first two in a terminal and records
them for this machine. To change them later, run `vee init --provider <id>
--model <model>`, which replaces this machine's provider, or
`vee init --effort <level>`.

## What we measured

We score Vee on a public offline code-review benchmark: 45 pull requests from
five open-source projects, with expected findings written by humans and an
LLM judge that matches findings to them. We tuned Vee's instructions on five
other pull requests, which are not in these numbers.

- **Precision:** the share of Vee's findings that match a real issue.
- **Recall:** the share of real issues that Vee found.
- **F1:** their balance.

| Setup | Precision | Recall | F1 |
|---|---|---|---|
| Sonnet, effort `low` | 42% | 44% | 43 |
| Opus, effort `low` | 39% | 56% | 46 |
| Opus, effort `medium`: findings that block | 48% | 50% | 49 |
| Opus, effort `high`: findings that block | 50% | 49% | 49 |
| Opus, effort `high`: every finding shown | 42% | 64% | 51 |

At effort `medium` and `high`, every finding is shown, but only findings
reported by a majority of runs can block the gate. The other findings are
advisory.

## Choose the model

- **Claude Code CLI with `claude-opus-5-5`** found the most defects.
- **`claude-sonnet-5-5`** is faster and cheaper, and found about a fifth
  fewer defects.
- **Codex, Gemini and other agent CLIs** use the model configured in the CLI
  unless you pass `--model`. We have not measured them yet.
- **A local Ollama model** keeps your source on this machine. Vee prefers it
  when one is installed. We have not measured local models on the benchmark
  yet. Expect fewer defects found than with the largest hosted models,
  especially with models under about 30B parameters.

## Choose the effort

| Effort | Runs per reviewer | Use it for |
|---|---|---|
| `low` | 1 | Iterating on a change; the fastest and cheapest review |
| `medium` | 3 | Gate reviews. One-off false alarms do not block, at about three times the time and tokens of `low` |
| `high` | 5 | Changes where missing a defect is expensive. It finds the most, at about five times the cost of `low` |

- **This machine:** `vee init --effort medium` sets the effort for every
  reviewer whose repository configuration sets neither `effort` nor
  `samples`.
- **One review:** `vee review --effort high` overrides it.
- **A team-wide setting:** set `effort` on the reviewer in `.vee.yaml`.

## Tell reviewers what matters

- **Keep reviewer instructions focused.** The default correctness reviewer
  looks for concrete defects. Add examples that matter in your codebase to
  `.vee/reviewers/correctness.md`, such as "every query must filter by
  tenant".
- **Raise the bar where it matters.** Set `policy.severity_floors` for
  sensitive paths and categories, so that any defect there blocks. See
  [ADR 0018](../adr/0018-fixed-finding-rubric-and-severity-floors.md).
- **Add advisory reviewers when you want them.** `architecture` and
  `task-alignment` are scaffolded and disabled. Enable them for design
  feedback and for checking a change against its work item.
- **Give reviewers the context a diff lacks.** List architecture notes or key
  interfaces in a reviewer's `context_files`.

## Review small changes

Reviews are most accurate on focused changes. A change too large for the
model's context is reviewed in part, and the review says so. Split large
changes, and review often while you work.
