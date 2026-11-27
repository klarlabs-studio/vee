# ADR 0044: Team analytics without a server

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

Teams want one view of how Vee does across their repositories: how often
the gate passes, how often its approvals are overridden, what the reviews
cost, and whether approved rules cut false positives. Vee already writes
each of these per repository:

- `vee analytics` writes `quality-analytics`;
- `vee ci approvals` writes `approval-report`;
- `vee rules effectiveness` writes `rule-effectiveness`.

A hosted dashboard would need a server, accounts and the teams' data in
one place. Vee has no server, and its local-first promise rules one out.

## Decision

**Aggregate the documents a team already has.** `vee analytics aggregate
<paths>` reads those three documents, from files or directories of `.json`
files. It recognizes each kind by its fields and skips anything else,
saying why. `NAME=PATH` labels a document; otherwise an approval report is
labelled with its repository and the rest with their file names. Teams
collect the documents however suits them, for example as CI artifacts.

**Rates are recomputed, never averaged.** Every count is summed. Each rate
is the summed numerator over the summed denominator, and the report shows
both:

- finding accuracy and actionability;
- approval agreement and override;
- rules' false positives and non-actionable findings, before and after
  activation.

Averaging per-repository rates would weight a repository with two labelled
findings like one with two thousand.

**No person is named.** The inputs hold no authors. The approval report's
per-pull-request cases are not copied, so the report holds only counts,
rates and the labels of its sources.

**One static report.** `--html <file>` writes a single self-contained page
from the same view as the terminal output. It loads nothing from
elsewhere, runs no script, sets a restrictive content security policy, and
escapes every value, so it can be published as a CI artifact as it is. The
JSON follows `team-analytics-v1`.

## Consequences

- A team gets a cross-repository view with nothing to host, and the
  documents stay wherever the team keeps them.
- A document given twice is counted twice. The report lists its sources so
  this can be seen, but it cannot detect it.
- Quality analytics cover only the reviews saved where each document was
  written. A CI runner keeps none unless its store is kept between runs, so
  approval reports, which read the host, are the most complete cross-run
  source.
- Estimated cost covers only runs with explicit token usage and a
  configured price, and the report says how many runs that is.
