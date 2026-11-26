# ADR 0029: Security scanner presets and a regulated policy

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Vee gates on SARIF from any trusted analyzer (ADR 0002), but each team had
to work out the command line for its scanners and write the profiles
itself. Teams in regulated settings also need a policy where a person
approves every change, whatever the approval guards allow; Vee had no way
to say that for one policy profile. And in CI, which keeps no earlier
verification runs, a policy that required an analyzer always left the
review incomplete.

## Decision

- **Presets, not a scanner.** `vee init` looks for nox, gitleaks, semgrep,
  trivy and osv-scanner on the machine. For each one Vee can use, a new
  repository's `.vee.yaml` gets a verification profile that writes SARIF to
  stdout:
  - nox (`scan`, with OSV advisories), network, blocking at `error`. It
    exits non-zero when it reports results, which with valid SARIF is a
    complete run; `--offline` and `egress: local` scan without the network;
  - gitleaks (`dir`, redacted, exit code 0), local, blocking at `error` and
    `warning`, since gitleaks gives results no level and SARIF reads that as
    `warning`;
  - semgrep (`p/default`, metrics off), network, blocking at `error`;
  - trivy (`fs`, vulnerabilities, secrets and misconfiguration), network,
    blocking at `error`.

  osv-scanner is reported but not set up: its SARIF gives no line for a
  result, and Vee counts only results on changed lines, so it could never
  block. In an existing repository, `vee init` does not change `.vee.yaml`;
  it prints the configuration to add.
- **Two policy profiles.** Both require the scanners found.
  - `security`: the default policy, with security findings raised to at
    least `high`.
  - `regulated`: blocks `medium` findings too, confidence threshold 70,
    unreviewed files block, security findings and changes under `auth`,
    `crypto`, `payments`, `migrations` and `.github/workflows` raised to at
    least `high`, and `automatic_approval: false`.

  A profile rather than a separate pack keeps one place to edit; `vee packs
  export` shares it across repositories like any profile.
- **`policy.automatic_approval`.** `false` makes approval eligibility fail a
  new `policy` stage for reviews gated under that policy. Pack merging can
  turn it off but never back on.
- **CI runs required verifications.** `vee ci run` and the commands that
  review run each verification profile the selected policy requires on the
  change before reviewing. A profile that cannot run is reported and leaves
  the gate incomplete, as before.

## Consequences

- A team gets a scanner-backed gate by installing the scanner and running
  `vee init`, or by pasting the printed configuration.
- The scanners must be installed on CI runners; the Action does not install
  them.
- nox (with advisories), semgrep and trivy use the network; their
  profiles declare `egress: network`, so `offline: true` repositories cannot
  use them.
- The path floors in `regulated` are conventions; teams should edit them to
  their own sensitive paths.
