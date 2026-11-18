# ADR 0006: Portable canonical paths and child-process environments

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

The first Windows CI runs failed in ways Linux and macOS never showed:

- `std::fs::canonicalize` returns Windows paths in verbatim form (`\\?\C:\...`).
  Those paths do not round-trip through `file://` URLs (SARIF locations,
  language-server workspace URIs) and do not compare equal to the plain paths
  that tools report. When only one side of a containment check was
  canonicalized, every file looked like it was outside the repository.
- Vee starts verification commands, reviewer CLIs, and analyzers (gopls,
  tsserver, rust-analyzer, Python) from an empty environment plus an explicit
  allowlist, usually `PATH` and `HOME`. On Windows that is not enough: Node
  and many other programs need `SYSTEMROOT`, Go needs `LOCALAPPDATA` for its
  build cache, and Cargo needs `USERPROFILE`.

## Decision

1. **One canonicalization.** All Vee code canonicalizes through
   `vee_core::paths::CanonicalPath::canonical` (or `vee_core::paths::canonicalize`),
   which uses `dunce` to return the plain form whenever Windows can express the
   path without the verbatim prefix. On other platforms it is
   `std::fs::canonicalize`. Clippy's `disallowed-methods` (in `clippy.toml`)
   rejects direct `std` canonicalization, so every compared path has one form.
2. **A platform environment for child processes.** Processes that start from
   an empty environment also receive `vee_process::PLATFORM_ENVIRONMENT`: on
   Windows the OS variables programs need to start and to locate temporary and
   per-user directories (`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`, `TEMP`,
   `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, and similar). None carries
   credentials. Explicitly allowed variables are applied afterwards and win. On
   Linux and macOS the list is empty.

## Consequences

- Linux and macOS behaviour is unchanged, including verification command
  digests.
- On Windows, the platform variables are not part of verification command
  digests: they describe the machine, not the command, and the allowlisted
  variables remain digest-bound. A verification profile still has to allow any
  tool-specific variable it relies on (for example `GOPATH` or `CARGO_HOME`).
- New code that calls `std::fs::canonicalize` or `Path::canonicalize` fails
  `cargo clippy -D warnings`.
