# ADR 0005: Rename Vero to Vee

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

The product was called Vero. The maintainer wanted a name that reads as a
protector, and chose V, after the protagonist of the game Cyberpunk 2077.

A bare `v` does not work as a command: the V programming language installs its
compiler as `v` (Homebrew `vlang`), so the two would shadow each other on PATH. A
single letter also cannot be searched for or registered as a package name.

Vero had not been released. There were no tags, packages, Homebrew cask, or
remote, and the version was 0.1.0, so nobody outside this repository depends on
the old names.

## Decision

Rename the product to **Vee**, the spoken form of V, everywhere:

- the binary `vee` and the crates `vee-*` (the CLI package is `vee`);
- the repository config `.vee.yaml` and the local state directory `.vee/`;
- the environment variables `VEE_*`;
- schema `$id`s and the attestation predicate type, under
  `https://vee.klarlabs.de/` (a subdomain of the maintainer's `klarlabs.de`,
  which also hosts the `go.klarlabs.de` modules);
- the MCP server name, the bundled skills (`vee-*`), the UI, the docs, and the
  markers Vee writes into hosted review comments.

There is no compatibility layer: `.vero.yaml`, `.vero/`, and `VERO_*` are not
read. The game inspires the name only; Vee uses none of its names, artwork, or
logos.

## Consequences

- Anyone using a pre-release build renames `.vero.yaml` to `.vee.yaml`, `.vero/`
  to `.vee/` (and `vero.sqlite` inside it to `vee.sqlite`), and `VERO_*`
  variables to `VEE_*`.
- Schema `$id`s and the attestation predicate type changed. Nothing was
  published under the old identifiers.
- `vee.klarlabs.de` is an identifier namespace for schema `$id`s and the
  attestation predicate type. The identifiers are stable whether or not the
  URLs resolve; serving the schemas there is optional. `vee.dev` is not used
  because it belongs to someone else.
- Comments that pre-release builds posted on hosted pull requests carry the old
  `vero` marker. Vee will not find them, so it posts new comments next to them
  instead of updating them.
