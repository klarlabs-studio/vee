# ADR 0040: Signed and notarized macOS binaries

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

The macOS binaries carried only the linker's ad-hoc signature. That is
enough when they are installed through Homebrew or the shell installer,
because neither sets the quarantine attribute. A binary downloaded in a
browser is quarantined, though, and Gatekeeper refuses it as coming from
an unidentified developer until the user overrides the refusal. The
maintainer signature ([ADR 0039](0039-releases-signed-with-a-maintainer-key.md))
does not help here: macOS checks Apple's chain of trust, not ours.

## Decision

**dist signs; a script checks and notarizes.** `macos-sign = true` makes
dist sign each macOS binary with `codesign`, using a Developer ID
Application certificate imported into a temporary keychain from the
`CODESIGN_*` secrets. `CODESIGN_OPTIONS=runtime` turns on the hardened
runtime, which notarization requires. dist 0.34 does not notarize, so
`scripts/notarize-macos.py` runs after `dist build` on each macOS runner:

1. It extracts the binary from each macOS archive, so it checks exactly
   what will ship.
2. It refuses a binary without a Developer ID signature, a team
   identifier, a secure timestamp or the hardened runtime.
3. It submits the binary to Apple's notary service with `notarytool` and an
   App Store Connect API key, and fails the job unless Apple accepts it.

**Missing secrets fail the release.** dist only warns when the signing
secrets are absent and builds unsigned binaries. A release that silently
went out unsigned would undo this decision, so the check fails instead.

**The signing key lives in CI.** Unlike the maintainer key, Apple signing
has to happen before the archives exist, so the certificate is a
repository secret. It is scoped to the build job, and the notary key only
to the notarization step. A compromised workflow could sign malware with
the certificate; the maintainer signature and the provenance attestation
still tell a verifier which binaries the project published, and Apple can
revoke the certificate.

**No stapling.** A ticket can be stapled to an app bundle, a disk image or
an installer package, but not to a bare command-line binary. Gatekeeper
fetches the ticket online when the binary first runs. Shipping a `.pkg` or
`.dmg` only to staple a ticket is not worth another artifact format.

## Consequences

- A binary downloaded in a browser runs without a Gatekeeper override, when
  the machine is online the first time it runs.
- Releases need six repository secrets and an Apple Developer Program
  membership; a lapsed membership or an expired certificate fails the
  release rather than shipping unsigned binaries.
- Notarization adds a few minutes to each macOS build job.
- Windows binaries remain unsigned.
