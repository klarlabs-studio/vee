#!/bin/sh
# Install a Vee release binary on Linux or macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/klarlabs-studio/vee/main/scripts/install.sh | sh
#
# Environment:
#   VEE_VERSION       release tag to install, for example v0.2.0 (default: the latest release)
#   VEE_INSTALL_DIR   directory for the binary (default: $HOME/.local/bin)
#   VEE_RELEASE_BASE  where release files are served, for a mirror; requires VEE_VERSION
#                     (default: https://github.com/klarlabs-studio/vee/releases/download/<version>)
#
# The archive is checked against the release's SHA256SUMS. To also check where it
# was built, run: gh attestation verify <archive> --repo klarlabs-studio/vee
set -eu

repo="klarlabs-studio/vee"

fail() {
  echo "vee install: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

# Everything runs from main, called on the last line, so a download of this
# script that was cut short does nothing.
main() {
  need curl
  need tar
  install_dir="${VEE_INSTALL_DIR:-$HOME/.local/bin}"

  case "$(uname -s)" in
    Linux)
      os="unknown-linux-gnu"
      if ldd --version 2>&1 | grep -qi musl; then
        fail "the release binaries need glibc; on musl systems such as Alpine, build from source or use the container image"
      fi
      ;;
    Darwin) os="apple-darwin" ;;
    *) fail "unsupported operating system $(uname -s); on Windows, download the .zip from the releases page" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture $(uname -m)" ;;
  esac

  version="${VEE_VERSION:-}"
  if [ -z "$version" ]; then
    [ -z "${VEE_RELEASE_BASE:-}" ] || fail "set VEE_VERSION when using VEE_RELEASE_BASE"
    # The latest-release page redirects to the tag; this needs no API quota.
    latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest") \
      || fail "could not reach the releases page"
    version="${latest##*/}"
    case "$version" in
      v[0-9]*) ;;
      *) fail "no published release found; set VEE_VERSION or build from source" ;;
    esac
  fi

  name="vee-${version}-${arch}-${os}"
  base="${VEE_RELEASE_BASE:-https://github.com/${repo}/releases/download/${version}}"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  curl -fsSL "${base}/${name}.tar.gz" -o "${work}/${name}.tar.gz" \
    || fail "release ${version} has no archive ${name}.tar.gz"
  curl -fsSL "${base}/SHA256SUMS" -o "${work}/SHA256SUMS" \
    || fail "release ${version} has no SHA256SUMS"

  expected=$(awk -v file="${name}.tar.gz" '$2 == file || $2 == "*" file { print $1 }' "${work}/SHA256SUMS")
  [ -n "$expected" ] || fail "SHA256SUMS has no entry for ${name}.tar.gz"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${work}/${name}.tar.gz" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${work}/${name}.tar.gz" | cut -d' ' -f1)
  else
    fail "sha256sum or shasum is required to verify the download"
  fi
  [ "$expected" = "$actual" ] || fail "checksum mismatch for ${name}.tar.gz; nothing was installed"

  tar -xzf "${work}/${name}.tar.gz" -C "$work"
  [ -f "${work}/${name}/vee" ] || fail "the archive does not contain ${name}/vee"
  mkdir -p "$install_dir"
  install -m 0755 "${work}/${name}/vee" "${install_dir}/vee"
  echo "Installed vee ${version} to ${install_dir}/vee"

  command -v git >/dev/null 2>&1 || echo "Vee needs Git at runtime; install it before running vee."
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *) echo "Add ${install_dir} to your PATH to run vee." ;;
  esac
}

main "$@"
