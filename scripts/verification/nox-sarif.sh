#!/bin/sh
# Run the nox security scanner offline and print its SARIF 2.1.0 report on stdout,
# the contract for Vero's trusted analyzer profiles. nox writes reports to a
# directory, so this uses a private temporary one outside the repository.
#
# Exit status: nox's own (0 clean, 1 findings) when a report was produced;
# 2 when no report exists, which Vero treats as an incomplete analyzer run.
set -u
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/vero-nox.XXXXXX") || exit 2
trap 'rm -rf "$report_dir"' EXIT HUP INT TERM

nox scan . --format sarif --output "$report_dir" --offline --tracked-only --quiet >&2
status=$?

if [ ! -s "$report_dir/results.sarif" ]; then
    echo "nox produced no SARIF report (exit $status)" >&2
    exit 2
fi
cat "$report_dir/results.sarif" || exit 2
exit "$status"
