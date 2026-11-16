#!/usr/bin/env bash
# Run the UefiSecureVault-Suite pytest suite from the repository root.
# Extra arguments are passed to pytest (for example: -k qemu --maxfail=1).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="/usr/local/bin:/usr/sbin:/sbin:${PATH}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 is required to run tests." >&2
    exit 1
fi
if ! python3 -c "import pytest" 2>/dev/null; then
    echo "[-] pytest is required. On Debian: apt-get install python3-pytest" >&2
    exit 1
fi

# Default: verbose, show skip reasons. Do not fail the wrapper on pytest != 0
# before printing a short reminder; still return pytest's exit status.
set +e
python3 -m pytest -v tests/ "$@"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "[-] pytest exited $rc" >&2
fi
exit "$rc"
