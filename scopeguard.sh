#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

PYTHON=""
for candidate in python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    echo "ScopeGuard requires Python 3.11 or newer." >&2
    exit 2
fi

if [ ! -x .venv/bin/python ]; then
    echo "Setting up ScopeGuard on first launch..."
    "$PYTHON" -m venv .venv
fi

if [ ! -f .venv/.scopeguard-installed ]; then
    echo "Installing ScopeGuard and its dependencies..."
    .venv/bin/python -m pip install --disable-pip-version-check -e "$(pwd)"
    : > .venv/.scopeguard-installed
fi

exec .venv/bin/scopeguard "$@"
