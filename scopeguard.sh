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

SG_PROJECT_HASH="$(.venv/bin/python -c 'import hashlib; from pathlib import Path; print(hashlib.sha256(Path("pyproject.toml").read_bytes()).hexdigest())')"
SG_INSTALLED_HASH=""
if [ -f .venv/.scopeguard-installed ]; then
    IFS= read -r SG_INSTALLED_HASH < .venv/.scopeguard-installed || true
fi
if [ "$SG_PROJECT_HASH" != "$SG_INSTALLED_HASH" ]; then
    echo "Installing or updating ScopeGuard and its dependencies..."
    .venv/bin/python -m pip install --disable-pip-version-check -e "$(pwd)"
    printf "%s\\n" "$SG_PROJECT_HASH" > .venv/.scopeguard-installed
fi

exec .venv/bin/scopeguard "$@"
