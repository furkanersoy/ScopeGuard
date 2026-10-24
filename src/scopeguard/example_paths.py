"""Resolve bundled API demo files for source and installed-package use."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


_BUNDLED_EXAMPLES = {
    "examples/api/openapi.yaml": "demo-openapi.yaml",
    "examples/scenarios/local-demo.yaml": "demo-scenario.yaml",
}


def default_example_path(repository_path: str) -> str:
    """Prefer a local checkout example, then use the copy bundled in the wheel."""
    local_path = Path(repository_path)
    if local_path.is_file():
        return str(local_path)

    resource_name = _BUNDLED_EXAMPLES.get(repository_path)
    if resource_name is None:
        return str(local_path)

    try:
        bundled_path = Path(str(files("scopeguard_demo").joinpath(resource_name)))
    except (ModuleNotFoundError, TypeError, AttributeError):
        return str(local_path)
    return str(bundled_path) if bundled_path.is_file() else str(local_path)
