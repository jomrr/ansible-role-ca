"""CA role filter plugins."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from ansible.errors import AnsibleFilterError  # type: ignore[import-not-found,import-untyped]

try:
    from ansible.module_utils.ca_validation import authority_map  # type: ignore[import-not-found,import-untyped]
except ModuleNotFoundError:
    spec = importlib.util.spec_from_file_location(
        "ca_validation",
        Path(__file__).resolve().parents[1] / "module_utils" / "ca_validation.py",
    )
    if spec is None or spec.loader is None:
        raise
    ca_validation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ca_validation)
    authority_map = ca_validation.authority_map


def ca_authority_map(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    try:
        return authority_map(authorities)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "ca_authority_map": ca_authority_map,
        }
