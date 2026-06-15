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


def ca_publish_needs_unpack(
    manifest_results: list[dict[str, Any]],
    target_name: str,
    manifest_sha256: dict[str, str],
) -> bool:
    """Return whether a publish target needs archive extraction."""
    current: dict[str, str] = {}
    for result in manifest_results:
        pair = result.get("ca_publish_pair") or []
        if len(pair) != 2:
            continue
        target = pair[0]
        area = str(pair[1])
        if not isinstance(target, dict) or target.get("name") != target_name:
            continue
        stat = result.get("stat") or {}
        if stat.get("exists") and stat.get("checksum"):
            current[area] = str(stat["checksum"])
    return any(current.get(area) != checksum for area, checksum in manifest_sha256.items())


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "ca_authority_map": ca_authority_map,
            "ca_publish_needs_unpack": ca_publish_needs_unpack,
        }
