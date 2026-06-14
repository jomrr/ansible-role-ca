"""CA role filter plugins."""

from __future__ import annotations

import re
from typing import Any

from ansible.errors import AnsibleFilterError  # type: ignore[import-not-found,import-untyped]


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _as_list(value: Any) -> list[Any]:
    """Return a list value or raise a filter error."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise AnsibleFilterError(f"Expected a list, got {type(value).__name__}")


def _string(value: Any) -> str:
    """Normalize optional values to strings for validation."""
    if value is None:
        return ""
    return str(value)


def _required(value: dict[str, Any], key: str, context: str) -> Any:
    """Return a required dictionary value or raise a filter error."""
    if key not in value or _string(value[key]) == "":
        raise AnsibleFilterError(f"{context} requires {key}")
    return value[key]


def ca_authority_map(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""

    result = {}
    for authority in _as_list(authorities):
        if not isinstance(authority, dict):
            raise AnsibleFilterError("Each ca_authorities item must be a dictionary")
        name = _string(_required(authority, "name", "Authority")).strip()
        if not SAFE_NAME_RE.match(name):
            raise AnsibleFilterError(
                f"Authority {name} has an unsafe name; use only letters, digits, dots, underscores, and hyphens"
            )
        if name in result:
            raise AnsibleFilterError(f"Duplicate authority name {name}")
        result[name] = authority

    for name, authority in result.items():
        parent = _string(_required(authority, "parent", f"Authority {name}")).strip()
        if parent not in result:
            raise AnsibleFilterError(
                f"Authority {name} references unknown parent {parent}"
            )
    return result


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "ca_authority_map": ca_authority_map,
        }
