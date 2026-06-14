"""Validation helpers shared by CA role modules and filter plugins."""

from __future__ import annotations

import re
from typing import Any

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SAFE_NAME_MESSAGE = (
    "use only letters, digits, dots, underscores, and hyphens"
)


def string_value(value: Any) -> str:
    """Normalize optional values to strings for validation."""
    if value is None:
        return ""
    return str(value)


def require_value(value: dict[str, Any], key: str, context: str) -> Any:
    """Return a required dictionary value or raise a validation error."""
    if key not in value or string_value(value[key]) == "":
        raise ValueError(f"{context} requires {key}")
    return value[key]


def safe_name(value: str, context: str) -> str:
    """Return a stripped safe object name or raise a validation error."""
    name = string_value(value).strip()
    if not SAFE_NAME_RE.match(name):
        raise ValueError(f"{context} {name} has an unsafe name; {SAFE_NAME_MESSAGE}")
    return name


def authority_map(
    authorities: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    if authorities is None:
        return {}
    if not isinstance(authorities, list):
        raise ValueError(f"Expected a list, got {type(authorities).__name__}")

    result = {}
    for authority in authorities:
        if not isinstance(authority, dict):
            raise ValueError("Each ca_authorities item must be a dictionary")
        name = safe_name(require_value(authority, "name", "Authority"), "Authority")
        if name in result:
            raise ValueError(f"Duplicate authority name {name}")
        result[name] = authority

    for name, authority in result.items():
        parent = string_value(require_value(authority, "parent", f"Authority {name}"))
        parent = parent.strip()
        if parent not in result:
            raise ValueError(f"Authority {name} references unknown parent {parent}")
    return result
