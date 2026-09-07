"""Ca inventory store helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ansible.module_utils.ca_file import (
    ca_lock_path,
    read_file,
    safe_path_component,
    write_file,
)


def _state_dir(base_dir: str) -> str:
    """Return the directory that stores inventory state fragments."""
    return f"{str(base_dir).rstrip('/')}/inventory/state"


def _inventory_path(base_dir: str) -> str:
    """Return the composed inventory path."""
    return f"{str(base_dir).rstrip('/')}/inventory/ca-inventory.json"


def _inventory_lock_path(base_dir: str) -> str:
    """Return the shared lock path for inventory state transactions."""
    return ca_lock_path(base_dir, "inventory", "state")


def _record_path(base_dir: str, *parts: str) -> str:
    """Return a JSON state fragment path below the inventory state directory."""
    safe_parts = [safe_path_component(part) for part in parts]
    return f"{_state_dir(base_dir)}/{'/'.join(safe_parts)}.json"


def _write_json(
    path: str,
    data: dict[str, Any],
    owner: Any,
    group: Any,
    mode: str,
) -> bool:
    """Write deterministic JSON state."""
    content = json.dumps(data, indent=2, sort_keys=True).encode() + b"\n"
    return write_file(path, content, owner, group, mode)


def _read_json(path: str) -> dict[str, Any]:
    """Read one JSON state fragment."""
    return json.loads(read_file(path).decode())


def _read_collection(base_dir: str, collection: str) -> list[dict[str, Any]]:
    """Read JSON state fragments below a collection directory."""
    root = Path(_state_dir(base_dir)) / collection
    if not root.is_dir():
        return []
    records = []
    for path in sorted(root.rglob("*.json")):
        if path.is_file():
            records.append(_read_json(str(path)))
    return records
