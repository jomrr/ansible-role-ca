"""Persist CRL sequence numbers independently of the public exports."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import file_lock
from ansible.module_utils.ca_inventory_store import (
    _inventory_lock_path,
    _read_json,
    _record_path,
    _write_json,
)


def _stored_number(path: str) -> int:
    """Read a sequence number, failing on corrupt state instead of resetting it."""
    try:
        record = _read_json(path)
    except FileNotFoundError:
        return 0
    number = record["crl_number"]
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ValueError(f"Invalid CRL number in {path}")
    return number


def last_crl_number(base_dir: str, name: str) -> int:
    """Read the authoritative sequence number independently of CRL exports."""
    with file_lock(_inventory_lock_path(base_dir)):
        return _stored_number(_record_path(base_dir, "crl_numbers", name))


def store_crl_number(params: dict[str, Any], number: int) -> bool:
    """Reserve the number before exporting its CRL; never move it backwards."""
    base_dir, name = str(params["base_dir"]), str(params["name"])
    with file_lock(_inventory_lock_path(base_dir)):
        path = _record_path(base_dir, "crl_numbers", name)
        if number < _stored_number(path):
            raise ValueError(f"Refusing to decrease CRL number for {name}")
        return _write_json(
            path,
            {"crl_number": number},
            params.get("owner"),
            params.get("group"),
            "0600",
        )
