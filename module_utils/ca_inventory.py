"""Ca inventory helpers."""

from __future__ import annotations

import json
from typing import Any

from ansible.module_utils.ca_file import file_lock, write_file
from ansible.module_utils.ca_inventory_records import (
    record_authority_inventory,
    record_certificate_inventory,
    record_crl_inventory,
)
from ansible.module_utils.ca_inventory_revocation import (
    _revocation_map,
    resolve_revocation_entries,
)
from ansible.module_utils.ca_inventory_store import (
    _inventory_lock_path,
    _inventory_path,
    _read_collection,
)
from ansible.module_utils.ca_renewal import renewal_status
from ansible.module_utils.ca_time import now_utc, parse_datetime

CRYPTOGRAPHY_IMPORT_ERROR = None

__all__ = [
    "_compose_inventory_if_configured_unlocked",
    "_compose_inventory_unlocked",
    "_status",
    "_with_status",
    "_write_composed_inventory_unlocked",
    "compose_inventory",
    "compose_inventory_if_configured",
    "record_authority_inventory",
    "record_certificate_inventory",
    "record_crl_inventory",
    "resolve_revocation_entries",
    "update_authority_inventory",
    "update_certificate_inventory",
    "update_certificates_inventory",
    "update_crl_inventory",
    "write_composed_inventory",
]


def update_authority_inventory(
    params: dict[str, Any],
    result: dict[str, Any],
) -> bool:
    """Record authority fragments and compose inventory in one transaction."""
    base_dir = str(params["base_dir"]).rstrip("/")
    with file_lock(_inventory_lock_path(base_dir)):
        changed = record_authority_inventory(params, result)
        return _compose_inventory_if_configured_unlocked(params) or changed


def update_certificate_inventory(
    params: dict[str, Any],
    model: dict[str, Any],
    result: dict[str, Any],
) -> bool:
    """Record certificate fragments and compose inventory in one transaction."""
    base_dir = str(params["base_dir"]).rstrip("/")
    with file_lock(_inventory_lock_path(base_dir)):
        changed = record_certificate_inventory(params, model, result)
        return _compose_inventory_if_configured_unlocked(params) or changed


def update_certificates_inventory(
    records: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
) -> bool:
    """Record multiple certificate fragments and compose inventory once."""
    if not records:
        return False

    base_dir = str(records[0][0]["base_dir"]).rstrip("/")
    with file_lock(_inventory_lock_path(base_dir)):
        changed = False
        for params, model, result in records:
            changed = record_certificate_inventory(params, model, result) or changed
        return _compose_inventory_if_configured_unlocked(records[0][0]) or changed


def update_crl_inventory(
    params: dict[str, Any],
    crl,
) -> bool:
    """Record CRL fragments and compose inventory in one transaction."""
    base_dir = str(params["base_dir"]).rstrip("/")
    with file_lock(_inventory_lock_path(base_dir)):
        changed = False
        for crl_format, path in params["paths"].items():
            crl_params = dict(params)
            crl_params["format"] = crl_format
            crl_params["path"] = path
            changed = record_crl_inventory(crl_params, crl) or changed
        return _compose_inventory_if_configured_unlocked(params) or changed


def _status(
    record: dict[str, Any],
    revocations: dict[tuple[str, str], dict],
) -> dict[str, Any]:
    """Return status for an issued certificate record."""
    issuer = str(record["issuer"])
    serial_hex = str(record["certificate"]["serial_number_hex"])
    revoked = revocations.get((issuer, serial_hex))
    if revoked is not None:
        return {"state": "revoked", "revocation": revoked}
    now = now_utc()
    not_before = parse_datetime(record["certificate"]["not_valid_before"])
    not_after = parse_datetime(record["certificate"]["not_valid_after"])
    if not_before is None or not_after is None:
        raise ValueError("certificate record must contain validity timestamps")
    if not_before > now:
        return {"state": "not_yet_valid"}
    if not_after <= now:
        return {"state": "expired"}
    return {"state": "valid"}


def _with_status(
    record: dict[str, Any],
    current_pointers: dict[str, dict[str, Any]],
    revocations: dict[tuple[str, str], dict],
) -> dict[str, Any]:
    """Return an issued certificate with status and current flag."""
    result = dict(record)
    pointer = current_pointers.get(str(record["name"]), {})
    result["current"] = pointer.get("issuer") == record.get("issuer") and pointer.get(
        "serial_number_hex"
    ) == record.get("certificate", {}).get("serial_number_hex")
    result["status"] = _status(record, revocations)
    result["renewal_status"] = renewal_status(
        record["certificate"],
        record.get("renewal"),
    )
    return result


def _compose_inventory_unlocked(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
) -> dict[str, Any]:
    """Compose inventory JSON while the state lock is held."""
    authorities = sorted(
        _read_collection(base_dir, "authorities"),
        key=lambda record: str(record.get("name", "")),
    )
    current_pointers = {
        str(record["name"]): record
        for record in _read_collection(base_dir, "current_certificates")
    }
    revocations = sorted(
        _read_collection(base_dir, "revocations"),
        key=lambda record: (
            str(record.get("issuer", "")),
            str(record.get("serial_number_hex", "")),
        ),
    )
    revocation_by_serial = _revocation_map(revocations)
    issued = [
        _with_status(record, current_pointers, revocation_by_serial)
        for record in _read_collection(base_dir, "issued_certificates")
    ]
    issued = sorted(
        issued,
        key=lambda record: (
            str(record.get("name", "")),
            str(record.get("issuer", "")),
            str(record.get("certificate", {}).get("serial_number_hex", "")),
        ),
    )
    crls = sorted(
        _read_collection(base_dir, "crls"),
        key=lambda record: (
            str(record.get("authority", "")),
            str(record.get("format", "")),
        ),
    )
    authority_certificates = sorted(
        _read_collection(base_dir, "authority_certificates"),
        key=lambda record: (
            str(record.get("name", "")),
            str(record.get("certificate", {}).get("serial_number_hex", "")),
        ),
    )
    return {
        "schema_version": 1,
        "ca_name": ca_name,
        "base_dir": str(base_dir).rstrip("/"),
        "base_url": base_url,
        "authorities": authorities,
        "authority_certificates": authority_certificates,
        "certificates": [record for record in issued if record["current"]],
        "issued_certificates": issued,
        "revocations": revocations,
        "crls": crls,
    }


def compose_inventory(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
) -> dict[str, Any]:
    """Compose inventory JSON from internal state fragments."""
    with file_lock(_inventory_lock_path(base_dir)):
        return _compose_inventory_unlocked(
            base_dir=base_dir,
            ca_name=ca_name,
            base_url=base_url,
        )


def write_composed_inventory(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
    owner: Any,
    group: Any,
    mode: str = "0644",
    force: bool = False,
) -> bool:
    """Write the composed CA inventory file in an inventory transaction."""
    with file_lock(_inventory_lock_path(base_dir)):
        return _write_composed_inventory_unlocked(
            base_dir=base_dir,
            ca_name=ca_name,
            base_url=base_url,
            owner=owner,
            group=group,
            mode=mode,
            force=force,
        )


def _write_composed_inventory_unlocked(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
    owner: Any,
    group: Any,
    mode: str = "0644",
    force: bool = False,
) -> bool:
    """Write the composed CA inventory file while the state lock is held."""
    content = (
        json.dumps(
            _compose_inventory_unlocked(
                base_dir=base_dir,
                ca_name=ca_name,
                base_url=base_url,
            ),
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    return write_file(
        _inventory_path(base_dir),
        content,
        owner,
        group,
        mode,
        force=force,
    )


def _compose_inventory_if_configured_unlocked(params: dict[str, Any]) -> bool:
    """Compose the central CA inventory if configured while the state lock is held."""
    ca_name = str(params.get("ca_name") or "")
    if not ca_name:
        return False
    return _write_composed_inventory_unlocked(
        base_dir=str(params["base_dir"]),
        ca_name=ca_name,
        base_url=str(params.get("base_url") or ""),
        owner=params.get("owner"),
        group=params.get("group"),
    )


def compose_inventory_if_configured(params: dict[str, Any]) -> bool:
    """Compose the central CA inventory when module parameters provide a CA name."""
    with file_lock(_inventory_lock_path(str(params["base_dir"]))):
        return _compose_inventory_if_configured_unlocked(params)
