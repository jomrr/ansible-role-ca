"""Ca inventory revocation helpers."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import file_lock
from ansible.module_utils.ca_inventory_store import (
    _inventory_lock_path,
    _read_collection,
)
from ansible.module_utils.ca_serial import normalize_hex, parse_serial, serial_hex
from ansible.module_utils.ca_time import now_utc, timestamp_z


def _split_fingerprint(value: Any) -> tuple[str, str]:
    """Return an optional fingerprint algorithm and normalized fingerprint."""
    text = str(value or "").strip()
    if ":" in text:
        prefix, payload = text.split(":", 1)
        algorithm = prefix.replace("-", "").lower()
        if algorithm in {"sha1", "sha256"}:
            return algorithm, normalize_hex(payload)
    return "", normalize_hex(text)


def _certificate_fingerprint_match(
    record: dict[str, Any],
    *,
    algorithm: str,
    fingerprint: str,
) -> bool:
    """Return whether a certificate record matches a normalized fingerprint."""
    fingerprints = record.get("certificate", {}).get("fingerprints", {})
    if algorithm:
        return normalize_hex(fingerprints.get(algorithm, "")) == fingerprint
    return any(normalize_hex(value) == fingerprint for value in fingerprints.values())


def _current_certificate_record(
    base_dir: str,
    *,
    name: str,
) -> dict[str, Any] | None:
    """Return the current certificate pointer for a certificate name."""
    for record in _read_collection(base_dir, "current_certificates"):
        if str(record.get("name")) == name:
            return record
    return None


def _issued_certificate_by_pointer(
    base_dir: str,
    pointer: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the issued certificate record referenced by a current pointer."""
    issuer = str(pointer.get("issuer", ""))
    serial = str(pointer.get("serial_number_hex", ""))
    for record in _read_collection(base_dir, "issued_certificates"):
        if (
            str(record.get("issuer", "")) == issuer
            and str(record.get("certificate", {}).get("serial_number_hex", ""))
            == serial
        ):
            return record
    return None


def _issued_certificate_by_fingerprint(
    base_dir: str,
    *,
    authority: str,
    algorithm: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Return one issued certificate record matching a fingerprint."""
    matches = [
        record
        for record in _read_collection(base_dir, "issued_certificates")
        if str(record.get("issuer", "")) == authority
        and _certificate_fingerprint_match(
            record,
            algorithm=algorithm,
            fingerprint=fingerprint,
        )
    ]
    if not matches:
        raise ValueError(
            f"No issued certificate with matching fingerprint was found for {authority}"
        )
    if len(matches) > 1:
        names = ", ".join(sorted(str(record.get("name", "")) for record in matches))
        raise ValueError(
            f"Fingerprint matches multiple certificates issued by {authority}: {names}"
        )
    return matches[0]


def _revocation_field(entry: dict[str, Any], *keys: str) -> Any:
    """Return the first non-empty revocation field from a list of aliases."""
    for key in keys:
        value = entry.get(key)
        if value not in (None, ""):
            return value
    return None


def _resolved_revocation_from_record(
    entry: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    """Return a revocation entry enriched from an issued certificate record."""
    certificate = record["certificate"]
    result = dict(entry)
    result["serial_number"] = certificate["serial_number"]
    result["serial_number_hex"] = certificate["serial_number_hex"]
    result["issuer"] = record["issuer"]
    result["certificate_name"] = record["name"]
    result["fingerprints"] = certificate.get("fingerprints", {})
    return result


def _resolve_revocation_entries_unlocked(
    *,
    base_dir: str,
    authority: str,
    entries: list[dict[str, Any]],
    name_bindings: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve revocation entries while the inventory state lock is held."""
    resolved = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            raise ValueError("Revocation entries must be dictionaries")

        issuer = str(entry.get("issuer", entry.get("authority", authority)) or "")
        if issuer and issuer != authority:
            raise ValueError(
                f"Revocation entry for authority {issuer} was passed to {authority}"
            )

        serial = _revocation_field(entry, "serial_number", "serial")
        if serial is not None:
            resolved.append({**entry, "serial_number": str(parse_serial(serial))})
            continue

        certificate_name = _revocation_field(
            entry,
            "name",
            "certificate",
            "certificate_name",
        )
        if certificate_name is not None:
            certificate_name = str(certificate_name)
            if certificate_name in name_bindings:
                resolved.append(
                    {
                        **name_bindings[certificate_name],
                        **entry,
                        "serial_number": name_bindings[certificate_name][
                            "serial_number"
                        ],
                    }
                )
                continue
            pointer = _current_certificate_record(
                base_dir,
                name=certificate_name,
            )
            if pointer is None:
                raise ValueError(
                    f"No current certificate named {certificate_name} was found"
                )
            if str(pointer.get("issuer", "")) != authority:
                raise ValueError(
                    f"Certificate {certificate_name} is issued by "
                    f"{pointer.get('issuer')}, not {authority}"
                )
            record = _issued_certificate_by_pointer(base_dir, pointer)
            if record is None:
                raise ValueError(
                    f"Inventory record for certificate {certificate_name} was not found"
                )
            resolved.append(
                _resolved_revocation_from_record(
                    {**entry, "selector_name": certificate_name}, record
                )
            )
            continue

        fingerprint_value = _revocation_field(entry, "fingerprint", "sha1", "sha256")
        if fingerprint_value is not None:
            algorithm = ""
            if entry.get("sha1") is not None:
                algorithm = "sha1"
            elif entry.get("sha256") is not None:
                algorithm = "sha256"
            parsed_algorithm, fingerprint = _split_fingerprint(fingerprint_value)
            algorithm = algorithm or parsed_algorithm
            record = _issued_certificate_by_fingerprint(
                base_dir,
                authority=authority,
                algorithm=algorithm,
                fingerprint=fingerprint,
            )
            resolved.append(_resolved_revocation_from_record(entry, record))
            continue

        raise ValueError(
            "Revocation entries require one of serial_number, serial, name, "
            "certificate, certificate_name, fingerprint, sha1, or sha256"
        )
    return resolved


def resolve_revocation_entries(
    *,
    base_dir: str,
    authority: str,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Combine persistent issuer/serial revocations with newly declared entries."""
    with file_lock(_inventory_lock_path(base_dir)):
        revoked = {
            str(event["serial_number"]): event
            for event in _read_collection(base_dir, "revocations")
            if event["issuer"] == authority
        }
        resolved = _resolve_revocation_entries_unlocked(
            base_dir=base_dir,
            authority=authority,
            entries=entries,
            name_bindings={
                event["selector_name"]: event
                for event in revoked.values()
                if event.get("selector_name")
            },
        )
        for entry in resolved:
            serial = str(parse_serial(entry["serial_number"]))
            previous = revoked.get(serial, {})
            event = _revocation_event(authority, {**previous, **entry})
            event["revocation_date"] = str(
                entry.get("revocation_date")
                or previous.get("revocation_date")
                or timestamp_z(now_utc())
            )
            revoked[serial] = event
        return sorted(revoked.values(), key=lambda event: int(event["serial_number"]))


def _revocation_event(authority: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Return one revocation event record from declarative input."""
    serial = parse_serial(entry.get("serial_number", entry.get("serial")))
    event = {
        "record_type": "revocation",
        "schema_version": 1,
        "issuer": authority,
        "serial_number": str(serial),
        "serial_number_hex": serial_hex(serial),
        "reason": str(entry.get("reason") or ""),
        "revocation_date": str(entry.get("revocation_date") or ""),
        "invalidity_date": str(entry.get("invalidity_date") or ""),
        "source": "declarative",
    }
    if entry.get("certificate_name"):
        event["certificate_name"] = str(entry["certificate_name"])
    if entry.get("selector_name"):
        event["selector_name"] = str(entry["selector_name"])
    if entry.get("fingerprints"):
        event["fingerprints"] = entry["fingerprints"]
    return event


def _revocation_map(revocations: list[dict[str, Any]]) -> dict[tuple[str, str], dict]:
    """Return revocation events keyed by issuer and serial hex."""
    result = {}
    for event in revocations:
        result[(str(event["issuer"]), str(event["serial_number_hex"]))] = event
    return result
