"""Internal CA inventory state helpers."""

from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    read_file,
    safe_path_component,
    write_file,
)

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
except Exception as exc:  # pragma: no cover - handled by callers
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None

SERIAL_CLEANUP_RE = re.compile(r"[^0-9A-Fa-f]")


def _state_dir(base_dir: str) -> str:
    """Return the directory that stores inventory state fragments."""
    return f"{str(base_dir).rstrip('/')}/inventory/state"


def _inventory_path(base_dir: str) -> str:
    """Return the composed inventory path."""
    return f"{str(base_dir).rstrip('/')}/inventory/ca-inventory.json"


def _record_path(base_dir: str, *parts: str) -> str:
    """Return a JSON state fragment path below the inventory state directory."""
    safe_parts = [safe_path_component(part) for part in parts]
    return f"{_state_dir(base_dir)}/{'/'.join(safe_parts)}.json"


def _load_certificate(path: str) -> x509.Certificate:
    """Load a PEM or DER X.509 certificate from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _utc(value: _dt.datetime) -> _dt.datetime:
    """Return a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _not_valid_before(cert: x509.Certificate) -> _dt.datetime:
    """Return a certificate not-before timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_before_utc", None)
    return value if value is not None else _utc(cert.not_valid_before)


def _not_valid_after(cert: x509.Certificate) -> _dt.datetime:
    """Return a certificate not-after timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else _utc(cert.not_valid_after)


def _timestamp(value: _dt.datetime) -> str:
    """Return an ISO-8601 UTC timestamp without microseconds."""
    return _utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> _dt.datetime:
    """Parse an inventory UTC timestamp."""
    return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _colon_hex(data: bytes) -> str:
    """Return colon-separated uppercase hex."""
    return ":".join(f"{byte:02X}" for byte in data)


def _serial_hex(value: int) -> str:
    """Return an even-length uppercase hexadecimal certificate serial."""
    text = f"{value:X}"
    return text if len(text) % 2 == 0 else f"0{text}"


def _parse_serial(value: Any) -> int:
    """Parse decimal, hexadecimal, or colon-separated certificate serials."""
    if isinstance(value, int):
        return value
    text = str(value)
    if ":" in text:
        return int(SERIAL_CLEANUP_RE.sub("", text), 16)
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def _normalize_hex(value: Any) -> str:
    """Return uppercase hexadecimal text without separators."""
    return SERIAL_CLEANUP_RE.sub("", str(value)).upper()


def _split_fingerprint(value: Any) -> tuple[str, str]:
    """Return an optional fingerprint algorithm and normalized fingerprint."""
    text = str(value or "").strip()
    if ":" in text:
        prefix, payload = text.split(":", 1)
        algorithm = prefix.replace("-", "").lower()
        if algorithm in {"sha1", "sha256"}:
            return algorithm, _normalize_hex(payload)
    return "", _normalize_hex(text)


def _name_attributes(name: x509.Name) -> list[dict[str, str]]:
    """Return a stable list of X.509 name attributes."""
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": getattr(attribute.oid, "_name", attribute.oid.dotted_string),
            "value": attribute.value,
        }
        for attribute in name
    ]


def _oid_name(oid) -> str:
    """Return a readable OID name with dotted-string fallback."""
    name = getattr(oid, "_name", "") or ""
    return name if name and name != "Unknown OID" else oid.dotted_string


def _general_name(name) -> str:
    """Return a compact string representation of a GeneralName."""
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RegisteredID):
        return f"RID:{name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        return f"otherName:{name.type_id.dotted_string};DER:{_colon_hex(name.value)}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name.value.rfc4514_string()}"
    return repr(name)


def _key_usage(value: x509.KeyUsage) -> list[str]:
    """Return key usage names set on an X.509 certificate."""
    usages = []
    if value.digital_signature:
        usages.append("digitalSignature")
    if value.content_commitment:
        usages.append("nonRepudiation")
    if value.key_encipherment:
        usages.append("keyEncipherment")
    if value.data_encipherment:
        usages.append("dataEncipherment")
    if value.key_agreement:
        usages.append("keyAgreement")
    if value.key_cert_sign:
        usages.append("keyCertSign")
    if value.crl_sign:
        usages.append("cRLSign")
    if value.key_agreement and value.encipher_only:
        usages.append("encipherOnly")
    if value.key_agreement and value.decipher_only:
        usages.append("decipherOnly")
    return usages


def _extension_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return selected certificate extensions for inventory use."""
    result: dict[str, Any] = {}
    for extension in cert.extensions:
        value = extension.value
        if isinstance(value, x509.BasicConstraints):
            result["basic_constraints"] = {
                "critical": extension.critical,
                "ca": value.ca,
                "path_length": value.path_length,
            }
        elif isinstance(value, x509.KeyUsage):
            result["key_usage"] = {
                "critical": extension.critical,
                "value": _key_usage(value),
            }
        elif isinstance(value, x509.ExtendedKeyUsage):
            result["extended_key_usage"] = {
                "critical": extension.critical,
                "value": [
                    {"oid": oid.dotted_string, "name": _oid_name(oid)}
                    for oid in value
                ],
            }
        elif isinstance(value, x509.SubjectAlternativeName):
            result["subject_alt_name"] = {
                "critical": extension.critical,
                "value": [_general_name(name) for name in value],
            }
        elif isinstance(value, x509.AuthorityInformationAccess):
            result["authority_information_access"] = [
                {
                    "method": item.access_method.dotted_string,
                    "method_name": _oid_name(item.access_method),
                    "location": _general_name(item.access_location),
                }
                for item in value
            ]
        elif isinstance(value, x509.CRLDistributionPoints):
            result["crl_distribution_points"] = [
                [_general_name(name) for name in point.full_name or []]
                for point in value
            ]
    return result


def _public_key_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return a small public key summary."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "size": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "ECDSA", "curve": key.curve.name, "size": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519"}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"type": "Ed448"}
    return {"type": key.__class__.__name__}


def _certificate_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return stable, non-secret metadata for one certificate."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_attributes": _name_attributes(cert.subject),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_attributes": _name_attributes(cert.issuer),
        "serial_number": str(cert.serial_number),
        "serial_number_hex": _serial_hex(cert.serial_number),
        "not_valid_before": _timestamp(_not_valid_before(cert)),
        "not_valid_after": _timestamp(_not_valid_after(cert)),
        "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
        "fingerprints": {
            "sha1": _colon_hex(cert.fingerprint(hashes.SHA1())),
            "sha256": _colon_hex(cert.fingerprint(hashes.SHA256())),
        },
        "public_key": _public_key_summary(cert),
        "extensions": _extension_summary(cert),
    }


def _authority_paths(
    base_dir: str,
    name: str,
    *,
    include_chain: bool,
) -> dict[str, str]:
    """Return derived authority artifact paths."""
    ca_file = f"{name}-ca"
    paths = {
        "private_key": f"{base_dir}/private/{ca_file}.key",
        "csr": f"{base_dir}/csr/{ca_file}.csr",
        "certificate_pem": f"{base_dir}/ca/{ca_file}.pem",
        "certificate_der": f"{base_dir}/ca/{ca_file}.der",
        "certificate_text": f"{base_dir}/ca/{ca_file}.txt",
        "crl_pem": f"{base_dir}/crl/{ca_file}.crl.pem",
        "crl_der": f"{base_dir}/crl/{ca_file}.crl",
    }
    if include_chain:
        paths["chain"] = f"{base_dir}/chains/{ca_file}-chain.pem"
    return paths


def _certificate_paths(base_dir: str, certificate: dict[str, Any]) -> dict[str, str]:
    """Return derived managed certificate artifact paths."""
    name = str(certificate["name"])
    output_dir = str(certificate.get("output_dir") or f"{base_dir}/certs/{name}")
    output_dir = output_dir.rstrip("/")
    return {
        "output_dir": output_dir,
        "private_key": f"{output_dir}/{name}.key",
        "csr": f"{base_dir}/csr/{name}.csr",
        "certificate_pem": f"{output_dir}/{name}.pem",
        "certificate_der": f"{output_dir}/{name}.der",
        "certificate_text": f"{output_dir}/{name}.txt",
        "chain": f"{output_dir}/{name}-chain.pem",
        "fullchain": f"{output_dir}/{name}-fullchain.pem",
        "fritzbox_bundle": f"{output_dir}/{name}-fritzbox.pem",
        "pkcs12_pfx": f"{output_dir}/{name}.pfx",
        "pkcs12_p12": f"{output_dir}/{name}.p12",
    }


def _certificate_record_paths(
    base_dir: str,
    certificate: dict[str, Any],
) -> dict[str, str]:
    """Return deterministic managed artifact paths for a certificate record."""
    paths = _certificate_paths(base_dir, certificate)
    formats = {str(item).lower() for item in certificate.get("formats", [])}
    keys = {"output_dir", "private_key", "csr", "certificate_pem", "chain"}
    if "der" in formats:
        keys.add("certificate_der")
    if "txt" in formats:
        keys.add("certificate_text")
    if "fullchain" in formats:
        keys.add("fullchain")
    if "fritzbox" in formats:
        keys.add("fritzbox_bundle")
    if "pfx" in formats:
        keys.add("pkcs12_pfx")
    if "p12" in formats:
        keys.add("pkcs12_p12")
    return {key: paths[key] for key in sorted(keys)}


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


def _certificate_fingerprint_match(
    record: dict[str, Any],
    *,
    algorithm: str,
    fingerprint: str,
) -> bool:
    """Return whether a certificate record matches a normalized fingerprint."""
    fingerprints = record.get("certificate", {}).get("fingerprints", {})
    if algorithm:
        return _normalize_hex(fingerprints.get(algorithm, "")) == fingerprint
    return any(_normalize_hex(value) == fingerprint for value in fingerprints.values())


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
    serial_hex = str(pointer.get("serial_number_hex", ""))
    for record in _read_collection(base_dir, "issued_certificates"):
        if (
            str(record.get("issuer", "")) == issuer
            and str(record.get("certificate", {}).get("serial_number_hex", ""))
            == serial_hex
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


def resolve_revocation_entries(
    *,
    base_dir: str,
    authority: str,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve revocation entries by serial number, certificate name, or fingerprint."""
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
            item = dict(entry)
            item["serial_number"] = str(_parse_serial(serial))
            resolved.append(item)
            continue

        certificate_name = _revocation_field(
            entry,
            "name",
            "certificate",
            "certificate_name",
        )
        if certificate_name is not None:
            pointer = _current_certificate_record(
                base_dir,
                name=str(certificate_name),
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
            resolved.append(_resolved_revocation_from_record(entry, record))
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


def record_authority_inventory(
    params: dict[str, Any],
    result: dict[str, Any],
) -> bool:
    """Record current authority state as an internal inventory fragment."""
    base_dir = str(params["base_dir"]).rstrip("/")
    name = str(params["name"])
    cert = _load_certificate(result["cert_path"])
    parent = str(params.get("parent") or name)
    self_signed = parent == name
    paths = _authority_paths(base_dir, name, include_chain=not self_signed)
    certificate = _certificate_summary(cert)
    record = {
        "record_type": "authority",
        "schema_version": 1,
        "name": name,
        "common_name": str(params.get("common_name") or ""),
        "parent": parent,
        "self_signed": self_signed,
        "days": params.get("days"),
        "certificate": certificate,
        "paths": paths,
    }
    return _write_json(
        _record_path(base_dir, "authorities", name),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )


def record_certificate_inventory(
    params: dict[str, Any],
    model: dict[str, Any],
    result: dict[str, Any],
) -> bool:
    """Record managed certificate issuance state as inventory fragments."""
    base_dir = str(params["base_dir"]).rstrip("/")
    name = str(model["name"])
    issuer = str(model["issuer"])
    cert = _load_certificate(result["cert_path"])
    certificate = _certificate_summary(cert)
    serial_hex = certificate["serial_number_hex"]
    paths = _certificate_record_paths(base_dir, model)
    record = {
        "record_type": "issued_certificate",
        "schema_version": 1,
        "name": name,
        "type": str(model.get("type", "")),
        "common_name": str(model.get("common_name", "")),
        "issuer": issuer,
        "days": model.get("days"),
        "formats": [str(item).lower() for item in model.get("formats", [])],
        "certificate": certificate,
        "paths": paths,
    }
    pointer = {
        "record_type": "current_certificate",
        "schema_version": 1,
        "name": name,
        "issuer": issuer,
        "serial_number_hex": serial_hex,
        "fingerprints": certificate["fingerprints"],
    }
    changed = _write_json(
        _record_path(base_dir, "issued_certificates", issuer, serial_hex),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    return (
        _write_json(
            _record_path(base_dir, "current_certificates", name),
            pointer,
            params.get("owner"),
            params.get("group"),
            "0644",
        )
        or changed
    )


def _crl_timestamp(value: _dt.datetime) -> str:
    """Return a CRL timestamp normalized to inventory text."""
    return _timestamp(value)


def _crl_update(crl, name: str):
    """Return a CRL timestamp across cryptography versions."""
    utc_name = f"{name}_utc"
    value = getattr(crl, utc_name, None)
    if value is not None:
        return value
    value = getattr(crl, name)
    return _utc(value)


def _crl_number(crl) -> int | None:
    """Return the CRL Number extension value when present."""
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def _crl_authority_key_identifier(crl) -> str:
    """Return the CRL Authority Key Identifier when present."""
    try:
        value = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return ""
    return _colon_hex(value.key_identifier or b"")


def _revoked_from_crl(crl) -> list[dict[str, Any]]:
    """Return revoked certificate metadata from a CRL object."""
    revoked = []
    for item in crl:
        reason = ""
        try:
            reason_ext = item.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        date = getattr(item, "revocation_date_utc", None)
        if date is None:
            date = _utc(item.revocation_date)
        record = {
            "serial_number": str(item.serial_number),
            "serial_number_hex": _serial_hex(item.serial_number),
            "reason": reason,
            "revocation_date": _timestamp(date),
        }
        try:
            invalidity_ext = item.extensions.get_extension_for_class(
                x509.InvalidityDate
            )
            invalidity_date = getattr(invalidity_ext.value, "invalidity_date_utc", None)
            if invalidity_date is None:
                invalidity_date = _utc(invalidity_ext.value.invalidity_date)
            record["invalidity_date"] = _timestamp(invalidity_date)
        except x509.ExtensionNotFound:
            pass
        revoked.append(record)
    return sorted(revoked, key=lambda entry: entry["serial_number_hex"])


def _revocation_event(authority: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Return one revocation event record from declarative input."""
    serial = _parse_serial(entry.get("serial_number", entry.get("serial")))
    event = {
        "record_type": "revocation",
        "schema_version": 1,
        "issuer": authority,
        "serial_number": str(serial),
        "serial_number_hex": _serial_hex(serial),
        "reason": str(entry.get("reason") or ""),
        "revocation_date": str(entry.get("revocation_date") or ""),
        "invalidity_date": str(entry.get("invalidity_date") or ""),
        "source": "declarative",
    }
    if entry.get("certificate_name"):
        event["certificate_name"] = str(entry["certificate_name"])
    if entry.get("fingerprints"):
        event["fingerprints"] = entry["fingerprints"]
    return event


def record_crl_inventory(
    params: dict[str, Any],
    crl,
) -> bool:
    """Record CRL and revocation state as internal inventory fragments."""
    base_dir = str(params["base_dir"]).rstrip("/")
    authority = str(params["name"])
    crl_format = str(params["format"])
    record = {
        "record_type": "crl",
        "schema_version": 1,
        "authority": authority,
        "format": crl_format,
        "path": params["path"],
        "issuer": crl.issuer.rfc4514_string(),
        "last_update": _crl_timestamp(_crl_update(crl, "last_update")),
        "next_update": _crl_timestamp(_crl_update(crl, "next_update")),
        "signature_algorithm": _oid_name(crl.signature_algorithm_oid),
        "crl_number": _crl_number(crl),
        "authority_key_identifier": _crl_authority_key_identifier(crl),
        "revoked_certificates": _revoked_from_crl(crl),
    }
    changed = _write_json(
        _record_path(base_dir, "crls", authority, crl_format),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    for entry in params.get("revoked_certificates") or []:
        event = _revocation_event(authority, entry)
        changed = (
            _write_json(
                _record_path(
                    base_dir,
                    "revocations",
                    authority,
                    event["serial_number_hex"],
                ),
                event,
                params.get("owner"),
                params.get("group"),
                "0644",
            )
            or changed
        )
    return changed


def _revocation_map(revocations: list[dict[str, Any]]) -> dict[tuple[str, str], dict]:
    """Return revocation events keyed by issuer and serial hex."""
    result = {}
    for event in revocations:
        result[(str(event["issuer"]), str(event["serial_number_hex"]))] = event
    return result


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
    now = _dt.datetime.now(_dt.timezone.utc)
    not_before = _parse_timestamp(record["certificate"]["not_valid_before"])
    not_after = _parse_timestamp(record["certificate"]["not_valid_after"])
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
    result["current"] = (
        pointer.get("issuer") == record.get("issuer")
        and pointer.get("serial_number_hex")
        == record.get("certificate", {}).get("serial_number_hex")
    )
    result["status"] = _status(record, revocations)
    return result


def compose_inventory(
    *,
    base_dir: str,
    ca_name: str,
    base_url: str,
) -> dict[str, Any]:
    """Compose inventory JSON from internal state fragments."""
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
    return {
        "schema_version": 1,
        "ca_name": ca_name,
        "base_dir": str(base_dir).rstrip("/"),
        "base_url": base_url,
        "authorities": authorities,
        "certificates": [record for record in issued if record["current"]],
        "issued_certificates": issued,
        "revocations": revocations,
        "crls": crls,
    }


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
    """Write the composed CA inventory file."""
    with file_lock(ca_lock_path(base_dir, "inventory", "compose")):
        content = json.dumps(
            compose_inventory(base_dir=base_dir, ca_name=ca_name, base_url=base_url),
            indent=2,
            sort_keys=True,
        ).encode() + b"\n"
        return write_file(
            _inventory_path(base_dir),
            content,
            owner,
            group,
            mode,
            force=force,
        )


def compose_inventory_if_configured(params: dict[str, Any]) -> bool:
    """Compose the central CA inventory when module parameters provide a CA name."""
    ca_name = str(params.get("ca_name") or "")
    if not ca_name:
        return False
    return write_composed_inventory(
        base_dir=str(params["base_dir"]),
        ca_name=ca_name,
        base_url=str(params.get("base_url") or ""),
        owner=params.get("owner"),
        group=params.get("group"),
    )
