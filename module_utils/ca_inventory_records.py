"""Ca inventory records helpers."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_inventory_revocation import (
    _revocation_event,
)
from ansible.module_utils.ca_inventory_store import (
    _record_path,
    _write_json,
)
from ansible.module_utils.ca_inventory_summary import (
    _certificate_summary,
    _crl_authority_key_identifier,
    _crl_number,
    _crl_update,
    _load_certificate,
    _oid_name,
    _revoked_from_crl,
)
from ansible.module_utils.ca_renewal import renewal_policy, renewal_status
from ansible.module_utils.ca_time import timestamp_z


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
    keys = {"output_dir", "csr", "certificate_pem", "chain"}
    if not certificate.get("csr_mode"):
        keys.add("private_key")
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
        "renewal": renewal_policy(params.get("renewal")),
        "renewal_status": renewal_status(certificate, params.get("renewal")),
        "certificate": certificate,
        "paths": paths,
    }
    changed = _write_json(
        _record_path(
            base_dir,
            "authority_certificates",
            name,
            certificate["serial_number_hex"],
        ),
        record,
        params.get("owner"),
        params.get("group"),
        "0644",
    )
    return (
        _write_json(
            _record_path(base_dir, "authorities", name),
            record,
            params.get("owner"),
            params.get("group"),
            "0644",
        )
        or changed
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
        "renewal": renewal_policy(model.get("renewal")),
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
        "last_update": timestamp_z(_crl_update(crl, "last_update")),
        "next_update": timestamp_z(_crl_update(crl, "next_update")),
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
