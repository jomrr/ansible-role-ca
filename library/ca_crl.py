#!/usr/bin/python
"""Manage CA role certificate revocation lists."""

from __future__ import annotations

import datetime as _dt

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_locks,
    read_file,
    sanitize_error,
    write_file,
)
from ansible.module_utils.ca_inventory import (  # type: ignore[import-not-found,import-untyped]
    resolve_revocation_entries,
    update_crl_inventory,
)
from ansible.module_utils.ca_serial import parse_serial  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_time import (  # type: ignore[import-not-found,import-untyped]
    now_utc,
    object_datetime,
    parse_datetime,
    timestamp_iso,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    load_certificate,
    load_private_key,
    signature_algorithm,
    subject_from_params,
)

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


REASON_FLAGS = {
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}
SUPPORTED_FORMATS = {"pem", "der"}


def _formats(value) -> list[str]:
    """Return normalized CRL output formats."""
    if isinstance(value, str):
        raise ValueError("formats must be a list")
    formats = [str(item).lower() for item in (value or ["pem", "der"])]
    unsupported = sorted(set(formats).difference(SUPPORTED_FORMATS))
    if unsupported:
        raise ValueError(f"Unsupported CRL formats: {', '.join(unsupported)}")
    return formats


def _load_crl(path: str) -> x509.CertificateRevocationList:
    """Load an existing PEM or DER CRL from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def _parse_revocation_date(value):
    """Parse a revocation timestamp or return the current UTC time."""
    if not value:
        return now_utc(strip_microseconds=True)
    parsed = parse_datetime(value)
    if parsed is None:
        raise ValueError("revocation date must not be empty")
    return parsed


def _revoked_signature(crl):
    """Return comparable revoked certificate entries from an existing CRL."""
    result = []
    for revoked in crl:
        reason = ""
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        invalidity_date = ""
        try:
            invalidity_ext = revoked.extensions.get_extension_for_class(
                x509.InvalidityDate
            )
            invalidity_date = timestamp_iso(
                object_datetime(invalidity_ext.value, "invalidity_date")
            )
        except x509.ExtensionNotFound:
            pass
        result.append((revoked.serial_number, reason, invalidity_date))
    return sorted(result)


def _desired_revoked(entries):
    """Return comparable revoked certificate entries from module params."""
    result = []
    for entry in entries or []:
        serial = parse_serial(entry.get("serial_number", entry.get("serial")))
        reason = str(entry.get("reason") or "")
        invalidity_date = ""
        if entry.get("invalidity_date"):
            invalidity_date = timestamp_iso(
                _parse_revocation_date(entry["invalidity_date"])
            )
        result.append((serial, reason, invalidity_date))
    return sorted(result)


def _crl_number(crl) -> int | None:
    """Return an existing CRL Number extension value."""
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def _authority_key_identifier(crl) -> bytes | None:
    """Return an existing CRL Authority Key Identifier."""
    try:
        return crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
    except x509.ExtensionNotFound:
        return None


def _desired_authority_key_identifier(ca_cert) -> bytes | None:
    """Return the desired CRL Authority Key Identifier."""
    return x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_cert.public_key()
    ).key_identifier


def _load_existing_crls(paths: dict[str, str]) -> dict[str, object | None]:
    """Load existing CRLs for all requested formats."""
    existing = {}
    for crl_format, path in paths.items():
        try:
            existing[crl_format] = _load_crl(path)
        except Exception:
            existing[crl_format] = None
    return existing


def _existing_numbers(existing_crls: dict[str, object | None]) -> list[int]:
    """Return all available CRL Number values from existing CRLs."""
    numbers = []
    for crl in existing_crls.values():
        if crl is None:
            continue
        number = _crl_number(crl)
        if number is not None:
            numbers.append(number)
    return numbers


def _same_existing_number(
    existing_crls: dict[str, x509.CertificateRevocationList | None],
) -> bool:
    """Return whether all requested existing CRLs have the same CRL Number."""
    numbers = [
        _crl_number(crl) if crl is not None else None
        for crl in existing_crls.values()
    ]
    return bool(numbers) and None not in numbers and len(set(numbers)) == 1


def _needs_rebuild(
    *,
    existing_crls: dict[str, x509.CertificateRevocationList | None],
    params: dict,
    comparison_crl: x509.CertificateRevocationList,
    desired_revoked: list[tuple[int, str, str]],
    desired_authority_key: bytes | None,
) -> bool:
    """Return whether existing CRLs differ from desired CRL state."""
    if not _same_existing_number(existing_crls):
        return True
    current_time = now_utc()
    issuer = subject_from_params(params)
    for crl in existing_crls.values():
        if crl is None:
            return True
        if crl.issuer != issuer:
            return True
        if crl.signature_algorithm_oid != comparison_crl.signature_algorithm_oid:
            return True
        if object_datetime(crl, "next_update") <= current_time:
            return True
        if _authority_key_identifier(crl) != desired_authority_key:
            return True
        if _revoked_signature(crl) != desired_revoked:
            return True
    return False


def _build_crl(params, *, crl_number: int, ca_cert, private_key):
    """Build and sign a CRL from module parameters."""
    now = now_utc(strip_microseconds=True)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject_from_params(params))
        .last_update(now)
        .next_update(now + _dt.timedelta(days=int(params["next_update_days"])))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_cert.public_key()
            ),
            critical=False,
        )
    )
    for entry in params["revoked_certificates"] or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                parse_serial(entry.get("serial_number", entry.get("serial")))
            )
            .revocation_date(_parse_revocation_date(entry.get("revocation_date")))
        )
        if entry.get("reason"):
            reason = REASON_FLAGS[str(entry["reason"])]
            revoked = revoked.add_extension(x509.CRLReason(reason), critical=False)
        if entry.get("invalidity_date"):
            revoked = revoked.add_extension(
                x509.InvalidityDate(_parse_revocation_date(entry["invalidity_date"])),
                critical=False,
            )
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm(private_key, params["digest"]),
    )


def _with_derived_paths(params: dict) -> dict:
    """Derive CRL and CA private key paths from base parameters."""
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    result["formats"] = _formats(result.get("formats"))
    result["paths"] = {
        "pem": f"{base_dir}/crl/{name}-ca.crl.pem",
        "der": f"{base_dir}/crl/{name}-ca.crl",
    }
    result["paths"] = {
        crl_format: path
        for crl_format, path in result["paths"].items()
        if crl_format in result["formats"]
    }
    result["privatekey_path"] = f"{base_dir}/private/{name}-ca.key"
    result["certificate_path"] = f"{base_dir}/ca/{name}-ca.pem"
    return result


def _write_crls(params: dict, crl) -> bool:
    """Write one CRL object to all requested output formats."""
    changed = False
    for crl_format, path in params["paths"].items():
        encoding = (
            serialization.Encoding.DER
            if crl_format == "der"
            else serialization.Encoding.PEM
        )
        changed = (
            write_file(
                path,
                crl.public_bytes(encoding),
                params["owner"],
                params["group"],
                params["mode"],
                force=params["force"],
            )
            or changed
        )
    return changed


def run_module():
    """Run the Ansible module for certificate revocation lists."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "base_url": {"type": "str", "default": ""},
            "ca_name": {"type": "str", "default": ""},
            "name": {"type": "str", "required": True},
            "formats": {
                "type": "list",
                "elements": "str",
                "default": ["pem", "der"],
            },
            "key_passphrase": {"type": "str", "required": True, "no_log": True},
            "common_name": {"type": "str", "required": True},
            "subject": {"type": "dict", "default": {}},
            "next_update_days": {"type": "int", "required": True},
            "revoked_certificates": {"type": "list", "elements": "dict", "default": []},
            "digest": {"type": "str", "default": "sha384"},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0644"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    params = _with_derived_paths(module.params)
    inventory_changed = False
    try:
        with file_locks(
            [
                ca_lock_path(params["base_dir"], "authority", params["name"]),
                ca_lock_path(params["base_dir"], "crl", params["name"]),
            ]
        ):
            params["privatekey_passphrase"] = params["key_passphrase"]
            params["revoked_certificates"] = resolve_revocation_entries(
                base_dir=str(params["base_dir"]),
                authority=str(params["name"]),
                entries=params["revoked_certificates"],
            )
            ca_cert = load_certificate(params["certificate_path"])
            private_key = load_private_key(
                params["privatekey_path"],
                params["privatekey_passphrase"],
            )
            existing_crls = _load_existing_crls(params["paths"])
            existing_numbers = _existing_numbers(existing_crls)
            comparison_number = existing_numbers[0] if existing_numbers else 1
            comparison_crl = _build_crl(
                params,
                crl_number=comparison_number,
                ca_cert=ca_cert,
                private_key=private_key,
            )
            desired_revoked = _desired_revoked(params["revoked_certificates"])
            changed = params["force"] or _needs_rebuild(
                existing_crls=existing_crls,
                params=params,
                comparison_crl=comparison_crl,
                desired_revoked=desired_revoked,
                desired_authority_key=_desired_authority_key_identifier(ca_cert),
            )
            if changed:
                crl_number = max(existing_numbers or [0]) + 1
                crl = _build_crl(
                    params,
                    crl_number=crl_number,
                    ca_cert=ca_cert,
                    private_key=private_key,
                )
            else:
                crl = next(crl for crl in existing_crls.values() if crl is not None)
                existing_crl_number = _crl_number(crl)
                if existing_crl_number is None:
                    raise ValueError("existing CRL is missing a CRL Number")
                crl_number = existing_crl_number

            changed = _write_crls(params, crl) or changed
            inventory_changed = update_crl_inventory(params, crl)
            changed = changed or inventory_changed
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(
        changed=changed,
        inventory_changed=inventory_changed,
        formats=params["formats"],
        paths=params["paths"],
        crl_number=crl_number,
    )


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
