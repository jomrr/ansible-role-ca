#!/usr/bin/python
"""Manage CA role certificate revocation lists."""

from __future__ import annotations

import datetime as _dt
import re

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import read_file, sanitize_error, write_file  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
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


def _load_crl(path: str):
    """Load an existing PEM or DER CRL from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def _parse_serial(value) -> int:
    """Parse decimal, hexadecimal, or colon-separated serial numbers."""
    if isinstance(value, int):
        return value
    text = str(value)
    if ":" in text:
        return int(re.sub(r"[^0-9A-Fa-f]", "", text), 16)
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def _parse_revocation_date(value):
    """Parse a revocation timestamp or return the current UTC time."""
    if not value:
        return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    text = str(value)
    if re.match(r"^\d{14}Z$", text):
        return _dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(
            tzinfo=_dt.timezone.utc
        )
    return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _revoked_signature(crl):
    """Return comparable revoked certificate entries from an existing CRL."""
    result = []
    for revoked in crl:
        reason = None
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        result.append((revoked.serial_number, reason))
    return sorted(result)


def _desired_revoked(entries):
    """Return comparable revoked certificate entries from module params."""
    result = []
    for entry in entries or []:
        serial = _parse_serial(entry.get("serial_number", entry.get("serial")))
        reason = entry.get("reason")
        result.append((serial, reason))
    return sorted(result)


def _build_crl(params):
    """Build and sign a CRL from module parameters."""
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject_from_params(params))
        .last_update(now)
        .next_update(now + _dt.timedelta(days=int(params["next_update_days"])))
    )
    for entry in params["revoked_certificates"] or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                _parse_serial(entry.get("serial_number", entry.get("serial")))
            )
            .revocation_date(_parse_revocation_date(entry.get("revocation_date")))
        )
        if entry.get("reason"):
            reason = REASON_FLAGS[str(entry["reason"])]
            revoked = revoked.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(revoked.build())
    private_key = load_private_key(
        params["privatekey_path"], params["privatekey_passphrase"]
    )
    return builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm(private_key, params["digest"]),
    )


def _with_derived_paths(params: dict) -> dict:
    """Derive CRL and CA private key paths from base parameters."""
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    result["path"] = (
        f"{base_dir}/crl/{name}-ca.crl"
        if result["format"] == "der"
        else f"{base_dir}/crl/{name}-ca.crl.pem"
    )
    result["privatekey_path"] = f"{base_dir}/private/{name}-ca.key"
    return result


def run_module():
    """Run the Ansible module for certificate revocation lists."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "format": {"type": "str", "choices": ["pem", "der"], "default": "pem"},
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
    try:
        params["privatekey_passphrase"] = params["key_passphrase"]
        crl = _build_crl(params)
        changed = params["force"]
        if not changed:
            try:
                existing = _load_crl(params["path"])
                changed = existing.issuer != subject_from_params(
                    params
                ) or _revoked_signature(existing) != _desired_revoked(
                    params["revoked_certificates"]
                )
            except Exception:
                changed = True
        encoding = (
            serialization.Encoding.DER
            if params["format"] == "der"
            else serialization.Encoding.PEM
        )
        content = crl.public_bytes(encoding) if changed else read_file(params["path"])
        changed = (
            write_file(
                params["path"],
                content,
                params["owner"],
                params["group"],
                params["mode"],
            )
            or changed
        )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(changed=changed)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
