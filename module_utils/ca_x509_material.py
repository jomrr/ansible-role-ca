"""Ca x509 material helpers."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from ansible.module_utils.ca_file import read_file, set_attrs, write_file
from ansible.module_utils.ca_serial import serial_hex
from ansible.module_utils.ca_time import certificate_not_valid_after, now_utc
from ansible.module_utils.ca_x509_extensions import (
    _add_extensions,
    _extensions_equal,
)
from ansible.module_utils.ca_x509_keys import (
    _as_public_key,
    _cert_public_key_bytes,
    _csr_common_name,
    _csr_public_key_bytes,
    _generate_private_key,
    _key_matches,
    _key_spec,
    _load_csr,
    _load_csr_bytes,
    _private_key_pem,
    _public_key_bytes,
    load_certificate,
    load_private_key,
    signature_algorithm,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def _ensure_directory(path: str | None, owner, group, mode) -> bool:
    """Create a directory and enforce requested attributes."""
    if not path:
        return False
    Path(path).mkdir(parents=True, exist_ok=True)
    return set_attrs(path, owner, group, mode)


def _archive_dir(params: dict, cert) -> str:
    """Return the archive directory for one existing certificate generation."""
    namespace = "authorities" if params.get("authority") else "certificates"
    serial = serial_hex(cert.serial_number)
    return (
        f"{str(params['base_dir']).rstrip('/')}/archive/"
        f"{namespace}/{params['name']}/{serial}"
    )


def _archive_path(params: dict, cert, source_path: str) -> str:
    """Return the archive path for an existing managed source path."""
    return f"{_archive_dir(params, cert)}/{Path(source_path).name}"


def _archive_file(params: dict, cert, source_path: str, mode: str) -> bool:
    """Copy a current managed file into its generation archive if present."""
    if cert is None or not source_path:
        return False
    try:
        content = read_file(source_path)
    except FileNotFoundError:
        return False
    return write_file(
        _archive_path(params, cert, source_path),
        content,
        params["owner"],
        params["group"],
        mode,
    )


def _archive_existing_material(
    params: dict, cert, *, include_private_key: bool
) -> bool:
    """Archive the current generation before replacing it."""
    if cert is None:
        return False
    changed = False
    public_paths = (
        params["cert_path"],
        params["csr_path"],
        params.get("der_path", ""),
        params.get("txt_path", ""),
        params.get("chain_path", ""),
    )
    for path in public_paths:
        changed = _archive_file(params, cert, path, params["public_mode"]) or changed
    if include_private_key:
        changed = (
            _archive_file(params, cert, params["key_path"], params["key_mode"])
            or changed
        )
    return changed


def _ensure_key(params, *, rekey: bool, existing_cert):
    """Ensure the private key exists with the requested key properties."""
    spec = _key_spec(params)
    key = None
    changed = False
    if not params["force"] and not rekey:
        try:
            key = load_private_key(params["key_path"], params["key_passphrase"])
        except FileNotFoundError:
            key = None
        if key is not None and not _key_matches(key, spec):
            _archive_file(params, existing_cert, params["key_path"], params["key_mode"])
            key = None
    if key is None:
        _archive_file(params, existing_cert, params["key_path"], params["key_mode"])
        key = _generate_private_key(spec)
        changed = True
        content = _private_key_pem(key, params["key_passphrase"])
        changed = (
            write_file(
                params["key_path"],
                content,
                params["owner"],
                params["group"],
                params["key_mode"],
            )
            or changed
        )
    else:
        changed = (
            set_attrs(
                params["key_path"],
                params["owner"],
                params["group"],
                params["key_mode"],
            )
            or changed
        )
    return key, changed


def _ensure_csr(params, key, subject, csr_extensions):
    """Ensure the CSR matches the requested subject, key, and extensions."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = _add_extensions(builder, csr_extensions)
    csr = builder.sign(key, signature_algorithm(key, params["digest"]))
    changed = params["force"]
    if not changed:
        try:
            existing = _load_csr(params["csr_path"])
            changed = (
                existing.subject != subject
                or _csr_public_key_bytes(existing) != _public_key_bytes(key)
                or not _extensions_equal(existing.extensions, csr_extensions)
            )
        except Exception:
            changed = True
    content = (
        csr.public_bytes(serialization.Encoding.PEM)
        if changed
        else read_file(params["csr_path"])
    )
    changed = (
        write_file(
            params["csr_path"],
            content,
            params["owner"],
            params["group"],
            params["public_mode"],
        )
        or changed
    )
    return csr, changed


def _external_csr_bytes(params: dict) -> bytes:
    """Return CSR bytes from inline content or a source path."""
    csr_content = params.get("csr_content")
    if csr_content:
        return str(csr_content).encode()
    csr_source_path = str(params.get("csr_source_path") or "")
    if csr_source_path:
        return read_file(csr_source_path)
    raise ValueError("csr_path or csr_content is required for CSR signing")


def _ensure_external_csr(params: dict):
    """Validate and copy an externally supplied CSR into the managed CSR path."""
    csr = _load_csr_bytes(_external_csr_bytes(params))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")

    common_name = str(params.get("common_name") or "").strip()
    csr_common_name = _csr_common_name(csr)
    if common_name and common_name != csr_common_name:
        raise ValueError(
            f"CSR common name {csr_common_name!r} does not match {common_name!r}"
        )

    content = csr.public_bytes(serialization.Encoding.PEM)
    changed = write_file(
        params["csr_path"],
        content,
        params["owner"],
        params["group"],
        params["public_mode"],
        force=params["force"],
    )
    return csr, changed


def _ensure_certificate(
    params,
    key,
    subject,
    cert_extensions,
    signer_key,
    signer_cert,
    renewal_decision,
    existing_cert,
):
    """Ensure the certificate matches the requested issuer and profile."""
    issuer = signer_cert.subject if signer_cert is not None else subject
    now = now_utc(strip_microseconds=True)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_as_public_key(key))
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=1))
        .not_valid_after(now + _dt.timedelta(days=int(params["days"])))
    )
    builder = _add_extensions(builder, cert_extensions)
    cert = builder.sign(
        private_key=signer_key,
        algorithm=signature_algorithm(signer_key, params["digest"]),
    )

    changed = params["force"] or renewal_decision["renew"]
    if not changed:
        try:
            existing = (
                existing_cert
                if existing_cert is not None
                else load_certificate(params["cert_path"])
            )
            current_time = now_utc()
            if certificate_not_valid_after(existing) <= current_time:
                changed = True
            else:
                changed = (
                    existing.subject != subject
                    or existing.issuer != issuer
                    or _cert_public_key_bytes(existing) != _public_key_bytes(key)
                    or not _extensions_equal(existing.extensions, cert_extensions)
                )
        except Exception:
            changed = True

    if changed:
        _archive_existing_material(
            params,
            existing_cert,
            include_private_key=False,
        )
        content = cert.public_bytes(serialization.Encoding.PEM)
    else:
        content = read_file(params["cert_path"])
        cert = load_certificate(params["cert_path"])

    changed = (
        write_file(
            params["cert_path"],
            content,
            params["owner"],
            params["group"],
            params["public_mode"],
        )
        or changed
    )
    return cert, changed
