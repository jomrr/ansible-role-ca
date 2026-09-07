"""Ca x509 helpers."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import ca_lock_path, file_locks, sanitize_error
from ansible.module_utils.ca_renewal import renewal_decision
from ansible.module_utils.ca_text import ensure_txt
from ansible.module_utils.ca_time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
)
from ansible.module_utils.ca_x509_exports import (
    _chain_certificates,
    _chain_content,
    _ensure_chain,
    _ensure_der,
    _ensure_fritzbox_bundle,
    _ensure_fullchain_bundle,
    _ensure_pkcs12_exports,
)
from ansible.module_utils.ca_x509_extensions import (
    _csr_subject_alt_name,
    _desired_extensions,
    subject_from_params,
)
from ansible.module_utils.ca_x509_keys import (
    _csr_common_name,
    _load_existing_certificate,
    digest_algorithm,
    load_certificate,
    load_certificates,
    load_private_key,
    signature_algorithm,
)
from ansible.module_utils.ca_x509_material import (
    _archive_existing_material,
    _ensure_certificate,
    _ensure_csr,
    _ensure_directory,
    _ensure_external_csr,
    _ensure_key,
)
from ansible.module_utils.ca_x509_params import (
    _external_csr_configured,
    _with_derived_paths,
    ca_authority_argument_spec,
    certificate_params,
    normalize_formats,
)

CRYPTOGRAPHY_IMPORT_ERROR = None

__all__ = [
    "CRYPTOGRAPHY_IMPORT_ERROR",
    "_ensure_x509_from_csr_locked",
    "_ensure_x509_locked",
    "_renewal_decision",
    "ca_authority_argument_spec",
    "certificate_params",
    "digest_algorithm",
    "ensure_x509",
    "ensure_x509_many",
    "load_certificate",
    "load_certificates",
    "load_private_key",
    "normalize_formats",
    "sanitize_error",
    "signature_algorithm",
    "subject_from_params",
]


def _renewal_decision(params: dict, existing_cert) -> dict[str, Any]:
    """Return renewal and rekey decisions for an existing certificate."""
    if existing_cert is None:
        return renewal_decision(
            force=bool(params.get("force")),
            not_before=None,
            not_after=None,
            policy_value=params.get("renewal"),
        )
    return renewal_decision(
        force=bool(params.get("force")),
        not_before=certificate_not_valid_before(existing_cert),
        not_after=certificate_not_valid_after(existing_cert),
        policy_value=params.get("renewal"),
    )


def ensure_x509(
    params: dict,
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> dict:
    """Ensure X.509 key, CSR, certificate, exports, and chain artifacts."""
    params = _with_derived_paths(
        params,
        authority=authority,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )
    lock_paths = [params["lock_path"]]
    if authority:
        lock_paths.append(ca_lock_path(params["base_dir"], "authority", "__graph__"))
    if signed:
        lock_paths.append(params["signer_lock_path"])
    with file_locks(lock_paths):
        return _ensure_x509_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )


def ensure_x509_many(
    params_list: list[dict],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> list[dict]:
    """Ensure multiple X.509 objects while caching shared signer material."""
    derived = [
        _with_derived_paths(
            params,
            authority=authority,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )
        for params in params_list
    ]
    if not signed or authority:
        return [
            ensure_x509(
                params,
                signed=signed,
                authority=authority,
                manage_directory=manage_directory,
                manage_chain=manage_chain,
            )
            for params in params_list
        ]

    groups: dict[str, list[tuple[int, dict]]] = {}
    order: list[str] = []
    for index, params in enumerate(derived):
        signer_lock_path = str(params["signer_lock_path"])
        if signer_lock_path not in groups:
            groups[signer_lock_path] = []
            order.append(signer_lock_path)
        groups[signer_lock_path].append((index, params))

    results: list[dict] = [{} for _ in derived]
    for signer_lock_path in order:
        group = groups[signer_lock_path]
        lock_paths = [signer_lock_path, *(params["lock_path"] for _, params in group)]
        with file_locks(lock_paths):
            first_params = group[0][1]
            signer_key = load_private_key(
                first_params["signer_key_path"],
                first_params["signer_key_passphrase"],
            )
            signer_cert = load_certificate(first_params["signer_cert_path"])
            needs_chain = any(
                set(params["formats"]).intersection(
                    {"pfx", "p12", "fullchain", "fritzbox"}
                )
                for _, params in group
            )
            chain_content = (
                _chain_content(first_params, signer_cert) if needs_chain else b""
            )
            extra_certs = (
                _chain_certificates(first_params, signer_cert) if needs_chain else []
            )
            for index, params in group:
                results[index] = _ensure_x509_locked(
                    params,
                    signed=signed,
                    manage_directory=manage_directory,
                    manage_chain=manage_chain,
                    signer_key=signer_key,
                    signer_cert=signer_cert,
                    chain_content=chain_content,
                    extra_certs=extra_certs,
                )
    return results


def _ensure_x509_from_csr_locked(
    params: dict,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer_key=None,
    signer_cert=None,
    chain_content: bytes | None = None,
) -> dict:
    """Ensure one signed certificate from an externally supplied CSR."""
    if not signed:
        raise ValueError("CSR signing requires an issuing CA")

    unsupported = sorted(
        set(params["formats"]).intersection({"pfx", "p12", "fritzbox"})
    )
    if unsupported:
        raise ValueError(
            "CSR signing cannot create formats that require a private key: "
            + ", ".join(unsupported)
        )

    directory_changed = False
    chain_changed = False
    if manage_directory:
        directory_changed = _ensure_directory(
            params["directory_path"],
            params["owner"],
            params["group"],
            params["directory_mode"],
        )

    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal_decision = _renewal_decision(params, existing_cert)
    if renewal_decision["rekey"]:
        renewal_decision = dict(renewal_decision)
        renewal_decision["rekey"] = False

    csr, csr_changed = _ensure_external_csr(params)
    subject = csr.subject

    if signer_key is None:
        signer_key = load_private_key(
            params["signer_key_path"], params["signer_key_passphrase"]
        )
    if signer_cert is None:
        signer_cert = load_certificate(params["signer_cert_path"])

    cert_extensions = _desired_extensions(
        params,
        csr.public_key(),
        signer_cert.public_key(),
        _csr_subject_alt_name(csr),
    )
    cert, cert_changed = _ensure_certificate(
        params,
        csr.public_key(),
        subject,
        cert_extensions,
        signer_key,
        signer_cert,
        renewal_decision,
        existing_cert,
    )
    der_changed = _ensure_der(params, cert)
    txt_changed = ensure_txt(params, cert)
    if manage_chain:
        chain_changed = _ensure_chain(params)

    chain_content = chain_content if chain_content is not None else b""
    if "fullchain" in params["formats"] and not chain_content:
        chain_content = _chain_content(params, signer_cert)
    fullchain_changed = _ensure_fullchain_bundle(params, cert, chain_content)

    return {
        "changed": directory_changed
        or csr_changed
        or cert_changed
        or der_changed
        or txt_changed
        or chain_changed
        or fullchain_changed,
        "directory_changed": directory_changed,
        "archive_changed": False,
        "key_changed": False,
        "csr_changed": csr_changed,
        "cert_changed": cert_changed,
        "der_changed": der_changed,
        "txt_changed": txt_changed,
        "chain_changed": chain_changed,
        "pkcs12_changed": False,
        "fullchain_changed": fullchain_changed,
        "fritzbox_bundle_changed": False,
        "formats": params["formats"],
        "renewal": renewal_decision,
        "csr_mode": True,
        "common_name": _csr_common_name(csr),
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
        "pkcs12_paths": {},
        "fullchain_path": params.get("fullchain_path", ""),
        "fritzbox_bundle_path": "",
    }


def _ensure_x509_locked(
    params: dict,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer_key=None,
    signer_cert=None,
    chain_content: bytes | None = None,
    extra_certs: list[Any] | None = None,
) -> dict:
    """Ensure one X.509 object while holding its object lock."""
    if _external_csr_configured(params):
        return _ensure_x509_from_csr_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
            signer_key=signer_key,
            signer_cert=signer_cert,
            chain_content=chain_content,
        )

    directory_changed = False
    chain_changed = False
    if manage_directory:
        directory_changed = _ensure_directory(
            params["directory_path"],
            params["owner"],
            params["group"],
            params["directory_mode"],
        )
    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal_decision = _renewal_decision(params, existing_cert)
    archive_changed = False
    if renewal_decision["rekey"]:
        archive_changed = _archive_existing_material(
            params,
            existing_cert,
            include_private_key=True,
        )
    key, key_changed = _ensure_key(
        params,
        rekey=renewal_decision["rekey"],
        existing_cert=existing_cert,
    )
    subject = subject_from_params(params)
    signer_key = signer_key or key
    if signed:
        if signer_key is key:
            signer_key = load_private_key(
                params["signer_key_path"], params["signer_key_passphrase"]
            )
        if signer_cert is None:
            signer_cert = load_certificate(params["signer_cert_path"])

    signer_public_key = (
        signer_cert.public_key() if signer_cert is not None else key.public_key()
    )
    csr_extensions = _desired_extensions(params, key.public_key(), signer_public_key)
    _, csr_changed = _ensure_csr(params, key, subject, csr_extensions)
    cert_extensions = _desired_extensions(params, key.public_key(), signer_public_key)
    cert, cert_changed = _ensure_certificate(
        params,
        key,
        subject,
        cert_extensions,
        signer_key,
        signer_cert,
        renewal_decision,
        existing_cert,
    )
    der_changed = _ensure_der(params, cert)
    txt_changed = ensure_txt(params, cert)
    if manage_chain:
        chain_changed = _ensure_chain(params)
    chain_content = chain_content if chain_content is not None else b""
    extra_certs = extra_certs if extra_certs is not None else []
    if not params["authority"] and set(params["formats"]).intersection(
        {"pfx", "p12", "fullchain", "fritzbox"}
    ):
        if not chain_content:
            chain_content = _chain_content(params, signer_cert)
        if not extra_certs:
            extra_certs = _chain_certificates(params, signer_cert)
    pkcs12_changed, pkcs12_paths = _ensure_pkcs12_exports(
        params,
        key,
        cert,
        extra_certs,
    )
    fullchain_changed = _ensure_fullchain_bundle(params, cert, chain_content)
    fritzbox_bundle_changed = _ensure_fritzbox_bundle(params, cert, chain_content)

    return {
        "changed": directory_changed
        or archive_changed
        or key_changed
        or csr_changed
        or cert_changed
        or der_changed
        or txt_changed
        or chain_changed
        or pkcs12_changed
        or fullchain_changed
        or fritzbox_bundle_changed,
        "directory_changed": directory_changed,
        "archive_changed": archive_changed,
        "key_changed": key_changed,
        "csr_changed": csr_changed,
        "cert_changed": cert_changed,
        "der_changed": der_changed,
        "txt_changed": txt_changed,
        "chain_changed": chain_changed,
        "pkcs12_changed": pkcs12_changed,
        "fullchain_changed": fullchain_changed,
        "fritzbox_bundle_changed": fritzbox_bundle_changed,
        "formats": params["formats"],
        "renewal": renewal_decision,
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
        "pkcs12_paths": pkcs12_paths,
        "fullchain_path": params.get("fullchain_path", ""),
        "fritzbox_bundle_path": params.get("fritzbox_bundle_path", ""),
    }
