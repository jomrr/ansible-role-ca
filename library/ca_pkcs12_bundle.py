#!/usr/bin/python
"""Manage CA role PKCS#12 bundles."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    read_file,
    sanitize_error,
    set_attrs,
    write_file,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    load_certificates,
    load_private_key,
)

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


def _public_key_bytes(key_or_cert) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a key or certificate."""
    key = (
        key_or_cert.public_key() if hasattr(key_or_cert, "public_key") else key_or_cert
    )
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_fingerprint(cert):
    """Return the SHA-256 fingerprint for a certificate."""
    return cert.fingerprint(hashes.SHA256())


def _existing_matches(path, passphrase, key, cert, extra_certs):
    """Return whether an existing PKCS#12 bundle matches desired content."""
    try:
        existing_key, existing_cert, existing_extra = pkcs12.load_key_and_certificates(
            read_file(path),
            passphrase.encode() if passphrase else None,
        )
    except Exception:
        return False
    if existing_key is None or existing_cert is None:
        return False
    if _public_key_bytes(existing_key) != _public_key_bytes(key.public_key()):
        return False
    if _cert_fingerprint(existing_cert) != _cert_fingerprint(cert):
        return False
    existing_fingerprints = sorted(
        _cert_fingerprint(item) for item in (existing_extra or [])
    )
    desired_fingerprints = sorted(_cert_fingerprint(item) for item in extra_certs)
    return existing_fingerprints == desired_fingerprints


def _paths(
    base_dir: str, name: str, output_dir: str | None, bundle_format: str
) -> dict[str, str]:
    """Derive PKCS#12 output and input paths."""
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    return {
        "path": f"{directory}/{name}.{bundle_format}",
        "key": f"{directory}/{name}.key",
        "cert": f"{directory}/{name}.pem",
        "chain": f"{directory}/{name}-chain.pem",
    }


def _params(params: dict) -> dict:
    """Merge certificate dictionary values and validate export passphrase."""
    certificate = dict(params.get("certificate") or {})
    result = dict(params)
    for key in ("output_dir", "key_passphrase", "passphrase", "friendly_name"):
        if result.get(key) is None and certificate.get(key) is not None:
            result[key] = certificate[key]
    if result.get("passphrase") is None:
        result["passphrase"] = certificate.get("pfx_passphrase")
    if result.get("friendly_name") is None:
        result["friendly_name"] = certificate.get("common_name") or result["name"]
    if not result.get("passphrase"):
        raise ValueError("PKCS#12 bundle requires pfx_passphrase or passphrase")
    return result


def run_module():
    """Run the Ansible module for PKCS#12 bundles."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "certificate": {"type": "dict", "no_log": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "format": {"type": "str", "choices": ["pfx", "p12"], "required": True},
            "friendly_name": {"type": "str"},
            "key_passphrase": {"type": "str", "no_log": True},
            "passphrase": {"type": "str", "no_log": True},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        params = _params(module.params)
        paths = _paths(
            params["base_dir"], params["name"], params["output_dir"], params["format"]
        )
        with file_lock(ca_lock_path(params["base_dir"], "certificate", params["name"])):
            key = load_private_key(paths["key"], params["key_passphrase"])
            cert = load_certificates(paths["cert"])[0]
            extra_certs = load_certificates(paths["chain"])
            changed = params["force"]
            if not changed:
                changed = not _existing_matches(
                    paths["path"], params["passphrase"], key, cert, extra_certs
                )
            if changed:
                content = pkcs12.serialize_key_and_certificates(
                    name=params["friendly_name"].encode(),
                    key=key,
                    cert=cert,
                    cas=extra_certs,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        params["passphrase"].encode()
                    ),
                )
                changed = write_file(
                    paths["path"],
                    content,
                    params["owner"],
                    params["group"],
                    params["mode"],
                    force=True,
                )
            else:
                changed = set_attrs(
                    paths["path"], params["owner"], params["group"], params["mode"]
                )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(changed=changed, path=paths["path"])


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
