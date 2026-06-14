#!/usr/bin/python
"""Manage CA role PKCS#12 bundles."""

from __future__ import annotations

import os
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import set_attrs, write_file  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


def _load_key(path: str, passphrase: str | None):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=passphrase.encode() if passphrase else None,
    )


def _load_certificates(path: str):
    data = Path(path).read_bytes()
    certs = []
    marker = b"-----END CERTIFICATE-----"
    if marker in data:
        chunks = data.split(marker)
        for chunk in chunks:
            if b"-----BEGIN CERTIFICATE-----" in chunk:
                certs.append(x509.load_pem_x509_certificate(chunk + marker + b"\n"))
    else:
        certs.append(x509.load_der_x509_certificate(data))
    return certs


def _public_key_bytes(key_or_cert) -> bytes:
    key = (
        key_or_cert.public_key() if hasattr(key_or_cert, "public_key") else key_or_cert
    )
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256())


def _existing_matches(path, passphrase, key, cert, extra_certs):
    try:
        existing_key, existing_cert, existing_extra = pkcs12.load_key_and_certificates(
            Path(path).read_bytes(),
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
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    return {
        "path": f"{directory}/{name}.{bundle_format}",
        "key": f"{directory}/{name}.key",
        "cert": f"{directory}/{name}.pem",
        "chain": f"{directory}/{name}-chain.pem",
    }


def run_module():
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "format": {"type": "str", "choices": ["pfx", "p12"], "required": True},
            "friendly_name": {"type": "str", "required": True},
            "key_passphrase": {"type": "str", "no_log": True},
            "passphrase": {"type": "str", "required": True, "no_log": True},
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

    params = module.params
    try:
        paths = _paths(
            params["base_dir"], params["name"], params["output_dir"], params["format"]
        )
        key = _load_key(paths["key"], params["key_passphrase"])
        cert = _load_certificates(paths["cert"])[0]
        extra_certs = _load_certificates(paths["chain"])
        changed = params["force"] or not os.path.exists(paths["path"])
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
        module.fail_json(msg=str(exc))
    module.exit_json(changed=changed, path=paths["path"])


def main():
    run_module()


if __name__ == "__main__":
    main()
