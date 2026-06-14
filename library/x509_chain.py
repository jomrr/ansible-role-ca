#!/usr/bin/python
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

import re

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import read_file, sanitize_error, write_file  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except Exception as exc:  # pragma: no cover - handled at runtime by Ansible
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


def _load_certificates(path: str):
    data = read_file(path)
    pem_blocks = PEM_CERT_RE.findall(data)
    if pem_blocks:
        return [x509.load_pem_x509_certificate(block) for block in pem_blocks]
    return [x509.load_der_x509_certificate(data)]


def _chain_content(paths: list[str]) -> bytes:
    certificates = []
    for path in paths:
        certificates.extend(_load_certificates(path))
    if not certificates:
        raise ValueError("certificate chain needs at least one certificate")
    return b"".join(
        cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
        for cert in certificates
    )


def _paths(base_dir: str, name: str, parent: str | None) -> tuple[str, list[str]]:
    base = base_dir.rstrip("/")
    certificates = [f"{base}/ca/{name}-ca.pem"]
    if parent and parent != name:
        certificates.append(f"{base}/chains/{parent}-ca-chain.pem")
    return f"{base}/chains/{name}-ca-chain.pem", certificates


def run_module():
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "parent": {"type": "str", "default": ""},
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

    params = module.params
    try:
        path, certificates = _paths(
            params["base_dir"], params["name"], params["parent"]
        )
        content = _chain_content(certificates)
        changed = write_file(
            path,
            content,
            params["owner"],
            params["group"],
            params["mode"],
            force=params["force"],
        )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(changed=changed, path=path)


def main():
    run_module()


if __name__ == "__main__":
    main()
