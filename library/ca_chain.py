#!/usr/bin/python
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    sanitize_error,
    write_file,
)
from ansible.module_utils.ca_x509 import load_certificates  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography.hazmat.primitives import serialization
except Exception as exc:  # pragma: no cover - handled at runtime by Ansible
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


def _chain_content(paths: list[str]) -> bytes:
    """Return normalized PEM content for an ordered certificate chain."""
    certificates = []
    for path in paths:
        certificates.extend(load_certificates(path))
    if not certificates:
        raise ValueError("certificate chain needs at least one certificate")
    return b"".join(
        cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
        for cert in certificates
    )


def _paths(base_dir: str, name: str, parent: str | None) -> tuple[str, list[str]]:
    """Derive the chain output path and source certificate paths."""
    base = base_dir.rstrip("/")
    certificates = [f"{base}/ca/{name}-ca.pem"]
    if parent and parent != name:
        certificates.append(f"{base}/chains/{parent}-ca-chain.pem")
    return f"{base}/chains/{name}-ca-chain.pem", certificates


def run_module():
    """Run the Ansible module for CA chain files."""
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
        with file_lock(ca_lock_path(params["base_dir"], "authority", params["name"])):
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
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
