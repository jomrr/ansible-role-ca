#!/usr/bin/python
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

import grp
import os
import pwd
import re
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule

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


def _uid(owner):
    if owner is None:
        return -1
    value = str(owner)
    if value.isdigit():
        return int(value)
    return pwd.getpwnam(value).pw_uid


def _gid(group):
    if group is None:
        return -1
    value = str(group)
    if value.isdigit():
        return int(value)
    return grp.getgrnam(value).gr_gid


def _set_attrs(path: str, owner, group, mode) -> bool:
    changed = False
    stat = os.stat(path)
    uid = _uid(owner)
    gid = _gid(group)
    if (uid != -1 and stat.st_uid != uid) or (gid != -1 and stat.st_gid != gid):
        os.chown(path, uid, gid)
        changed = True
    if mode is not None:
        desired = int(str(mode), 8)
        if (stat.st_mode & 0o7777) != desired:
            os.chmod(path, desired)
            changed = True
    return changed


def _load_certificates(path: str):
    data = Path(path).read_bytes()
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


def _write_file(path: str, content: bytes, owner, group, mode, force: bool) -> bool:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    changed = force or not os.path.exists(path)
    if not changed:
        changed = Path(path).read_bytes() != content
    if changed:
        tmp_path = f"{path}.ansible_tmp"
        Path(tmp_path).write_bytes(content)
        os.replace(tmp_path, path)
    return changed | _set_attrs(path, owner, group, mode)


def _paths(base_dir: str, name: str, parent: str | None) -> tuple[str, list[str]]:
    base = base_dir.rstrip("/")
    certificates = [f"{base}/ca/{name}-ca.pem"]
    if parent:
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
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    params = module.params
    try:
        path, certificates = _paths(params["base_dir"], params["name"], params["parent"])
        content = _chain_content(certificates)
        changed = _write_file(
            path,
            content,
            params["owner"],
            params["group"],
            params["mode"],
            params["force"],
        )
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(changed=changed, path=path)


def main():
    run_module()


if __name__ == "__main__":
    main()
