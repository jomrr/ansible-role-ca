#!/usr/bin/python
"""Manage CA role Diffie-Hellman parameter files."""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dh
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


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


def _existing_size(path: str):
    try:
        parameters = serialization.load_pem_parameters(Path(path).read_bytes())
        return parameters.parameter_numbers().p.bit_length()
    except Exception:
        return None


def run_module():
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "path": {"type": "path"},
            "size": {"type": "int", "default": 4096},
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
    path = params["path"] or f"{params['base_dir'].rstrip('/')}/dhparams.pem"
    try:
        changed = params["force"] or not os.path.exists(path) or _existing_size(path) != params["size"]
        if changed:
            parameters = dh.generate_parameters(generator=2, key_size=params["size"])
            content = parameters.parameter_bytes(
                serialization.Encoding.PEM,
                serialization.ParameterFormat.PKCS3,
            )
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            tmp_path = f"{path}.ansible_tmp"
            Path(tmp_path).write_bytes(content)
            os.replace(tmp_path, path)
        changed = _set_attrs(path, params["owner"], params["group"], params["mode"]) or changed
    except Exception as exc:
        module.fail_json(msg=str(exc))
    module.exit_json(changed=changed, path=path)


def main():
    run_module()


if __name__ == "__main__":
    main()
