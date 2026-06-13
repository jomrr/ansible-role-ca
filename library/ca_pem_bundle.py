#!/usr/bin/python
"""Assemble an idempotent PEM bundle from files on the managed host."""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule


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


def _read_sources(sources: list[str]) -> bytes:
    parts = []
    for source in sources:
        with open(source, "rb") as handle:
            content = handle.read().rstrip() + b"\n"
        parts.append(content)
    return b"".join(parts)


def _write_file(path: str, content: bytes, owner, group, mode, force: bool) -> bool:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    changed = force or not os.path.exists(path)
    if not changed:
        with open(path, "rb") as handle:
            changed = handle.read() != content
    if changed:
        tmp_path = f"{path}.ansible_tmp"
        with open(tmp_path, "wb") as handle:
            handle.write(content)
        os.replace(tmp_path, path)
    return changed | _set_attrs(path, owner, group, mode)


def run_module():
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "required": True},
            "sources": {"type": "list", "elements": "path", "required": True},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    params = module.params
    try:
        content = _read_sources(params["sources"])
        changed = _write_file(
            params["path"],
            content,
            params["owner"],
            params["group"],
            params["mode"],
            params["force"],
        )
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(changed=changed, path=params["path"])


def main():
    run_module()


if __name__ == "__main__":
    main()
