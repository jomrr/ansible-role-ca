"""File helpers shared by CA role modules."""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path
from typing import Any


def uid(owner: Any) -> int:
    if owner is None:
        return -1
    value = str(owner)
    if value.isdigit():
        return int(value)
    return pwd.getpwnam(value).pw_uid


def gid(group: Any) -> int:
    if group is None:
        return -1
    value = str(group)
    if value.isdigit():
        return int(value)
    return grp.getgrnam(value).gr_gid


def set_attrs(path: str, owner: Any, group: Any, mode: Any) -> bool:
    changed = False
    stat = os.stat(path)
    desired_uid = uid(owner)
    desired_gid = gid(group)
    owner_changed = desired_uid != -1 and stat.st_uid != desired_uid
    group_changed = desired_gid != -1 and stat.st_gid != desired_gid
    if owner_changed or group_changed:
        os.chown(path, desired_uid, desired_gid)
        changed = True
    if mode is not None:
        desired_mode = int(str(mode), 8)
        if (stat.st_mode & 0o7777) != desired_mode:
            os.chmod(path, desired_mode)
            changed = True
    return changed


def write_file(
    path: str,
    content: bytes,
    owner: Any,
    group: Any,
    mode: Any,
    *,
    force: bool = False,
) -> bool:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    changed = force or not os.path.exists(path)
    if not changed:
        changed = Path(path).read_bytes() != content
    if changed:
        tmp_path = f"{path}.ansible_tmp"
        Path(tmp_path).write_bytes(content)
        os.replace(tmp_path, path)
    attrs_changed = set_attrs(path, owner, group, mode)
    return changed or attrs_changed
