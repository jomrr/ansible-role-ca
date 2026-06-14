"""File helpers shared by CA role modules."""

from __future__ import annotations

import errno
import grp
import os
import pwd
import re
import tempfile
from pathlib import Path
from typing import Any

MASK = "********"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
SECRET_KEY_RE = re.compile(r"(?i)(passphrase|password|secret|token)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(passphrase|password|secret|token)\b\s*[:=]\s*([^\s,;]+)"
)


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


def _mode(mode: Any, fallback: int = 0o600) -> int:
    if mode is None:
        return fallback
    return int(str(mode), 8)


def _open_no_follow(path: str, flags: int) -> int:
    try:
        return os.open(path, flags | NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Refusing to follow symlink: {path}") from exc
        raise


def _read_file(path: str) -> bytes:
    with os.fdopen(_open_no_follow(path, os.O_RDONLY), "rb") as handle:
        return handle.read()


def read_file(path: str) -> bytes:
    return _read_file(path)


def _fsync_directory(path: str) -> None:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path, directory_flags)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def set_attrs(path: str, owner: Any, group: Any, mode: Any) -> bool:
    changed = False
    fd = _open_no_follow(path, os.O_RDONLY)
    try:
        stat = os.fstat(fd)
        desired_uid = uid(owner)
        desired_gid = gid(group)
        owner_changed = desired_uid != -1 and stat.st_uid != desired_uid
        group_changed = desired_gid != -1 and stat.st_gid != desired_gid
        if owner_changed or group_changed:
            os.fchown(fd, desired_uid, desired_gid)
            changed = True
        if mode is not None:
            desired_mode = _mode(mode)
            if (stat.st_mode & 0o7777) != desired_mode:
                os.fchmod(fd, desired_mode)
                changed = True
        return changed
    finally:
        os.close(fd)


def _secret_values(value: Any) -> set[str]:
    secrets: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) and item is not None:
                text = str(item)
                if len(text) >= 3:
                    secrets.add(text)
            else:
                secrets.update(_secret_values(item))
    elif isinstance(value, list):
        for item in value:
            secrets.update(_secret_values(item))
    return secrets


def sanitize_error(exc: BaseException, params: Any | None = None) -> str:
    message = str(exc) or exc.__class__.__name__
    for secret in sorted(_secret_values(params), key=len, reverse=True):
        message = message.replace(secret, MASK)
    return SECRET_ASSIGNMENT_RE.sub(r"\1=" + MASK, message)


def write_file(
    path: str,
    content: bytes,
    owner: Any,
    group: Any,
    mode: Any,
    *,
    force: bool = False,
) -> bool:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        changed = force or _read_file(path) != content
    except FileNotFoundError:
        changed = True
    if changed:
        tmp_path = None
        tmp_fd = -1
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".ansible_tmp",
                dir=str(target.parent),
            )
            os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "wb") as handle:
                tmp_fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            tmp_fd = _open_no_follow(tmp_path, os.O_RDWR)
            desired_uid = uid(owner)
            desired_gid = gid(group)
            if desired_uid != -1 or desired_gid != -1:
                os.fchown(tmp_fd, desired_uid, desired_gid)
            os.fchmod(tmp_fd, _mode(mode))
            os.close(tmp_fd)
            tmp_fd = -1
            os.replace(tmp_path, path)
            tmp_path = None
            _fsync_directory(str(target.parent))
        finally:
            if tmp_fd != -1:
                os.close(tmp_fd)
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
    attrs_changed = set_attrs(path, owner, group, mode)
    return changed or attrs_changed
