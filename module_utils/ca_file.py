"""File helpers shared by CA role modules."""

from __future__ import annotations

import errno
import fcntl
import grp
import os
import pwd
import re
import secrets
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Iterable

MASK = "********"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
SECRET_KEY_RE = re.compile(r"(?i)(passphrase|password|secret|token)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(passphrase|password|secret|token)\b\s*[:=]\s*([^\s,;]+)"
)
SAFE_PATH_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_path_component(value: Any) -> str:
    """Return a filesystem-safe path component for internal artifacts."""
    text = SAFE_PATH_COMPONENT_RE.sub("_", str(value).strip())
    return text.strip("._") or "unnamed"


def ca_lock_path(base_dir: str, namespace: str, name: str) -> str:
    """Return a shared lock path for one managed CA object."""
    stem = f"{safe_path_component(namespace)}-{safe_path_component(name)}"
    return f"{str(base_dir).rstrip('/')}/.locks/{stem}.lock"


@contextmanager
def file_lock(path: str):
    """Hold an exclusive advisory lock for one managed file operation."""
    lock_path = Path(path)
    lock_name = lock_path.name
    if not lock_name:
        raise ValueError(f"Refusing to lock directory path: {path}")
    parent_fd = _open_parent_directory(lock_path)
    try:
        os.fchmod(parent_fd, 0o700)
        fd = _open_no_follow(lock_name, os.O_CREAT | os.O_RDWR, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
    finally:
        os.close(parent_fd)


@contextmanager
def file_locks(paths: Iterable[str]):
    """Hold multiple exclusive advisory locks in deterministic order."""
    lock_paths = sorted({str(path) for path in paths if path})
    with ExitStack() as stack:
        for path in lock_paths:
            stack.enter_context(file_lock(path))
        yield


def uid(owner: Any) -> int:
    """Resolve an owner name or numeric string to a UID."""
    if owner is None:
        return -1
    value = str(owner)
    if value.isdigit():
        return int(value)
    return pwd.getpwnam(value).pw_uid


def gid(group: Any) -> int:
    """Resolve a group name or numeric string to a GID."""
    if group is None:
        return -1
    value = str(group)
    if value.isdigit():
        return int(value)
    return grp.getgrnam(value).gr_gid


def _mode(mode: Any, fallback: int = 0o600) -> int:
    """Convert an Ansible-style octal mode value to an integer."""
    if mode is None:
        return fallback
    return int(str(mode), 8)


def _open_no_follow(path: str, flags: int, *, dir_fd: int | None = None) -> int:
    """Open a path without following a final symlink."""
    try:
        if dir_fd is None:
            return os.open(path, flags | NOFOLLOW)
        return os.open(path, flags | NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Refusing to follow symlink: {path}") from exc
        raise


def _open_directory_no_follow(path: str, *, dir_fd: int | None = None) -> int:
    """Open a directory path without following a final symlink."""
    try:
        if dir_fd is None:
            return os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        return os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Refusing to follow symlinked directory: {path}") from exc
        if exc.errno == errno.ENOTDIR:
            raise ValueError(f"Refusing non-directory path component: {path}") from exc
        raise


def _open_parent_directory(path: Path) -> int:
    """Create and open a target parent directory without following symlinks."""
    parent = path.parent
    if parent.is_absolute():
        directory_fd = _open_directory_no_follow(os.sep)
        parts = parent.parts[1:]
    else:
        directory_fd = _open_directory_no_follow(".")
        parts = parent.parts

    try:
        for part in parts:
            if part in ("", "."):
                continue
            try:
                os.mkdir(part, 0o755, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = _open_directory_no_follow(part, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _read_file(path: str) -> bytes:
    """Read a file while refusing symlink targets."""
    with os.fdopen(_open_no_follow(path, os.O_RDONLY), "rb") as handle:
        return handle.read()


def _read_file_at(parent_fd: int, name: str) -> bytes:
    """Read a file below an opened directory without following symlinks."""
    fd = _open_no_follow(name, os.O_RDONLY, dir_fd=parent_fd)
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def read_file(path: str) -> bytes:
    """Read file content through the shared symlink-safe helper."""
    return _read_file(path)


def _fsync_directory_fd(directory_fd: int) -> None:
    """Flush directory metadata when the platform supports it."""
    try:
        os.fsync(directory_fd)
    except OSError:
        pass


def _set_attrs_fd(fd: int, owner: Any, group: Any, mode: Any) -> bool:
    """Apply owner, group, and mode to an opened file descriptor."""
    changed = False
    stat_result = os.fstat(fd)
    desired_uid = uid(owner)
    desired_gid = gid(group)
    owner_changed = desired_uid != -1 and stat_result.st_uid != desired_uid
    group_changed = desired_gid != -1 and stat_result.st_gid != desired_gid
    if owner_changed or group_changed:
        os.fchown(fd, desired_uid, desired_gid)
        changed = True
    if mode is not None:
        desired_mode = _mode(mode)
        if (stat_result.st_mode & 0o7777) != desired_mode:
            os.fchmod(fd, desired_mode)
            changed = True
    return changed


def _set_attrs_at(parent_fd: int, name: str, owner: Any, group: Any, mode: Any) -> bool:
    """Apply file attributes below an opened directory without following symlinks."""
    fd = _open_no_follow(name, os.O_RDONLY, dir_fd=parent_fd)
    try:
        return _set_attrs_fd(fd, owner, group, mode)
    finally:
        os.close(fd)


def set_attrs(path: str, owner: Any, group: Any, mode: Any) -> bool:
    """Apply owner, group, and mode to a path and report changes."""
    fd = _open_no_follow(path, os.O_RDONLY)
    try:
        return _set_attrs_fd(fd, owner, group, mode)
    finally:
        os.close(fd)


def _check_final_target(parent_fd: int, name: str, display_path: str) -> None:
    """Refuse an existing final symlink below an opened directory."""
    try:
        stat_result = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(stat_result.st_mode):
        raise ValueError(f"Refusing to replace symlink: {display_path}")


def _create_temp_file(parent_fd: int, target_name: str) -> tuple[int, str]:
    """Create a private temporary file below an opened directory."""
    for _ in range(100):
        tmp_name = f".{target_name}.{secrets.token_hex(8)}.ansible_tmp"
        try:
            tmp_fd = os.open(
                tmp_name,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            return tmp_fd, tmp_name
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique temporary file for {target_name}")


def _secret_values(value: Any) -> set[str]:
    """Collect secret-looking values from nested module parameters."""
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
    """Return an exception message with module secrets masked."""
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
    """Atomically write content and enforce file attributes."""
    target = Path(path)
    target_name = target.name
    if not target_name:
        raise ValueError(f"Refusing to write to directory path: {path}")

    parent_fd = _open_parent_directory(target)
    try:
        _check_final_target(parent_fd, target_name, path)
        try:
            changed = force or _read_file_at(parent_fd, target_name) != content
        except FileNotFoundError:
            changed = True

        if changed:
            tmp_name = None
            tmp_fd = -1
            try:
                tmp_fd, tmp_name = _create_temp_file(parent_fd, target_name)
                with os.fdopen(tmp_fd, "wb") as handle:
                    tmp_fd = -1
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                tmp_fd = _open_no_follow(tmp_name, os.O_RDWR, dir_fd=parent_fd)
                desired_uid = uid(owner)
                desired_gid = gid(group)
                if desired_uid != -1 or desired_gid != -1:
                    os.fchown(tmp_fd, desired_uid, desired_gid)
                os.fchmod(tmp_fd, _mode(mode))
                os.close(tmp_fd)
                tmp_fd = -1
                os.replace(
                    tmp_name,
                    target_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                tmp_name = None
                _fsync_directory_fd(parent_fd)
            finally:
                if tmp_fd != -1:
                    os.close(tmp_fd)
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
        attrs_changed = _set_attrs_at(parent_fd, target_name, owner, group, mode)
        return changed or attrs_changed
    finally:
        os.close(parent_fd)
