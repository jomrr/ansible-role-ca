#!/usr/bin/python
"""Create deterministic public AIA/CDP publish archives on the managed host."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    read_file,
    sanitize_error,
    set_attrs,
    write_file,
)

AREA_DIRECTORY = {
    "aia": "aia",
    "cdp": "crl",
    "crl": "crl",
}
MANIFEST_NAME = ".ca-publish-manifest.json"
MTIME = 0


def _mode(value: Any, fallback: int = 0o644) -> int:
    """Return an integer mode from an Ansible-style octal mode value."""
    if value is None:
        return fallback
    return int(str(value), 8)


def _archive_path(area: str, filename: str) -> str:
    """Return a safe relative archive path for one public artifact."""
    directory = AREA_DIRECTORY.get(str(area))
    if directory is None:
        raise ValueError(f"Unsupported publish artifact area: {area}")
    path = PurePosixPath(str(filename))
    if path.name != str(filename) or path.name in ("", ".", ".."):
        raise ValueError(f"Unsafe publish artifact filename: {filename}")
    return str(PurePosixPath(directory) / path.name)


def _add_bytes(
    archive: tarfile.TarFile,
    path: str,
    content: bytes,
    mode: int,
) -> None:
    """Add bytes to a tar archive with deterministic metadata."""
    info = tarfile.TarInfo(path)
    info.size = len(content)
    info.mtime = MTIME
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(content))


def _manifest_content(directory: str, entries: list[dict[str, Any]]) -> bytes:
    """Return deterministic JSON manifest content for one publish directory."""
    manifest = {
        "schema_version": 1,
        "directory": directory,
        "files": sorted(entries, key=lambda item: item["path"]),
    }
    return (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _archive_content(
    artifacts: list[dict[str, Any]],
    artifact_mode: Any,
) -> tuple[bytes, list[str], dict[str, str]]:
    """Return deterministic tar bytes and archive paths for public artifacts."""
    mode = _mode(artifact_mode)
    archive_paths: set[str] = set()
    manifests: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    manifest_sha256: dict[str, str] = {}
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for artifact in sorted(
            artifacts,
            key=lambda item: (str(item.get("area", "")), str(item.get("file", ""))),
        ):
            area = str(artifact.get("area", ""))
            filename = str(artifact.get("file", ""))
            source = str(artifact.get("src", ""))
            archive_path = _archive_path(area, filename)
            if archive_path in archive_paths:
                raise ValueError(f"Duplicate publish archive path: {archive_path}")
            content = read_file(source)
            digest = hashlib.sha256(content).hexdigest()
            directory = archive_path.split("/", 1)[0]
            _add_bytes(archive, archive_path, content, mode)
            archive_paths.add(archive_path)
            manifests[directory].append(
                {
                    "path": archive_path,
                    "source": source,
                    "size": len(content),
                    "sha256": digest,
                }
            )

        for directory in sorted(manifests):
            manifest_path = str(PurePosixPath(directory) / MANIFEST_NAME)
            manifest_content = _manifest_content(directory, manifests[directory])
            _add_bytes(
                archive,
                manifest_path,
                manifest_content,
                mode,
            )
            manifest_sha256[directory] = hashlib.sha256(manifest_content).hexdigest()
            archive_paths.add(manifest_path)

    return buffer.getvalue(), sorted(archive_paths), manifest_sha256


def run_module() -> None:
    """Run the Ansible module for deterministic public publish archives."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "dest": {"type": "path", "required": True},
            "artifacts": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "artifact_mode": {"type": "str", "default": "0644"},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    params = module.params
    try:
        with file_lock(ca_lock_path(params["base_dir"], "publish", "archive")):
            content, archive_paths, manifest_sha256 = _archive_content(
                params["artifacts"],
                params["artifact_mode"],
            )
            changed = params["force"]
            if not changed:
                try:
                    changed = read_file(params["dest"]) != content
                except FileNotFoundError:
                    changed = True
            if changed:
                write_file(
                    params["dest"],
                    content,
                    params["owner"],
                    params["group"],
                    params["mode"],
                    force=True,
                )
            else:
                changed = (
                    set_attrs(
                        params["dest"],
                        params["owner"],
                        params["group"],
                        params["mode"],
                    )
                    or changed
                )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, params))

    module.exit_json(
        changed=changed,
        path=params["dest"],
        archive_paths=archive_paths,
        manifest_sha256=manifest_sha256,
    )


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
