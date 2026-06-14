#!/usr/bin/python
"""Assemble an idempotent FritzBox PEM import bundle."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    read_file,
    sanitize_error,
    write_file,
)

FRITZBOX_BUNDLE_ORDER = ["certificate", "chain", "private_key"]


def _read_sources(sources: list[str]) -> bytes:
    """Read and concatenate source files with single trailing newlines."""
    parts = []
    for source in sources:
        parts.append(read_file(source).rstrip() + b"\n")
    return b"".join(parts)


def _bundle_paths(
    base_dir: str, name: str, output_dir: str | None
) -> tuple[str, list[str]]:
    """Derive the FritzBox bundle path and ordered input paths."""
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    sources = {
        "private_key": f"{directory}/{name}.key",
        "certificate": f"{directory}/{name}.pem",
        "chain": f"{directory}/{name}-chain.pem",
    }
    return (
        f"{directory}/{name}-fritzbox.pem",
        [sources[item] for item in FRITZBOX_BUNDLE_ORDER],
    )


def _params(params: dict) -> dict:
    """Merge optional certificate dictionary values into module params."""
    certificate = dict(params.get("certificate") or {})
    result = dict(params)
    if result.get("output_dir") is None and certificate.get("output_dir") is not None:
        result["output_dir"] = certificate["output_dir"]
    return result


def run_module():
    """Run the Ansible module for FritzBox PEM bundles."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "certificate": {"type": "dict", "no_log": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    try:
        params = _params(module.params)
        path, sources = _bundle_paths(
            params["base_dir"],
            params["name"],
            params["output_dir"],
        )
        with file_lock(ca_lock_path(params["base_dir"], "certificate", params["name"])):
            content = _read_sources(sources)
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
