#!/usr/bin/python
"""Assemble an idempotent PEM fullchain bundle on the managed host."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import read_file, sanitize_error, write_file  # type: ignore[import-not-found,import-untyped]


def _read_sources(sources: list[str]) -> bytes:
    """Read and concatenate source files with single trailing newlines."""
    parts = []
    for source in sources:
        parts.append(read_file(source).rstrip() + b"\n")
    return b"".join(parts)


def _bundle_paths(
    base_dir: str, name: str, output_dir: str | None
) -> tuple[str, list[str]]:
    """Derive the fullchain bundle path and ordered input paths."""
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    return (
        f"{directory}/{name}-fullchain.pem",
        [
            f"{directory}/{name}.pem",
            f"{directory}/{name}-chain.pem",
        ],
    )


def _params(params: dict) -> dict:
    """Merge optional certificate dictionary values into module params."""
    certificate = dict(params.get("certificate") or {})
    result = dict(params)
    if result.get("output_dir") is None and certificate.get("output_dir") is not None:
        result["output_dir"] = certificate["output_dir"]
    return result


def run_module():
    """Run the Ansible module for PEM fullchain bundles."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "certificate": {"type": "dict", "no_log": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0644"},
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
