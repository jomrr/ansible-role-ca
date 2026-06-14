#!/usr/bin/python
"""Assemble an idempotent PEM bundle from files on the managed host."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import read_file, sanitize_error, write_file  # type: ignore[import-not-found,import-untyped]


def _read_sources(sources: list[str]) -> bytes:
    parts = []
    for source in sources:
        parts.append(read_file(source).rstrip() + b"\n")
    return b"".join(parts)


def _bundle_paths(
    base_dir: str, name: str, output_dir: str | None, order: list[str]
) -> tuple[str, list[str]]:
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    sources = {
        "private_key": f"{directory}/{name}.key",
        "certificate": f"{directory}/{name}.pem",
        "chain": f"{directory}/{name}-chain.pem",
    }
    return f"{directory}/{name}-fritzbox.pem", [sources[item] for item in order]


def run_module():
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "order": {
                "type": "list",
                "elements": "str",
                "default": ["private_key", "certificate", "chain"],
            },
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0600"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    params = module.params
    try:
        path, sources = _bundle_paths(
            params["base_dir"],
            params["name"],
            params["output_dir"],
            params["order"],
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
    run_module()


if __name__ == "__main__":
    main()
