#!/usr/bin/python
"""Manage CA role Diffie-Hellman parameter files."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    read_file,
    sanitize_error,
    set_attrs,
    write_file,
)

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dh
except Exception as exc:  # pragma: no cover
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


def _existing_size(path: str):
    try:
        parameters = serialization.load_pem_parameters(read_file(path))
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
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    params = module.params
    path = params["path"] or f"{params['base_dir'].rstrip('/')}/dhparams.pem"
    try:
        changed = params["force"] or _existing_size(path) != params["size"]
        if changed:
            parameters = dh.generate_parameters(generator=2, key_size=params["size"])
            content = parameters.parameter_bytes(
                serialization.Encoding.PEM,
                serialization.ParameterFormat.PKCS3,
            )
            write_file(
                path,
                content,
                params["owner"],
                params["group"],
                params["mode"],
                force=True,
            )
        else:
            changed = (
                set_attrs(path, params["owner"], params["group"], params["mode"])
                or changed
            )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(changed=changed, path=path)


def main():
    run_module()


if __name__ == "__main__":
    main()
