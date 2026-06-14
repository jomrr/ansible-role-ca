#!/usr/bin/python
"""Manage a CA authority certificate."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_inventory import (  # type: ignore[import-not-found,import-untyped]
    update_authority_inventory,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    ca_authority_argument_spec,
    ensure_x509,
    sanitize_error,
)

ROOT_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:1"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}
ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def _apply_authority_defaults(params: dict, defaults: dict) -> dict:
    """Apply authority defaults without overriding explicit module values."""
    result = dict(params)
    for key, value in defaults.items():
        if result.get(key) in (None, "", []):
            result[key] = list(value) if isinstance(value, list) else value
    return result


def _authority_params(params: dict) -> tuple[dict, bool]:
    """Return normalized authority parameters and whether it is parent-signed."""
    result = dict(params)
    name = str(result["name"]).strip()
    parent = str(result.get("parent") or name).strip()
    if not name:
        raise ValueError("Authority name must not be empty")
    if not parent:
        parent = name

    signed = parent != name
    defaults = ISSUING_CA_DEFAULTS if signed else ROOT_CA_DEFAULTS
    result = _apply_authority_defaults(result, defaults)
    result["name"] = name
    result["parent"] = parent

    if signed:
        parent_key_passphrase = result.get("parent_key_passphrase")
        if not parent_key_passphrase:
            raise ValueError("Parent-signed authorities require parent_key_passphrase")
        result["signer_key_passphrase"] = parent_key_passphrase

    return result, signed


def run_module():
    """Run the Ansible module for CA authorities."""
    module = AnsibleModule(
        argument_spec=ca_authority_argument_spec(),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        params, signed = _authority_params(module.params)
        result = ensure_x509(params, signed=signed, authority=True)
        inventory_changed = update_authority_inventory(params, result)
        result["inventory_changed"] = inventory_changed
        result["changed"] = result["changed"] or inventory_changed
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
