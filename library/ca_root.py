#!/usr/bin/python
"""Manage a self-signed Root CA certificate."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    ensure_x509,
    sanitize_error,
    x509_argument_spec,
)

ROOT_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:1"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha512",
}


def run_module():
    """Run the Ansible module for a self-signed Root CA."""
    module = AnsibleModule(
        argument_spec=x509_argument_spec(authority=True, defaults=ROOT_CA_DEFAULTS),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        result = ensure_x509(module.params, signed=False, authority=True)
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
