#!/usr/bin/python
"""Manage an Issuing CA certificate signed by a parent CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    ca_authority_argument_spec,
    ensure_x509,
    sanitize_error,
)

ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def run_module():
    """Run the Ansible module for an issuing CA."""
    module = AnsibleModule(
        argument_spec=ca_authority_argument_spec(
            signed=True,
            defaults=ISSUING_CA_DEFAULTS,
        ),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        params = dict(module.params)
        params["signer_key_passphrase"] = params["parent_key_passphrase"]
        result = ensure_x509(params, signed=True, authority=True)
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
