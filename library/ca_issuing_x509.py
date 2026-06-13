#!/usr/bin/python
"""Manage an issuing CA certificate signed by a parent CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_x509_common import (
    CRYPTOGRAPHY_IMPORT_ERROR,
    ensure_x509,
    x509_argument_spec,
)


def run_module():
    module = AnsibleModule(
        argument_spec=x509_argument_spec(signer=True),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    try:
        result = ensure_x509(module.params, signed=True)
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
