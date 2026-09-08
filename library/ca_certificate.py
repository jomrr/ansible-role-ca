#!/usr/bin/python
"""Dispatch one managed CA role certificate to the built-in X.509 profiles."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_certificate_engine import (
    ensure_certificate_artifacts,
    single_certificate_argument_spec,
)
from ansible.module_utils.ca_x509 import (
    CRYPTOGRAPHY_IMPORT_ERROR,
    sanitize_error,
)


def run_module():
    """Run the Ansible module for dispatched certificate profiles."""
    module = AnsibleModule(
        argument_spec=single_certificate_argument_spec(),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        result = ensure_certificate_artifacts(module.params)
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
