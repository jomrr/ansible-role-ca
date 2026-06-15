#!/usr/bin/python
"""Dispatch managed CA role certificates in one batch."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_certificate_engine import (  # type: ignore[import-not-found,import-untyped]
    batch_certificate_argument_spec,
    ensure_certificate_batch,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    sanitize_error,
)


def run_module():
    """Run the Ansible module for batched certificate profiles."""
    module = AnsibleModule(
        argument_spec=batch_certificate_argument_spec(),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        result = ensure_certificate_batch(module.params)
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
