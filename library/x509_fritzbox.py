#!/usr/bin/python
"""Manage a FritzBox certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    CERTIFICATE_DEFAULT_FORMATS,
    CRYPTOGRAPHY_IMPORT_ERROR,
    apply_certificate_profile,
    ensure_x509,
    sanitize_error,
    x509_certificate_argument_spec,
    x509_certificate_params,
)


def run_module():
    """Run the Ansible module for FritzBox certificate profiles."""
    spec = x509_certificate_argument_spec()
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    params = x509_certificate_params(
        module.params,
        default_formats=CERTIFICATE_DEFAULT_FORMATS["fritzbox"],
    )
    try:
        params = apply_certificate_profile(params, "fritzbox")
        result = ensure_x509(
            params, signed=True, manage_directory=True, manage_chain=True
        )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
