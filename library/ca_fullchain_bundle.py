#!/usr/bin/python
"""Assemble an idempotent PEM fullchain bundle on the managed host."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import sanitize_error  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_pem_bundle import (  # type: ignore[import-not-found,import-untyped]
    ensure_pem_bundle,
    pem_bundle_argument_spec,
)


def run_module():
    """Run the Ansible module for PEM fullchain bundles."""
    module = AnsibleModule(
        argument_spec=pem_bundle_argument_spec(default_mode="0644"),
        supports_check_mode=False,
    )

    try:
        result = ensure_pem_bundle(
            module.params,
            suffix="fullchain",
            order=["certificate", "chain"],
        )
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
