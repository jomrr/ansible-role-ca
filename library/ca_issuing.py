#!/usr/bin/python
"""Manage an Issuing CA certificate signed by a parent CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.x509_common import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    ensure_x509,
    x509_argument_spec,
)

ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha512",
}


def run_module():
    spec = x509_argument_spec(
        authority=True,
        signer=True,
        defaults=ISSUING_CA_DEFAULTS,
    )
    spec["parent_key_passphrase"] = spec.pop("signer_key_passphrase")
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        params = dict(module.params)
        params["signer_key_passphrase"] = params.pop("parent_key_passphrase")
        result = ensure_x509(params, signed=True, authority=True)
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
