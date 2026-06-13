#!/usr/bin/python
"""Manage a FritzBox end-entity certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_x509_common import (
    CRYPTOGRAPHY_IMPORT_ERROR,
    ensure_x509,
    x509_argument_spec,
)


FRITZBOX_DIGESTS = {"sha1", "sha224", "sha256", "sha384"}


def run_module():
    module = AnsibleModule(
        argument_spec=x509_argument_spec(directory=True, signer=True, chain=True),
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    params = module.params
    digest = str(params["digest"]).replace("-", "").lower()
    if digest not in FRITZBOX_DIGESTS:
        module.fail_json(msg="FritzBox certificates support digests up to sha384")
    params["basic_constraints"] = ["CA:FALSE"]
    try:
        result = ensure_x509(params, signed=True, manage_directory=True, manage_chain=True)
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
