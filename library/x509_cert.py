#!/usr/bin/python
"""Manage an end-entity certificate signed by an issuing CA."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.x509_common import (
    CRYPTOGRAPHY_IMPORT_ERROR,
    apply_profile_defaults,
    ensure_x509,
    x509_argument_spec,
)


PROFILE_DEFAULTS = {
    "tls_server": {
        "default_dns_san": True,
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["serverAuth"],
    },
    "tls_client": {
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["clientAuth"],
    },
    "eap_tls_client": {
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["clientAuth"],
    },
}


def run_module():
    spec = x509_argument_spec(directory=True, signer=True)
    spec["issuer_key_passphrase"] = spec.pop("signer_key_passphrase")
    spec["profile"] = {
        "type": "str",
        "choices": sorted(PROFILE_DEFAULTS),
        "default": "tls_server",
    }
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    try:
        params = dict(module.params)
        params["signer_key_passphrase"] = params.pop("issuer_key_passphrase")
        params = apply_profile_defaults(
            params,
            PROFILE_DEFAULTS[params["profile"]],
        )
        result = ensure_x509(params, signed=True, manage_directory=True, manage_chain=True)
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
