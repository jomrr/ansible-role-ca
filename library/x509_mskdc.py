#!/usr/bin/python
"""Manage an MSKDC/Samba AD domain controller certificate."""

from __future__ import annotations

import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.x509_common import (
    CRYPTOGRAPHY_IMPORT_ERROR,
    apply_profile_defaults,
    ensure_x509,
    x509_certificate_argument_spec,
    x509_certificate_params,
)

KRB5_REALM_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]*$")
GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
GUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")


MSKDC_DEFAULTS = {
    "default_dns_san": True,
    "digest": "sha256",
    "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": [
        "serverAuth",
        "clientAuth",
        "1.3.6.1.5.2.3.5",
    ],
    "raw_extensions": [
        {
            "oid": "1.3.6.1.4.1.311.20.2",
            "value": "ASN1:BMPSTRING:DomainController",
        }
    ],
}


def _ad_guid_hex(value) -> str:
    guid = str(value or "").lower().strip().strip("{}")
    guid_hex = re.sub(r"[-: ]", "", guid)

    if GUID_RE.match(guid):
        return (
            guid[6:8]
            + guid[4:6]
            + guid[2:4]
            + guid[0:2]
            + guid[11:13]
            + guid[9:11]
            + guid[16:18]
            + guid[14:16]
            + guid[19:23]
            + guid[24:36]
        ).upper()

    if GUID_HEX_RE.match(guid_hex):
        return guid_hex.upper()

    raise ValueError(
        "mskdc certificate requires ad_object_guid as canonical GUID or raw 16-byte hex"
    )


def _apply_mskdc_extensions(params: dict) -> dict:
    result = dict(params)
    realm = str(result.pop("krb5_realm") or "").strip().upper()
    if not KRB5_REALM_RE.match(realm):
        raise ValueError("mskdc certificate requires a valid krb5_realm for PKINIT")

    prefix = re.sub(r"[^A-Za-z0-9_]", "_", f"pkinit_{result['name']}")
    san = list(result.get("san") or [])
    san.append(f"otherName:1.3.6.1.5.2.2;SEQUENCE:{prefix}_principal")
    result["san"] = san
    result["pkinit"] = {"realm": realm}

    raw_extensions = [
        extension
        for extension in (result.get("raw_extensions") or [])
        if str(extension.get("oid")) != "1.3.6.1.4.1.311.25.1"
    ]
    raw_extensions.append(
        {
            "oid": "1.3.6.1.4.1.311.25.1",
            "value": (
                "ASN1:FORMAT:HEX,OCTETSTRING:"
                + _ad_guid_hex(result.pop("ad_object_guid"))
            ),
        }
    )
    result["raw_extensions"] = raw_extensions
    return result


def run_module():
    spec = x509_certificate_argument_spec()
    spec["krb5_realm"] = {"type": "str", "required": True}
    spec["ad_object_guid"] = {"type": "str", "required": True}
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    try:
        params = x509_certificate_params(module.params)
        params = _apply_mskdc_extensions(params)
        params = apply_profile_defaults(params, MSKDC_DEFAULTS)
        result = ensure_x509(params, signed=True, manage_directory=True, manage_chain=True)
    except Exception as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
