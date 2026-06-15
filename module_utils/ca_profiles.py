"""Certificate profile defaults and profile-specific normalization."""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "CERTIFICATE_DEFAULT_FORMATS",
    "CERTIFICATE_PROFILE_DEFAULTS",
    "FRITZBOX_DIGESTS",
    "IDENTITY_CERTIFICATE_DEFAULTS",
    "STANDARD_CERTIFICATE_DEFAULTS",
    "apply_certificate_profile",
    "apply_profile_defaults",
]


KRB5_REALM_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]*$")
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
GUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")

STANDARD_CERTIFICATE_DEFAULTS: dict[str, dict[str, Any]] = {
    "tls_server": {
        "default_dns_san": True,
        "digest": "sha384",
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["serverAuth"],
    },
    "tls_client": {
        "digest": "sha384",
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["clientAuth"],
    },
    "eap_tls_client": {
        "digest": "sha384",
        "key_usage": ["digitalSignature", "keyEncipherment"],
        "extended_key_usage": ["clientAuth"],
    },
}
IDENTITY_CERTIFICATE_DEFAULTS: dict[str, dict[str, Any]] = {
    "identity": {
        "digest": "sha384",
        "key_usage": ["digitalSignature", "keyEncipherment", "nonRepudiation"],
        "extended_key_usage": [
            "clientAuth",
            "emailProtection",
            "1.3.6.1.4.1.311.20.2.2",
        ],
    },
    "identity_full": {
        "digest": "sha384",
        "key_usage": ["digitalSignature", "keyEncipherment", "nonRepudiation"],
        "extended_key_usage": [
            "clientAuth",
            "emailProtection",
            "codeSigning",
            "1.3.6.1.4.1.311.20.2.2",
        ],
    },
}
MSKDC_CERTIFICATE_DEFAULTS: dict[str, Any] = {
    "default_dns_san": True,
    "digest": "sha384",
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
FRITZBOX_CERTIFICATE_DEFAULTS: dict[str, Any] = {
    "default_dns_san": True,
    "digest": "sha384",
    "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": ["serverAuth", "clientAuth"],
}
CERTIFICATE_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    **STANDARD_CERTIFICATE_DEFAULTS,
    **IDENTITY_CERTIFICATE_DEFAULTS,
    "mskdc": MSKDC_CERTIFICATE_DEFAULTS,
    "fritzbox": FRITZBOX_CERTIFICATE_DEFAULTS,
}
CERTIFICATE_DEFAULT_FORMATS: dict[str, list[str]] = {
    "tls_server": ["pem", "der", "txt"],
    "tls_client": ["pem", "der", "txt"],
    "eap_tls_client": ["pem", "der", "txt"],
    "mskdc": ["pem", "der", "txt"],
    "identity": ["pem", "der", "txt", "pfx"],
    "identity_full": ["pem", "der", "txt", "pfx"],
    "fritzbox": ["pem", "der", "txt", "fritzbox"],
}
FRITZBOX_DIGESTS = {"sha1", "sha224", "sha256", "sha384"}


def _merge_raw_extensions(defaults, overrides):
    """Merge default raw extensions with caller overrides by OID."""
    overrides = list(overrides or [])
    override_oids = {str(item.get("oid")) for item in overrides}
    merged = [
        dict(item)
        for item in (defaults or [])
        if str(item.get("oid")) not in override_oids
    ]
    merged.extend(overrides)
    return merged


def _ad_guid_hex(value) -> str:
    """Return AD objectGUID bytes as uppercase hex in directory byte order."""
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
    """Add PKINIT SAN and NTDS objectGUID extensions to module params."""
    result = dict(params)
    realm = str(result.pop("krb5_realm", "") or "").strip().upper()
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
                + _ad_guid_hex(result.pop("ad_object_guid", ""))
            ),
        }
    )
    result["raw_extensions"] = raw_extensions
    return result


def apply_profile_defaults(params: dict, defaults: dict) -> dict:
    """Apply certificate profile defaults without overriding explicit values."""
    result = dict(params)
    for key in ("key_usage", "extended_key_usage"):
        value = defaults.get(key)
        if value is not None and not result.get(key):
            result[key] = list(value)

    if defaults.get("raw_extensions"):
        result["raw_extensions"] = _merge_raw_extensions(
            defaults["raw_extensions"],
            result.get("raw_extensions"),
        )

    if defaults.get("digest") and not result.get("digest"):
        result["digest"] = defaults["digest"]

    if defaults.get("default_dns_san"):
        common_name = str(result.get("common_name") or "").strip()
        san = list(result.get("san") or [])
        if common_name and not any(str(item).startswith("DNS:") for item in san):
            san.append(f"DNS:{common_name}")
        result["san"] = san

    return result


def apply_certificate_profile(params: dict, profile: str) -> dict:
    """Apply built-in certificate profile defaults and validations."""
    if profile not in CERTIFICATE_PROFILE_DEFAULTS:
        raise ValueError(f"Unsupported certificate profile {profile}")

    result = dict(params)
    result["profile"] = profile
    if profile == "mskdc":
        result = _apply_mskdc_extensions(result)

    result = apply_profile_defaults(result, CERTIFICATE_PROFILE_DEFAULTS[profile])

    if profile == "fritzbox":
        digest = str(result["digest"]).replace("-", "").lower()
        if digest not in FRITZBOX_DIGESTS:
            raise ValueError("FritzBox certificates support digests up to sha384")

    return result
