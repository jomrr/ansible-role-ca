"""CA role filter plugins."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from ansible.errors import AnsibleFilterError


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
KRB5_REALM_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]*$")
GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
GUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise AnsibleFilterError(f"Expected a list, got {type(value).__name__}")


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _required(value: dict[str, Any], key: str, context: str) -> Any:
    if key not in value or _string(value[key]) == "":
        raise AnsibleFilterError(f"{context} requires {key}")
    return value[key]


def _ad_guid_hex(value: Any) -> str:
    guid = _string(value).lower().strip().strip("{}")
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

    raise AnsibleFilterError(
        "mskdc certificate requires ad_object_guid as canonical GUID or raw 16-byte hex"
    )


def _certificate_subject(
    certificate: dict[str, Any], subject_defaults: dict[str, Any]
) -> list[dict[str, Any]]:
    subject = [
        {"C": certificate.get("country", subject_defaults["country"])},
        {"ST": certificate.get("state", subject_defaults["state"])},
        {"L": certificate.get("locality", subject_defaults["locality"])},
        {"O": certificate.get("organization", subject_defaults["organization"])},
        {
            "OU": certificate.get(
                "organizational_unit", subject_defaults["organizational_unit"]
            )
        },
        {"CN": certificate["common_name"]},
    ]

    if _string(certificate.get("email")):
        subject.append({"emailAddress": certificate["email"]})

    return subject


def ca_certificate_model(
    certificate: dict[str, Any],
    certificate_types: dict[str, dict[str, Any]],
    authorities: dict[str, Any],
    _base_dir: str,
    default_certificate_days: int,
    kerberos_realm: str,
    subject_defaults: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one declarative certificate into the model used by tasks."""

    if not isinstance(certificate, dict):
        raise AnsibleFilterError("Each ca_certificates item must be a dictionary")

    name = _string(_required(certificate, "name", "Certificate")).strip()
    cert_type = _string(_required(certificate, "type", f"Certificate {name}")).strip()
    common_name = _string(
        _required(certificate, "common_name", f"Certificate {name}")
    ).strip()

    if not SAFE_NAME_RE.match(name):
        raise AnsibleFilterError(
            f"Certificate {name} has an unsafe name; use only letters, digits, dots, underscores, and hyphens"
        )

    if cert_type not in certificate_types:
        raise AnsibleFilterError(f"Certificate {name} uses unknown type {cert_type}")

    profile = deepcopy(certificate_types[cert_type])
    issuer = _string(_required(profile, "issuer", f"Certificate type {cert_type}"))
    if issuer not in authorities:
        raise AnsibleFilterError(
            f"Certificate type {cert_type} references unknown issuer {issuer}"
        )

    for field in _as_list(profile.get("required_fields")):
        _required(certificate, _string(field), f"Certificate {name}")

    formats = [str(item).lower() for item in _as_list(profile.get("formats"))]
    unsupported_formats = sorted(
        set(formats).difference({"pem", "der", "pfx", "p12", "fritzbox"})
    )
    if unsupported_formats:
        raise AnsibleFilterError(
            f"Certificate {name} has unsupported formats: {', '.join(unsupported_formats)}"
        )

    if set(formats).intersection({"pfx", "p12"}) and not _string(
        certificate.get("pfx_passphrase")
    ):
        raise AnsibleFilterError(
            f"Certificate {name} uses PFX/PKCS#12 output and requires pfx_passphrase"
        )

    san = [str(item) for item in _as_list(profile.get("san"))]
    san.extend(str(item) for item in _as_list(certificate.get("san")))

    if profile.get("default_dns_san", False) and not any(
        item.startswith("DNS:") for item in san
    ):
        san.append(f"DNS:{common_name}")

    raw_extensions = deepcopy(_as_list(profile.get("raw_extensions")))
    dynamic_extensions = {
        str(item) for item in _as_list(profile.get("dynamic_extensions"))
    }
    pkinit = {"prefix": "", "realm": ""}

    if cert_type == "mskdc" or dynamic_extensions.intersection(
        {"ntds_object_guid", "krb5_principal_name"}
    ):
        if "ntds_object_guid" in dynamic_extensions or cert_type == "mskdc":
            raw_extensions.append(
                {
                    "oid": "1.3.6.1.4.1.311.25.1",
                    "value": (
                        "ASN1:FORMAT:HEX,OCTETSTRING:"
                        + _ad_guid_hex(certificate.get("ad_object_guid"))
                    ),
                }
            )

        if "krb5_principal_name" in dynamic_extensions or cert_type == "mskdc":
            realm = (
                _string(certificate.get("krb5_realm") or kerberos_realm)
                .strip()
                .upper()
            )
            if not KRB5_REALM_RE.match(realm):
                raise AnsibleFilterError(
                    f"Certificate {name} requires a valid krb5_realm for PKINIT"
                )
            prefix = re.sub(r"[^A-Za-z0-9_]", "_", f"pkinit_{name}")
            san.append(f"otherName:1.3.6.1.5.2.2;SEQUENCE:{prefix}_principal")
            pkinit = {"prefix": prefix, "realm": realm}

    model = deepcopy(certificate)
    model.update(
        {
            "name": name,
            "type": cert_type,
            "common_name": common_name,
            "issuer": issuer,
            "formats": formats,
            "days": certificate.get(
                "days", profile.get("days", default_certificate_days)
            ),
            "digest": certificate.get("digest", profile.get("digest", "")),
            "key_usage": _as_list(profile.get("key_usage")),
            "extended_key_usage": _as_list(profile.get("extended_key_usage")),
            "raw_extensions": raw_extensions,
            "san": san,
            "csr_san": [
                item
                for item in san
                if ";FORMAT:" not in item and ";SEQUENCE:" not in item
            ],
            "subject": _certificate_subject(certificate, subject_defaults),
            "privatekey_passphrase": _string(
                certificate.get("privatekey_passphrase")
            ),
            "pfx_passphrase": _string(certificate.get("pfx_passphrase")),
            "pkinit": pkinit,
        }
    )

    output_dir = _string(certificate.get("output_dir")).strip()
    if output_dir:
        model["output_dir"] = output_dir

    return model


def ca_certificate_models(
    certificates: list[dict[str, Any]],
    certificate_types: dict[str, dict[str, Any]],
    authorities: dict[str, Any],
    base_dir: str,
    default_certificate_days: int,
    kerberos_realm: str,
    subject_defaults: dict[str, Any],
) -> list[dict[str, Any]]:
    """Resolve all declarative certificates into task-ready models."""

    return [
        ca_certificate_model(
            certificate,
            certificate_types,
            authorities,
            base_dir,
            default_certificate_days,
            kerberos_realm,
            subject_defaults,
        )
        for certificate in _as_list(certificates)
    ]


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        return {
            "ca_certificate_model": ca_certificate_model,
            "ca_certificate_models": ca_certificate_models,
        }
