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


def _as_dict(value: Any, context: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise AnsibleFilterError(f"{context} must be a dictionary")


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


def ca_authority_map(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""

    result = {}
    for authority in _as_list(authorities):
        if not isinstance(authority, dict):
            raise AnsibleFilterError("Each ca_authorities item must be a dictionary")
        name = _string(_required(authority, "name", "Authority")).strip()
        if not SAFE_NAME_RE.match(name):
            raise AnsibleFilterError(
                f"Authority {name} has an unsafe name; use only letters, digits, dots, underscores, and hyphens"
            )
        if name in result:
            raise AnsibleFilterError(f"Duplicate authority name {name}")
        result[name] = authority

    for name, authority in result.items():
        parent = _string(_required(authority, "parent", f"Authority {name}")).strip()
        if parent not in result:
            raise AnsibleFilterError(
                f"Authority {name} references unknown parent {parent}"
            )
    return result


def ca_certificate_model(
    certificate: dict[str, Any],
    certificate_types: dict[str, dict[str, Any]],
    authorities: list[dict[str, Any]],
    _base_dir: str,
    default_certificate_days: int,
    kerberos_realm: str,
    subject: dict[str, Any],
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

    authority_map = ca_authority_map(authorities)
    profile = deepcopy(certificate_types[cert_type])
    issuer = _string(_required(profile, "issuer", f"Certificate type {cert_type}"))
    if issuer not in authority_map:
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

    san = [str(item) for item in _as_list(certificate.get("san"))]
    raw_extensions = deepcopy(_as_list(certificate.get("raw_extensions")))
    pkinit = {"prefix": "", "realm": ""}

    if cert_type == "mskdc":
        raw_extensions.append(
            {
                "oid": "1.3.6.1.4.1.311.25.1",
                "value": (
                    "ASN1:FORMAT:HEX,OCTETSTRING:"
                    + _ad_guid_hex(certificate.get("ad_object_guid"))
                ),
            }
        )
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

    subject_values = deepcopy(_as_dict(subject, "ca_subject"))
    subject_values.update(_as_dict(certificate.get("subject"), f"Certificate {name} subject"))

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
            "san": san,
            "csr_san": [
                item
                for item in san
                if ";FORMAT:" not in item and ";SEQUENCE:" not in item
            ],
            "privatekey_passphrase": _string(
                certificate.get("privatekey_passphrase")
            ),
            "pfx_passphrase": _string(certificate.get("pfx_passphrase")),
            "pkinit": pkinit,
            "subject": subject_values,
        }
    )

    if raw_extensions:
        model["raw_extensions"] = raw_extensions

    output_dir = _string(certificate.get("output_dir")).strip()
    if output_dir:
        model["output_dir"] = output_dir

    return model


def ca_certificate_models(
    certificates: list[dict[str, Any]],
    certificate_types: dict[str, dict[str, Any]],
    authorities: list[dict[str, Any]],
    base_dir: str,
    default_certificate_days: int,
    kerberos_realm: str,
    subject: dict[str, Any],
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
            subject,
        )
        for certificate in _as_list(certificates)
    ]


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        return {
            "ca_authority_map": ca_authority_map,
            "ca_certificate_model": ca_certificate_model,
            "ca_certificate_models": ca_certificate_models,
        }
