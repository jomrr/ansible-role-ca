"""CA role filter plugins."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from ansible.errors import AnsibleFilterError  # type: ignore[import-not-found,import-untyped]


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _as_list(value: Any) -> list[Any]:
    """Return a list value or raise a filter error."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise AnsibleFilterError(f"Expected a list, got {type(value).__name__}")


def _as_dict(value: Any, context: str) -> dict[str, Any]:
    """Return a dictionary value or raise a contextual filter error."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise AnsibleFilterError(f"{context} must be a dictionary")


def _string(value: Any) -> str:
    """Normalize optional values to strings for validation."""
    if value is None:
        return ""
    return str(value)


def _required(value: dict[str, Any], key: str, context: str) -> Any:
    """Return a required dictionary value or raise a filter error."""
    if key not in value or _string(value[key]) == "":
        raise AnsibleFilterError(f"{context} requires {key}")
    return value[key]


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
    issuer_authority = authority_map[issuer]
    default_days = issuer_authority.get("default_days")
    if "days" not in certificate and default_days is None:
        raise AnsibleFilterError(
            f"Certificate {name} needs days or issuer authority {issuer} needs default_days"
        )

    for field in _as_list(profile.get("required_fields")):
        _required(certificate, _string(field), f"Certificate {name}")

    formats = None
    if "formats" in certificate:
        formats = [str(item).lower() for item in _as_list(certificate.get("formats"))]
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
    krb5_realm = (
        _string(certificate.get("krb5_realm") or kerberos_realm).strip().upper()
    )

    subject_values = deepcopy(_as_dict(subject, "ca_subject"))
    subject_values.update(
        _as_dict(certificate.get("subject"), f"Certificate {name} subject")
    )

    model = deepcopy(certificate)
    model.update(
        {
            "name": name,
            "type": cert_type,
            "common_name": common_name,
            "issuer": issuer,
            "days": certificate.get("days", default_days),
            "san": san,
            "key_passphrase": _string(certificate.get("key_passphrase")),
            "pfx_passphrase": _string(certificate.get("pfx_passphrase")),
            "krb5_realm": krb5_realm,
            "subject": subject_values,
        }
    )

    if formats is not None:
        model["formats"] = formats

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
    kerberos_realm: str,
    subject: dict[str, Any],
) -> list[dict[str, Any]]:
    """Resolve all declarative certificates into task-ready models."""

    return [
        ca_certificate_model(
            certificate,
            certificate_types,
            authorities,
            kerberos_realm,
            subject,
        )
        for certificate in _as_list(certificates)
    ]


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "ca_authority_map": ca_authority_map,
            "ca_certificate_models": ca_certificate_models,
        }
