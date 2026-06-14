#!/usr/bin/python
"""Dispatch managed CA role certificates to the built-in X.509 profiles."""

from __future__ import annotations

import re
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_profiles import (  # type: ignore[import-not-found,import-untyped]
    CERTIFICATE_DEFAULT_FORMATS,
    CERTIFICATE_PROFILE_DEFAULTS,
    apply_certificate_profile,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    CRYPTOGRAPHY_IMPORT_ERROR,
    certificate_params,
    ensure_x509,
    normalize_formats,
    sanitize_error,
)

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SUPPORTED_FORMATS = {"pem", "der", "txt", "pfx", "p12", "fullchain", "fritzbox"}


def _as_list(value: Any) -> list[Any]:
    """Return a list value or raise a module error."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise ValueError(f"Expected a list, got {type(value).__name__}")


def _as_dict(value: Any, context: str) -> dict[str, Any]:
    """Return a dictionary value or raise a contextual module error."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise ValueError(f"{context} must be a dictionary")


def _string(value: Any) -> str:
    """Normalize optional values to strings for validation."""
    if value is None:
        return ""
    return str(value)


def _required(value: dict[str, Any], key: str, context: str) -> Any:
    """Return a required dictionary value or raise a module error."""
    if key not in value or _string(value[key]) == "":
        raise ValueError(f"{context} requires {key}")
    return value[key]


def _authority_map(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    result = {}
    for authority in _as_list(authorities):
        if not isinstance(authority, dict):
            raise ValueError("Each ca_authorities item must be a dictionary")
        name = _string(_required(authority, "name", "Authority")).strip()
        if not SAFE_NAME_RE.match(name):
            raise ValueError(
                f"Authority {name} has an unsafe name; use only letters, digits, "
                "dots, underscores, and hyphens"
            )
        if name in result:
            raise ValueError(f"Duplicate authority name {name}")
        result[name] = authority

    for name, authority in result.items():
        parent = _string(_required(authority, "parent", f"Authority {name}")).strip()
        if parent not in result:
            raise ValueError(f"Authority {name} references unknown parent {parent}")
    return result


def _profile_formats(value: Any, profile: str) -> list[str]:
    """Resolve certificate output formats for a profile."""
    formats = (
        CERTIFICATE_DEFAULT_FORMATS[profile]
        if value is None
        else normalize_formats(value)
    )
    unsupported = sorted(set(formats).difference(SUPPORTED_FORMATS))
    if unsupported:
        raise ValueError(f"Unsupported certificate formats: {', '.join(unsupported)}")
    return formats


def _resolve_certificate(params: dict) -> tuple[dict, dict]:
    """Resolve a declarative role certificate into module parameters."""
    certificate = _as_dict(params.get("certificate"), "certificate")
    name = _string(_required(certificate, "name", "Certificate")).strip()
    cert_type = _string(_required(certificate, "type", f"Certificate {name}")).strip()
    common_name = _string(
        _required(certificate, "common_name", f"Certificate {name}")
    ).strip()

    if not SAFE_NAME_RE.match(name):
        raise ValueError(
            f"Certificate {name} has an unsafe name; use only letters, digits, "
            "dots, underscores, and hyphens"
        )
    if cert_type not in CERTIFICATE_PROFILE_DEFAULTS:
        raise ValueError(f"Certificate {name} uses unknown profile {cert_type}")

    certificate_types = _as_dict(params.get("certificate_types"), "certificate_types")
    if cert_type not in certificate_types:
        raise ValueError(f"Certificate {name} uses unknown type {cert_type}")

    profile = _as_dict(certificate_types[cert_type], f"Certificate type {cert_type}")
    issuer = _string(_required(profile, "issuer", f"Certificate type {cert_type}"))
    authorities = _authority_map(params["authorities"])
    if issuer not in authorities:
        raise ValueError(f"Certificate type {cert_type} references unknown issuer {issuer}")

    issuer_authority = authorities[issuer]
    issuer_passphrase = _string(
        _required(issuer_authority, "key_passphrase", f"Authority {issuer}")
    )
    default_days = issuer_authority.get("default_days")
    days = certificate.get("days", default_days)
    if days is None or _string(days) == "":
        raise ValueError(
            f"Certificate {name} needs days or issuer authority {issuer} "
            "needs default_days"
        )

    for field in _as_list(profile.get("required_fields")):
        _required(certificate, _string(field), f"Certificate {name}")

    formats = _profile_formats(certificate.get("formats"), cert_type)
    if set(formats).intersection({"pfx", "p12"}) and not _string(
        certificate.get("pfx_passphrase") or certificate.get("passphrase")
    ):
        raise ValueError(
            f"Certificate {name} uses PFX/PKCS#12 output and requires pfx_passphrase"
        )

    subject = dict(_as_dict(params.get("subject"), "subject"))
    subject.update(_as_dict(certificate.get("subject"), f"Certificate {name} subject"))

    model = dict(certificate)
    model.update(
        {
            "name": name,
            "type": cert_type,
            "common_name": common_name,
            "issuer": issuer,
            "days": days,
            "formats": formats,
            "subject": subject,
        }
    )
    if cert_type == "mskdc":
        model["krb5_realm"] = _string(
            certificate.get("krb5_realm") or params.get("kerberos_realm")
        ).strip().upper()

    module_params = {
        "base_dir": params["base_dir"],
        "base_url": params["base_url"],
        "certificate": model,
        "name": name,
        "issuer": issuer,
        "issuer_key_passphrase": issuer_passphrase,
        "common_name": common_name,
        "days": days,
        "owner": params["owner"],
        "group": params["group"],
        "force": params["force"],
    }
    return model, module_params


def run_module():
    """Run the Ansible module for dispatched certificate profiles."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "base_url": {"type": "str", "default": ""},
            "certificate": {"type": "dict", "required": True, "no_log": True},
            "certificate_types": {"type": "dict", "required": True},
            "authorities": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "no_log": True,
            },
            "kerberos_realm": {"type": "str", "default": ""},
            "subject": {"type": "dict", "default": {}},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    try:
        model, module_params = _resolve_certificate(module.params)
        params = certificate_params(
            module_params,
            default_formats=CERTIFICATE_DEFAULT_FORMATS[model["type"]],
        )
        params = apply_certificate_profile(params, model["type"])
        result = ensure_x509(
            params, signed=True, manage_directory=True, manage_chain=True
        )
        formats = [str(item).lower() for item in model["formats"]]
        result["formats"] = formats
        result["pkcs12_formats"] = [
            item for item in formats if item in {"pfx", "p12"}
        ]
        result["fullchain_bundle"] = "fullchain" in formats
        result["fritzbox_bundle"] = "fritzbox" in formats
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(name=model["name"], profile=model["type"], **result)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
