"""Shared certificate dispatcher implementation for the CA role."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_inventory import (  # type: ignore[import-not-found,import-untyped]
    update_certificate_inventory,
    update_certificates_inventory,
)
from ansible.module_utils.ca_profiles import (  # type: ignore[import-not-found,import-untyped]
    CERTIFICATE_DEFAULT_FORMATS,
    CERTIFICATE_PROFILE_DEFAULTS,
    apply_certificate_profile,
)
from ansible.module_utils.ca_x509 import (  # type: ignore[import-not-found,import-untyped]
    certificate_params,
    ensure_x509,
    ensure_x509_many,
    normalize_formats,
)
from ansible.module_utils.ca_validation import (  # type: ignore[import-not-found,import-untyped]
    authority_map,
    require_value,
    safe_name,
    string_value,
)

SUPPORTED_FORMATS = {"pem", "der", "txt", "pfx", "p12", "fullchain", "fritzbox"}


def certificate_common_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the shared argument spec for certificate dispatcher modules."""
    return {
        "base_dir": {"type": "path", "required": True},
        "base_url": {"type": "str", "default": ""},
        "ca_name": {"type": "str", "default": ""},
        "certificate_types": {"type": "dict", "required": True},
        "authorities": {
            "type": "list",
            "elements": "dict",
            "required": True,
            "no_log": True,
        },
        "kerberos_realm": {"type": "str", "default": ""},
        "subject": {"type": "dict", "default": {}},
        "renewal": {"type": "dict", "default": {}},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "force": {"type": "bool", "default": False},
    }


def single_certificate_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the argument spec for the single-certificate module."""
    spec = certificate_common_argument_spec()
    spec["certificate"] = {"type": "dict", "required": True, "no_log": True}
    return spec


def batch_certificate_argument_spec() -> dict[str, dict[str, Any]]:
    """Return the argument spec for the certificate batch module."""
    spec = certificate_common_argument_spec()
    spec["certificates"] = {
        "type": "list",
        "elements": "dict",
        "required": True,
        "no_log": True,
    }
    return spec


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


def _resolve_certificate(
    params: dict[str, Any], certificate: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve a declarative role certificate into X.509 module parameters."""
    certificate = _as_dict(
        params.get("certificate") if certificate is None else certificate,
        "certificate",
    )
    name = safe_name(require_value(certificate, "name", "Certificate"), "Certificate")
    cert_type = string_value(
        require_value(certificate, "type", f"Certificate {name}")
    ).strip()
    common_name = string_value(
        require_value(certificate, "common_name", f"Certificate {name}")
    ).strip()

    if cert_type not in CERTIFICATE_PROFILE_DEFAULTS:
        raise ValueError(f"Certificate {name} uses unknown profile {cert_type}")

    certificate_types = _as_dict(params.get("certificate_types"), "certificate_types")
    if cert_type not in certificate_types:
        raise ValueError(f"Certificate {name} uses unknown type {cert_type}")

    profile = _as_dict(certificate_types[cert_type], f"Certificate type {cert_type}")
    issuer = string_value(
        require_value(profile, "issuer", f"Certificate type {cert_type}")
    )
    authorities = authority_map(params["authorities"])
    if issuer not in authorities:
        raise ValueError(f"Certificate type {cert_type} references unknown issuer {issuer}")

    issuer_authority = authorities[issuer]
    issuer_passphrase = string_value(
        require_value(issuer_authority, "key_passphrase", f"Authority {issuer}")
    )
    default_days = issuer_authority.get("default_days")
    days = certificate.get("days", default_days)
    if days is None or string_value(days) == "":
        raise ValueError(
            f"Certificate {name} needs days or issuer authority {issuer} "
            "needs default_days"
        )

    for field in _as_list(profile.get("required_fields")):
        require_value(certificate, string_value(field), f"Certificate {name}")

    formats = _profile_formats(certificate.get("formats"), cert_type)
    if set(formats).intersection({"pfx", "p12"}) and not string_value(
        certificate.get("pfx_passphrase") or certificate.get("passphrase")
    ):
        raise ValueError(
            f"Certificate {name} uses PFX/PKCS#12 output and requires pfx_passphrase"
        )

    subject = dict(_as_dict(params.get("subject"), "subject"))
    subject.update(_as_dict(certificate.get("subject"), f"Certificate {name} subject"))
    renewal = dict(_as_dict(params.get("renewal"), "renewal"))
    renewal.update(_as_dict(certificate.get("renewal"), f"Certificate {name} renewal"))

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
            "renewal": renewal,
        }
    )
    if cert_type == "mskdc":
        model["krb5_realm"] = string_value(
            certificate.get("krb5_realm") or params.get("kerberos_realm")
        ).strip().upper()

    module_params = {
        "base_dir": params["base_dir"],
        "base_url": params["base_url"],
        "ca_name": params["ca_name"],
        "certificate": model,
        "name": name,
        "issuer": issuer,
        "issuer_key_passphrase": issuer_passphrase,
        "common_name": common_name,
        "days": days,
        "renewal": renewal,
        "owner": params["owner"],
        "group": params["group"],
        "force": params["force"],
    }
    return model, module_params


def prepare_certificate_artifacts(
    params: dict[str, Any], certificate: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the resolved certificate model and X.509 helper parameters."""
    model, module_params = _resolve_certificate(params, certificate)
    x509_params = certificate_params(
        module_params,
        default_formats=CERTIFICATE_DEFAULT_FORMATS[model["type"]],
    )
    x509_params = apply_certificate_profile(x509_params, model["type"])
    return model, x509_params


def _ensure_prepared_certificate_artifacts(
    model: dict[str, Any], x509_params: dict[str, Any]
) -> dict[str, Any]:
    """Ensure artifacts for an already resolved certificate model."""
    result = ensure_x509(
        x509_params,
        signed=True,
        manage_directory=True,
        manage_chain=True,
    )
    result["name"] = model["name"]
    result["profile"] = model["type"]
    result["formats"] = [str(item).lower() for item in model["formats"]]
    return result


def _finalize_prepared_certificate_result(
    model: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Add dispatcher metadata to a prepared X.509 result."""
    result["name"] = model["name"]
    result["profile"] = model["type"]
    result["formats"] = [str(item).lower() for item in model["formats"]]
    return result


def ensure_certificate_artifacts(
    params: dict[str, Any], certificate: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Ensure one managed certificate and update its inventory state."""
    model, x509_params = prepare_certificate_artifacts(params, certificate)
    result = _ensure_prepared_certificate_artifacts(model, x509_params)
    inventory_changed = update_certificate_inventory(x509_params, model, result)
    result["inventory_changed"] = inventory_changed
    result["changed"] = result["changed"] or inventory_changed
    return result


def ensure_certificate_batch(params: dict[str, Any]) -> dict[str, Any]:
    """Ensure a list of managed certificates and compose inventory once."""
    prepared: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for index, certificate in enumerate(_as_list(params.get("certificates"))):
        model, x509_params = prepare_certificate_artifacts(
            params,
            _as_dict(certificate, f"certificates[{index}]"),
        )
        prepared.append((index, model, x509_params))

    issuer_order: list[str] = []
    issuer_groups: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
    for item in prepared:
        issuer = str(item[1]["issuer"])
        if issuer not in issuer_groups:
            issuer_groups[issuer] = []
            issuer_order.append(issuer)
        issuer_groups[issuer].append(item)

    raw_results = ensure_x509_many(
        [x509_params for _, _, x509_params in prepared],
        signed=True,
        manage_directory=True,
        manage_chain=True,
    )
    results: list[dict[str, Any]] = [{} for _ in prepared]
    inventory_records: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    changed = False
    for (index, model, x509_params), raw_result in zip(prepared, raw_results):
        result = _finalize_prepared_certificate_result(model, raw_result)
        result["inventory_changed"] = False
        results[index] = result
        inventory_records.append((x509_params, model, result))
        changed = changed or bool(result["changed"])

    inventory_changed = update_certificates_inventory(inventory_records)
    if inventory_changed:
        changed = True

    return {
        "changed": changed,
        "inventory_changed": inventory_changed,
        "count": len(results),
        "issuer_groups": {issuer: len(issuer_groups[issuer]) for issuer in issuer_order},
        "results": results,
    }
