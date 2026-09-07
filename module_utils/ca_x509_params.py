"""Ca x509 params helpers."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import ca_lock_path


def _external_csr_configured(params: dict) -> bool:
    """Return whether certificate issuance should use an externally supplied CSR."""
    return bool(params.get("csr_source_path") or params.get("csr_content"))


def _base_url(params: dict, name: str, key: str) -> str:
    """Derive an AIA or CDP URL from explicit or base URL parameters."""
    value = str(params.get(key) or "").rstrip("/")
    if not value:
        base_url = str(params.get("base_url") or "").rstrip("/")
        if base_url:
            suffix = "aia" if key == "aia_base_url" else "crl"
            value = f"{base_url}/{suffix}"
    return f"{value}/{name}" if value else ""


def _with_derived_paths(
    params: dict,
    *,
    authority: bool,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
) -> dict:
    """Derive managed file paths and publication URLs from base parameters."""
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    formats = normalize_formats(result.get("formats"))
    result["formats"] = formats
    result["base_dir"] = base_dir
    result["authority"] = authority

    if authority:
        ca_file = f"{name}-ca"
        result["lock_path"] = ca_lock_path(base_dir, "authority", name)
        result["key_path"] = f"{base_dir}/private/{ca_file}.key"
        result["csr_path"] = f"{base_dir}/csr/{ca_file}.csr"
        result["cert_path"] = f"{base_dir}/ca/{ca_file}.pem"
        result["der_path"] = f"{base_dir}/ca/{ca_file}.der" if "der" in formats else ""
        result["txt_path"] = f"{base_dir}/ca/{ca_file}.txt" if "txt" in formats else ""
        if signed:
            parent = str(result["parent"])
            parent_file = f"{parent}-ca"
            result["signer_lock_path"] = ca_lock_path(base_dir, "authority", parent)
            result["signer_cert_path"] = f"{base_dir}/ca/{parent_file}.pem"
            result["signer_key_path"] = f"{base_dir}/private/{parent_file}.key"
        authority_file = f"{result['parent'] if signed else name}-ca"
        result["aia_url"] = _base_url(result, f"{authority_file}.der", "aia_base_url")
        result["cdp_url"] = _base_url(result, f"{authority_file}.crl", "cdp_base_url")
        result["directory_path"] = None
        result["chain_src_path"] = ""
        result["chain_path"] = ""
        return result

    output_dir = str(result.get("output_dir") or f"{base_dir}/certs/{name}").rstrip("/")
    issuer = str(result["issuer"])
    issuer_file = f"{issuer}-ca"
    external_csr = _external_csr_configured(result)
    result["lock_path"] = ca_lock_path(base_dir, "certificate", name)
    result["output_dir"] = output_dir
    result["key_path"] = "" if external_csr else f"{output_dir}/{name}.key"
    result["csr_path"] = f"{base_dir}/csr/{name}.csr"
    result["cert_path"] = f"{output_dir}/{name}.pem"
    result["der_path"] = f"{output_dir}/{name}.der" if "der" in formats else ""
    result["txt_path"] = f"{output_dir}/{name}.txt" if "txt" in formats else ""
    result["fullchain_path"] = (
        f"{output_dir}/{name}-fullchain.pem" if "fullchain" in formats else ""
    )
    result["fritzbox_bundle_path"] = (
        f"{output_dir}/{name}-fritzbox.pem" if "fritzbox" in formats else ""
    )
    result["pkcs12_paths"] = {
        export_format: f"{output_dir}/{name}.{export_format}"
        for export_format in ("pfx", "p12")
        if export_format in formats
    }
    result["directory_path"] = output_dir if manage_directory else None
    if signed:
        result["signer_lock_path"] = ca_lock_path(base_dir, "authority", issuer)
        result["signer_cert_path"] = f"{base_dir}/ca/{issuer_file}.pem"
        result["signer_key_path"] = f"{base_dir}/private/{issuer_file}.key"
    result["chain_src_path"] = (
        f"{base_dir}/chains/{issuer_file}-chain.pem" if manage_chain else ""
    )
    result["chain_path"] = f"{output_dir}/{name}-chain.pem" if manage_chain else ""
    result["aia_url"] = _base_url(result, f"{issuer_file}.der", "aia_base_url")
    result["cdp_url"] = _base_url(result, f"{issuer_file}.crl", "cdp_base_url")
    return result


def ca_authority_argument_spec(
    *,
    defaults: dict | None = None,
):
    """Build the argument spec for CA authority modules."""
    spec: dict[str, dict[str, Any]] = {
        "base_dir": {"type": "path", "required": True},
        "base_url": {"type": "str", "default": ""},
        "ca_name": {"type": "str", "default": ""},
        "name": {"type": "str", "required": True},
        "parent": {"type": "str", "default": ""},
        "formats": {
            "type": "list",
            "elements": "str",
            "default": ["pem", "der", "txt"],
        },
        "key_type": {"type": "str", "default": "RSA"},
        "key_size": {"type": "int", "default": 4096},
        "subject_ordered": {"type": "list", "elements": "dict", "default": []},
        "common_name": {"type": "str"},
        "email": {"type": "str"},
        "subject": {"type": "dict", "default": {}},
        "basic_constraints": {
            "type": "list",
            "elements": "str",
        },
        "key_usage": {"type": "list", "elements": "str"},
        "key_usage_critical": {"type": "bool", "default": True},
        "extended_key_usage": {"type": "list", "elements": "str", "default": []},
        "extended_key_usage_critical": {"type": "bool", "default": False},
        "san": {"type": "list", "elements": "str", "default": []},
        "san_critical": {"type": "bool", "default": False},
        "aia_base_url": {"type": "str", "default": ""},
        "cdp_base_url": {"type": "str", "default": ""},
        "raw_extensions": {"type": "list", "elements": "dict", "default": []},
        "pkinit": {"type": "dict", "default": {}},
        "days": {"type": "int", "required": True},
        "renewal": {"type": "dict", "default": {}},
        "digest": {"type": "str", "default": "sha384"},
        "include_identifiers": {"type": "bool", "default": True},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "key_mode": {"type": "str", "default": "0600"},
        "public_mode": {"type": "str", "default": "0644"},
        "force": {"type": "bool", "default": False},
        "key_passphrase": {
            "type": "str",
            "required": True,
            "no_log": True,
        },
        "parent_key_passphrase": {
            "type": "str",
            "no_log": True,
        },
    }
    for key, value in (defaults or {}).items():
        if key in spec:
            spec[key]["default"] = value
    return spec


def normalize_formats(formats: Any) -> list[str]:
    """Return normalized certificate output format names."""
    if isinstance(formats, str):
        raise ValueError("formats must be a list")
    return [str(item).lower() for item in (formats or [])]


def certificate_params(
    params: dict, *, default_formats: list[str] | None = None
) -> dict:
    """Merge certificate dictionaries with explicit module parameters."""
    result: dict[str, Any] = {
        "base_url": "",
        "output_dir": None,
        "csr_content": None,
        "csr_source_path": None,
        "key_type": "RSA",
        "key_size": 4096,
        "key_passphrase": None,
        "subject_ordered": [],
        "email": None,
        "subject": {},
        "basic_constraints": ["CA:FALSE"],
        "key_usage": [],
        "key_usage_critical": True,
        "extended_key_usage": [],
        "extended_key_usage_critical": False,
        "san": [],
        "san_critical": False,
        "aia_base_url": "",
        "cdp_base_url": "",
        "raw_extensions": [],
        "pkinit": {},
        "renewal": {},
        "include_identifiers": True,
        "key_mode": "0600",
        "public_mode": "0644",
        "directory_mode": "0755",
    }
    certificate = dict(params.get("certificate") or {})
    certificate_formats = certificate.pop("formats", None)
    module_formats = params.get("formats")
    module_params = {
        key: value
        for key, value in params.items()
        if key not in ("certificate", "formats") and value is not None
    }
    result.update(certificate)
    result.update(module_params)
    if result.get("csr_path"):
        result["csr_source_path"] = result.pop("csr_path")
    formats = module_formats if module_formats is not None else certificate_formats
    if formats is None:
        formats = (
            default_formats if default_formats is not None else ["pem", "der", "txt"]
        )
    result["formats"] = normalize_formats(formats)
    result["signer_key_passphrase"] = result.pop("issuer_key_passphrase")
    return result
