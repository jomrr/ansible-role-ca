#!/usr/bin/python
"""Verify the CA role Molecule scenario without shelling out to OpenSSL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ca_verify_certificates import (
    _check_chains,
    _check_crl,
    _check_default_digests,
    _check_fritzbox,
    _check_mskdc,
    _check_pkcs12,
    _check_public_keys,
)
from ansible.module_utils.ca_verify_common import (
    CRL_FORMATS,
    _authority_name,
    _authority_paths,
    _certificate_expected_paths,
    _certificate_issuer,
    _certificate_name,
    _certificate_type,
    _publish_paths,
    _revocation_items,
)


def _check_files(
    base_dir: Path,
    publish_root: Path,
    authorities: list[dict[str, Any]],
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> int:
    """Check expected and absent files."""
    try:
        expected = _authority_paths(base_dir, authorities)
    except Exception as exc:
        errors.append(str(exc))
        expected = []
    for certificate in certificates:
        expected.extend(_certificate_expected_paths(base_dir, certificate))
    published = _publish_paths(publish_root, authorities)

    for path in expected:
        if not path.exists():
            errors.append(f"missing file: {path}")
    for path in published:
        if not path.exists():
            errors.append(f"missing published file: {path}")
    return len(expected) + len(published)


def _check_publication_modes(
    publish_root: Path,
    authorities: list[dict[str, Any]],
    publish_mode: str,
    errors: list[str],
) -> None:
    """Check file mode overrides independently of publication directory modes."""
    for path in _publish_paths(publish_root, authorities):
        if path.stat().st_mode & 0o7777 != int(publish_mode, 8):
            errors.append(f"published file mode differs from {publish_mode}: {path}")
    for path in (publish_root, publish_root / "aia", publish_root / "crl"):
        if path.stat().st_mode & 0o7777 != 0o755:
            errors.append(f"publish directory mode differs from 0755: {path}")


def _find_named(items: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Return one inventory item by name."""
    for item in items:
        if item.get("name") == name:
            return item
    raise KeyError(name)


def _check_inventory(
    base_dir: Path,
    ca_name: str,
    authorities: list[dict[str, Any]],
    certificates: list[dict[str, Any]],
    certificate_types: dict[str, Any],
    revocations: dict[str, Any],
    renewal: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate the composed CA inventory."""
    inventory_path = base_dir / "inventory/ca-inventory.json"
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"could not read inventory {inventory_path}: {exc}")
        return

    revocation_by_name = {
        str(item.get("name")): item for item in _revocation_items(revocations)
    }
    expected_counts = {
        "authorities": len(authorities),
        "authority_certificates": len(authorities),
        "certificates": len(certificates),
        "issued_certificates": len(certificates),
        "crls": len(authorities) * len(CRL_FORMATS),
        "revocations": len(revocation_by_name),
    }
    if inventory.get("schema_version") != 1:
        errors.append("inventory schema_version is not 1")
    if inventory.get("ca_name") != ca_name:
        errors.append(f"inventory ca_name is not {ca_name}")
    for key, expected in expected_counts.items():
        actual = len(inventory.get(key, []))
        if actual != expected:
            errors.append(f"inventory {key} count is {actual}, expected {expected}")

    inventory_certificates = inventory.get("certificates", [])
    authority_map = {_authority_name(authority): authority for authority in authorities}

    for certificate in certificates:
        name = _certificate_name(certificate)
        try:
            record = _find_named(inventory_certificates, name)
        except KeyError:
            errors.append(f"missing inventory certificate: {name}")
            continue
        issuer = _certificate_issuer(certificate, certificate_types)
        if record.get("issuer") != issuer:
            errors.append(f"{name} issuer is {record.get('issuer')}, expected {issuer}")
        if record.get("type") != _certificate_type(certificate):
            errors.append(
                f"{name} type is {record.get('type')}, expected {_certificate_type(certificate)}"
            )
        if not record.get("current"):
            errors.append(f"{name} is not marked current")
        if not record.get("certificate", {}).get("fingerprints", {}).get("sha256"):
            errors.append(f"{name} SHA-256 fingerprint is missing")

        revocation = revocation_by_name.get(name)
        if revocation:
            if record.get("status", {}).get("state") != "revoked":
                errors.append(f"{name} is not marked revoked")
            reason = str(revocation.get("reason", ""))
            if (
                reason
                and record.get("status", {}).get("revocation", {}).get("reason")
                != reason
            ):
                errors.append(f"{name} revocation reason is not {reason}")
        elif record.get("status", {}).get("state") != "valid":
            errors.append(f"{name} is not marked valid")

        issuer_authority = authority_map.get(issuer, {})
        expected_days = int(
            certificate.get("days") or issuer_authority.get("default_days") or 0
        )
        warn_before = int(renewal.get("warn_before_days") or 0)
        if expected_days and warn_before >= expected_days:
            if record.get("renewal_status", {}).get("state") != "warning":
                errors.append(f"{name} renewal status is not warning")


def run_module() -> None:
    """Run the Molecule CA verifier module."""
    module = AnsibleModule(
        argument_spec={
            "ca_name": {"type": "str", "required": True},
            "base_dir": {"type": "path", "required": True},
            "publish_root": {"type": "path", "required": True},
            "publish_mode": {"type": "str", "default": "0644"},
            "authorities": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "no_log": True,
            },
            "certificates": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "no_log": True,
            },
            "certificate_types": {"type": "dict", "required": True},
            "revocations": {"type": "dict", "default": {}},
            "renewal": {"type": "dict", "default": {}},
        },
        supports_check_mode=True,
    )
    base_dir = Path(module.params["base_dir"])
    publish_root = Path(module.params["publish_root"])
    authorities = module.params["authorities"]
    certificates = module.params["certificates"]
    certificate_types = module.params["certificate_types"]
    revocations = module.params["revocations"]
    renewal = module.params["renewal"]
    errors: list[str] = []
    checked_files = _check_files(
        base_dir, publish_root, authorities, certificates, errors
    )
    checks = (
        lambda: _check_publication_modes(
            publish_root, authorities, module.params["publish_mode"], errors
        ),
        lambda: _check_inventory(
            base_dir,
            module.params["ca_name"],
            authorities,
            certificates,
            certificate_types,
            revocations,
            renewal,
            errors,
        ),
        lambda: _check_default_digests(base_dir, authorities, certificates, errors),
        lambda: _check_public_keys(base_dir, certificates, errors),
        lambda: _check_chains(base_dir, certificates, certificate_types, errors),
        lambda: _check_mskdc(base_dir, certificates, errors),
        lambda: _check_fritzbox(base_dir, certificates, errors),
        lambda: _check_pkcs12(base_dir, certificates, errors),
        lambda: _check_crl(base_dir, authorities, revocations, errors),
    )
    checked_chains = 0
    for check in checks:
        try:
            result = check()
        except Exception as exc:
            errors.append(str(exc))
            continue
        if isinstance(result, int):
            checked_chains = result

    if errors:
        module.fail_json(msg="CA Molecule verification failed", errors=errors)
    module.exit_json(
        changed=False,
        checked_files=checked_files,
        checked_chains=checked_chains,
    )


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
