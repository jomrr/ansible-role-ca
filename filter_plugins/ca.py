"""CA role filter plugins."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from ansible.errors import AnsibleFilterError  # type: ignore[import-not-found,import-untyped]

try:
    from ansible.module_utils.ca_validation import authority_map  # type: ignore[import-not-found,import-untyped]
except ModuleNotFoundError:
    spec = importlib.util.spec_from_file_location(
        "ca_validation",
        Path(__file__).resolve().parents[1] / "module_utils" / "ca_validation.py",
    )
    if spec is None or spec.loader is None:
        raise
    ca_validation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ca_validation)
    authority_map = ca_validation.authority_map


def ca_authority_map(authorities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return authorities keyed by name and validate the public list shape."""
    try:
        return authority_map(authorities)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc


def _base_dir(value: Any) -> str:
    """Return a normalized base directory string."""
    return str(value).rstrip("/")


def ca_publish_aia_artifacts(
    authorities: list[dict[str, Any]],
    base_dir: str,
) -> list[dict[str, str]]:
    """Return CA certificate and chain artifacts for AIA publication."""
    try:
        authority_by_name = authority_map(authorities)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc

    root = _base_dir(base_dir)
    artifacts = []
    for name, authority in authority_by_name.items():
        ca_stem = f"{name}-ca"
        for artifact_format in ("pem", "der", "txt"):
            artifacts.append(
                {
                    "area": "aia",
                    "src": f"{root}/ca/{ca_stem}.{artifact_format}",
                    "file": f"{ca_stem}.{artifact_format}",
                    "format": artifact_format,
                    "kind": "certificate",
                }
            )
        parent = str(authority.get("parent") or name)
        if parent == name:
            continue
        chain_stem = f"{name}-ca-chain"
        for artifact_format in ("pem", "der", "txt"):
            artifacts.append(
                {
                    "area": "aia",
                    "src": f"{root}/chains/{chain_stem}.{artifact_format}",
                    "file": f"{chain_stem}.{artifact_format}",
                    "format": artifact_format,
                    "kind": "chain",
                }
            )
    return artifacts


def ca_publish_cdp_artifacts(
    authorities: list[dict[str, Any]],
    base_dir: str,
) -> list[dict[str, str]]:
    """Return CRL artifacts for CDP publication."""
    try:
        authority_by_name = authority_map(authorities)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc

    root = _base_dir(base_dir)
    artifacts = []
    for name in authority_by_name:
        ca_stem = f"{name}-ca"
        artifacts.extend(
            [
                {
                    "area": "cdp",
                    "src": f"{root}/crl/{ca_stem}.crl.pem",
                    "file": f"{ca_stem}.crl.pem",
                    "format": "pem",
                    "kind": "crl",
                },
                {
                    "area": "cdp",
                    "src": f"{root}/crl/{ca_stem}.crl",
                    "file": f"{ca_stem}.crl",
                    "format": "der",
                    "kind": "crl",
                },
            ]
        )
    return artifacts


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Any]:
        """Return the filters exported by this plugin."""
        return {
            "ca_authority_map": ca_authority_map,
            "ca_publish_aia_artifacts": ca_publish_aia_artifacts,
            "ca_publish_cdp_artifacts": ca_publish_cdp_artifacts,
        }
