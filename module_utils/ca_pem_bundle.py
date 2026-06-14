"""Shared PEM bundle helpers for CA role modules."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_lock,
    read_file,
    write_file,
)

SOURCE_NAMES = {
    "private_key": "{name}.key",
    "certificate": "{name}.pem",
    "chain": "{name}-chain.pem",
}


def pem_bundle_argument_spec(*, default_mode: str) -> dict[str, dict[str, Any]]:
    """Return the common argument spec for PEM bundle modules."""
    return {
        "base_dir": {"type": "path", "required": True},
        "certificate": {"type": "dict", "no_log": True},
        "name": {"type": "str", "required": True},
        "output_dir": {"type": "path"},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "mode": {"type": "str", "default": default_mode},
        "force": {"type": "bool", "default": False},
    }


def certificate_output_dir(
    *,
    base_dir: str,
    name: str,
    output_dir: str | None,
) -> str:
    """Return the certificate output directory for a bundle."""
    return (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")


def pem_bundle_params(params: dict[str, Any]) -> dict[str, Any]:
    """Merge optional certificate dictionary values into module params."""
    certificate = dict(params.get("certificate") or {})
    result = dict(params)
    if result.get("output_dir") is None and certificate.get("output_dir") is not None:
        result["output_dir"] = certificate["output_dir"]
    return result


def pem_bundle_paths(
    *,
    base_dir: str,
    name: str,
    output_dir: str | None,
    suffix: str,
    order: list[str],
) -> tuple[str, list[str]]:
    """Return the output bundle path and ordered input paths."""
    directory = certificate_output_dir(
        base_dir=base_dir,
        name=name,
        output_dir=output_dir,
    )
    sources = {
        key: f"{directory}/{template.format(name=name)}"
        for key, template in SOURCE_NAMES.items()
    }
    unknown = sorted(set(order).difference(sources))
    if unknown:
        raise ValueError(f"Unsupported PEM bundle source names: {', '.join(unknown)}")
    return (
        f"{directory}/{name}-{suffix}.pem",
        [sources[item] for item in order],
    )


def pem_bundle_content(sources: list[str]) -> bytes:
    """Read and concatenate source files with single trailing newlines."""
    return b"".join(read_file(source).rstrip() + b"\n" for source in sources)


def ensure_pem_bundle(
    params: dict[str, Any],
    *,
    suffix: str,
    order: list[str],
) -> dict[str, Any]:
    """Ensure a PEM bundle exists with the requested source order."""
    model = pem_bundle_params(params)
    path, sources = pem_bundle_paths(
        base_dir=model["base_dir"],
        name=model["name"],
        output_dir=model["output_dir"],
        suffix=suffix,
        order=order,
    )
    with file_lock(ca_lock_path(model["base_dir"], "certificate", model["name"])):
        changed = write_file(
            path,
            pem_bundle_content(sources),
            model["owner"],
            model["group"],
            model["mode"],
            force=model["force"],
        )
    return {"changed": changed, "path": path}
