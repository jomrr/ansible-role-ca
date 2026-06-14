#!/usr/bin/python
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

from pathlib import Path

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
    ca_lock_path,
    file_locks,
    sanitize_error,
    write_file,
)
from ansible.module_utils.ca_serial import serial_hex  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_x509 import load_certificates  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except Exception as exc:  # pragma: no cover - handled at runtime by Ansible
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


def _chain_path(base_dir: str, name: str) -> str:
    """Return the derived CA chain output path."""
    return f"{base_dir.rstrip('/')}/chains/{name}-ca-chain.pem"


def _versioned_chain_path(base_dir: str, name: str, cert: x509.Certificate) -> str:
    """Return the generation-specific CA chain output path."""
    serial = serial_hex(cert.serial_number)
    return f"{base_dir.rstrip('/')}/chains/{name}-ca-chain-{serial}.pem"


def _authority_name(path: Path) -> str:
    """Return the authority short name from a CA certificate path."""
    return path.name[: -len("-ca.pem")]


def _load_authorities(base_dir: str) -> dict[str, x509.Certificate]:
    """Load all CA certificates below the managed CA directory."""
    authorities = {}
    for path in sorted((Path(base_dir.rstrip("/")) / "ca").glob("*-ca.pem")):
        certificates = load_certificates(str(path))
        if certificates:
            authorities[_authority_name(path)] = certificates[0]
    return authorities


def _authority_lock_paths(base_dir: str, name: str) -> list[str]:
    """Return locks for the target authority and every readable CA certificate."""
    ca_dir = Path(base_dir.rstrip("/")) / "ca"
    authority_names = {_authority_name(path) for path in ca_dir.glob("*-ca.pem")}
    authority_names.add(name)
    return [
        ca_lock_path(base_dir, "authority", authority_name)
        for authority_name in authority_names
    ]


def _authority_key_identifier(cert: x509.Certificate) -> bytes | None:
    """Return the certificate Authority Key Identifier when present."""
    try:
        value = cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return None
    return value.key_identifier


def _subject_key_identifier(cert: x509.Certificate) -> bytes | None:
    """Return the certificate Subject Key Identifier when present."""
    try:
        value = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return None
    return value.digest


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Return whether the certificate is self-issued."""
    return cert.subject == cert.issuer


def _issuer_matches(
    cert: x509.Certificate,
    candidate: x509.Certificate,
) -> bool:
    """Return whether candidate is the issuer certificate for cert."""
    if candidate.subject != cert.issuer:
        return False
    authority_key = _authority_key_identifier(cert)
    subject_key = _subject_key_identifier(candidate)
    return authority_key is None or subject_key is None or authority_key == subject_key


def _issuer_name(
    cert: x509.Certificate,
    authorities: dict[str, x509.Certificate],
    current_name: str,
) -> str:
    """Return the authority short name that issued cert."""
    matches = [
        name
        for name, candidate in authorities.items()
        if name != current_name and _issuer_matches(cert, candidate)
    ]
    if not matches:
        raise ValueError(
            f"issuer certificate for authority {current_name} was not found"
        )
    if len(matches) > 1:
        names = ", ".join(sorted(matches))
        raise ValueError(
            f"issuer certificate for authority {current_name} is ambiguous: {names}"
        )
    return matches[0]


def _ordered_chain(base_dir: str, name: str) -> list[x509.Certificate]:
    """Return the ordered certificate chain for one CA authority."""
    authorities = _load_authorities(base_dir)
    if name not in authorities:
        raise ValueError(f"authority certificate {name}-ca.pem was not found")

    chain = []
    current_name = name
    seen = set()
    while True:
        if current_name in seen:
            raise ValueError(f"authority chain for {name} contains a loop")
        seen.add(current_name)
        cert = authorities[current_name]
        chain.append(cert)
        if _is_self_signed(cert):
            return chain
        current_name = _issuer_name(cert, authorities, current_name)


def _remove_file(path: str) -> bool:
    """Remove a managed file if it exists."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return False
    return True


def _existing_chain(path: str) -> list[x509.Certificate]:
    """Load an existing chain or return an empty list when absent."""
    try:
        return load_certificates(path)
    except FileNotFoundError:
        return []


def _chain_content(certificates: list[x509.Certificate]) -> bytes:
    """Return normalized PEM content for an ordered certificate chain."""
    if not certificates:
        raise ValueError("certificate chain needs at least one certificate")
    return b"".join(
        cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
        for cert in certificates
    )


def run_module():
    """Run the Ansible module for CA chain files."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "owner": {"type": "str"},
            "group": {"type": "str"},
            "mode": {"type": "str", "default": "0644"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    params = module.params
    try:
        path = _chain_path(params["base_dir"], params["name"])
        with file_locks(
            [
                ca_lock_path(params["base_dir"], "authority", "__graph__"),
                *_authority_lock_paths(params["base_dir"], params["name"]),
            ]
        ):
            certificates = _ordered_chain(params["base_dir"], params["name"])
            if len(certificates) == 1 and _is_self_signed(certificates[0]):
                changed = _remove_file(path)
                state = "absent"
            else:
                content = _chain_content(certificates)
                previous = _existing_chain(path)
                changed = False
                if previous:
                    changed = write_file(
                        _versioned_chain_path(
                            params["base_dir"],
                            params["name"],
                            previous[0],
                        ),
                        _chain_content(previous),
                        params["owner"],
                        params["group"],
                        params["mode"],
                    )
                changed = write_file(
                    path,
                    content,
                    params["owner"],
                    params["group"],
                    params["mode"],
                    force=params["force"],
                ) or changed
                changed = write_file(
                    _versioned_chain_path(
                        params["base_dir"],
                        params["name"],
                        certificates[0],
                    ),
                    content,
                    params["owner"],
                    params["group"],
                    params["mode"],
                    force=params["force"],
                ) or changed
                state = "present"
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(changed=changed, path=path, state=state)


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
