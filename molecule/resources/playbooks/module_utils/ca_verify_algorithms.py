"""Exercise signature changes and CSR key usage through the issuance modules."""

from __future__ import annotations

from pathlib import Path

from ansible.module_utils.ca_certificate_engine import (
    ensure_certificate_artifacts,
    ensure_certificate_batch,
)
from ansible.module_utils.ca_verify_common import _load_pem_cert
from cryptography import x509


def _check_sha1_rejection(params: dict, certificate: dict) -> None:
    """Reject SHA-1 before creating material, including for EdDSA subject keys."""
    for key_type in ("ECDSA", "Ed25519"):
        rejected = dict(
            certificate, name=f"sha1-{key_type}", key_type=key_type, digest="SHA-1"
        )
        for batch in (False, True):
            try:
                if batch:
                    ensure_certificate_batch(dict(params, certificates=[rejected]))
                else:
                    ensure_certificate_artifacts(params, rejected)
            except ValueError as exc:
                if "SHA-1" not in str(exc):
                    raise ValueError(f"Unexpected digest rejection: {exc}") from exc
            else:
                raise ValueError("SHA-1 issuance was accepted")
            root = Path(params["base_dir"])
            if (root / "certs" / rejected["name"]).exists() or (
                root / "csr" / f"{rejected['name']}.csr"
            ).exists():
                raise ValueError("Rejected SHA-1 request created certificate material")


def _check_csr_key_usage(params: dict, certificate: dict, csr_path: str) -> None:
    """Use an EC CSR despite RSA config and preserve its signature on reissue."""
    external = dict(
        certificate,
        name="algorithm-external",
        key_type="RSA",
        csr_content=Path(csr_path).read_text(encoding="ascii"),
        digest="sha256",
    )
    original = ensure_certificate_artifacts(params, external)
    cert = _load_pem_cert(Path(original["cert_path"]))
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment:
        raise ValueError("EC CSR inherited RSA keyEncipherment from configuration")
    external["digest"] = "sha512"
    updated = ensure_certificate_artifacts(params, external)
    if not updated["cert_changed"] or updated["csr_changed"]:
        raise ValueError("External CSR digest change did not retain its original CSR")
    digest = _load_pem_cert(Path(updated["cert_path"])).signature_hash_algorithm
    if digest is None or digest.name != "sha512":
        raise ValueError("External CSR certificate did not receive the selected digest")
    if ensure_certificate_artifacts(params, external)["changed"]:
        raise ValueError("External CSR digest change was not idempotent")


def check_algorithm_changes(params: dict, certificate: dict) -> None:
    """Change only the digest in single and batch issuance without replacing keys."""
    certificate = dict(certificate, name="algorithm-check", digest="sha384")
    first = ensure_certificate_artifacts(params, certificate)
    key_content = Path(first["cert_path"]).with_suffix(".key").read_bytes()
    previous_serial = _load_pem_cert(Path(first["cert_path"])).serial_number
    for digest, batch in (("sha256", False), ("sha512", True)):
        certificate["digest"] = digest
        changed = (
            ensure_certificate_batch(dict(params, certificates=[certificate]))[
                "results"
            ][0]
            if batch
            else ensure_certificate_artifacts(params, certificate)
        )
        cert = _load_pem_cert(Path(changed["cert_path"]))
        csr = x509.load_pem_x509_csr(Path(changed["csr_path"]).read_bytes())
        if not changed["cert_changed"] or not changed["csr_changed"]:
            raise ValueError("Digest change did not reissue both certificate and CSR")
        cert_digest = cert.signature_hash_algorithm
        csr_digest = csr.signature_hash_algorithm
        if (
            cert_digest is None
            or csr_digest is None
            or cert_digest.name != digest
            or csr_digest.name != digest
        ):
            raise ValueError(
                "Certificate or CSR retained the previous signature digest"
            )
        if (
            cert.serial_number == previous_serial
            or Path(changed["cert_path"]).with_suffix(".key").read_bytes()
            != key_content
        ):
            raise ValueError(
                "Digest change retained the serial or replaced the private key"
            )
        if ensure_certificate_artifacts(params, certificate)["changed"]:
            raise ValueError("Changed digest was not idempotent")
        previous_serial = cert.serial_number
    _check_csr_key_usage(params, certificate, first["csr_path"])
    _check_sha1_rejection(params, certificate)
