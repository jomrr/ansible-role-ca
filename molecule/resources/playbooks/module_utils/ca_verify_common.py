"""Shared data and X.509 helpers for CA Molecule verification."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

CERTIFICATE_DEFAULT_FORMATS = {
    "tls_server": ["pem", "der", "txt"],
    "tls_client": ["pem", "der", "txt"],
    "eap_tls_client": ["pem", "der", "txt"],
    "mskdc": ["pem", "der", "txt"],
    "identity": ["pem", "der", "txt", "pfx"],
    "identity_full": ["pem", "der", "txt", "pfx"],
    "fritzbox": ["pem", "der", "txt", "fritzbox"],
}
AUTHORITY_FORMATS = ("pem", "der", "txt")
CHAIN_FORMATS = ("pem", "der", "txt")
CRL_FORMATS = ("der", "pem")
REASON_FLAG_NAMES = {
    "aa_compromise",
    "affiliation_changed",
    "ca_compromise",
    "certificate_hold",
    "cessation_of_operation",
    "key_compromise",
    "privilege_withdrawn",
    "remove_from_crl",
    "superseded",
    "unspecified",
}


def _read(path: Path) -> bytes:
    """Read one file as bytes."""
    return path.read_bytes()


def _load_pem_cert(path: Path) -> x509.Certificate:
    """Load one PEM certificate."""
    return x509.load_pem_x509_certificate(_read(path))


def _load_pem_certs(path: Path) -> list[x509.Certificate]:
    """Load concatenated PEM certificates."""
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        _read(path),
        re.DOTALL,
    )
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def _public_key_bytes(key) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a public key."""
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _authority_name(authority: dict[str, Any]) -> str:
    """Return a CA authority name."""
    return str(authority.get("name", "")).strip()


def _authority_file(authority: dict[str, Any]) -> str:
    """Return a CA authority file stem."""
    return f"{_authority_name(authority)}-ca"


def _authority_is_root(authority: dict[str, Any]) -> bool:
    """Return whether an authority is self-signed."""
    name = _authority_name(authority)
    return str(authority.get("parent", "")).strip() == name


def _certificate_name(certificate: dict[str, Any]) -> str:
    """Return a managed certificate name."""
    return str(certificate.get("name", "")).strip()


def _certificate_type(certificate: dict[str, Any]) -> str:
    """Return a managed certificate type."""
    return str(certificate.get("type", "")).strip()


def _certificate_formats(certificate: dict[str, Any]) -> list[str]:
    """Return the effective output formats for a managed certificate."""
    value = certificate.get("formats")
    if value is None:
        value = CERTIFICATE_DEFAULT_FORMATS.get(
            _certificate_type(certificate), ["pem", "der", "txt"]
        )
    if isinstance(value, str):
        raise ValueError(
            f"certificate {_certificate_name(certificate)} formats must be a list"
        )
    return [str(item).lower() for item in value]


def _certificate_output_dir(base_dir: Path, certificate: dict[str, Any]) -> Path:
    """Return the managed certificate output directory."""
    name = _certificate_name(certificate)
    return Path(str(certificate.get("output_dir") or base_dir / "certs" / name))


def _certificate_pem_path(base_dir: Path, certificate: dict[str, Any]) -> Path:
    """Return the primary PEM certificate path."""
    name = _certificate_name(certificate)
    return _certificate_output_dir(base_dir, certificate) / f"{name}.pem"


def _certificate_uses_csr(certificate: dict[str, Any]) -> bool:
    """Return whether a certificate is issued from an external CSR."""
    return bool(certificate.get("csr_content") or certificate.get("csr_path"))


def _certificate_csr(certificate: dict[str, Any]):
    """Load a certificate's configured CSR."""
    if certificate.get("csr_content"):
        return x509.load_pem_x509_csr(str(certificate["csr_content"]).encode())
    if certificate.get("csr_path"):
        return x509.load_pem_x509_csr(Path(str(certificate["csr_path"])).read_bytes())
    raise ValueError(f"{_certificate_name(certificate)} has no configured CSR")


def _certificate_expected_paths(
    base_dir: Path, certificate: dict[str, Any]
) -> list[Path]:
    """Return public managed certificate artifacts expected on disk."""
    name = _certificate_name(certificate)
    directory = _certificate_output_dir(base_dir, certificate)
    formats = set(_certificate_formats(certificate))
    paths = [directory / f"{name}.pem"]
    if "der" in formats:
        paths.append(directory / f"{name}.der")
    if "txt" in formats:
        paths.append(directory / f"{name}.txt")
    if "fullchain" in formats:
        paths.append(directory / f"{name}-fullchain.pem")
    if "fritzbox" in formats:
        paths.append(directory / f"{name}-fritzbox.pem")
    if "pfx" in formats:
        paths.append(directory / f"{name}.pfx")
    if "p12" in formats:
        paths.append(directory / f"{name}.p12")
    return paths


def _certificate_issuer(
    certificate: dict[str, Any], certificate_types: dict[str, Any]
) -> str:
    """Return the issuing authority for a managed certificate."""
    profile = certificate_types.get(_certificate_type(certificate), {})
    if not isinstance(profile, dict):
        return ""
    return str(profile.get("issuer", "")).strip()


def _authority_paths(base_dir: Path, authorities: list[dict[str, Any]]) -> list[Path]:
    """Return expected local CA authority artifacts."""
    paths = [base_dir / "inventory/ca-inventory.json"]
    for authority in authorities:
        name = _authority_name(authority)
        stem = _authority_file(authority)
        paths.extend(
            base_dir / "ca" / f"{stem}.{suffix}" for suffix in AUTHORITY_FORMATS
        )
        paths.extend(
            (
                base_dir / "crl" / f"{stem}.crl",
                base_dir / "crl" / f"{stem}.crl.pem",
            )
        )
        if not _authority_is_root(authority):
            paths.extend(
                base_dir / "chains" / f"{stem}-chain.{suffix}"
                for suffix in CHAIN_FORMATS
            )
        else:
            root_chain = base_dir / "chains" / f"{name}-ca-chain.pem"
            if root_chain.exists():
                raise ValueError(f"root CA chain should be omitted: {root_chain}")
    return paths


def _publish_paths(publish_root: Path, authorities: list[dict[str, Any]]) -> list[Path]:
    """Return expected published CA and CRL artifacts."""
    paths: list[Path] = []
    for authority in authorities:
        stem = _authority_file(authority)
        paths.extend(
            publish_root / "aia" / f"{stem}.{suffix}" for suffix in AUTHORITY_FORMATS
        )
        paths.extend(
            (
                publish_root / "crl" / f"{stem}.crl",
                publish_root / "crl" / f"{stem}.crl.pem",
            )
        )
        if not _authority_is_root(authority):
            paths.extend(
                publish_root / "aia" / f"{stem}-chain.{suffix}"
                for suffix in CHAIN_FORMATS
            )
    return paths


def _revocation_items(revocations: dict[str, Any]) -> list[dict[str, Any]]:
    """Return flattened revocation declarations."""
    items: list[dict[str, Any]] = []
    for authority, entries in revocations.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                item = dict(entry)
                item["authority"] = str(authority)
                items.append(item)
    return items


def _reason_flag(reason: str) -> x509.ReasonFlags | None:
    """Return the cryptography reason flag for a configured reason."""
    normalized = str(reason).strip()
    if normalized not in REASON_FLAG_NAMES:
        return None
    return getattr(x509.ReasonFlags, normalized)


def _cert_not_before(cert: x509.Certificate) -> datetime:
    """Return a timezone-aware not-before timestamp."""
    value = getattr(cert, "not_valid_before_utc", None)
    return (
        value
        if value is not None
        else cert.not_valid_before.replace(tzinfo=timezone.utc)
    )


def _cert_not_after(cert: x509.Certificate) -> datetime:
    """Return a timezone-aware not-after timestamp."""
    value = getattr(cert, "not_valid_after_utc", None)
    return (
        value
        if value is not None
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    )


def _assert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify a certificate signature with the issuer public key."""
    key = issuer.public_key()
    digest = cert.signature_hash_algorithm
    if isinstance(key, rsa.RSAPublicKey):
        if digest is None:
            raise ValueError("RSA certificate has no signature digest")
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            digest,
        )
        return
    if isinstance(key, ec.EllipticCurvePublicKey):
        if digest is None:
            raise ValueError("ECDSA certificate has no signature digest")
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(digest),
        )
        return
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(cert.signature, cert.tbs_certificate_bytes)
        return
    raise ValueError(f"Unsupported issuer public key type: {type(key).__name__}")


def _is_ca(cert: x509.Certificate) -> bool:
    """Return whether a certificate has CA basic constraints."""
    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return False
    return bool(basic_constraints.ca)


def _verify_chain(leaf: x509.Certificate, chain: list[x509.Certificate]) -> None:
    """Verify a leaf certificate against an ordered issuer chain."""
    if not chain:
        raise ValueError("chain must contain at least one issuer CA")
    now = datetime.now(timezone.utc)
    current = leaf
    for issuer in chain:
        if current.issuer != issuer.subject:
            raise ValueError(
                f"issuer mismatch: {current.subject.rfc4514_string()} is not issued by {issuer.subject.rfc4514_string()}"
            )
        if not (_cert_not_before(current) <= now <= _cert_not_after(current)):
            raise ValueError(
                f"certificate is outside its validity window: {current.subject.rfc4514_string()}"
            )
        _assert_signature(current, issuer)
        current = issuer
    root = chain[-1]
    if root.issuer != root.subject:
        raise ValueError("root certificate is not self-issued")
    if not _is_ca(root):
        raise ValueError("root certificate is not marked as CA")
    for issuer in chain[:-1]:
        if not _is_ca(issuer):
            raise ValueError(
                f"issuer certificate is not marked as CA: {issuer.subject.rfc4514_string()}"
            )
    _assert_signature(root, root)
