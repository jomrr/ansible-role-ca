#!/usr/bin/python
"""Verify the CA role Molecule scenario without shelling out to OpenSSL."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import (
        CRLEntryExtensionOID,
        ExtendedKeyUsageOID,
        ObjectIdentifier,
    )
except Exception as import_error:  # pragma: no cover - exercised on target host
    CRYPTOGRAPHY_IMPORT_ERROR = import_error
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


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
        value = CERTIFICATE_DEFAULT_FORMATS.get(_certificate_type(certificate), ["pem", "der", "txt"])
    if isinstance(value, str):
        raise ValueError(f"certificate {_certificate_name(certificate)} formats must be a list")
    return [str(item).lower() for item in value]


def _certificate_output_dir(base_dir: Path, certificate: dict[str, Any]) -> Path:
    """Return the managed certificate output directory."""
    name = _certificate_name(certificate)
    return Path(str(certificate.get("output_dir") or base_dir / "certs" / name))


def _certificate_pem_path(base_dir: Path, certificate: dict[str, Any]) -> Path:
    """Return the primary PEM certificate path."""
    name = _certificate_name(certificate)
    return _certificate_output_dir(base_dir, certificate) / f"{name}.pem"


def _certificate_expected_paths(base_dir: Path, certificate: dict[str, Any]) -> list[Path]:
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


def _certificate_issuer(certificate: dict[str, Any], certificate_types: dict[str, Any]) -> str:
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
        paths.extend(base_dir / "ca" / f"{stem}.{suffix}" for suffix in AUTHORITY_FORMATS)
        paths.extend(
            (
                base_dir / "crl" / f"{stem}.crl",
                base_dir / "crl" / f"{stem}.crl.pem",
            )
        )
        if not _authority_is_root(authority):
            paths.extend(base_dir / "chains" / f"{stem}-chain.{suffix}" for suffix in CHAIN_FORMATS)
        else:
            root_chain = base_dir / "chains" / f"{name}-ca-chain.pem"
            if root_chain.exists():
                raise ValueError(f"root CA chain should be omitted: {root_chain}")
    return paths


def _publish_paths(publish_root: Path, authorities: list[dict[str, Any]]) -> list[Path]:
    """Return expected published CA and CRL artifacts."""
    paths = [
        publish_root / "aia" / ".ca-publish-manifest.json",
        publish_root / "crl" / ".ca-publish-manifest.json",
    ]
    for authority in authorities:
        stem = _authority_file(authority)
        paths.extend(publish_root / "aia" / f"{stem}.{suffix}" for suffix in AUTHORITY_FORMATS)
        paths.extend(
            (
                publish_root / "crl" / f"{stem}.crl",
                publish_root / "crl" / f"{stem}.crl.pem",
            )
        )
        if not _authority_is_root(authority):
            paths.extend(publish_root / "aia" / f"{stem}-chain.{suffix}" for suffix in CHAIN_FORMATS)
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
    return value if value is not None else cert.not_valid_before.replace(tzinfo=timezone.utc)


def _cert_not_after(cert: x509.Certificate) -> datetime:
    """Return a timezone-aware not-after timestamp."""
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else cert.not_valid_after.replace(tzinfo=timezone.utc)


def _assert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify a certificate signature with the issuer public key."""
    key = issuer.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(cert.signature, cert.tbs_certificate_bytes)
        return
    raise ValueError(f"Unsupported issuer public key type: {type(key).__name__}")


def _is_ca(cert: x509.Certificate) -> bool:
    """Return whether a certificate has CA basic constraints."""
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
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
            raise ValueError(f"certificate is outside its validity window: {current.subject.rfc4514_string()}")
        _assert_signature(current, issuer)
        current = issuer
    root = chain[-1]
    if root.issuer != root.subject:
        raise ValueError("root certificate is not self-issued")
    if not _is_ca(root):
        raise ValueError("root certificate is not marked as CA")
    for issuer in chain[:-1]:
        if not _is_ca(issuer):
            raise ValueError(f"issuer certificate is not marked as CA: {issuer.subject.rfc4514_string()}")
    _assert_signature(root, root)


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
    authority_records = inventory.get("authorities", [])
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
            errors.append(f"{name} type is {record.get('type')}, expected {_certificate_type(certificate)}")
        if not record.get("current"):
            errors.append(f"{name} is not marked current")
        if not record.get("certificate", {}).get("fingerprints", {}).get("sha256"):
            errors.append(f"{name} SHA-256 fingerprint is missing")

        revocation = revocation_by_name.get(name)
        if revocation:
            if record.get("status", {}).get("state") != "revoked":
                errors.append(f"{name} is not marked revoked")
            reason = str(revocation.get("reason", ""))
            if reason and record.get("status", {}).get("revocation", {}).get("reason") != reason:
                errors.append(f"{name} revocation reason is not {reason}")
        elif record.get("status", {}).get("state") != "valid":
            errors.append(f"{name} is not marked valid")

        issuer_authority = authority_map.get(issuer, {})
        expected_days = int(certificate.get("days") or issuer_authority.get("default_days") or 0)
        warn_before = int(renewal.get("warn_before_days") or 0)
        if expected_days and warn_before >= expected_days:
            if record.get("renewal_status", {}).get("state") != "warning":
                errors.append(f"{name} renewal status is not warning")

    for authority in authorities:
        if _authority_is_root(authority):
            continue
        name = _authority_name(authority)
        try:
            record = _find_named(authority_records, name)
        except KeyError:
            errors.append(f"missing inventory authority: {name}")
            continue
        serial = record.get("certificate", {}).get("serial_number_hex")
        versioned_chain = base_dir / f"chains/{name}-ca-chain-{serial}.pem"
        if not serial or not versioned_chain.exists():
            errors.append(f"missing versioned {name} CA chain: {versioned_chain}")


def _check_default_digests(
    base_dir: Path,
    authorities: list[dict[str, Any]],
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate default certificate signature digests."""
    paths = [
        base_dir / "ca" / f"{_authority_file(authority)}.pem"
        for authority in authorities
    ]
    paths.extend(_certificate_pem_path(base_dir, certificate) for certificate in certificates)
    for path in paths:
        cert = _load_pem_cert(path)
        digest = cert.signature_hash_algorithm
        if digest is None or digest.name != "sha384":
            errors.append(f"{path} signature digest is not sha384")


def _check_public_keys(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate generated certificate public key algorithms."""
    for certificate in certificates:
        name = _certificate_name(certificate)
        key_type = str(certificate.get("key_type") or "RSA").upper().replace("-", "")
        key_size = certificate.get("key_size")
        key = _load_pem_cert(_certificate_pem_path(base_dir, certificate)).public_key()
        if key_type == "RSA":
            expected_size = int(key_size or 4096)
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size != expected_size:
                errors.append(f"{name} public key is not RSA {expected_size}")
        elif key_type in {"ECDSA", "EC", "ECC"}:
            expected_size = int(key_size or 256)
            expected_curve = "secp384r1" if expected_size == 384 else "secp256r1"
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != expected_curve:
                errors.append(f"{name} public key is not ECDSA {expected_size}")
        elif key_type in {"ECDSAP256", "ECP256", "P256", "PRIME256V1", "SECP256R1"}:
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
                errors.append(f"{name} public key is not ECDSA P-256")
        elif key_type in {"ECDSAP384", "ECP384", "P384", "SECP384R1"}:
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
                errors.append(f"{name} public key is not ECDSA P-384")
        elif key_type in {"ED25519", "EDDSA25519"}:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                errors.append(f"{name} public key is not Ed25519")
        elif key_type in {"ED448", "EDDSA448"}:
            if not isinstance(key, ed448.Ed448PublicKey):
                errors.append(f"{name} public key is not Ed448")
        else:
            errors.append(f"{name} uses unsupported verify key_type {key_type}")


def _issuer_chain(base_dir: Path, issuer: str) -> list[x509.Certificate]:
    """Return the issuer chain for a certificate."""
    chain_path = base_dir / "chains" / f"{issuer}-ca-chain.pem"
    if chain_path.exists():
        return _load_pem_certs(chain_path)
    return [_load_pem_cert(base_dir / "ca" / f"{issuer}-ca.pem")]


def _check_chains(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    certificate_types: dict[str, Any],
    errors: list[str],
) -> int:
    """Validate issued certificate chains."""
    checked = 0
    for certificate in certificates:
        name = _certificate_name(certificate)
        issuer = _certificate_issuer(certificate, certificate_types)
        if not issuer:
            errors.append(f"{name} has no issuer in certificate_types")
            continue
        try:
            _verify_chain(_load_pem_cert(_certificate_pem_path(base_dir, certificate)), _issuer_chain(base_dir, issuer))
            checked += 1
        except Exception as exc:
            errors.append(f"chain validation failed for {name}: {exc}")
    return checked


def _check_mskdc(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate MSKDC certificate extensions."""
    for certificate in certificates:
        if _certificate_type(certificate) != "mskdc":
            continue
        name = _certificate_name(certificate)
        cert = _load_pem_cert(_certificate_pem_path(base_dir, certificate))
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            errors.append(f"{name} MSKDC certificate has no EKU extension")
            continue
        required_ekus = {
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ObjectIdentifier("1.3.6.1.5.2.3.5"),
        }
        missing_ekus = required_ekus.difference(set(eku))
        if missing_ekus:
            errors.append(f"{name} MSKDC certificate is missing EKUs: {sorted(str(oid) for oid in missing_ekus)}")

        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            errors.append(f"{name} MSKDC certificate has no SAN extension")
        else:
            pkinit_oid = ObjectIdentifier("1.3.6.1.5.2.2")
            if not any(isinstance(entry, x509.OtherName) and entry.type_id == pkinit_oid for entry in san):
                errors.append(f"{name} MSKDC certificate has no PKINIT KRB5PrincipalName SAN")

        for oid_text in ("1.3.6.1.4.1.311.20.2", "1.3.6.1.4.1.311.25.1"):
            try:
                cert.extensions.get_extension_for_oid(ObjectIdentifier(oid_text))
            except x509.ExtensionNotFound:
                errors.append(f"{name} MSKDC certificate is missing extension OID {oid_text}")


def _check_fritzbox(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate FritzBox certificate and bundle behavior."""
    for certificate in certificates:
        if _certificate_type(certificate) != "fritzbox":
            continue
        name = _certificate_name(certificate)
        directory = _certificate_output_dir(base_dir, certificate)
        if "fritzbox" in set(_certificate_formats(certificate)):
            bundle = (directory / f"{name}-fritzbox.pem").read_text(encoding="utf-8")
            markers = re.findall(r"^-----BEGIN (CERTIFICATE|.*PRIVATE KEY)-----$", bundle, re.MULTILINE)
            if not markers:
                errors.append(f"{name} FritzBox bundle has no PEM markers")
            else:
                if markers[0] != "CERTIFICATE":
                    errors.append(f"{name} FritzBox bundle does not start with a certificate")
                if "PRIVATE KEY" not in markers[-1]:
                    errors.append(f"{name} FritzBox bundle does not end with a private key")
                if markers[:-1].count("CERTIFICATE") < 2:
                    errors.append(f"{name} FritzBox bundle does not contain certificate plus chain before the private key")

        cert = _load_pem_cert(_certificate_pem_path(base_dir, certificate))
        digest = cert.signature_hash_algorithm
        if digest is None or digest.name != "sha384":
            errors.append(f"{name} FritzBox certificate signature digest is not sha384")
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            errors.append(f"{name} FritzBox certificate has no basic constraints")
        else:
            if basic_constraints.ca:
                errors.append(f"{name} FritzBox certificate is marked as CA")
            if basic_constraints.path_length is not None:
                errors.append(f"{name} FritzBox certificate has a path length restriction")


def _check_pkcs12(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate Identity PKCS#12 exports."""
    for certificate in certificates:
        name = _certificate_name(certificate)
        formats = set(_certificate_formats(certificate))
        passphrase = str(certificate.get("pfx_passphrase") or certificate.get("passphrase") or "")
        for bundle_format in sorted(formats.intersection({"pfx", "p12"})):
            if not passphrase:
                errors.append(f"{name} PKCS#12 bundle has no configured passphrase")
                continue
            try:
                key, cert, _additional = pkcs12.load_key_and_certificates(
                    _read(_certificate_output_dir(base_dir, certificate) / f"{name}.{bundle_format}"),
                    passphrase.encode("utf-8"),
                )
            except Exception as exc:
                errors.append(f"could not parse PKCS#12 bundle for {name}.{bundle_format}: {exc}")
                continue
            if key is None or cert is None:
                errors.append(f"PKCS#12 bundle for {name}.{bundle_format} does not contain key and certificate")


def _revoked_has_reason(
    entry: x509.RevokedCertificate,
    reason: x509.ReasonFlags,
) -> bool:
    """Return whether a revoked certificate has a specific reason."""
    try:
        value = entry.extensions.get_extension_for_class(x509.CRLReason).value
    except x509.ExtensionNotFound:
        return False
    return value.reason == reason


def _revoked_has_invalidity_date(entry: x509.RevokedCertificate) -> bool:
    """Return whether a revoked certificate has Invalidity Date."""
    try:
        entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.INVALIDITY_DATE)
    except x509.ExtensionNotFound:
        return False
    return True


def _check_crl(
    base_dir: Path,
    authorities: list[dict[str, Any]],
    revocations: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate DER and PEM CRL content."""
    for authority in authorities:
        name = _authority_name(authority)
        stem = _authority_file(authority)
        der_crl = x509.load_der_x509_crl(_read(base_dir / "crl" / f"{stem}.crl"))
        pem_crl = x509.load_pem_x509_crl(_read(base_dir / "crl" / f"{stem}.crl.pem"))
        digest = der_crl.signature_hash_algorithm
        if digest is None or digest.name != "sha384":
            errors.append(f"{name} DER CRL signature digest is not sha384")
        for crl, label in ((der_crl, "DER"), (pem_crl, "PEM")):
            for extension_class, description in (
                (x509.CRLNumber, "CRL Number"),
                (x509.AuthorityKeyIdentifier, "Authority Key Identifier"),
            ):
                try:
                    crl.extensions.get_extension_for_class(extension_class)
                except x509.ExtensionNotFound:
                    errors.append(f"{name} {label} CRL is missing {description}")

        try:
            der_number = der_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            pem_number = pem_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        except x509.ExtensionNotFound:
            continue
        if der_number != pem_number:
            errors.append(f"{name} DER and PEM CRL numbers differ")

        revoked = list(der_crl)
        authority_revocations = [
            entry
            for entry in revocations.get(name, [])
            if isinstance(entry, dict)
        ]
        if authority_revocations and not revoked:
            errors.append(f"{name} DER CRL has no revoked certificates")
            continue
        for revocation in authority_revocations:
            reason = str(revocation.get("reason", ""))
            reason_flag = _reason_flag(reason)
            if reason and reason_flag and not any(_revoked_has_reason(entry, reason_flag) for entry in revoked):
                errors.append(f"{name} DER CRL has no {reason} revocation reason")
            if revocation.get("invalidity_date") and not any(_revoked_has_invalidity_date(entry) for entry in revoked):
                errors.append(f"{name} DER CRL has no Invalidity Date entry")


def run_module() -> None:
    """Run the Molecule CA verifier module."""
    module = AnsibleModule(
        argument_spec={
            "ca_name": {"type": "str", "required": True},
            "base_dir": {"type": "path", "required": True},
            "publish_root": {"type": "path", "required": True},
            "authorities": {"type": "list", "elements": "dict", "required": True, "no_log": True},
            "certificates": {"type": "list", "elements": "dict", "required": True, "no_log": True},
            "certificate_types": {"type": "dict", "required": True},
            "revocations": {"type": "dict", "default": {}},
            "renewal": {"type": "dict", "default": {}},
        },
        supports_check_mode=True,
    )
    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}")

    base_dir = Path(module.params["base_dir"])
    publish_root = Path(module.params["publish_root"])
    authorities = module.params["authorities"]
    certificates = module.params["certificates"]
    certificate_types = module.params["certificate_types"]
    revocations = module.params["revocations"]
    renewal = module.params["renewal"]
    errors: list[str] = []
    checked_files = _check_files(base_dir, publish_root, authorities, certificates, errors)
    checks = (
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
