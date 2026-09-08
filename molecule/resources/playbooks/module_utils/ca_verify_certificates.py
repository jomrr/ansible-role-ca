"""Certificate and CRL checks for the CA Molecule scenario."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ansible.module_utils.ca_verify_common import (
    _authority_file,
    _authority_name,
    _certificate_csr,
    _certificate_formats,
    _certificate_issuer,
    _certificate_name,
    _certificate_output_dir,
    _certificate_pem_path,
    _certificate_type,
    _certificate_uses_csr,
    _load_pem_cert,
    _load_pem_certs,
    _public_key_bytes,
    _read,
    _reason_flag,
    _verify_chain,
)
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    ObjectIdentifier,
)


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
    paths.extend(
        _certificate_pem_path(base_dir, certificate) for certificate in certificates
    )
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
        cert = _load_pem_cert(_certificate_pem_path(base_dir, certificate))
        if _certificate_uses_csr(certificate):
            csr = _certificate_csr(certificate)
            private_key_path = (
                _certificate_output_dir(base_dir, certificate) / f"{name}.key"
            )
            if private_key_path.exists():
                errors.append(
                    f"{name} CSR certificate should not have a managed private key"
                )
            if cert.subject != csr.subject:
                errors.append(f"{name} subject does not match configured CSR")
            if _public_key_bytes(cert.public_key()) != _public_key_bytes(
                csr.public_key()
            ):
                errors.append(f"{name} public key does not match configured CSR")
            continue

        key_type = str(certificate.get("key_type") or "RSA").upper().replace("-", "")
        key_size = certificate.get("key_size")
        key = cert.public_key()
        if key_type == "RSA":
            expected_size = int(key_size or 4096)
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size != expected_size:
                errors.append(f"{name} public key is not RSA {expected_size}")
        elif key_type in {"ECDSA", "EC", "ECC"}:
            expected_size = int(key_size or 256)
            expected_curve = "secp384r1" if expected_size == 384 else "secp256r1"
            if (
                not isinstance(key, ec.EllipticCurvePublicKey)
                or key.curve.name != expected_curve
            ):
                errors.append(f"{name} public key is not ECDSA {expected_size}")
        elif key_type in {"ECDSAP256", "ECP256", "P256", "PRIME256V1", "SECP256R1"}:
            if (
                not isinstance(key, ec.EllipticCurvePublicKey)
                or key.curve.name != "secp256r1"
            ):
                errors.append(f"{name} public key is not ECDSA P-256")
        elif key_type in {"ECDSAP384", "ECP384", "P384", "SECP384R1"}:
            if (
                not isinstance(key, ec.EllipticCurvePublicKey)
                or key.curve.name != "secp384r1"
            ):
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
            leaf = _load_pem_cert(_certificate_pem_path(base_dir, certificate))
            chain = _issuer_chain(base_dir, issuer)
            _verify_chain(leaf, chain)
            for bundle_format in set(_certificate_formats(certificate)).intersection(
                {"fullchain", "fritzbox"}
            ):
                bundle = _load_pem_certs(
                    _certificate_output_dir(base_dir, certificate)
                    / f"{name}-{bundle_format}.pem"
                )
                _verify_chain(bundle[0], bundle[1:])
                if bundle != [leaf, *chain]:
                    errors.append(
                        f"{name} {bundle_format} bundle has stale certificates"
                    )
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
            errors.append(
                f"{name} MSKDC certificate is missing EKUs: {sorted(str(oid) for oid in missing_ekus)}"
            )

        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            errors.append(f"{name} MSKDC certificate has no SAN extension")
        else:
            pkinit_oid = ObjectIdentifier("1.3.6.1.5.2.2")
            if not any(
                isinstance(entry, x509.OtherName) and entry.type_id == pkinit_oid
                for entry in san
            ):
                errors.append(
                    f"{name} MSKDC certificate has no PKINIT KRB5PrincipalName SAN"
                )

        for oid_text in ("1.3.6.1.4.1.311.20.2", "1.3.6.1.4.1.311.25.1"):
            try:
                cert.extensions.get_extension_for_oid(ObjectIdentifier(oid_text))
            except x509.ExtensionNotFound:
                errors.append(
                    f"{name} MSKDC certificate is missing extension OID {oid_text}"
                )


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
            markers = re.findall(
                r"^-----BEGIN (CERTIFICATE|.*PRIVATE KEY)-----$", bundle, re.MULTILINE
            )
            if not markers:
                errors.append(f"{name} FritzBox bundle has no PEM markers")
            else:
                if markers[0] != "CERTIFICATE":
                    errors.append(
                        f"{name} FritzBox bundle does not start with a certificate"
                    )
                if "PRIVATE KEY" not in markers[-1]:
                    errors.append(
                        f"{name} FritzBox bundle does not end with a private key"
                    )
                if markers[:-1].count("CERTIFICATE") < 2:
                    errors.append(
                        f"{name} FritzBox bundle does not contain certificate plus chain before the private key"
                    )

        cert = _load_pem_cert(_certificate_pem_path(base_dir, certificate))
        digest = cert.signature_hash_algorithm
        if digest is None or digest.name != "sha384":
            errors.append(f"{name} FritzBox certificate signature digest is not sha384")
        try:
            basic_constraints = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            errors.append(f"{name} FritzBox certificate has no basic constraints")
        else:
            if basic_constraints.ca:
                errors.append(f"{name} FritzBox certificate is marked as CA")
            if basic_constraints.path_length is not None:
                errors.append(
                    f"{name} FritzBox certificate has a path length restriction"
                )


def _check_pkcs12(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate Identity PKCS#12 exports."""
    for certificate in certificates:
        name = _certificate_name(certificate)
        formats = set(_certificate_formats(certificate))
        passphrase = str(
            certificate.get("pfx_passphrase") or certificate.get("passphrase") or ""
        )
        for bundle_format in sorted(formats.intersection({"pfx", "p12"})):
            if not passphrase:
                errors.append(f"{name} PKCS#12 bundle has no configured passphrase")
                continue
            try:
                key, cert, additional = pkcs12.load_key_and_certificates(
                    _read(
                        _certificate_output_dir(base_dir, certificate)
                        / f"{name}.{bundle_format}"
                    ),
                    passphrase.encode("utf-8"),
                )
            except Exception as exc:
                errors.append(
                    f"could not parse PKCS#12 bundle for {name}.{bundle_format}: {exc}"
                )
                continue
            if key is None or cert is None:
                errors.append(
                    f"PKCS#12 bundle for {name}.{bundle_format} does not contain key and certificate"
                )
            else:
                _verify_chain(cert, list(additional or []))


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
            der_number = der_crl.extensions.get_extension_for_class(
                x509.CRLNumber
            ).value.crl_number
            pem_number = pem_crl.extensions.get_extension_for_class(
                x509.CRLNumber
            ).value.crl_number
        except x509.ExtensionNotFound:
            continue
        if der_number != pem_number:
            errors.append(f"{name} DER and PEM CRL numbers differ")

        revoked = list(der_crl)
        authority_revocations = [
            entry for entry in revocations.get(name, []) if isinstance(entry, dict)
        ]
        if authority_revocations and not revoked:
            errors.append(f"{name} DER CRL has no revoked certificates")
            continue
        for revocation in authority_revocations:
            reason = str(revocation.get("reason", ""))
            reason_flag = _reason_flag(reason)
            if (
                reason
                and reason_flag
                and not any(
                    _revoked_has_reason(entry, reason_flag) for entry in revoked
                )
            ):
                errors.append(f"{name} DER CRL has no {reason} revocation reason")
            if revocation.get("invalidity_date") and not any(
                _revoked_has_invalidity_date(entry) for entry in revoked
            ):
                errors.append(f"{name} DER CRL has no Invalidity Date entry")
