"""Certificate and CRL checks for the CA Molecule scenario."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    NameOID,
    ObjectIdentifier,
)

from .ca_verify_common import (
    authority_file,
    authority_name,
    certificate_csr,
    certificate_formats,
    certificate_issuer,
    certificate_name,
    certificate_output_dir,
    certificate_pem_path,
    certificate_type,
    certificate_uses_csr,
    load_pem_cert,
    load_pem_certs,
    public_key_bytes,
    read,
    reason_flag,
    verify_chain,
)


def _check_digest(
    signed, signing_key, expected: str, label: str, errors: list[str]
) -> None:
    """Check the configured hash, or EdDSA's algorithm-defined hash mode."""
    expected_hash = (
        None
        if isinstance(signing_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
        else expected
    )
    actual = signed.signature_hash_algorithm
    if (actual.name if actual is not None else None) != expected_hash:
        errors.append(f"{label} signature digest differs from {expected_hash}")


def check_digests(base_dir: Path, params: dict, errors: list[str]) -> None:
    """Validate CA, certificate, and managed CSR signature hash selection."""
    for authority in params["authorities"]:
        path = base_dir / "ca" / f"{authority['name']}-ca.pem"
        cert = load_pem_cert(path)
        issuer = load_pem_cert(base_dir / "ca" / f"{authority['parent']}-ca.pem")
        _check_digest(
            cert,
            issuer.public_key(),
            authority.get("digest", "sha384"),
            str(path),
            errors,
        )
        _check_key_type(cert.public_key(), authority, str(path), errors)
        csr = x509.load_pem_x509_csr(
            read(base_dir / "csr" / f"{authority['name']}-ca.csr")
        )
        _check_digest(
            csr,
            cert.public_key(),
            authority.get("digest", "sha384"),
            str(path) + " CSR",
            errors,
        )
    for certificate in params["certificates"]:
        path = certificate_pem_path(base_dir, certificate)
        cert = load_pem_cert(path)
        issuer_name = certificate_issuer(certificate, params["certificate_types"])
        issuer = load_pem_cert(base_dir / "ca" / f"{issuer_name}-ca.pem")
        _check_digest(
            cert,
            issuer.public_key(),
            certificate.get("digest", "sha384"),
            str(path),
            errors,
        )
        if not certificate_uses_csr(certificate):
            csr = x509.load_pem_x509_csr(
                read(base_dir / "csr" / f"{certificate['name']}.csr")
            )
            _check_digest(
                csr,
                cert.public_key(),
                certificate.get("digest", "sha384"),
                str(path) + " CSR",
                errors,
            )


def check_public_keys(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    subject: dict[str, str],
    errors: list[str],
) -> None:
    """Validate generated certificate public key algorithms."""
    for certificate in certificates:
        name = certificate_name(certificate)
        cert = load_pem_cert(certificate_pem_path(base_dir, certificate))
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if usage.key_encipherment != isinstance(cert.public_key(), rsa.RSAPublicKey):
            errors.append(
                f"{name} keyEncipherment default does not match its public key"
            )
        if certificate_uses_csr(certificate):
            csr = certificate_csr(certificate)
            private_key_path = (
                certificate_output_dir(base_dir, certificate) / f"{name}.key"
            )
            if private_key_path.exists():
                errors.append(
                    f"{name} CSR certificate should not have a managed private key"
                )
            _check_csr_identity(cert, certificate, subject, errors)
            if public_key_bytes(cert.public_key()) != public_key_bytes(
                csr.public_key()
            ):
                errors.append(f"{name} public key does not match configured CSR")
            continue

        _check_key_type(cert.public_key(), certificate, name, errors)


def _check_csr_identity(
    cert: x509.Certificate,
    certificate: dict[str, Any],
    subject: dict[str, str],
    errors: list[str],
) -> None:
    """Check the fixture's approved subject and DNS SANs independently of its CSR."""
    name = certificate_name(certificate)
    approved = subject | certificate.get("subject", {})
    subject_oids = {
        "country": NameOID.COUNTRY_NAME,
        "state": NameOID.STATE_OR_PROVINCE_NAME,
        "locality": NameOID.LOCALITY_NAME,
        "organization": NameOID.ORGANIZATION_NAME,
        "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    }
    expected = {oid: approved[field] for field, oid in subject_oids.items()}
    expected[NameOID.COMMON_NAME] = certificate["common_name"]
    actual = {attribute.oid: attribute.value for attribute in cert.subject}
    if actual != expected:
        errors.append(f"{name} subject does not match approved configuration")
    actual_san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    expected_san = x509.SubjectAlternativeName(
        [x509.DNSName(value.removeprefix("DNS:")) for value in certificate["san"]]
    )
    if actual_san.value != expected_san:
        errors.append(f"{name} SANs do not match approved configuration")


def _check_key_type(key, certificate: dict, name: str, errors: list[str]) -> None:
    """Check the requested public key type and size for a CA or end certificate."""
    key_type = (
        str(certificate.get("key_type") or "RSA")
        .upper()
        .replace("-", "")
        .replace("_", "")
    )
    key_size = certificate.get("key_size")
    if key_type == "RSA":
        expected_size = int(key_size or 4096)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != expected_size:
            errors.append(f"{name} public key is not RSA {expected_size}")
    elif key_type in {
        "ECDSA",
        "EC",
        "ECDSAP256",
        "ECP256",
        "P256",
        "PRIME256V1",
        "SECP256R1",
        "ECDSAP384",
        "ECP384",
        "P384",
        "SECP384R1",
    }:
        use_p384 = key_type in {"ECDSAP384", "ECP384", "P384", "SECP384R1"} or (
            key_type in {"ECDSA", "EC"} and int(key_size or 256) == 384
        )
        expected_curve = "secp384r1" if use_p384 else "secp256r1"
        if (
            not isinstance(key, ec.EllipticCurvePublicKey)
            or key.curve.name != expected_curve
        ):
            errors.append(f"{name} public key is not ECDSA {expected_curve}")
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
        return load_pem_certs(chain_path)
    return []


def check_chains(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    certificate_types: dict[str, Any],
    errors: list[str],
) -> int:
    """Validate issued certificate chains."""
    root = load_pem_cert(base_dir / "ca/root-ca.pem")
    checked = 0
    for certificate in certificates:
        name = certificate_name(certificate)
        issuer = certificate_issuer(certificate, certificate_types)
        if not issuer:
            errors.append(f"{name} has no issuer in certificate_types")
            continue
        try:
            leaf = load_pem_cert(certificate_pem_path(base_dir, certificate))
            chain = _issuer_chain(base_dir, issuer)
            verify_chain(leaf, chain, root)
            for bundle_format in set(certificate_formats(certificate)).intersection(
                {"fullchain", "fritzbox", "bundle"}
            ):
                bundle = load_pem_certs(
                    certificate_output_dir(base_dir, certificate)
                    / f"{name}-{bundle_format}.pem"
                )
                verify_chain(bundle[0], bundle[1:], root)
                if bundle != [leaf, *chain]:
                    errors.append(
                        f"{name} {bundle_format} bundle has stale certificates"
                    )
            checked += 1
        except (OSError, ValueError, InvalidSignature, UnsupportedAlgorithm) as exc:
            errors.append(f"chain validation failed for {name}: {exc}")
    return checked


def check_mskdc(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate MSKDC certificate extensions."""
    for certificate in certificates:
        if certificate_type(certificate) != "mskdc":
            continue
        name = certificate_name(certificate)
        cert = load_pem_cert(certificate_pem_path(base_dir, certificate))
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
                f"{name} MSKDC certificate is missing EKUs: "
                f"{sorted(str(oid) for oid in missing_ekus)}"
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

        for oid_text, expected in (
            ("1.3.6.1.4.1.311.20.2", True),
            ("1.3.6.1.4.1.311.25.1", bool((certificate.get("ad_object_guid") or "").strip())),
        ):
            present = any(ext.oid.dotted_string == oid_text for ext in cert.extensions)
            if present != expected:
                errors.append(
                    f"{name} MSKDC extension OID {oid_text} presence differs from configuration"
                )


def check_fritzbox(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Validate FritzBox certificate and bundle behavior."""
    for certificate in certificates:
        if certificate_type(certificate) != "fritzbox":
            continue
        name = certificate_name(certificate)
        directory = certificate_output_dir(base_dir, certificate)
        if "fritzbox" in set(certificate_formats(certificate)):
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
                        f"{name} FritzBox bundle does not contain certificate plus "
                        "chain before the private key"
                    )

        cert = load_pem_cert(certificate_pem_path(base_dir, certificate))
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


def check_pkcs12(
    base_dir: Path,
    certificates: list[dict[str, Any]],
    passphrases: dict[str, str],
    errors: list[str],
) -> None:
    """Validate Identity PKCS#12 exports."""
    root = load_pem_cert(base_dir / "ca/root-ca.pem")
    for certificate in certificates:
        name = certificate_name(certificate)
        formats = set(certificate_formats(certificate))
        passphrase = passphrases.get(name) or ""
        for bundle_format in sorted(formats.intersection({"pfx", "p12"})):
            if not passphrase:
                errors.append(f"{name} PKCS#12 bundle has no configured passphrase")
                continue
            try:
                key, cert, additional = pkcs12.load_key_and_certificates(
                    read(
                        certificate_output_dir(base_dir, certificate)
                        / f"{name}.{bundle_format}"
                    ),
                    passphrase.encode("utf-8"),
                )
            except (ValueError, UnsupportedAlgorithm) as exc:
                errors.append(
                    f"could not parse PKCS#12 bundle for {name}.{bundle_format}: {exc}"
                )
                continue
            if key is None or cert is None:
                errors.append(
                    f"PKCS#12 bundle for {name}.{bundle_format} "
                    "does not contain key and certificate"
                )
            else:
                verify_chain(cert, list(additional or []), root)


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


def check_crl(
    base_dir: Path,
    authorities: list[dict[str, Any]],
    revocations: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate DER and PEM CRL content."""
    for authority in authorities:
        name = authority_name(authority)
        stem = authority_file(authority)
        der_crl = x509.load_der_x509_crl(read(base_dir / "crl" / f"{stem}.crl"))
        pem_crl = x509.load_pem_x509_crl(read(base_dir / "crl" / f"{stem}.crl.pem"))
        _check_digest(
            der_crl,
            load_pem_cert(base_dir / "ca" / f"{stem}.pem").public_key(),
            authority.get("crl_digest", "sha384"),
            name + " CRL",
            errors,
        )
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

        _check_crl_revocations(list(der_crl), revocations.get(name, []), name, errors)


def _check_crl_revocations(
    revoked: list[x509.RevokedCertificate],
    revocations: list[dict[str, Any]],
    name: str,
    errors: list[str],
) -> None:
    """Check the configured revocation entries in an exported CRL."""
    authority_revocations = [
        entry for entry in revocations if isinstance(entry, dict)
    ]
    if authority_revocations and not revoked:
        errors.append(f"{name} DER CRL has no revoked certificates")
        return
    for revocation in authority_revocations:
        reason = str(revocation.get("reason", ""))
        expected_reason = reason_flag(reason)
        if (
            reason
            and expected_reason
            and not any(
                _revoked_has_reason(entry, expected_reason) for entry in revoked
            )
        ):
            errors.append(f"{name} DER CRL has no {reason} revocation reason")
        if revocation.get("invalidity_date") and not any(
            _revoked_has_invalidity_date(entry) for entry in revoked
        ):
            errors.append(f"{name} DER CRL has no Invalidity Date entry")
