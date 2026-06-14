"""Deterministic text exports for X.509 certificates."""

from __future__ import annotations

import datetime as _dt

from ansible.module_utils.ca_file import write_file  # type: ignore[import-not-found,import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa


def _not_valid_after_utc(cert):
    """Return a certificate expiration timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    value = cert.not_valid_after
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _not_valid_before_utc(cert):
    """Return a certificate start timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    value = cert.not_valid_before
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _hex(value: bytes | None) -> str:
    """Return colon-separated uppercase hex."""
    if value is None:
        return ""
    return ":".join(f"{byte:02X}" for byte in value)


def _oid_name(oid) -> str:
    """Return a readable OID name with a dotted-string fallback."""
    name = getattr(oid, "_name", "") or ""
    return name if name and name != "Unknown OID" else oid.dotted_string


def _datetime_text(value: _dt.datetime) -> str:
    """Return a stable UTC timestamp for certificate text exports."""
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _public_key_text(public_key) -> list[str]:
    """Return readable subject public key information."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return [
            "            Public Key Algorithm: rsaEncryption",
            f"            Public-Key: ({public_key.key_size} bit)",
        ]
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return [
            "            Public Key Algorithm: id-ecPublicKey",
            f"            Curve: {public_key.curve.name}",
            f"            Public-Key: ({public_key.key_size} bit)",
        ]
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return ["            Public Key Algorithm: ED25519"]
    if isinstance(public_key, ed448.Ed448PublicKey):
        return ["            Public Key Algorithm: ED448"]
    return [f"            Public Key Algorithm: {public_key.__class__.__name__}"]


def _key_usage_text(value) -> str:
    """Return readable Key Usage values."""
    usages = []
    if value.digital_signature:
        usages.append("Digital Signature")
    if value.content_commitment:
        usages.append("Non Repudiation")
    if value.key_encipherment:
        usages.append("Key Encipherment")
    if value.data_encipherment:
        usages.append("Data Encipherment")
    if value.key_agreement:
        usages.append("Key Agreement")
    if value.key_cert_sign:
        usages.append("Certificate Sign")
    if value.crl_sign:
        usages.append("CRL Sign")
    if value.key_agreement and value.encipher_only:
        usages.append("Encipher Only")
    if value.key_agreement and value.decipher_only:
        usages.append("Decipher Only")
    return ", ".join(usages)


def _general_name_text(name) -> str:
    """Return readable GeneralName text."""
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RegisteredID):
        return f"RID:{name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        return f"otherName:{name.type_id.dotted_string};DER:{_hex(name.value)}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name.value.rfc4514_string()}"
    return repr(name)


def _extension_value_text(value) -> list[str]:
    """Return readable text lines for a certificate extension value."""
    if isinstance(value, x509.BasicConstraints):
        parts = [f"CA:{str(value.ca).upper()}"]
        if value.path_length is not None:
            parts.append(f"pathlen:{value.path_length}")
        return [", ".join(parts)]
    if isinstance(value, x509.KeyUsage):
        return [_key_usage_text(value)]
    if isinstance(value, x509.ExtendedKeyUsage):
        return [", ".join(_oid_name(oid) for oid in value)]
    if isinstance(value, x509.SubjectAlternativeName):
        return [", ".join(_general_name_text(name) for name in value)]
    if isinstance(value, x509.AuthorityInformationAccess):
        return [
            f"{_oid_name(item.access_method)} - {_general_name_text(item.access_location)}"
            for item in value
        ]
    if isinstance(value, x509.CRLDistributionPoints):
        lines = []
        for point in value:
            if point.full_name:
                names = ", ".join(_general_name_text(name) for name in point.full_name)
                lines.append(f"Full Name: {names}")
            if point.crl_issuer:
                issuers = ", ".join(
                    _general_name_text(name) for name in point.crl_issuer
                )
                lines.append(f"CRL Issuer: {issuers}")
        return lines
    if isinstance(value, x509.SubjectKeyIdentifier):
        return [_hex(value.digest)]
    if isinstance(value, x509.AuthorityKeyIdentifier):
        lines = []
        if value.key_identifier:
            lines.append(f"keyid:{_hex(value.key_identifier)}")
        if value.authority_cert_issuer:
            issuers = ", ".join(
                _general_name_text(name) for name in value.authority_cert_issuer
            )
            lines.append(f"issuer:{issuers}")
        if value.authority_cert_serial_number is not None:
            lines.append(f"serial:{value.authority_cert_serial_number}")
        return lines
    if isinstance(value, x509.UnrecognizedExtension):
        return [f"DER:{_hex(value.value)}"]
    return [repr(value)]


def _certificate_text(cert) -> bytes:
    """Return a deterministic text representation of a certificate."""
    lines = [
        "Certificate:",
        "    Data:",
        f"        Version: {cert.version.name}",
        f"        Serial Number: {cert.serial_number}",
        f"        Signature Algorithm: {_oid_name(cert.signature_algorithm_oid)}",
        f"        Issuer: {cert.issuer.rfc4514_string()}",
        "        Validity:",
        f"            Not Before: {_datetime_text(_not_valid_before_utc(cert))}",
        f"            Not After : {_datetime_text(_not_valid_after_utc(cert))}",
        f"        Subject: {cert.subject.rfc4514_string()}",
        "        Subject Public Key Info:",
    ]
    lines.extend(_public_key_text(cert.public_key()))
    if cert.extensions:
        lines.append("        X509v3 extensions:")
        for extension in cert.extensions:
            suffix = "critical" if extension.critical else ""
            lines.append(f"            {_oid_name(extension.oid)}: {suffix}".rstrip())
            lines.extend(
                f"                {line}" for line in _extension_value_text(extension.value)
            )
    lines.append(f"    Signature Algorithm: {_oid_name(cert.signature_algorithm_oid)}")
    return ("\n".join(lines) + "\n").encode()


def ensure_txt(params, cert):
    """Ensure the optional text certificate export exists."""
    if not params["txt_path"]:
        return False
    return write_file(
        params["txt_path"],
        _certificate_text(cert),
        params["owner"],
        params["group"],
        params["public_mode"],
    )
