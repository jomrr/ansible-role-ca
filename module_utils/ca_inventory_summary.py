"""Ca inventory summary helpers."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.ca_file import read_file
from ansible.module_utils.ca_serial import colon_hex, serial_hex
from ansible.module_utils.ca_time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
    object_datetime,
    timestamp_z,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


def _load_certificate(path: str) -> x509.Certificate:
    """Load a PEM or DER X.509 certificate from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _name_attributes(name: x509.Name) -> list[dict[str, str]]:
    """Return a stable list of X.509 name attributes."""
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": getattr(attribute.oid, "_name", attribute.oid.dotted_string),
            "value": str(attribute.value),
        }
        for attribute in name
    ]


def _oid_name(oid) -> str:
    """Return a readable OID name with dotted-string fallback."""
    name = getattr(oid, "_name", "") or ""
    return name if name and name != "Unknown OID" else oid.dotted_string


def _general_name(name) -> str:
    """Return a compact string representation of a GeneralName."""
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
        return f"otherName:{name.type_id.dotted_string};DER:{colon_hex(name.value)}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name.value.rfc4514_string()}"
    return repr(name)


def _key_usage(value: x509.KeyUsage) -> list[str]:
    """Return key usage names set on an X.509 certificate."""
    usages = []
    if value.digital_signature:
        usages.append("digitalSignature")
    if value.content_commitment:
        usages.append("nonRepudiation")
    if value.key_encipherment:
        usages.append("keyEncipherment")
    if value.data_encipherment:
        usages.append("dataEncipherment")
    if value.key_agreement:
        usages.append("keyAgreement")
    if value.key_cert_sign:
        usages.append("keyCertSign")
    if value.crl_sign:
        usages.append("cRLSign")
    if value.key_agreement and value.encipher_only:
        usages.append("encipherOnly")
    if value.key_agreement and value.decipher_only:
        usages.append("decipherOnly")
    return usages


def _extension_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return selected certificate extensions for inventory use."""
    result: dict[str, Any] = {}
    for extension in cert.extensions:
        value = extension.value
        if isinstance(value, x509.BasicConstraints):
            result["basic_constraints"] = {
                "critical": extension.critical,
                "ca": value.ca,
                "path_length": value.path_length,
            }
        elif isinstance(value, x509.KeyUsage):
            result["key_usage"] = {
                "critical": extension.critical,
                "value": _key_usage(value),
            }
        elif isinstance(value, x509.ExtendedKeyUsage):
            result["extended_key_usage"] = {
                "critical": extension.critical,
                "value": [
                    {"oid": oid.dotted_string, "name": _oid_name(oid)} for oid in value
                ],
            }
        elif isinstance(value, x509.SubjectAlternativeName):
            result["subject_alt_name"] = {
                "critical": extension.critical,
                "value": [_general_name(name) for name in value],
            }
        elif isinstance(value, x509.AuthorityInformationAccess):
            result["authority_information_access"] = [
                {
                    "method": item.access_method.dotted_string,
                    "method_name": _oid_name(item.access_method),
                    "location": _general_name(item.access_location),
                }
                for item in value
            ]
        elif isinstance(value, x509.CRLDistributionPoints):
            result["crl_distribution_points"] = [
                [_general_name(name) for name in point.full_name or []]
                for point in value
            ]
    return result


def _public_key_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return a small public key summary."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "size": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "ECDSA", "curve": key.curve.name, "size": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519"}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"type": "Ed448"}
    return {"type": key.__class__.__name__}


def _certificate_summary(cert: x509.Certificate) -> dict[str, Any]:
    """Return stable, non-secret metadata for one certificate."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "subject_attributes": _name_attributes(cert.subject),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_attributes": _name_attributes(cert.issuer),
        "serial_number": str(cert.serial_number),
        "serial_number_hex": serial_hex(cert.serial_number),
        "not_valid_before": timestamp_z(certificate_not_valid_before(cert)),
        "not_valid_after": timestamp_z(certificate_not_valid_after(cert)),
        "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
        "fingerprints": {
            "sha1": colon_hex(cert.fingerprint(hashes.SHA1())),
            "sha256": colon_hex(cert.fingerprint(hashes.SHA256())),
        },
        "public_key": _public_key_summary(cert),
        "extensions": _extension_summary(cert),
    }


def _crl_update(crl, name: str):
    """Return a CRL timestamp across cryptography versions."""
    return object_datetime(crl, name)


def _crl_number(crl) -> int | None:
    """Return the CRL Number extension value when present."""
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def _crl_authority_key_identifier(crl) -> str:
    """Return the CRL Authority Key Identifier when present."""
    try:
        value = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return ""
    return colon_hex(value.key_identifier or b"")


def _revoked_from_crl(crl) -> list[dict[str, Any]]:
    """Return revoked certificate metadata from a CRL object."""
    revoked = []
    for item in crl:
        reason = ""
        try:
            reason_ext = item.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        date = object_datetime(item, "revocation_date")
        record = {
            "serial_number": str(item.serial_number),
            "serial_number_hex": serial_hex(item.serial_number),
            "reason": reason,
            "revocation_date": timestamp_z(date),
        }
        try:
            invalidity_ext = item.extensions.get_extension_for_class(
                x509.InvalidityDate
            )
            invalidity_date = object_datetime(invalidity_ext.value, "invalidity_date")
            record["invalidity_date"] = timestamp_z(invalidity_date)
        except x509.ExtensionNotFound:
            pass
        revoked.append(record)
    return sorted(revoked, key=lambda entry: entry["serial_number_hex"])
