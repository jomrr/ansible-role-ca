"""Ca x509 extensions helpers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from ansible.module_utils.ca_x509_encoding import (
    _der_bmp_string,
    _der_octet_string,
    _der_pkinit_principal,
    _der_utf8_string,
)
from cryptography import x509
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)

NAME_OIDS = {
    "C": NameOID.COUNTRY_NAME,
    "countryName": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "localityName": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "organizationName": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "commonName": NameOID.COMMON_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
}


EXTENDED_KEY_USAGE_OIDS = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
    "smartcardLogon": x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),
}


def _subject(subject_ordered) -> x509.Name:
    """Build an X.509 name from ordered subject attributes."""
    attributes = []
    for item in subject_ordered or []:
        if len(item) != 1:
            raise ValueError("subject_ordered entries must contain exactly one item")
        key, value = next(iter(item.items()))
        if value is None or str(value) == "":
            continue
        oid = NAME_OIDS.get(str(key))
        if oid is None:
            raise ValueError(f"Unsupported subject attribute {key}")
        attributes.append(x509.NameAttribute(oid, str(value)))
    return x509.Name(attributes)


def subject_from_params(params: dict) -> x509.Name:
    """Build an X.509 subject from module parameters."""
    if params.get("subject_ordered"):
        return _subject(params["subject_ordered"])

    common_name = str(params.get("common_name") or "").strip()
    if not common_name:
        raise ValueError("subject_ordered or common_name is required")

    subject_values = params.get("subject") or {}
    subject = [
        {"C": subject_values.get("country", subject_values.get("C", ""))},
        {"ST": subject_values.get("state", subject_values.get("ST", ""))},
        {"L": subject_values.get("locality", subject_values.get("L", ""))},
        {"O": subject_values.get("organization", subject_values.get("O", ""))},
        {
            "OU": subject_values.get(
                "organizational_unit",
                subject_values.get("OU", ""),
            )
        },
        {"CN": common_name},
    ]
    email = str(params.get("email") or "").strip()
    if email:
        subject.append({"emailAddress": email})
    return _subject(subject)


def _basic_constraints(values):
    """Build a BasicConstraints extension value from OpenSSL-like tokens."""
    ca = False
    path_length = None
    for value in values or []:
        text = str(value)
        if text.upper() == "CA:TRUE":
            ca = True
        elif text.upper() == "CA:FALSE":
            ca = False
        elif text.lower().startswith("pathlen:"):
            path_length = int(text.split(":", 1)[1])
    if not ca:
        path_length = None
    return x509.BasicConstraints(ca=ca, path_length=path_length)


def _key_usage(values: Iterable[str] | None) -> x509.KeyUsage:
    """Build a KeyUsage extension value from role tokens."""
    names = {str(value) for value in values or []}
    key_agreement = "keyAgreement" in names
    return x509.KeyUsage(
        digital_signature="digitalSignature" in names,
        content_commitment=bool({"nonRepudiation", "contentCommitment"} & names),
        key_encipherment="keyEncipherment" in names,
        data_encipherment="dataEncipherment" in names,
        key_agreement=key_agreement,
        key_cert_sign="keyCertSign" in names,
        crl_sign="cRLSign" in names,
        encipher_only=key_agreement and "encipherOnly" in names,
        decipher_only=key_agreement and "decipherOnly" in names,
    )


def _extended_key_usage(values):
    """Build an ExtendedKeyUsage extension value from names or OIDs."""
    oids = []
    for value in values or []:
        text = str(value)
        if text in EXTENDED_KEY_USAGE_OIDS:
            oids.append(EXTENDED_KEY_USAGE_OIDS[text])
        else:
            oids.append(x509.ObjectIdentifier(text))
    return x509.ExtendedKeyUsage(oids)


def _other_name_value(value: str, pkinit_realm: str | None) -> bytes:
    """Encode supported otherName payload syntaxes."""
    if value.startswith("UTF8:"):
        return _der_utf8_string(value.split(":", 1)[1])
    if value.startswith("SEQUENCE:"):
        if not pkinit_realm:
            raise ValueError("SEQUENCE otherName requires pkinit.realm")
        return _der_pkinit_principal(pkinit_realm)
    raise ValueError(f"Unsupported otherName value {value}")


def _subject_alt_name(values, pkinit_realm: str | None):
    """Build a SubjectAlternativeName extension from OpenSSL-like values."""
    names: list[x509.GeneralName] = []
    for value in values or []:
        kind, payload = str(value).split(":", 1)
        kind_lower = kind.lower()
        if kind_lower == "dns":
            names.append(x509.DNSName(payload))
        elif kind_lower == "ip":
            names.append(x509.IPAddress(ipaddress.ip_address(payload)))
        elif kind_lower in {"email", "rfc822"}:
            names.append(x509.RFC822Name(payload))
        elif kind_lower == "uri":
            names.append(x509.UniformResourceIdentifier(payload))
        elif kind_lower == "rid":
            names.append(x509.RegisteredID(x509.ObjectIdentifier(payload)))
        elif kind_lower == "othername":
            oid, other_value = payload.split(";", 1)
            names.append(
                x509.OtherName(
                    x509.ObjectIdentifier(oid),
                    _other_name_value(other_value, pkinit_realm),
                )
            )
        else:
            raise ValueError(f"Unsupported SAN type {kind}")
    return x509.SubjectAlternativeName(names)


def _raw_extension_value(value: str) -> bytes:
    """Encode supported raw extension value syntaxes as DER bytes."""
    if value.startswith("ASN1:BMPSTRING:"):
        return _der_bmp_string(value.split(":", 2)[2])
    if value.startswith("ASN1:UTF8String:"):
        return _der_utf8_string(value.split(":", 2)[2])
    if value.startswith("ASN1:FORMAT:HEX,OCTETSTRING:"):
        raw = value.rsplit(":", 1)[1]
        return _der_octet_string(bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", raw)))
    if value.startswith("DER:"):
        return bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", value.split(":", 1)[1]))
    raise ValueError(f"Unsupported raw extension value {value}")


def _csr_subject_alt_name(csr):
    """Return the CSR SAN extension value and critical flag when present."""
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    return extension.value, extension.critical


def _desired_extensions(params, public_key, signer_public_key, csr_san=None):
    """Build the desired certificate or CSR extension list."""
    extensions = [
        (
            x509.ExtensionOID.BASIC_CONSTRAINTS,
            True,
            _basic_constraints(params["basic_constraints"]),
        ),
        (
            x509.ExtensionOID.KEY_USAGE,
            bool(params["key_usage_critical"]),
            _key_usage(params["key_usage"]),
        ),
    ]
    if params["extended_key_usage"]:
        extensions.append(
            (
                x509.ExtensionOID.EXTENDED_KEY_USAGE,
                bool(params["extended_key_usage_critical"]),
                _extended_key_usage(params["extended_key_usage"]),
            )
        )
    if params["san"]:
        realm = (params["pkinit"] or {}).get("realm") or None
        extensions.append(
            (
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                bool(params["san_critical"]),
                _subject_alt_name(params["san"], realm),
            )
        )
    elif params.get("use_csr_san", True) and csr_san is not None:
        san_value, san_critical = csr_san
        extensions.append(
            (
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                bool(san_critical),
                san_value,
            )
        )
    if params["aia_url"]:
        extensions.append(
            (
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                False,
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(params["aia_url"]),
                        )
                    ]
                ),
            )
        )
    if params["cdp_url"]:
        extensions.append(
            (
                x509.ExtensionOID.CRL_DISTRIBUTION_POINTS,
                False,
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[
                                x509.UniformResourceIdentifier(params["cdp_url"])
                            ],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
            )
        )
    for extension in params["raw_extensions"] or []:
        oid = x509.ObjectIdentifier(str(extension["oid"]))
        extensions.append(
            (
                oid,
                bool(extension.get("critical", False)),
                x509.UnrecognizedExtension(
                    oid,
                    _raw_extension_value(str(extension["value"])),
                ),
            )
        )
    if params["include_identifiers"]:
        extensions.append(
            (
                x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                False,
                x509.SubjectKeyIdentifier.from_public_key(public_key),
            )
        )
        extensions.append(
            (
                x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                False,
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_public_key),
            )
        )
    return extensions


def _add_extensions(builder, extensions):
    """Add extensions to a cryptography builder and reject duplicates."""
    seen = set()
    for oid, critical, value in extensions:
        if oid in seen:
            raise ValueError(f"Duplicate extension OID {oid.dotted_string}")
        seen.add(oid)
        builder = builder.add_extension(value, critical=critical)
    return builder


def _extension_maps(extensions):
    """Return extensions keyed by dotted OID string."""
    return {ext.oid.dotted_string: ext for ext in extensions}


def _name_token(name):
    """Return a comparable token for a GeneralName."""
    if isinstance(name, x509.DNSName):
        return ("DNS", name.value)
    if isinstance(name, x509.RFC822Name):
        return ("email", name.value)
    if isinstance(name, x509.UniformResourceIdentifier):
        return ("URI", name.value)
    if isinstance(name, x509.IPAddress):
        return ("IP", str(name.value))
    if isinstance(name, x509.RegisteredID):
        return ("RID", name.value.dotted_string)
    if isinstance(name, x509.OtherName):
        return ("otherName", name.type_id.dotted_string, name.value)
    if isinstance(name, x509.DirectoryName):
        return ("dirName", name.value.rfc4514_string())
    return (name.__class__.__name__, repr(name))


def _distribution_point_token(point):
    """Return a comparable token for a CRL distribution point."""
    full_name = tuple(_name_token(name) for name in point.full_name or [])
    crl_issuer = tuple(_name_token(name) for name in point.crl_issuer or [])
    reasons = tuple(sorted(reason.name for reason in point.reasons or []))
    relative_name = (
        point.relative_name.rfc4514_string() if point.relative_name else None
    )
    return (full_name, relative_name, reasons, crl_issuer)


def _extension_token(extension):
    """Return a comparable token for an X.509 extension."""
    value = extension.value
    if isinstance(value, x509.BasicConstraints):
        return ("basic_constraints", value.ca, value.path_length)
    if isinstance(value, x509.KeyUsage):
        return (
            "key_usage",
            value.digital_signature,
            value.content_commitment,
            value.key_encipherment,
            value.data_encipherment,
            value.key_agreement,
            value.key_cert_sign,
            value.crl_sign,
            value.encipher_only if value.key_agreement else None,
            value.decipher_only if value.key_agreement else None,
        )
    if isinstance(value, x509.ExtendedKeyUsage):
        return ("extended_key_usage", tuple(oid.dotted_string for oid in value))
    if isinstance(value, x509.SubjectAlternativeName):
        return ("subject_alt_name", tuple(_name_token(name) for name in value))
    if isinstance(value, x509.AuthorityInformationAccess):
        return (
            "authority_information_access",
            tuple(
                (
                    description.access_method.dotted_string,
                    _name_token(description.access_location),
                )
                for description in value
            ),
        )
    if isinstance(value, x509.CRLDistributionPoints):
        return (
            "crl_distribution_points",
            tuple(_distribution_point_token(point) for point in value),
        )
    if isinstance(value, x509.SubjectKeyIdentifier):
        return ("subject_key_identifier", value.digest)
    if isinstance(value, x509.AuthorityKeyIdentifier):
        issuers = tuple(_name_token(name) for name in value.authority_cert_issuer or [])
        return (
            "authority_key_identifier",
            value.key_identifier,
            issuers,
            value.authority_cert_serial_number,
        )
    if isinstance(value, x509.UnrecognizedExtension):
        return ("unrecognized", value.oid.dotted_string, value.value)
    return (value.__class__.__name__, repr(value))


def _extensions_equal(existing, desired) -> bool:
    """Compare existing cryptography extensions to desired extension tuples."""
    existing_map = _extension_maps(existing)
    desired_map = {
        oid.dotted_string: x509.Extension(oid, critical, value)
        for oid, critical, value in desired
    }
    if set(existing_map) != set(desired_map):
        return False
    for oid, ext in desired_map.items():
        if existing_map[oid].critical != ext.critical:
            return False
        if _extension_token(existing_map[oid]) != _extension_token(ext):
            return False
    return True
