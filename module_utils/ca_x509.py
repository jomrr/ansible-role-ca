"""Shared X.509 helpers for role modules."""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from pathlib import Path
from typing import Any

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from ansible.module_utils.ca_file import (  # type: ignore[import-not-found,import-untyped]
        ca_lock_path,
        file_locks,
        read_file,
        sanitize_error,
        set_attrs,
        write_file,
    )
    from ansible.module_utils.ca_renewal import renewal_decision  # type: ignore[import-not-found,import-untyped]
    from ansible.module_utils.ca_serial import serial_hex  # type: ignore[import-not-found,import-untyped]
    from ansible.module_utils.ca_text import ensure_txt  # type: ignore[import-not-found,import-untyped]
    from ansible.module_utils.ca_time import (  # type: ignore[import-not-found,import-untyped]
        certificate_not_valid_after,
        certificate_not_valid_before,
        now_utc,
    )
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import (
        AuthorityInformationAccessOID,
        ExtendedKeyUsageOID,
        NameOID,
    )
except Exception as exc:  # pragma: no cover - handled at runtime by Ansible
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None

__all__ = [
    "CRYPTOGRAPHY_IMPORT_ERROR",
    "ca_authority_argument_spec",
    "digest_algorithm",
    "ensure_x509",
    "ensure_x509_many",
    "load_certificates",
    "load_private_key",
    "normalize_formats",
    "sanitize_error",
    "signature_algorithm",
    "subject_from_params",
    "certificate_params",
]


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

PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


def _der_len(length: int) -> bytes:
    """Encode a DER length octet sequence."""
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, value: bytes) -> bytes:
    """Encode a DER tag-length-value object."""
    return bytes([tag]) + _der_len(len(value)) + value


def _der_sequence(*values: bytes) -> bytes:
    """Encode values as a DER SEQUENCE."""
    return _der(0x30, b"".join(values))


def _der_context(number: int, value: bytes) -> bytes:
    """Encode an explicitly tagged DER context-specific value."""
    return _der(0xA0 + number, value)


def _der_integer(value: int) -> bytes:
    """Encode a non-negative integer as DER INTEGER."""
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _der_general_string(value: str) -> bytes:
    """Encode an ASCII value as DER GeneralString."""
    return _der(0x1B, value.encode("ascii"))


def _der_utf8_string(value: str) -> bytes:
    """Encode a value as DER UTF8String."""
    return _der(0x0C, value.encode("utf-8"))


def _der_bmp_string(value: str) -> bytes:
    """Encode a value as DER BMPString."""
    return _der(0x1E, value.encode("utf-16-be"))


def _der_octet_string(value: bytes) -> bytes:
    """Encode bytes as a DER OCTET STRING."""
    return _der(0x04, value)


def _der_pkinit_principal(realm: str) -> bytes:
    """Encode the MSKDC PKINIT KRB5PrincipalName otherName value."""
    name_string = _der_sequence(
        _der_general_string("krbtgt"), _der_general_string(realm)
    )
    principal_name = _der_sequence(
        _der_context(0, _der_integer(2)),
        _der_context(1, name_string),
    )
    return _der_sequence(
        _der_context(0, _der_general_string(realm)),
        _der_context(1, principal_name),
    )


def digest_algorithm(name: str) -> hashes.HashAlgorithm:
    """Return a cryptography hash object for a digest name."""
    normalized = name.replace("-", "").lower()
    digests: dict[str, Any] = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    if normalized not in digests:
        raise ValueError(f"Unsupported digest {name}")
    return digests[normalized]()


def _key_type(value: Any) -> str:
    """Normalize role key type aliases to an internal key type."""
    normalized = re.sub(r"[^A-Za-z0-9]", "", str(value or "RSA")).upper()
    aliases = {
        "RSA": "RSA",
        "EC": "ECDSA",
        "ECDSA": "ECDSA",
        "ECDSAP256": "ECDSA_P256",
        "ECP256": "ECDSA_P256",
        "P256": "ECDSA_P256",
        "PRIME256V1": "ECDSA_P256",
        "SECP256R1": "ECDSA_P256",
        "ECDSAP384": "ECDSA_P384",
        "ECP384": "ECDSA_P384",
        "P384": "ECDSA_P384",
        "SECP384R1": "ECDSA_P384",
        "ED25519": "ED25519",
        "EDDSA25519": "ED25519",
        "ED448": "ED448",
        "EDDSA448": "ED448",
    }
    if normalized not in aliases:
        raise ValueError(f"Unsupported key_type {value}")
    return aliases[normalized]


def _ec_curve(size: Any):
    """Return the supported ECDSA curve for a requested key size."""
    curve_size = 256 if size in (None, "", 0, 4096) else int(size)
    if curve_size == 256:
        return ec.SECP256R1()
    if curve_size == 384:
        return ec.SECP384R1()
    raise ValueError("ECDSA key_size must be 256 or 384")


def _key_spec(params: dict) -> dict[str, Any]:
    """Resolve module key parameters to a concrete key specification."""
    key_type = _key_type(params.get("key_type"))
    key_size = params.get("key_size")
    if key_type == "RSA":
        return {"type": "RSA", "size": int(key_size or 4096)}
    if key_type == "ECDSA":
        curve = _ec_curve(key_size)
        return {"type": "ECDSA", "curve": curve}
    if key_type == "ECDSA_P256":
        return {"type": "ECDSA", "curve": ec.SECP256R1()}
    if key_type == "ECDSA_P384":
        return {"type": "ECDSA", "curve": ec.SECP384R1()}
    return {"type": key_type}


def _key_matches(key, spec: dict[str, Any]) -> bool:
    """Return whether an existing private key matches the requested spec."""
    if spec["type"] == "RSA":
        return isinstance(key, rsa.RSAPrivateKey) and key.key_size == spec["size"]
    if spec["type"] == "ECDSA":
        return (
            isinstance(key, ec.EllipticCurvePrivateKey)
            and key.curve.name == spec["curve"].name
        )
    if spec["type"] == "ED25519":
        return isinstance(key, ed25519.Ed25519PrivateKey)
    if spec["type"] == "ED448":
        return isinstance(key, ed448.Ed448PrivateKey)
    return False


def _generate_private_key(spec: dict[str, Any]):
    """Generate a private key for a resolved key specification."""
    if spec["type"] == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=spec["size"])
    if spec["type"] == "ECDSA":
        return ec.generate_private_key(spec["curve"])
    if spec["type"] == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()
    if spec["type"] == "ED448":
        return ed448.Ed448PrivateKey.generate()
    raise ValueError(f"Unsupported key type {spec['type']}")


def signature_algorithm(private_key, digest: str):
    """Return the signing hash or None for EdDSA private keys."""
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    return digest_algorithm(digest)


def _ensure_directory(path: str | None, owner, group, mode) -> bool:
    """Create a directory and enforce requested attributes."""
    if not path:
        return False
    Path(path).mkdir(parents=True, exist_ok=True)
    return set_attrs(path, owner, group, mode)


def load_private_key(path: str, passphrase: str | None):
    """Load a PEM private key from disk."""
    return serialization.load_pem_private_key(
        read_file(path),
        password=passphrase.encode() if passphrase else None,
    )


def _private_key_pem(key, passphrase: str | None) -> bytes:
    """Serialize a private key as encrypted or unencrypted PKCS#8 PEM."""
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def _as_public_key(key):
    """Return a public key object from a private or public key object."""
    public_key_types = (
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
    )
    if isinstance(key, public_key_types):
        return key
    return key.public_key()


def _public_key_bytes(key) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a private or public key."""
    return _as_public_key(key).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_public_key_bytes(cert) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a certificate."""
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_fingerprint(cert) -> bytes:
    """Return a SHA-256 certificate fingerprint."""
    return cert.fingerprint(hashes.SHA256())


def _csr_public_key_bytes(csr) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a CSR."""
    return csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_csr(path: str):
    """Load a PEM certificate signing request from disk."""
    return x509.load_pem_x509_csr(read_file(path))


def _load_csr_bytes(data: bytes):
    """Load a PEM or DER certificate signing request from bytes."""
    try:
        return x509.load_pem_x509_csr(data)
    except ValueError:
        return x509.load_der_x509_csr(data)


def _csr_common_name(csr) -> str:
    """Return the first CSR common name when present."""
    values = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else ""


def load_certificate(path: str):
    """Load a PEM or DER certificate from disk."""
    data = read_file(path)
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def load_certificates(path: str):
    """Load one or more certificates from a PEM or DER source."""
    data = read_file(path)
    pem_blocks = PEM_CERT_RE.findall(data)
    if pem_blocks:
        return [x509.load_pem_x509_certificate(block) for block in pem_blocks]
    return [x509.load_der_x509_certificate(data)]


def _load_existing_certificate(path: str):
    """Return an existing certificate or None when it cannot be loaded."""
    try:
        return load_certificate(path)
    except Exception:
        return None


def _renewal_decision(params: dict, existing_cert) -> dict[str, Any]:
    """Return renewal and rekey decisions for an existing certificate."""
    if existing_cert is None:
        return renewal_decision(
            force=bool(params.get("force")),
            not_before=None,
            not_after=None,
            policy_value=params.get("renewal"),
        )
    return renewal_decision(
        force=bool(params.get("force")),
        not_before=certificate_not_valid_before(existing_cert),
        not_after=certificate_not_valid_after(existing_cert),
        policy_value=params.get("renewal"),
    )


def _archive_dir(params: dict, cert) -> str:
    """Return the archive directory for one existing certificate generation."""
    namespace = "authorities" if params.get("authority") else "certificates"
    serial = serial_hex(cert.serial_number)
    return (
        f"{str(params['base_dir']).rstrip('/')}/archive/"
        f"{namespace}/{params['name']}/{serial}"
    )


def _archive_path(params: dict, cert, source_path: str) -> str:
    """Return the archive path for an existing managed source path."""
    return f"{_archive_dir(params, cert)}/{Path(source_path).name}"


def _archive_file(params: dict, cert, source_path: str, mode: str) -> bool:
    """Copy a current managed file into its generation archive if present."""
    if cert is None or not source_path:
        return False
    try:
        content = read_file(source_path)
    except FileNotFoundError:
        return False
    return write_file(
        _archive_path(params, cert, source_path),
        content,
        params["owner"],
        params["group"],
        mode,
    )


def _archive_existing_material(params: dict, cert, *, include_private_key: bool) -> bool:
    """Archive the current generation before replacing it."""
    if cert is None:
        return False
    changed = False
    public_paths = (
        params["cert_path"],
        params["csr_path"],
        params.get("der_path", ""),
        params.get("txt_path", ""),
        params.get("chain_path", ""),
    )
    for path in public_paths:
        changed = _archive_file(params, cert, path, params["public_mode"]) or changed
    if include_private_key:
        changed = (
            _archive_file(params, cert, params["key_path"], params["key_mode"])
            or changed
        )
    return changed


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


def _key_usage(values):
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
        encipher_only=("encipherOnly" in names) if key_agreement else None,
        decipher_only=("decipherOnly" in names) if key_agreement else None,
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
        extension = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
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


def _ensure_key(params, *, rekey: bool, existing_cert):
    """Ensure the private key exists with the requested key properties."""
    spec = _key_spec(params)
    key = None
    changed = False
    if not params["force"] and not rekey:
        try:
            key = load_private_key(params["key_path"], params["key_passphrase"])
        except Exception:
            key = None
        if key is not None and not _key_matches(key, spec):
            _archive_file(params, existing_cert, params["key_path"], params["key_mode"])
            key = None
    if key is None:
        _archive_file(params, existing_cert, params["key_path"], params["key_mode"])
        key = _generate_private_key(spec)
        changed = True
        content = _private_key_pem(key, params["key_passphrase"])
        changed = (
            write_file(
                params["key_path"],
                content,
                params["owner"],
                params["group"],
                params["key_mode"],
            )
            or changed
        )
    else:
        changed = (
            set_attrs(
                params["key_path"],
                params["owner"],
                params["group"],
                params["key_mode"],
            )
            or changed
        )
    return key, changed


def _ensure_csr(params, key, subject, csr_extensions):
    """Ensure the CSR matches the requested subject, key, and extensions."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = _add_extensions(builder, csr_extensions)
    csr = builder.sign(key, signature_algorithm(key, params["digest"]))
    changed = params["force"]
    if not changed:
        try:
            existing = _load_csr(params["csr_path"])
            changed = (
                existing.subject != subject
                or _csr_public_key_bytes(existing) != _public_key_bytes(key)
                or not _extensions_equal(existing.extensions, csr_extensions)
            )
        except Exception:
            changed = True
    content = (
        csr.public_bytes(serialization.Encoding.PEM)
        if changed
        else read_file(params["csr_path"])
    )
    changed = (
        write_file(
            params["csr_path"],
            content,
            params["owner"],
            params["group"],
            params["public_mode"],
        )
        or changed
    )
    return csr, changed


def _external_csr_configured(params: dict) -> bool:
    """Return whether certificate issuance should use an externally supplied CSR."""
    return bool(params.get("csr_source_path") or params.get("csr_content"))


def _external_csr_bytes(params: dict) -> bytes:
    """Return CSR bytes from inline content or a source path."""
    csr_content = params.get("csr_content")
    if csr_content:
        return str(csr_content).encode()
    csr_source_path = str(params.get("csr_source_path") or "")
    if csr_source_path:
        return read_file(csr_source_path)
    raise ValueError("csr_path or csr_content is required for CSR signing")


def _ensure_external_csr(params: dict):
    """Validate and copy an externally supplied CSR into the managed CSR path."""
    csr = _load_csr_bytes(_external_csr_bytes(params))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")

    common_name = str(params.get("common_name") or "").strip()
    csr_common_name = _csr_common_name(csr)
    if common_name and common_name != csr_common_name:
        raise ValueError(
            f"CSR common name {csr_common_name!r} does not match {common_name!r}"
        )

    content = csr.public_bytes(serialization.Encoding.PEM)
    changed = write_file(
        params["csr_path"],
        content,
        params["owner"],
        params["group"],
        params["public_mode"],
        force=params["force"],
    )
    return csr, changed


def _ensure_certificate(
    params,
    key,
    subject,
    cert_extensions,
    signer_key,
    signer_cert,
    renewal_decision,
    existing_cert,
):
    """Ensure the certificate matches the requested issuer and profile."""
    issuer = signer_cert.subject if signer_cert is not None else subject
    now = now_utc(strip_microseconds=True)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_as_public_key(key))
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=1))
        .not_valid_after(now + _dt.timedelta(days=int(params["days"])))
    )
    builder = _add_extensions(builder, cert_extensions)
    cert = builder.sign(
        private_key=signer_key,
        algorithm=signature_algorithm(signer_key, params["digest"]),
    )

    changed = params["force"] or renewal_decision["renew"]
    if not changed:
        try:
            existing = existing_cert if existing_cert is not None else load_certificate(params["cert_path"])
            current_time = now_utc()
            if certificate_not_valid_after(existing) <= current_time:
                changed = True
            else:
                changed = (
                    existing.subject != subject
                    or existing.issuer != issuer
                    or _cert_public_key_bytes(existing) != _public_key_bytes(key)
                    or not _extensions_equal(existing.extensions, cert_extensions)
                )
        except Exception:
            changed = True

    if changed:
        _archive_existing_material(
            params,
            existing_cert,
            include_private_key=False,
        )
        content = cert.public_bytes(serialization.Encoding.PEM)
    else:
        content = read_file(params["cert_path"])
        cert = load_certificate(params["cert_path"])

    changed = (
        write_file(
            params["cert_path"],
            content,
            params["owner"],
            params["group"],
            params["public_mode"],
        )
        or changed
    )
    return cert, changed


def _ensure_der(params, cert):
    """Ensure the optional DER certificate export exists."""
    if not params["der_path"]:
        return False
    return write_file(
        params["der_path"],
        cert.public_bytes(serialization.Encoding.DER),
        params["owner"],
        params["group"],
        params["public_mode"],
    )


def _ensure_chain(params):
    """Ensure the optional certificate chain copy exists."""
    if not params["chain_src_path"] or not params["chain_path"]:
        return False
    content = read_file(params["chain_src_path"])
    return write_file(
        params["chain_path"],
        content,
        params["owner"],
        params["group"],
        params["public_mode"],
    )


def _chain_content(params, signer_cert) -> bytes:
    """Return the issuing chain content for certificate export bundles."""
    for path in (params.get("chain_path"), params.get("chain_src_path")):
        if not path:
            continue
        try:
            return read_file(path).rstrip() + b"\n"
        except FileNotFoundError:
            continue
    if signer_cert is not None:
        return signer_cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
    raise ValueError("certificate chain is required for bundle export formats")


def _chain_certificates(params, signer_cert):
    """Return issuing chain certificates for PKCS#12 exports."""
    for path in (params.get("chain_path"), params.get("chain_src_path")):
        if not path:
            continue
        try:
            return load_certificates(path)
        except FileNotFoundError:
            continue
    return [signer_cert] if signer_cert is not None else []


def _pkcs12_existing_matches(path, passphrase, key, cert, extra_certs) -> bool:
    """Return whether an existing PKCS#12 bundle matches desired content."""
    try:
        existing_key, existing_cert, existing_extra = pkcs12.load_key_and_certificates(
            read_file(path),
            passphrase.encode() if passphrase else None,
        )
    except Exception:
        return False
    if existing_key is None or existing_cert is None:
        return False
    if _public_key_bytes(existing_key) != _public_key_bytes(key):
        return False
    if _cert_fingerprint(existing_cert) != _cert_fingerprint(cert):
        return False
    existing_fingerprints = sorted(
        _cert_fingerprint(item) for item in (existing_extra or [])
    )
    desired_fingerprints = sorted(_cert_fingerprint(item) for item in extra_certs)
    return existing_fingerprints == desired_fingerprints


def _pkcs12_passphrase(params) -> str:
    """Return the configured PKCS#12 passphrase."""
    return str(params.get("passphrase") or params.get("pfx_passphrase") or "")


def _ensure_pkcs12_exports(params, key, cert, extra_certs) -> tuple[bool, dict[str, str]]:
    """Ensure requested PKCS#12 export formats exist."""
    paths = {
        export_format: params["pkcs12_paths"][export_format]
        for export_format in ("pfx", "p12")
        if export_format in params["formats"]
    }
    if not paths:
        return False, {}

    passphrase = _pkcs12_passphrase(params)
    if not passphrase:
        raise ValueError("PKCS#12 bundle requires pfx_passphrase or passphrase")
    friendly_name = str(params.get("friendly_name") or params.get("common_name") or params["name"])
    content = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=key,
        cert=cert,
        cas=extra_certs,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )

    changed = False
    for path in paths.values():
        export_changed = bool(params["force"]) or not _pkcs12_existing_matches(
            path,
            passphrase,
            key,
            cert,
            extra_certs,
        )
        if export_changed:
            changed = (
                write_file(
                    path,
                    content,
                    params["owner"],
                    params["group"],
                    params["key_mode"],
                    force=True,
                )
                or changed
            )
        else:
            changed = (
                set_attrs(path, params["owner"], params["group"], params["key_mode"])
                or changed
            )
    return changed, paths


def _pem_join(*parts: bytes) -> bytes:
    """Join PEM sections with exactly one trailing newline per section."""
    return b"".join(part.rstrip() + b"\n" for part in parts if part)


def _ensure_fullchain_bundle(params, cert, chain_content: bytes) -> bool:
    """Ensure the requested PEM fullchain bundle exists."""
    if "fullchain" not in params["formats"]:
        return False
    content = _pem_join(cert.public_bytes(serialization.Encoding.PEM), chain_content)
    return write_file(
        params["fullchain_path"],
        content,
        params["owner"],
        params["group"],
        params["public_mode"],
        force=params["force"],
    )


def _ensure_fritzbox_bundle(params, cert, chain_content: bytes) -> bool:
    """Ensure the requested FritzBox PEM import bundle exists."""
    if "fritzbox" not in params["formats"]:
        return False
    content = _pem_join(
        cert.public_bytes(serialization.Encoding.PEM),
        chain_content,
        read_file(params["key_path"]),
    )
    return write_file(
        params["fritzbox_bundle_path"],
        content,
        params["owner"],
        params["group"],
        params["key_mode"],
        force=params["force"],
    )


def _base_url(params: dict, name: str, key: str) -> str:
    """Derive an AIA or CDP URL from explicit or base URL parameters."""
    value = str(params.get(key) or "").rstrip("/")
    if not value:
        base_url = str(params.get("base_url") or "").rstrip("/")
        if base_url:
            suffix = "aia" if key == "aia_base_url" else "crl"
            value = f"{base_url}/{suffix}"
    return f"{value}/{name}" if value else ""


def _with_derived_paths(
    params: dict,
    *,
    authority: bool,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
) -> dict:
    """Derive managed file paths and publication URLs from base parameters."""
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    formats = normalize_formats(result.get("formats"))
    result["formats"] = formats
    result["base_dir"] = base_dir
    result["authority"] = authority

    if authority:
        ca_file = f"{name}-ca"
        result["lock_path"] = ca_lock_path(base_dir, "authority", name)
        result["key_path"] = f"{base_dir}/private/{ca_file}.key"
        result["csr_path"] = f"{base_dir}/csr/{ca_file}.csr"
        result["cert_path"] = f"{base_dir}/ca/{ca_file}.pem"
        result["der_path"] = f"{base_dir}/ca/{ca_file}.der" if "der" in formats else ""
        result["txt_path"] = f"{base_dir}/ca/{ca_file}.txt" if "txt" in formats else ""
        if signed:
            parent = str(result["parent"])
            parent_file = f"{parent}-ca"
            result["signer_lock_path"] = ca_lock_path(base_dir, "authority", parent)
            result["signer_cert_path"] = f"{base_dir}/ca/{parent_file}.pem"
            result["signer_key_path"] = f"{base_dir}/private/{parent_file}.key"
        authority_file = f"{ca_file}"
        result["aia_url"] = _base_url(result, f"{authority_file}.der", "aia_base_url")
        result["cdp_url"] = _base_url(result, f"{authority_file}.crl", "cdp_base_url")
        result["directory_path"] = None
        result["chain_src_path"] = ""
        result["chain_path"] = ""
        return result

    output_dir = str(result.get("output_dir") or f"{base_dir}/certs/{name}").rstrip("/")
    issuer = str(result["issuer"])
    issuer_file = f"{issuer}-ca"
    external_csr = _external_csr_configured(result)
    result["lock_path"] = ca_lock_path(base_dir, "certificate", name)
    result["output_dir"] = output_dir
    result["key_path"] = "" if external_csr else f"{output_dir}/{name}.key"
    result["csr_path"] = f"{base_dir}/csr/{name}.csr"
    result["cert_path"] = f"{output_dir}/{name}.pem"
    result["der_path"] = f"{output_dir}/{name}.der" if "der" in formats else ""
    result["txt_path"] = f"{output_dir}/{name}.txt" if "txt" in formats else ""
    result["fullchain_path"] = (
        f"{output_dir}/{name}-fullchain.pem" if "fullchain" in formats else ""
    )
    result["fritzbox_bundle_path"] = (
        f"{output_dir}/{name}-fritzbox.pem" if "fritzbox" in formats else ""
    )
    result["pkcs12_paths"] = {
        export_format: f"{output_dir}/{name}.{export_format}"
        for export_format in ("pfx", "p12")
        if export_format in formats
    }
    result["directory_path"] = output_dir if manage_directory else None
    if signed:
        result["signer_lock_path"] = ca_lock_path(base_dir, "authority", issuer)
        result["signer_cert_path"] = f"{base_dir}/ca/{issuer_file}.pem"
        result["signer_key_path"] = f"{base_dir}/private/{issuer_file}.key"
    result["chain_src_path"] = (
        f"{base_dir}/chains/{issuer_file}-chain.pem" if manage_chain else ""
    )
    result["chain_path"] = f"{output_dir}/{name}-chain.pem" if manage_chain else ""
    result["aia_url"] = _base_url(result, f"{issuer_file}.der", "aia_base_url")
    result["cdp_url"] = _base_url(result, f"{issuer_file}.crl", "cdp_base_url")
    return result


def ca_authority_argument_spec(
    *,
    defaults: dict | None = None,
):
    """Build the argument spec for CA authority modules."""
    spec: dict[str, dict[str, Any]] = {
        "base_dir": {"type": "path", "required": True},
        "base_url": {"type": "str", "default": ""},
        "ca_name": {"type": "str", "default": ""},
        "name": {"type": "str", "required": True},
        "parent": {"type": "str", "default": ""},
        "formats": {
            "type": "list",
            "elements": "str",
            "default": ["pem", "der", "txt"],
        },
        "key_type": {"type": "str", "default": "RSA"},
        "key_size": {"type": "int", "default": 4096},
        "subject_ordered": {"type": "list", "elements": "dict", "default": []},
        "common_name": {"type": "str"},
        "email": {"type": "str"},
        "subject": {"type": "dict", "default": {}},
        "basic_constraints": {
            "type": "list",
            "elements": "str",
        },
        "key_usage": {"type": "list", "elements": "str"},
        "key_usage_critical": {"type": "bool", "default": True},
        "extended_key_usage": {"type": "list", "elements": "str", "default": []},
        "extended_key_usage_critical": {"type": "bool", "default": False},
        "san": {"type": "list", "elements": "str", "default": []},
        "san_critical": {"type": "bool", "default": False},
        "aia_base_url": {"type": "str", "default": ""},
        "cdp_base_url": {"type": "str", "default": ""},
        "raw_extensions": {"type": "list", "elements": "dict", "default": []},
        "pkinit": {"type": "dict", "default": {}},
        "days": {"type": "int", "required": True},
        "digest": {"type": "str", "default": "sha384"},
        "include_identifiers": {"type": "bool", "default": True},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "key_mode": {"type": "str", "default": "0600"},
        "public_mode": {"type": "str", "default": "0644"},
        "force": {"type": "bool", "default": False},
        "key_passphrase": {
            "type": "str",
            "required": True,
            "no_log": True,
        },
        "parent_key_passphrase": {
            "type": "str",
            "no_log": True,
        },
    }
    for key, value in (defaults or {}).items():
        if key in spec:
            spec[key]["default"] = value
    return spec


def normalize_formats(formats: Any) -> list[str]:
    """Return normalized certificate output format names."""
    if isinstance(formats, str):
        raise ValueError("formats must be a list")
    return [str(item).lower() for item in (formats or [])]


def certificate_params(
    params: dict, *, default_formats: list[str] | None = None
) -> dict:
    """Merge certificate dictionaries with explicit module parameters."""
    result: dict[str, Any] = {
        "base_url": "",
        "output_dir": None,
        "csr_content": None,
        "csr_source_path": None,
        "key_type": "RSA",
        "key_size": 4096,
        "key_passphrase": None,
        "subject_ordered": [],
        "email": None,
        "subject": {},
        "basic_constraints": ["CA:FALSE"],
        "key_usage": [],
        "key_usage_critical": True,
        "extended_key_usage": [],
        "extended_key_usage_critical": False,
        "san": [],
        "san_critical": False,
        "aia_base_url": "",
        "cdp_base_url": "",
        "raw_extensions": [],
        "pkinit": {},
        "renewal": {},
        "include_identifiers": True,
        "key_mode": "0600",
        "public_mode": "0644",
        "directory_mode": "0755",
    }
    certificate = dict(params.get("certificate") or {})
    certificate_formats = certificate.pop("formats", None)
    module_formats = params.get("formats")
    module_params = {
        key: value
        for key, value in params.items()
        if key not in ("certificate", "formats") and value is not None
    }
    result.update(certificate)
    result.update(module_params)
    if result.get("csr_path"):
        result["csr_source_path"] = result.pop("csr_path")
    formats = module_formats if module_formats is not None else certificate_formats
    if formats is None:
        formats = (
            default_formats if default_formats is not None else ["pem", "der", "txt"]
        )
    result["formats"] = normalize_formats(formats)
    result["signer_key_passphrase"] = result.pop("issuer_key_passphrase")
    return result


def ensure_x509(
    params: dict,
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> dict:
    """Ensure X.509 key, CSR, certificate, exports, and chain artifacts."""
    params = _with_derived_paths(
        params,
        authority=authority,
        signed=signed,
        manage_directory=manage_directory,
        manage_chain=manage_chain,
    )
    lock_paths = [params["lock_path"]]
    if authority:
        lock_paths.append(ca_lock_path(params["base_dir"], "authority", "__graph__"))
    if signed:
        lock_paths.append(params["signer_lock_path"])
    with file_locks(lock_paths):
        return _ensure_x509_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )


def ensure_x509_many(
    params_list: list[dict],
    *,
    signed: bool,
    authority: bool = False,
    manage_directory: bool = False,
    manage_chain: bool = False,
) -> list[dict]:
    """Ensure multiple X.509 objects while caching shared signer material."""
    derived = [
        _with_derived_paths(
            params,
            authority=authority,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )
        for params in params_list
    ]
    if not signed or authority:
        return [
            ensure_x509(
                params,
                signed=signed,
                authority=authority,
                manage_directory=manage_directory,
                manage_chain=manage_chain,
            )
            for params in params_list
        ]

    groups: dict[str, list[tuple[int, dict]]] = {}
    order: list[str] = []
    for index, params in enumerate(derived):
        signer_lock_path = str(params["signer_lock_path"])
        if signer_lock_path not in groups:
            groups[signer_lock_path] = []
            order.append(signer_lock_path)
        groups[signer_lock_path].append((index, params))

    results: list[dict] = [{} for _ in derived]
    for signer_lock_path in order:
        group = groups[signer_lock_path]
        lock_paths = [signer_lock_path, *(params["lock_path"] for _, params in group)]
        with file_locks(lock_paths):
            first_params = group[0][1]
            signer_key = load_private_key(
                first_params["signer_key_path"],
                first_params["signer_key_passphrase"],
            )
            signer_cert = load_certificate(first_params["signer_cert_path"])
            needs_chain = any(
                set(params["formats"]).intersection({"pfx", "p12", "fullchain", "fritzbox"})
                for _, params in group
            )
            chain_content = _chain_content(first_params, signer_cert) if needs_chain else b""
            extra_certs = _chain_certificates(first_params, signer_cert) if needs_chain else []
            for index, params in group:
                results[index] = _ensure_x509_locked(
                    params,
                    signed=signed,
                    manage_directory=manage_directory,
                    manage_chain=manage_chain,
                    signer_key=signer_key,
                    signer_cert=signer_cert,
                    chain_content=chain_content,
                    extra_certs=extra_certs,
                )
    return results


def _ensure_x509_from_csr_locked(
    params: dict,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer_key=None,
    signer_cert=None,
    chain_content: bytes | None = None,
) -> dict:
    """Ensure one signed certificate from an externally supplied CSR."""
    if not signed:
        raise ValueError("CSR signing requires an issuing CA")

    unsupported = sorted(
        set(params["formats"]).intersection({"pfx", "p12", "fritzbox"})
    )
    if unsupported:
        raise ValueError(
            "CSR signing cannot create formats that require a private key: "
            + ", ".join(unsupported)
        )

    directory_changed = False
    chain_changed = False
    if manage_directory:
        directory_changed = _ensure_directory(
            params["directory_path"],
            params["owner"],
            params["group"],
            params["directory_mode"],
        )

    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal_decision = _renewal_decision(params, existing_cert)
    if renewal_decision["rekey"]:
        renewal_decision = dict(renewal_decision)
        renewal_decision["rekey"] = False

    csr, csr_changed = _ensure_external_csr(params)
    subject = csr.subject

    if signer_key is None:
        signer_key = load_private_key(
            params["signer_key_path"], params["signer_key_passphrase"]
        )
    if signer_cert is None:
        signer_cert = load_certificate(params["signer_cert_path"])

    cert_extensions = _desired_extensions(
        params,
        csr.public_key(),
        signer_cert.public_key(),
        _csr_subject_alt_name(csr),
    )
    cert, cert_changed = _ensure_certificate(
        params,
        csr.public_key(),
        subject,
        cert_extensions,
        signer_key,
        signer_cert,
        renewal_decision,
        existing_cert,
    )
    der_changed = _ensure_der(params, cert)
    txt_changed = ensure_txt(params, cert)
    if manage_chain:
        chain_changed = _ensure_chain(params)

    chain_content = chain_content if chain_content is not None else b""
    if "fullchain" in params["formats"] and not chain_content:
        chain_content = _chain_content(params, signer_cert)
    fullchain_changed = _ensure_fullchain_bundle(params, cert, chain_content)

    return {
        "changed": directory_changed
        or csr_changed
        or cert_changed
        or der_changed
        or txt_changed
        or chain_changed
        or fullchain_changed,
        "directory_changed": directory_changed,
        "archive_changed": False,
        "key_changed": False,
        "csr_changed": csr_changed,
        "cert_changed": cert_changed,
        "der_changed": der_changed,
        "txt_changed": txt_changed,
        "chain_changed": chain_changed,
        "pkcs12_changed": False,
        "fullchain_changed": fullchain_changed,
        "fritzbox_bundle_changed": False,
        "formats": params["formats"],
        "renewal": renewal_decision,
        "csr_mode": True,
        "common_name": _csr_common_name(csr),
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
        "pkcs12_paths": {},
        "fullchain_path": params.get("fullchain_path", ""),
        "fritzbox_bundle_path": "",
    }


def _ensure_x509_locked(
    params: dict,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
    signer_key=None,
    signer_cert=None,
    chain_content: bytes | None = None,
    extra_certs: list[Any] | None = None,
) -> dict:
    """Ensure one X.509 object while holding its object lock."""
    if _external_csr_configured(params):
        return _ensure_x509_from_csr_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
            signer_key=signer_key,
            signer_cert=signer_cert,
            chain_content=chain_content,
        )

    directory_changed = False
    chain_changed = False
    if manage_directory:
        directory_changed = _ensure_directory(
            params["directory_path"],
            params["owner"],
            params["group"],
            params["directory_mode"],
        )
    existing_cert = _load_existing_certificate(params["cert_path"])
    renewal_decision = _renewal_decision(params, existing_cert)
    archive_changed = False
    if renewal_decision["rekey"]:
        archive_changed = _archive_existing_material(
            params,
            existing_cert,
            include_private_key=True,
        )
    key, key_changed = _ensure_key(
        params,
        rekey=renewal_decision["rekey"],
        existing_cert=existing_cert,
    )
    subject = subject_from_params(params)
    signer_key = signer_key or key
    if signed:
        if signer_key is key:
            signer_key = load_private_key(
                params["signer_key_path"], params["signer_key_passphrase"]
            )
        if signer_cert is None:
            signer_cert = load_certificate(params["signer_cert_path"])

    signer_public_key = (
        signer_cert.public_key() if signer_cert is not None else key.public_key()
    )
    csr_extensions = _desired_extensions(params, key.public_key(), signer_public_key)
    _, csr_changed = _ensure_csr(params, key, subject, csr_extensions)
    cert_extensions = _desired_extensions(params, key.public_key(), signer_public_key)
    cert, cert_changed = _ensure_certificate(
        params,
        key,
        subject,
        cert_extensions,
        signer_key,
        signer_cert,
        renewal_decision,
        existing_cert,
    )
    der_changed = _ensure_der(params, cert)
    txt_changed = ensure_txt(params, cert)
    if manage_chain:
        chain_changed = _ensure_chain(params)
    chain_content = chain_content if chain_content is not None else b""
    extra_certs = extra_certs if extra_certs is not None else []
    if not params["authority"] and set(params["formats"]).intersection(
        {"pfx", "p12", "fullchain", "fritzbox"}
    ):
        if not chain_content:
            chain_content = _chain_content(params, signer_cert)
        if not extra_certs:
            extra_certs = _chain_certificates(params, signer_cert)
    pkcs12_changed, pkcs12_paths = _ensure_pkcs12_exports(
        params,
        key,
        cert,
        extra_certs,
    )
    fullchain_changed = _ensure_fullchain_bundle(params, cert, chain_content)
    fritzbox_bundle_changed = _ensure_fritzbox_bundle(params, cert, chain_content)

    return {
        "changed": directory_changed
        or archive_changed
        or key_changed
        or csr_changed
        or cert_changed
        or der_changed
        or txt_changed
        or chain_changed
        or pkcs12_changed
        or fullchain_changed
        or fritzbox_bundle_changed,
        "directory_changed": directory_changed,
        "archive_changed": archive_changed,
        "key_changed": key_changed,
        "csr_changed": csr_changed,
        "cert_changed": cert_changed,
        "der_changed": der_changed,
        "txt_changed": txt_changed,
        "chain_changed": chain_changed,
        "pkcs12_changed": pkcs12_changed,
        "fullchain_changed": fullchain_changed,
        "fritzbox_bundle_changed": fritzbox_bundle_changed,
        "formats": params["formats"],
        "renewal": renewal_decision,
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
        "pkcs12_paths": pkcs12_paths,
        "fullchain_path": params.get("fullchain_path", ""),
        "fritzbox_bundle_path": params.get("fritzbox_bundle_path", ""),
    }
