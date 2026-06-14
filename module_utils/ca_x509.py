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
        file_lock,
        read_file,
        sanitize_error,
        set_attrs,
        write_file,
    )
    from ansible.module_utils.ca_text import ensure_txt  # type: ignore[import-not-found,import-untyped]
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
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


def _as_bool(value: Any) -> bool:
    """Return a predictable boolean for module dictionaries."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int = 0) -> int:
    """Return an integer with an empty-value default."""
    if value in (None, ""):
        return default
    return int(value)


def _parse_datetime(value: Any) -> _dt.datetime | None:
    """Parse an ISO-8601 or ASN.1-style UTC timestamp."""
    if value in (None, ""):
        return None
    if isinstance(value, _dt.datetime):
        result = value
    else:
        text = str(value).strip()
        if re.match(r"^\d{14}Z$", text):
            result = _dt.datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            result = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if result.tzinfo is None:
        return result.replace(tzinfo=_dt.timezone.utc)
    return result.astimezone(_dt.timezone.utc)


def _serial_hex(value: int) -> str:
    """Return an even-length uppercase certificate serial."""
    text = f"{value:X}"
    return text if len(text) % 2 == 0 else f"0{text}"


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


def _public_key_bytes(key) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a private key."""
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _cert_public_key_bytes(cert) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a certificate."""
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _csr_public_key_bytes(csr) -> bytes:
    """Return DER SubjectPublicKeyInfo bytes for a CSR."""
    return csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_csr(path: str):
    """Load a PEM certificate signing request from disk."""
    return x509.load_pem_x509_csr(read_file(path))


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
    """Return a certificate not-before timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    value = cert.not_valid_before
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _load_existing_certificate(path: str):
    """Return an existing certificate or None when it cannot be loaded."""
    try:
        return load_certificate(path)
    except Exception:
        return None


def _renewal_policy(params: dict) -> dict[str, Any]:
    """Return normalized renewal policy values."""
    renewal = dict(params.get("renewal") or {})
    return {
        "warn_before_days": _as_int(renewal.get("warn_before_days"), 0),
        "renew_before_days": _as_int(renewal.get("renew_before_days"), 0),
        "renew_at": str(renewal.get("renew_at") or ""),
        "rekey": _as_bool(renewal.get("rekey", False)),
    }


def _renewal_decision(params: dict, existing_cert) -> dict[str, Any]:
    """Return renewal and rekey decisions for an existing certificate."""
    policy = _renewal_policy(params)
    now = _dt.datetime.now(_dt.timezone.utc)
    decision: dict[str, Any] = {
        "renew": False,
        "rekey": False,
        "reason": "",
        "warning": False,
        "days_remaining": None,
        "policy": policy,
    }
    if params.get("force"):
        decision.update({"renew": True, "rekey": True, "reason": "force"})
        return decision
    if existing_cert is None:
        decision["reason"] = "missing"
        return decision

    not_before = _not_valid_before_utc(existing_cert)
    not_after = _not_valid_after_utc(existing_cert)
    seconds_remaining = (not_after - now).total_seconds()
    decision["days_remaining"] = max(0, int(seconds_remaining // 86400))

    if policy["warn_before_days"] > 0:
        warning_at = not_after - _dt.timedelta(days=policy["warn_before_days"])
        decision["warning"] = now >= warning_at

    if not_after <= now:
        decision.update({"renew": True, "reason": "expired"})
    else:
        renew_at = _parse_datetime(policy["renew_at"])
        if renew_at is not None and not_before < renew_at <= now:
            decision.update({"renew": True, "reason": "scheduled"})
        elif policy["renew_before_days"] > 0:
            renew_window = not_after - _dt.timedelta(days=policy["renew_before_days"])
            if now >= renew_window:
                decision.update({"renew": True, "reason": "renewal_window"})

    if decision["renew"] and policy["rekey"]:
        decision["rekey"] = True
    return decision


def _archive_dir(params: dict, cert) -> str:
    """Return the archive directory for one existing certificate generation."""
    namespace = "authorities" if params.get("authority") else "certificates"
    serial = _serial_hex(cert.serial_number)
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


def _desired_extensions(params, public_key, signer_public_key):
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
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
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
            current_time = _dt.datetime.now(_dt.timezone.utc)
            if _not_valid_after_utc(existing) <= current_time:
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
    result["lock_path"] = ca_lock_path(base_dir, "certificate", name)
    result["output_dir"] = output_dir
    result["key_path"] = f"{output_dir}/{name}.key"
    result["csr_path"] = f"{base_dir}/csr/{name}.csr"
    result["cert_path"] = f"{output_dir}/{name}.pem"
    result["der_path"] = f"{output_dir}/{name}.der" if "der" in formats else ""
    result["txt_path"] = f"{output_dir}/{name}.txt" if "txt" in formats else ""
    result["directory_path"] = output_dir if manage_directory else None
    if signed:
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
        "renewal": {"type": "dict", "default": {}},
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
    result = {
        "base_url": "",
        "output_dir": None,
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
    with file_lock(params["lock_path"]):
        return _ensure_x509_locked(
            params,
            signed=signed,
            manage_directory=manage_directory,
            manage_chain=manage_chain,
        )


def _ensure_x509_locked(
    params: dict,
    *,
    signed: bool,
    manage_directory: bool,
    manage_chain: bool,
) -> dict:
    """Ensure one X.509 object while holding its object lock."""
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
    signer_key = key
    signer_cert = None
    if signed:
        signer_key = load_private_key(
            params["signer_key_path"], params["signer_key_passphrase"]
        )
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

    return {
        "changed": directory_changed
        or archive_changed
        or key_changed
        or csr_changed
        or cert_changed
        or der_changed
        or txt_changed
        or chain_changed,
        "directory_changed": directory_changed,
        "archive_changed": archive_changed,
        "key_changed": key_changed,
        "csr_changed": csr_changed,
        "cert_changed": cert_changed,
        "der_changed": der_changed,
        "txt_changed": txt_changed,
        "chain_changed": chain_changed,
        "formats": params["formats"],
        "renewal": renewal_decision,
        "csr_path": params["csr_path"],
        "cert_path": params["cert_path"],
        "txt_path": params["txt_path"],
    }
