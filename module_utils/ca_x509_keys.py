"""Ca x509 keys helpers."""

from __future__ import annotations

import re
from typing import Any

from ansible.module_utils.ca_file import read_file
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
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
