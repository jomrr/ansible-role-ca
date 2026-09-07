"""Ca x509 encoding helpers."""

from __future__ import annotations


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
