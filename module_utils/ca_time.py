"""Shared UTC timestamp helpers for CA role modules."""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

ASN1_UTC_RE = re.compile(r"^\d{14}Z$")


def utc(value: _dt.datetime) -> _dt.datetime:
    """Return a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def now_utc(*, strip_microseconds: bool = False) -> _dt.datetime:
    """Return the current UTC time."""
    value = _dt.datetime.now(_dt.timezone.utc)
    if strip_microseconds:
        return value.replace(microsecond=0)
    return value


def parse_datetime(value: Any) -> _dt.datetime | None:
    """Parse an ISO-8601 or ASN.1-style UTC timestamp."""
    if value in (None, ""):
        return None
    if isinstance(value, _dt.datetime):
        return utc(value)
    text = str(value).strip()
    if ASN1_UTC_RE.match(text):
        return _dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(
            tzinfo=_dt.timezone.utc
        )
    return utc(_dt.datetime.fromisoformat(text.replace("Z", "+00:00")))


def timestamp_z(value: _dt.datetime) -> str:
    """Return an ISO-8601 UTC timestamp with a Z suffix."""
    return utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_iso(value: _dt.datetime) -> str:
    """Return an ISO-8601 UTC timestamp with an explicit offset."""
    return utc(value).replace(microsecond=0).isoformat()


def datetime_text(value: _dt.datetime) -> str:
    """Return a stable UTC timestamp for certificate text exports."""
    return utc(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def certificate_not_valid_before(cert: Any) -> _dt.datetime:
    """Return a certificate not-before timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_before_utc", None)
    return value if value is not None else utc(cert.not_valid_before)


def certificate_not_valid_after(cert: Any) -> _dt.datetime:
    """Return a certificate not-after timestamp normalized to UTC."""
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else utc(cert.not_valid_after)


def object_datetime(obj: Any, name: str) -> _dt.datetime:
    """Return a named cryptography timestamp across versioned UTC attributes."""
    value = getattr(obj, f"{name}_utc", None)
    if value is not None:
        return value
    return utc(getattr(obj, name))
