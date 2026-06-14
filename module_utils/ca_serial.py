"""Shared serial number and hexadecimal helpers for CA role modules."""

from __future__ import annotations

import re
from typing import Any

SERIAL_CLEANUP_RE = re.compile(r"[^0-9A-Fa-f]")


def colon_hex(data: bytes | None) -> str:
    """Return colon-separated uppercase hex."""
    if data is None:
        return ""
    return ":".join(f"{byte:02X}" for byte in data)


def serial_hex(value: int) -> str:
    """Return an even-length uppercase certificate serial."""
    text = f"{value:X}"
    return text if len(text) % 2 == 0 else f"0{text}"


def parse_serial(value: Any) -> int:
    """Parse decimal, hexadecimal, or colon-separated certificate serials."""
    if isinstance(value, int):
        return value
    text = str(value)
    if ":" in text:
        return int(SERIAL_CLEANUP_RE.sub("", text), 16)
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def normalize_hex(value: Any) -> str:
    """Return uppercase hexadecimal text without separators."""
    return SERIAL_CLEANUP_RE.sub("", str(value)).upper()
