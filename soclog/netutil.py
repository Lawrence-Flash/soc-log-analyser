"""Small IP helpers. No network access."""

from __future__ import annotations

import ipaddress


def usable_ip(value: object) -> str | None:
    """Return a host IP, or None for blanks, placeholders, and loopback.

    Documentation ranges such as 203.0.113.0/24 are kept. They are normal
    unicast addresses and the sample logs use them on purpose.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    if "%" in text:
        text = text.split("%", 1)[0]
    if text.lower() in {"", "-", "local", "unknown", "::1", "0.0.0.0"}:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)
