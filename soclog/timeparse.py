"""Timestamp parsing for syslog, access logs, and Windows exports.

Every timestamp is returned as a naive datetime in UTC. Callers that pass
`default_year` (used for traditional syslog lines, which have no year) get
that year exactly. Otherwise a timestamp more than a day in the future is
treated as the previous year, which is the usual December-log-in-January case.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_FRACTION = re.compile(
    r"(?P<head>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tail>Z|[+-]\d{2}:?\d{2})?$"
)
_DOTNET_DATE = re.compile(r"^/Date\((?P<ms>-?\d+)\)/$")


def parse_timestamp(
    value: str,
    *,
    default_year: int | None = None,
    now: datetime | None = None,
) -> datetime:
    """Parse one timestamp into naive UTC."""
    text = value.strip()
    if not text:
        raise ValueError("empty timestamp")

    dotnet = _DOTNET_DATE.fullmatch(text)
    if dotnet:
        millis = int(dotnet.group("ms"))
        return datetime.fromtimestamp(millis / 1000, timezone.utc).replace(tzinfo=None)

    iso = _parse_iso(text)
    if iso is not None:
        return iso

    apache = _parse_apache(text)
    if apache is not None:
        return apache

    return _parse_syslog(text, default_year=default_year, now=now)


def _parse_iso(text: str) -> datetime | None:
    match = _FRACTION.fullmatch(text)
    if not match:
        return None
    frac = (match.group("frac") or "")[:6].ljust(6, "0") if match.group("frac") else ""
    tail = match.group("tail") or ""
    if tail == "Z":
        tail = "+00:00"
    elif re.fullmatch(r"[+-]\d{4}", tail):
        tail = f"{tail[:3]}:{tail[3:]}"
    body = match.group("head")
    if frac:
        body = f"{body}.{frac}"
    try:
        parsed = datetime.fromisoformat(body + tail)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _parse_apache(text: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    return None


def _parse_syslog(text: str, *, default_year: int | None, now: datetime | None) -> datetime:
    normalised = re.sub(r"\s+", " ", text.strip())
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    year = default_year if default_year is not None else current.year
    try:
        parsed = datetime.strptime(f"{year} {normalised}", "%Y %b %d %H:%M:%S")
    except ValueError as exc:
        raise ValueError(f"unrecognised timestamp: {text}") from exc
    if default_year is None and parsed - current > timedelta(days=1):
        parsed = parsed.replace(year=year - 1)
    return parsed


def format_timestamp(value: datetime) -> str:
    """Format a naive UTC datetime for reports."""
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
