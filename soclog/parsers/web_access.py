"""Parser for Apache and Nginx combined access logs."""

from __future__ import annotations

import re

from soclog.models import Event
from soclog.netutil import usable_ip
from soclog.timeparse import parse_timestamp

# Combined: host ident user [time] "request" status size "referer" "user-agent"
COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r"(?P<status>\d{3})\s+\S+\s+"
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_web_access(text: str) -> tuple[list[Event], int]:
    """Return one event per combined-log request, plus an unparsed count."""
    events: list[Event] = []
    unparsed = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = COMBINED.match(stripped)
        if not match:
            unparsed += 1
            continue
        try:
            timestamp = parse_timestamp(match.group("ts"))
            status = int(match.group("status"))
        except ValueError:
            unparsed += 1
            continue
        events.append(
            Event(
                timestamp=timestamp,
                event_type="http_request",
                raw=stripped,
                src_ip=usable_ip(match.group("ip")),
                user=_user(match.group("user")),
                method=match.group("method"),
                path=match.group("path"),
                status=status,
                user_agent=match.group("ua"),
                source_format="web-access",
            )
        )
    return events, unparsed


def _user(value: str) -> str | None:
    if value in {"", "-"}:
        return None
    return value
