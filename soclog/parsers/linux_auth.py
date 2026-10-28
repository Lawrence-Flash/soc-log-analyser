"""Parser for Linux auth.log and secure (sshd, sudo, useradd, usermod)."""

from __future__ import annotations

import re
from enum import Enum

from soclog.models import Event
from soclog.netutil import usable_ip
from soclog.timeparse import parse_timestamp

_ISO = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_SYSLOG_TS = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
LINE = re.compile(
    rf"^(?P<ts>{_ISO}|{_SYSLOG_TS})\s+"
    rf"(?P<host>\S+)\s+"
    rf"(?P<proc>[\w./+-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    rf"(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"Failed password for (?:invalid user |illegal user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_NEW_USER = re.compile(r"\bnew user:\s+name=(?P<user>[^,\s]+)")
_GROUP = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_SHADOW_GROUP = re.compile(r"add '[^']+' to shadow group ")
_ACCOUNT_PROCESSES = {"useradd", "adduser", "usermod"}


class _Line(Enum):
    QUIET = "quiet"
    UNPARSED = "unparsed"


def parse_linux_auth(
    text: str,
    *,
    default_year: int | None = None,
    now=None,
) -> tuple[list[Event], int]:
    """Return modelled events and a count of lines that are not syslog."""
    events: list[Event] = []
    unparsed = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parsed = LINE.match(stripped)
        if not parsed:
            unparsed += 1
            continue
        event = _classify(stripped, parsed, default_year=default_year, now=now)
        if event is _Line.UNPARSED:
            unparsed += 1
        elif event is not _Line.QUIET:
            events.append(event)
    return events, unparsed


def _classify(raw: str, match: re.Match[str], *, default_year: int | None, now) -> Event | _Line:
    try:
        timestamp = parse_timestamp(match.group("ts"), default_year=default_year, now=now)
    except ValueError:
        return _Line.UNPARSED
    message = match.group("msg")
    process = match.group("proc")
    base = {
        "timestamp": timestamp,
        "raw": raw,
        "hostname": match.group("host"),
        "source_format": "linux-auth",
    }

    if process.startswith("sshd"):
        failed = _FAILED.search(message)
        if failed:
            return Event(
                event_type="ssh_failed",
                user=_clean_user(failed.group("user")),
                src_ip=usable_ip(failed.group("ip")),
                **base,
            )
        accepted = _ACCEPTED.search(message)
        if accepted:
            return Event(
                event_type="ssh_success",
                user=_clean_user(accepted.group("user")),
                src_ip=usable_ip(accepted.group("ip")),
                **base,
            )
        return _Line.QUIET

    if process == "sudo":
        command = re.search(r"\bCOMMAND=(?P<cmd>.+)$", message)
        user = re.match(r"\s*(?P<user>\S+)\s+:", message)
        if command and user:
            return Event(
                event_type="sudo_command",
                user=_clean_user(user.group("user")),
                command=command.group("cmd").strip(),
                **base,
            )
        return _Line.QUIET

    if process in _ACCOUNT_PROCESSES and _SHADOW_GROUP.search(message):
        return _Line.QUIET

    if process in {"useradd", "adduser"}:
        created = _NEW_USER.search(message)
        if created:
            return Event(event_type="user_created", user=_clean_user(created.group("user")), **base)
        return _Line.QUIET

    if process == "usermod":
        group = _GROUP.search(message)
        if group:
            return Event(
                event_type="group_membership",
                user=_clean_user(group.group("user")),
                group=group.group("group").strip(),
                **base,
            )
        return _Line.QUIET

    return _Line.QUIET


def _clean_user(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if text in {"", "-"}:
        return None
    return text
