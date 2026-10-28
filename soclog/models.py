"""Shared records for parsed events and alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def severity_at_least(severity: str, minimum: str) -> bool:
    """Return True when `severity` is as serious as `minimum`."""
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]


@dataclass
class Event:
    """One normalised log record. Timestamps are naive UTC."""

    timestamp: datetime
    event_type: str
    raw: str
    src_ip: str | None = None
    user: str | None = None
    actor: str | None = None
    group: str | None = None
    command: str | None = None
    path: str | None = None
    method: str | None = None
    status: int | None = None
    user_agent: str | None = None
    event_id: int | None = None
    hostname: str | None = None
    source_format: str = ""


@dataclass
class ParseResult:
    """Outcome of reading one log file."""

    path: str
    format: str
    events: list[Event]
    unparsed: int


@dataclass
class Alert:
    """One detection result. `id` is assigned after severity filtering."""

    id: str
    rule_id: str
    rule_type: str
    title: str
    severity: str
    mitre_id: str
    mitre_name: str
    timestamp_start: datetime
    timestamp_end: datetime
    source_ip: str | None
    user: str | None
    evidence: list[str]
    what_to_do_next: str
    event_count: int
    source: str = ""
    source_format: str = ""
    suppress_if_covered_by: str = ""


@dataclass
class Analysis:
    """Parsed events and the alerts raised from them."""

    result: ParseResult
    alerts: list[Alert] = field(default_factory=list)
