"""Guess which parser a file needs. The guess is only used for --format auto."""

from __future__ import annotations

import json
import re

from soclog.parsers.linux_auth import LINE as LINUX_LINE
from soclog.parsers.web_access import COMBINED

FORMATS = ("auto", "linux-auth", "web-access", "windows-json", "windows-csv")
_EVENT_KEYS = {"eventid", "eventcode", "id"}


def detect_format(text: str) -> str:
    """Return a concrete format name or raise ValueError."""
    stripped = text.lstrip("\ufeff")
    if not stripped.strip():
        raise ValueError("log is empty")

    sample: list[str] = []
    for line in stripped.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        sample.append(item)
        if len(sample) >= 40:
            break
    if not sample:
        raise ValueError("log has no records")

    if _looks_like_windows_json(stripped, sample):
        return "windows-json"

    header_key = re.sub(r"[^a-z0-9]", "", sample[0].lower())
    if "," in sample[0] and "eventid" in header_key:
        return "windows-csv"

    web = sum(1 for line in sample if COMBINED.match(line))
    linux = sum(1 for line in sample if LINUX_LINE.match(line))
    if web == 0 and linux == 0:
        raise ValueError("could not detect the log format; pass --format")
    if web == linux:
        raise ValueError("log format is ambiguous; pass --format")
    return "web-access" if web > linux else "linux-auth"


def _looks_like_windows_json(text: str, sample: list[str]) -> bool:
    first = sample[0]
    if not first.startswith("{") and not first.startswith("["):
        return False
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _looks_like_ndjson(sample)
    return _json_shape(data)


def _looks_like_ndjson(sample: list[str]) -> bool:
    objects = 0
    for line in sample:
        if not line.startswith("{"):
            return False
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(item, dict) or not _has_event_id(item):
            return False
        objects += 1
    return objects > 0


def _json_shape(data: object) -> bool:
    if isinstance(data, list):
        if not data:
            return True
        return all(isinstance(item, dict) for item in data[:5]) and _has_event_id(data[0])
    if isinstance(data, dict):
        for key in ("events", "Events", "records", "Records"):
            value = data.get(key)
            if isinstance(value, list):
                return True
        return _has_event_id(data)
    return False


def _has_event_id(item: dict) -> bool:
    keys = {re.sub(r"[^a-z0-9]", "", str(key).lower()) for key in item}
    return bool(keys & _EVENT_KEYS)
