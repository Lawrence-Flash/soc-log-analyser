"""Parser for Windows Security events exported as JSON or CSV.

Accepts a JSON list, a wrapper object with an events/records list, one JSON
object, or newline-delimited JSON. CSV needs a header row. Field names are
matched loosely (EventID, Event ID, event_id).
"""

from __future__ import annotations

import csv
import io
import json
import re
from enum import Enum

from soclog.models import Event
from soclog.netutil import usable_ip
from soclog.timeparse import parse_timestamp


class _Decision(Enum):
    """A record we understood but do not model, or one we could not read."""

    QUIET = "quiet"
    UNPARSED = "unparsed"

# Logon types that represent a person or a remote authentication rather than a
# service or batch job. Missing logon type is kept, because many CSV exports
# omit it. See the limitations in the README.
_LOGON_TYPES = {2, 3, 7, 8, 10, 11}
_GROUP_EVENTS = {4728, 4732, 4756}
_NOISE_USERS = {
    "-",
    "system",
    "local service",
    "network service",
    "anonymous logon",
}
_TIME_KEYS = ("timecreated", "timestamp", "utctime", "timegenerated", "systemtime")
_HOST_KEYS = ("computer", "computername", "machinename", "hostname", "host")
_IP_KEYS = ("ipaddress", "sourceip", "sourceaddress", "clientip", "clientaddress", "ip")
_TARGET_USER_KEYS = ("targetusername", "targetuser", "accountname")
_SUBJECT_USER_KEYS = ("subjectusername", "subjectuser")
_MEMBER_KEYS = ("membername", "membersid")
_GROUP_KEYS = ("groupname", "group")
_COMMAND_KEYS = ("commandline", "processcommandline")
_PROCESS_KEYS = ("newprocessname", "processname", "image")
_LOGON_KEYS = ("logontype",)
_MESSAGE_KEYS = ("message", "msg")


def parse_windows_json(text: str) -> tuple[list[Event], int]:
    """Parse a JSON or NDJSON Windows export."""
    records, unparsed, raw_lines = _load_json_records(text)
    events: list[Event] = []
    for record, raw in zip(records, raw_lines, strict=True):
        event = event_from_mapping(record, raw=raw, source_format="windows-json")
        if isinstance(event, Event):
            events.append(event)
        elif event is _Decision.UNPARSED:
            unparsed += 1
    return events, unparsed


def parse_windows_csv(text: str) -> tuple[list[Event], int]:
    """Parse a CSV Windows export. Blank lines and # comments are ignored."""
    lines = text.lstrip("\ufeff").splitlines()
    start = 0
    while start < len(lines) and (not lines[start].strip() or lines[start].lstrip().startswith("#")):
        start += 1
    if start >= len(lines):
        return [], 0
    data_lines = [line for line in lines[start + 1 :] if line.strip() and not line.lstrip().startswith("#")]
    body = lines[start] + "\n" + "\n".join(data_lines)
    reader = csv.DictReader(io.StringIO(body))
    events: list[Event] = []
    unparsed = 0
    parsed_rows = list(reader)
    if len(parsed_rows) != len(data_lines):
        # A quoted newline would desync the original line from the record.
        # Fall back to a compact rendering of the record.
        data_lines = [""] * len(parsed_rows)
    for raw_line, row in zip(data_lines, parsed_rows, strict=True):
        if row is None:
            unparsed += 1
            continue
        record = _normalise(row)
        raw = raw_line if raw_line else json.dumps(record, ensure_ascii=False)
        event = event_from_mapping(record, raw=raw, source_format="windows-csv")
        if isinstance(event, Event):
            events.append(event)
        elif event is _Decision.UNPARSED:
            unparsed += 1
    return events, unparsed


def event_from_mapping(record: dict, *, raw: str, source_format: str) -> Event | _Decision:
    """Convert one object of string or JSON values into an Event.

    Unparsed means the record did not have a usable id and timestamp, or a
    known event was missing the field that defines it. Quiet means the record
    was readable and deliberately ignored (service logons, machine accounts,
    event ids this tool does not model).
    """
    if not isinstance(record, dict):
        return _Decision.UNPARSED
    normalised = _normalise(record)
    event_id = _event_id(normalised)
    timestamp_text = _first(normalised, _TIME_KEYS)
    if event_id is None or not timestamp_text:
        return _Decision.UNPARSED
    try:
        timestamp = parse_timestamp(str(timestamp_text))
    except ValueError:
        return _Decision.UNPARSED

    message = _first(normalised, _MESSAGE_KEYS) or ""
    scraped = _scrape_message(str(message)) if message else {}
    hostname = _as_text(_first(normalised, _HOST_KEYS))
    src_ip = usable_ip(_first(normalised, _IP_KEYS)) or usable_ip(scraped.get("ip"))
    target_user = _clean_user(_first(normalised, _TARGET_USER_KEYS)) or _clean_user(
        scraped.get("target_user")
    )
    subject_user = _clean_user(_first(normalised, _SUBJECT_USER_KEYS)) or _clean_user(
        scraped.get("subject_user")
    )
    member = _clean_user(_first(normalised, _MEMBER_KEYS)) or _clean_user(scraped.get("member"))
    group = _clean_group(_first(normalised, _GROUP_KEYS)) or _clean_group(scraped.get("group"))
    command = _as_text(_first(normalised, _COMMAND_KEYS)) or scraped.get("command")
    process = _as_text(_first(normalised, _PROCESS_KEYS)) or scraped.get("process")
    logon_type = _logon_type(_first(normalised, _LOGON_KEYS) or scraped.get("logon_type"))

    base = {
        "timestamp": timestamp,
        "raw": raw,
        "hostname": hostname,
        "event_id": event_id,
        "source_format": source_format,
    }

    if event_id in {4624, 4625}:
        if logon_type is not None and logon_type not in _LOGON_TYPES:
            return _Decision.QUIET
        user = target_user
        if _noise_user(user):
            return _Decision.QUIET
        return Event(
            event_type="win_logon_success" if event_id == 4624 else "win_logon_failed",
            user=user,
            actor=subject_user,
            src_ip=src_ip,
            **base,
        )

    if event_id == 4720:
        if not target_user:
            return _Decision.UNPARSED
        return Event(
            event_type="win_user_created",
            user=target_user,
            actor=subject_user,
            **base,
        )

    if event_id in _GROUP_EVENTS:
        # On 4728/4732/4756 the group is often TargetUserName and the member is MemberName.
        group_name = group or (_clean_group(target_user) if target_user else None)
        member_name = member or (target_user if group and target_user != group else None)
        if not group_name:
            return _Decision.UNPARSED
        return Event(
            event_type="group_membership",
            user=member_name,
            actor=subject_user,
            group=group_name,
            **base,
        )

    if event_id == 4688:
        command_text = (str(command).strip() if command else "") or (str(process).strip() if process else "")
        if not command_text:
            return _Decision.UNPARSED
        return Event(
            event_type="process",
            user=subject_user or target_user,
            command=command_text,
            **base,
        )

    if event_id == 1102:
        return Event(
            event_type="audit_log_cleared",
            user=subject_user or target_user,
            actor=subject_user,
            **base,
        )

    return _Decision.QUIET


def _load_json_records(text: str) -> tuple[list[dict], int, list[str]]:
    payload = text.lstrip("\ufeff").strip()
    if not payload:
        return [], 0, []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return _load_ndjson(payload)
    records, dropped = _unwrap(data)
    raw = [json.dumps(record, ensure_ascii=False, separators=(",", ":")) for record in records]
    return records, dropped, raw


def _load_ndjson(payload: str) -> tuple[list[dict], int, list[str]]:
    records: list[dict] = []
    raw_lines: list[str] = []
    unparsed = 0
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            unparsed += 1
            continue
        if isinstance(item, dict):
            records.append(item)
            raw_lines.append(stripped)
        else:
            unparsed += 1
    return records, unparsed, raw_lines


def _unwrap(data: object) -> tuple[list[dict], int]:
    if isinstance(data, list):
        records = [item for item in data if isinstance(item, dict)]
        return records, len(data) - len(records)
    if isinstance(data, dict):
        for key in ("events", "Events", "records", "Records"):
            value = data.get(key)
            if isinstance(value, list):
                records = [item for item in value if isinstance(item, dict)]
                return records, len(value) - len(records)
        return [data], 0
    return [], 1


def _normalise(record: dict) -> dict:
    normalised: dict = {}
    for key, value in record.items():
        if key is None:
            continue
        norm_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if isinstance(value, str):
            value = value.strip()
        normalised[norm_key] = value
    return normalised


def _first(record: dict, keys: tuple[str, ...]) -> object | None:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "":
            continue
        return value
    return None


def _event_id(record: dict) -> int | None:
    for key in ("eventid", "eventcode"):
        parsed = _as_int(record.get(key))
        if parsed is not None:
            return parsed
    parsed = _as_int(record.get("id"))
    if parsed is not None and 1 <= parsed <= 65535:
        return parsed
    return None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    text = str(value).strip()
    if re.fullmatch(r"\d+", text):
        return int(text)
    return None


def _logon_type(value: object) -> int | None:
    return _as_int(value)


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_user(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-"}:
        return None
    return text


def _clean_group(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _noise_user(user: str | None) -> bool:
    if user is None:
        return True
    if user.endswith("$"):
        return True
    return user.lower() in _NOISE_USERS


def _scrape_message(message: str) -> dict[str, str]:
    """Pull common fields out of a rendered Event 4625/4688/4732 message."""
    found: dict[str, str] = {}
    ip_match = re.search(r"Source Network Address:\s*(\S+)", message)
    if ip_match:
        found["ip"] = ip_match.group(1)
    failed = re.search(
        r"Account For Which Logon Failed:\s*(.*?)\n\s*(?:Failure Information|Network Information)",
        message,
        re.IGNORECASE | re.DOTALL,
    )
    if failed:
        name = re.search(r"Account Name:\s*(\S+)", failed.group(1))
        if name:
            found["target_user"] = name.group(1)
    logon = re.search(r"Logon Type:\s*(\d+)", message)
    if logon:
        found["logon_type"] = logon.group(1)
    group = re.search(r"Group Name:\s*(.+)", message)
    if group:
        found["group"] = group.group(1).strip()
    member = re.search(r"Member:\s*.*?Account Name:\s*(\S+)", message, re.DOTALL)
    if member:
        found["member"] = member.group(1)
    command = re.search(r"(?:Process Command Line|CommandLine):\s*(.+)", message)
    if command:
        found["command"] = command.group(1).strip()
    process = re.search(r"New Process Name:\s*(.+)", message)
    if process:
        found["process"] = process.group(1).strip()
    subject = re.search(r"Subject:\s*.*?Account Name:\s*(\S+)", message, re.DOTALL)
    if subject:
        found["subject_user"] = subject.group(1)
    return found
