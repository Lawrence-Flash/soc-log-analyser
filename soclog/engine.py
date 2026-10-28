"""Apply soclog/rules.json to normalised events.

Correlation rules (counts, distinct accounts, success after failures, quiet
hours) are implemented here and configured from the rules file. Pattern rules
are the regular expressions in that file, so a new URI or command pattern does
not need a code change.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from soclog.models import SEVERITIES, Alert, Event

_EVIDENCE_LIMIT = 8
_MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_RULE_TYPES = {
    "count_threshold",
    "distinct_threshold",
    "success_after_failures",
    "unusual_hours",
    "match",
    "regex",
}


def rules_path() -> Path:
    return Path(__file__).with_name("rules.json")


def load_rules(path: Path | None = None) -> list[dict]:
    """Load and check the rule file. Raises ValueError on a bad rule."""
    source = path or rules_path()
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"rules file is not valid JSON: {exc}") from exc
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules file must contain a non-empty rules list")
    seen: set[str] = set()
    for rule in rules:
        _validate_rule(rule, seen)
    return rules


def evaluate(events: list[Event], rules: list[dict]) -> list[Alert]:
    """Return alerts for every enabled rule. Ids are assigned later."""
    alerts: list[Alert] = []
    for rule in rules:
        if rule.get("enabled", True) is False:
            continue
        _ensure_compiled(rule)
        handler = _HANDLERS[rule["type"]]
        alerts.extend(handler(events, rule))
    return _suppress(alerts)


def _ensure_compiled(rule: dict) -> None:
    if rule.get("type") == "regex" and "_pattern" not in rule:
        rule["_pattern"] = re.compile(rule["pattern"])
    if "_field_regex" not in rule:
        rule["_field_regex"] = [
            (field, re.compile(pattern)) for field, pattern in (rule.get("field_regex") or {}).items()
        ]


def _validate_rule(rule: dict, seen: set[str]) -> None:
    if not isinstance(rule, dict):
        raise ValueError("each rule must be an object")
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("each rule needs an id")
    if rule_id in seen:
        raise ValueError(f"duplicate rule id: {rule_id}")
    seen.add(rule_id)
    missing = [key for key in ("type", "title", "severity", "mitre_id", "mitre_name", "recommendation") if not rule.get(key)]
    if missing:
        raise ValueError(f"rule {rule_id} is missing {', '.join(missing)}")
    if rule["type"] not in _RULE_TYPES:
        raise ValueError(f"rule {rule_id} has unknown type {rule['type']}")
    if rule["severity"] not in SEVERITIES:
        raise ValueError(f"rule {rule_id} has unknown severity {rule['severity']}")
    if not _MITRE_ID.fullmatch(rule["mitre_id"]):
        raise ValueError(f"rule {rule_id} has an implausible MITRE id {rule['mitre_id']}")
    for extra in ("spray_mitre_id",):
        if extra in rule and not _MITRE_ID.fullmatch(str(rule[extra])):
            raise ValueError(f"rule {rule_id} has an implausible {extra}")
    if rule["type"] == "regex":
        try:
            rule["_pattern"] = re.compile(rule["pattern"])
        except re.error as exc:
            raise ValueError(f"rule {rule_id} has an invalid pattern: {exc}") from exc
        if not rule.get("fields"):
            raise ValueError(f"rule {rule_id} needs fields")
    compiled_fields = []
    for field, pattern in (rule.get("field_regex") or {}).items():
        try:
            compiled_fields.append((field, re.compile(pattern)))
        except re.error as exc:
            raise ValueError(f"rule {rule_id} has an invalid field pattern: {exc}") from exc
    rule["_field_regex"] = compiled_fields


def _count_threshold(events: list[Event], rule: dict) -> list[Alert]:
    selected = _select(events, rule)
    alerts: list[Alert] = []
    for grouped in _group(selected, rule.get("group_by") or []).values():
        for cluster in _threshold_clusters(
            grouped,
            int(rule["window_seconds"]),
            lambda window: len(window) >= int(rule["threshold"]),
        ):
            alerts.append(_alert(rule, cluster))
    return alerts


def _distinct_threshold(events: list[Event], rule: dict) -> list[Alert]:
    field = rule["distinct_field"]
    minimum = int(rule["min_distinct"])
    maximum = rule.get("max_per_value")

    def predicate(window: list[Event]) -> bool:
        counts: dict[object, int] = defaultdict(int)
        for event in window:
            value = getattr(event, field)
            if value:
                counts[value] += 1
        if len(counts) < minimum:
            return False
        if maximum is not None and max(counts.values()) > int(maximum):
            return False
        return True

    alerts: list[Alert] = []
    selected = _select(events, rule)
    for grouped in _group(selected, rule.get("group_by") or []).values():
        for cluster in _threshold_clusters(grouped, int(rule["window_seconds"]), predicate):
            alerts.append(_alert(rule, cluster, users=len({getattr(e, field) for e in cluster if getattr(e, field)})))
    return alerts


def _success_after_failures(events: list[Event], rule: dict) -> list[Alert]:
    window = timedelta(seconds=int(rule["window_seconds"]))
    threshold = int(rule["threshold"])
    failures = [event for event in _select(events, rule, types_key="failure_types") if event.src_ip]
    successes = [event for event in _select(events, rule, types_key="success_types") if event.src_ip]
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for failure in failures:
        by_ip[failure.src_ip or ""].append(failure)

    pending: list[list[Event]] = []
    for success in sorted(successes, key=lambda item: item.timestamp):
        prior = [
            failure
            for failure in by_ip[success.src_ip or ""]
            if timedelta(0) <= success.timestamp - failure.timestamp <= window
        ]
        if len(prior) >= threshold:
            pending.append(prior + [success])
    alerts: list[Alert] = []
    for cluster in _merge_overlaps(pending):
        failure_events = [event for event in cluster if event.event_type in set(rule["failure_types"])]
        override = _spray_override(failure_events, rule)
        alerts.append(_alert(rule, cluster, user_types=set(rule["success_types"]), **override))
    return alerts


def _unusual_hours(events: list[Event], rule: dict) -> list[Alert]:
    start = int(rule["start_hour"])
    end = int(rule["end_hour"])
    selected = [event for event in _select(events, rule) if _hour_is_unusual(event.timestamp.hour, start, end)]
    alerts: list[Alert] = []
    grouped = _group(selected, rule.get("group_by") or ["user", "src_ip"], keep_missing=True)
    window = int(rule.get("window_seconds", 43200))
    for events_in_group in grouped.values():
        for cluster in _gap_clusters(events_in_group, window):
            alerts.append(_alert(rule, cluster))
    return alerts


def _match(events: list[Event], rule: dict) -> list[Alert]:
    return [_alert(rule, [event]) for event in _select(events, rule)]


def _regex(events: list[Event], rule: dict) -> list[Alert]:
    pattern: re.Pattern[str] = rule["_pattern"]
    fields = list(rule["fields"])
    hits: list[Event] = []
    for event in _select(events, rule):
        if any(_field_text(event, field) and pattern.search(_field_text(event, field)) for field in fields):
            hits.append(event)
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in hits:
        grouped[_regex_key(event)].append(event)
    alerts: list[Alert] = []
    window = int(rule.get("window_seconds", 600))
    for events_in_group in grouped.values():
        for cluster in _gap_clusters(events_in_group, window):
            alerts.append(_alert(rule, cluster))
    return alerts


_HANDLERS = {
    "count_threshold": _count_threshold,
    "distinct_threshold": _distinct_threshold,
    "success_after_failures": _success_after_failures,
    "unusual_hours": _unusual_hours,
    "match": _match,
    "regex": _regex,
}


def _select(events: list[Event], rule: dict, types_key: str = "event_types") -> list[Event]:
    allowed = set(rule.get(types_key) or [])
    required = list(rule.get("require_fields") or [])
    where = rule.get("where") or {}
    field_regex = rule.get("_field_regex") or []
    selected: list[Event] = []
    for event in events:
        if allowed and event.event_type not in allowed:
            continue
        if any(getattr(event, key) != value for key, value in where.items()):
            continue
        if any(not (getattr(event, field) and pattern.search(str(getattr(event, field)))) for field, pattern in field_regex):
            continue
        if any(getattr(event, field) in (None, "") for field in required):
            continue
        selected.append(event)
    return selected


def _group(events: list[Event], fields: list[str], keep_missing: bool = False) -> dict[tuple, list[Event]]:
    groups: dict[tuple, list[Event]] = defaultdict(list)
    if not fields:
        if events:
            groups[()] = list(events)
        return groups
    for event in events:
        key = []
        skip = False
        for field in fields:
            value = getattr(event, field)
            if value in (None, ""):
                if not keep_missing:
                    skip = True
                    break
                value = "-"
            key.append(value)
        if not skip:
            groups[tuple(key)].append(event)
    return groups


def _threshold_clusters(events: list[Event], window_seconds: int, predicate) -> list[list[Event]]:
    ordered = sorted(events, key=lambda item: item.timestamp)
    if not ordered:
        return []
    window = timedelta(seconds=window_seconds)
    flagged = [False] * len(ordered)
    left = 0
    for right, event in enumerate(ordered):
        while event.timestamp - ordered[left].timestamp > window:
            left += 1
        if predicate(ordered[left : right + 1]):
            for index in range(left, right + 1):
                flagged[index] = True
    return _flagged_runs(ordered, flagged, window)


def _flagged_runs(ordered: list[Event], flagged: list[bool], window: timedelta) -> list[list[Event]]:
    clusters: list[list[Event]] = []
    index = 0
    total = len(ordered)
    while index < total:
        if not flagged[index]:
            index += 1
            continue
        end = index
        while (
            end + 1 < total
            and flagged[end + 1]
            and ordered[end + 1].timestamp - ordered[end].timestamp <= window
        ):
            end += 1
        clusters.append(ordered[index : end + 1])
        index = end + 1
    return clusters


def _gap_clusters(events: list[Event], window_seconds: int) -> list[list[Event]]:
    ordered = sorted(events, key=lambda item: item.timestamp)
    if not ordered:
        return []
    window = timedelta(seconds=window_seconds)
    clusters: list[list[Event]] = [[ordered[0]]]
    for event in ordered[1:]:
        if event.timestamp - clusters[-1][-1].timestamp <= window:
            clusters[-1].append(event)
        else:
            clusters.append([event])
    return clusters


def _merge_overlaps(clusters: list[list[Event]]) -> list[list[Event]]:
    """Merge clusters that share a source IP and overlap in time."""
    merged: list[list[Event]] = []
    for cluster in clusters:
        ip = _one_value(cluster, "src_ip")
        start = min(event.timestamp for event in cluster)
        end = max(event.timestamp for event in cluster)
        placed = False
        for existing in merged:
            if _one_value(existing, "src_ip") != ip:
                continue
            existing_start = min(event.timestamp for event in existing)
            existing_end = max(event.timestamp for event in existing)
            if start <= existing_end and existing_start <= end:
                seen = {event.raw for event in existing}
                for event in cluster:
                    if event.raw not in seen:
                        existing.append(event)
                        seen.add(event.raw)
                placed = True
                break
        if not placed:
            merged.append(list(cluster))
    return merged


def _spray_override(failures: list[Event], rule: dict) -> dict:
    if "spray_mitre_id" not in rule:
        return {}
    counts: dict[str, int] = defaultdict(int)
    for event in failures:
        if event.user:
            counts[event.user] += 1
    minimum = int(rule.get("spray_min_distinct", 5))
    maximum = int(rule.get("spray_max_per_value", 4))
    if len(counts) >= minimum and counts and max(counts.values()) <= maximum:
        return {
            "mitre_id": rule["spray_mitre_id"],
            "mitre_name": rule["spray_mitre_name"],
            "title": rule.get("spray_title", rule["title"]),
        }
    return {}


def _alert(
    rule: dict,
    events: list[Event],
    *,
    users: int | None = None,
    user_types: set[str] | None = None,
    mitre_id: str | None = None,
    mitre_name: str | None = None,
    title: str | None = None,
) -> Alert:
    ordered = sorted(events, key=lambda item: item.timestamp)
    user_events = [event for event in ordered if user_types is None or event.event_type in user_types]
    user_text = _join_users(user_events or ordered)
    ip = _one_value(ordered, "src_ip")
    group = _one_value(ordered, "group")
    distinct_users = users if users is not None else len({event.user for event in ordered if event.user})
    title_text = title or rule["title"]
    try:
        rendered = title_text.format(
            count=len(ordered),
            users=distinct_users,
            src_ip=ip or "unknown",
            group=group or "unknown",
            user=user_text or "unknown",
        )
    except (KeyError, IndexError, ValueError):
        rendered = title_text
    return Alert(
        id="",
        rule_id=rule["id"],
        rule_type=rule["type"],
        title=rendered,
        severity=rule["severity"],
        mitre_id=mitre_id or rule["mitre_id"],
        mitre_name=mitre_name or rule["mitre_name"],
        timestamp_start=ordered[0].timestamp,
        timestamp_end=ordered[-1].timestamp,
        source_ip=ip,
        user=user_text,
        evidence=[event.raw for event in ordered[-_EVIDENCE_LIMIT:]],
        what_to_do_next=rule["recommendation"].strip(),
        event_count=len(ordered),
        suppress_if_covered_by=str(rule.get("suppress_if_covered_by") or ""),
    )


def _suppress(alerts: list[Alert]) -> list[Alert]:
    covers: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        covers[alert.rule_id].append(alert)
    kept: list[Alert] = []
    for alert in alerts:
        cover_id = alert.suppress_if_covered_by
        if cover_id and alert.source_ip:
            hidden = any(
                other.source_ip == alert.source_ip and _overlaps(alert, other)
                for other in covers.get(cover_id, [])
            )
            if hidden:
                continue
        kept.append(alert)
    return kept


def _overlaps(left: Alert, right: Alert) -> bool:
    return left.timestamp_start <= right.timestamp_end and right.timestamp_start <= left.timestamp_end


def _hour_is_unusual(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _regex_key(event: Event) -> tuple[str, str]:
    if event.src_ip:
        return ("ip", event.src_ip)
    if event.user:
        return ("user", event.user)
    if event.hostname:
        return ("host", event.hostname)
    return ("none", "")


def _field_text(event: Event, field: str) -> str:
    value = getattr(event, field)
    return "" if value is None else str(value)


def _join_users(events: list[Event]) -> str | None:
    names: list[str] = []
    for event in events:
        if event.user and event.user not in names:
            names.append(event.user)
    if not names:
        return None
    if len(names) == 1:
        return names[0]
    shown = names[:6]
    text = ", ".join(shown)
    extra = len(names) - len(shown)
    if extra:
        text += f" (+{extra})"
    return text


def _one_value(events: list[Event], field: str) -> str | None:
    values = []
    for event in events:
        value = getattr(event, field)
        if value and value not in values:
            values.append(value)
    if len(values) == 1:
        return str(values[0])
    return None
