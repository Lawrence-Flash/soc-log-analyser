"""Terminal, JSON, and Markdown renderers. No colour unless asked."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from soclog import __version__
from soclog.models import SEVERITIES, Analysis, Alert
from soclog.timeparse import format_timestamp


def use_color(stream) -> bool:
    """Colour only for a terminal, and never when NO_COLOR is set."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def render_terminal(analyses: list[Analysis], *, min_severity: str, color: bool) -> str:
    lines: list[str] = [f"soclog {__version__}", f"minimum severity: {min_severity}"]
    if len(analyses) > 1:
        lines.append("Alert ids are numbered in time order across every file in this run.")
    lines.append("")
    total = 0
    for analysis in analyses:
        result = analysis.result
        counts = _counts(analysis.alerts)
        total += len(analysis.alerts)
        lines.append(f"source: {result.path}")
        lines.append(f"format: {result.format}")
        lines.append(f"events: {len(result.events)}")
        lines.append(f"unparsed lines: {result.unparsed}")
        lines.append(f"alerts: {len(analysis.alerts)} ({_count_text(counts)})")
        lines.append("")
        if not analysis.alerts:
            lines.append("No alerts at or above this severity.")
            lines.append("")
            continue
        for alert in analysis.alerts:
            lines.extend(_alert_block(alert, color))
            lines.append("")
    lines.append(f"total alerts: {total}")
    return "\n".join(lines).rstrip() + "\n"


def render_json(analyses: list[Analysis], *, min_severity: str, generated: datetime) -> str:
    payload = {
        "tool": "soclog",
        "version": __version__,
        "generated": format_timestamp(generated),
        "min_severity": min_severity,
        "alert_count": sum(len(analysis.alerts) for analysis in analyses),
        "sources": [_source_json(analysis) for analysis in analyses],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_markdown(analyses: list[Analysis], *, generated: datetime, min_severity: str) -> str:
    alerts = sorted(
        (alert for analysis in analyses for alert in analysis.alerts),
        key=lambda alert: (alert.timestamp_start, alert.id),
    )
    synthetic = bool(analyses) and all(_is_sample(analysis.result.path) for analysis in analyses)
    lines = [
        "# SOC log analysis report",
        "",
        f"- Generated: {format_timestamp(generated)}",
        f"- Tool: soclog {__version__}",
        f"- Minimum severity: {min_severity}",
        "- Times are UTC.",
        "",
    ]
    if synthetic:
        lines.append(
            "These files are the synthetic samples shipped with soclog. "
            "The addresses are documentation ranges from RFC 5737. Nothing here is a real incident."
        )
        lines.append("")
    lines.append(
        "This is a heuristic triage of the log lines below. It is not a declaration that an incident happened."
    )
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append("| File | Format | Events | Unparsed lines | Alerts |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for analysis in analyses:
        result = analysis.result
        lines.append(
            "| {path} | {fmt} | {events} | {unparsed} | {alerts} |".format(
                path=_cell(result.path),
                fmt=_cell(result.format),
                events=len(result.events),
                unparsed=result.unparsed,
                alerts=len(analysis.alerts),
            )
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if not alerts:
        lines.append("No alerts at or above this severity.")
        lines.append("")
    else:
        lines.append("| ID | Severity | When (UTC) | Source IP | User | Title | ATT&CK |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for alert in alerts:
            lines.append(
                "| {id} | {severity} | {when} | {ip} | {user} | {title} | {mitre} |".format(
                    id=_cell(alert.id),
                    severity=_cell(alert.severity),
                    when=_cell(_short_range(alert)),
                    ip=_cell(alert.source_ip),
                    user=_cell(alert.user),
                    title=_cell(alert.title),
                    mitre=_cell(f"{alert.mitre_id} {alert.mitre_name}"),
                )
            )
        lines.append("")
    lines.append("## ATT&CK techniques seen")
    lines.append("")
    techniques = _techniques(alerts)
    if not techniques:
        lines.append("None.")
        lines.append("")
    else:
        lines.append("| Technique | Name | Alerts |")
        lines.append("| --- | --- | ---: |")
        for technique_id, name, count in techniques:
            lines.append(f"| {_cell(technique_id)} | {_cell(name)} | {count} |")
        lines.append("")
    lines.append("## Timeline")
    lines.append("")
    if not alerts:
        lines.append("No alerts.")
        lines.append("")
    else:
        for alert in sorted(alerts, key=lambda item: (item.timestamp_start, item.id)):
            lines.append(
                f"- {format_timestamp(alert.timestamp_start)} — {alert.id} — "
                f"{alert.severity} — {alert.title} ({alert.mitre_id})"
            )
        lines.append("")
    lines.append("## Alerts")
    lines.append("")
    if not alerts:
        lines.append("No alerts.")
        lines.append("")
    for alert in alerts:
        lines.extend(_markdown_alert(alert))
    return "\n".join(lines).rstrip() + "\n"


def _alert_block(alert: Alert, color: bool) -> list[str]:
    label = _paint(alert.severity, alert.severity, color)
    title = _paint(alert.title, alert.severity, color)
    lines = [
        f"{alert.id}  {label}  {title}",
        f"  rule:       {alert.rule_id}",
        f"  ATT&CK:     {alert.mitre_id} {alert.mitre_name}",
        f"  when:       {_short_range(alert)}",
        f"  source IP:  {alert.source_ip or '-'}",
        f"  user:       {alert.user or '-'}",
        f"  events:     {alert.event_count}",
        f"  next:       {alert.what_to_do_next}",
        "  evidence:",
    ]
    shown = _terminal_evidence(alert)
    for line in shown:
        lines.append(f"    | {line}")
    hidden = alert.event_count - len(shown)
    if hidden > 0:
        lines.append(f"    | … {hidden} more event(s) not shown here")
    return lines


def _terminal_evidence(alert: Alert) -> list[str]:
    """Show the start of the cluster and the latest lines, so a final success stays visible."""
    evidence = alert.evidence
    if len(evidence) <= 3:
        return evidence
    return [evidence[0], evidence[-2], evidence[-1]]


def _markdown_alert(alert: Alert) -> list[str]:
    lines = [
        f"### {alert.id} — {alert.title}",
        "",
        f"- Severity: {alert.severity}",
        f"- Rule: `{alert.rule_id}`",
        f"- ATT&CK: {alert.mitre_id} {alert.mitre_name}",
        f"- When (UTC): {format_timestamp(alert.timestamp_start)} to {format_timestamp(alert.timestamp_end)}",
        f"- Source IP: {alert.source_ip or '-'}",
        f"- User: {alert.user or '-'}",
        f"- Log: `{alert.source}` ({alert.source_format})",
        f"- Events in this alert: {alert.event_count}",
        f"- What to do next: {alert.what_to_do_next}",
        "",
        "Evidence:",
        "",
        "~~~~",
        *alert.evidence,
        "~~~~",
        "",
    ]
    if alert.event_count > len(alert.evidence):
        lines.insert(-2, f"… {alert.event_count - len(alert.evidence)} more event(s) not shown")
    return lines


def _source_json(analysis: Analysis) -> dict:
    result = analysis.result
    return {
        "path": result.path,
        "format": result.format,
        "events_parsed": len(result.events),
        "unparsed_lines": result.unparsed,
        "alerts": [_alert_json(alert) for alert in analysis.alerts],
    }


def _alert_json(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity,
        "mitre": {"id": alert.mitre_id, "name": alert.mitre_name},
        "timestamp_start": format_timestamp(alert.timestamp_start),
        "timestamp_end": format_timestamp(alert.timestamp_end),
        "source_ip": alert.source_ip,
        "user": alert.user,
        "event_count": alert.event_count,
        "evidence": alert.evidence,
        "what_to_do_next": alert.what_to_do_next,
        "source": alert.source,
        "format": alert.source_format,
    }


def _counts(alerts: list[Alert]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for alert in alerts:
        counts[alert.severity] += 1
    return counts


def _count_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{name} {counts[name]}" for name in SEVERITIES)


def _techniques(alerts: list[Alert]) -> list[tuple[str, str, int]]:
    order: list[str] = []
    names: dict[str, str] = {}
    counts: dict[str, int] = {}
    for alert in alerts:
        if alert.mitre_id not in names:
            order.append(alert.mitre_id)
            names[alert.mitre_id] = alert.mitre_name
            counts[alert.mitre_id] = 0
        counts[alert.mitre_id] += 1
    return [(technique_id, names[technique_id], counts[technique_id]) for technique_id in order]


def _short_range(alert: Alert) -> str:
    start = alert.timestamp_start
    end = alert.timestamp_end
    if start == end:
        return format_timestamp(start)
    if start.date() == end.date():
        return f"{start.strftime('%Y-%m-%d %H:%M:%SZ')}–{end.strftime('%H:%M:%SZ')}"
    return f"{format_timestamp(start)}–{format_timestamp(end)}"


def _paint(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    codes = {"critical": "1;91", "high": "31", "medium": "33", "low": "36"}
    return f"\033[{codes[severity]}m{text}\033[0m"


def _cell(value: object) -> str:
    if value is None or value == "":
        text = "-"
    else:
        text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _is_sample(path: str) -> bool:
    return "samples" in Path(path).parts
