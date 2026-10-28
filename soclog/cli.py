"""Command line for `python3 -m soclog`."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from soclog import __version__
from soclog.engine import evaluate, load_rules
from soclog.models import SEVERITIES, SEVERITY_RANK, Analysis, ParseResult, severity_at_least
from soclog.parsers import PARSERS, detect_format
from soclog.render import render_json, render_markdown, render_terminal, use_color

_SAMPLE_FILES = (
    "linux-auth.log",
    "web-access.log",
    "windows-security.json",
    "windows-security.csv",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soclog",
        description="Offline triage for Linux auth, web access, and Windows Security logs.",
    )
    parser.add_argument("--version", action="version", version=f"soclog {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    analyse = commands.add_parser("analyse", help="analyse one log file")
    analyse.add_argument("file", type=Path, help="log file to read")
    _add_output_arguments(analyse)
    analyse.add_argument(
        "--format",
        choices=("auto", "linux-auth", "web-access", "windows-json", "windows-csv"),
        default="auto",
        help="log format (default: auto)",
    )

    demo = commands.add_parser("demo", help="analyse the synthetic samples shipped with soclog")
    _add_output_arguments(demo)
    return parser


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", dest="json_output", help="write JSON to stdout")
    parser.add_argument("--report", type=Path, help="write a Markdown report to this path")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="hide alerts below this severity; exit 1 when any remain (default: low)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 0 if code is None else int(code)
    try:
        return _run(args)
    except BrokenPipeError:
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    rules = load_rules()
    if args.command == "analyse":
        analyses = [analyse_path(args.file, args.format, rules)]
    elif args.command == "demo":
        analyses = [analyse_path(path, "auto", rules) for path in sample_paths()]
    else:
        raise ValueError(f"unknown command: {args.command}")

    _finalise(analyses, args.min_severity)
    generated = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            render_markdown(analyses, generated=generated, min_severity=args.min_severity),
            encoding="utf-8",
        )
    if args.json_output:
        sys.stdout.write(render_json(analyses, min_severity=args.min_severity, generated=generated))
    else:
        color = use_color(sys.stdout)
        sys.stdout.write(render_terminal(analyses, min_severity=args.min_severity, color=color))
    alert_count = sum(len(analysis.alerts) for analysis in analyses)
    return 1 if alert_count else 0


def analyse_path(path: Path, fmt: str, rules: list[dict]) -> Analysis:
    if not path.is_file():
        raise ValueError(f"file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    detected = detect_format(text) if fmt == "auto" else fmt
    if detected not in PARSERS:
        raise ValueError(f"unknown format: {detected}")
    events, unparsed = PARSERS[detected](text)
    for event in events:
        event.source_format = detected
    alerts = evaluate(events, rules)
    shown = _display_path(path)
    for alert in alerts:
        alert.source = shown
        alert.source_format = detected
    return Analysis(ParseResult(shown, detected, events, unparsed), alerts)


def _display_path(path: Path) -> str:
    """Prefer a path relative to the working directory so reports stay portable."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def sample_paths() -> list[Path]:
    root = Path(__file__).resolve().parent.parent / "samples"
    if not root.is_dir():
        raise ValueError("samples directory not found next to the soclog package")
    paths = [root / name for name in _SAMPLE_FILES]
    missing = [str(path.name) for path in paths if not path.is_file()]
    if missing:
        raise ValueError("missing sample files: " + ", ".join(missing))
    return paths


def _finalise(analyses: list[Analysis], minimum: str) -> None:
    combined = []
    for analysis in analyses:
        analysis.alerts = [alert for alert in analysis.alerts if severity_at_least(alert.severity, minimum)]
        combined.extend(analysis.alerts)
    combined.sort(
        key=lambda alert: (
            alert.timestamp_start,
            -SEVERITY_RANK[alert.severity],
            alert.rule_id,
            alert.source_ip or "",
            alert.user or "",
        )
    )
    for index, alert in enumerate(combined, start=1):
        alert.id = f"SOC-{index:03d}"
    for analysis in analyses:
        analysis.alerts.sort(key=lambda alert: (alert.timestamp_start, alert.id))
