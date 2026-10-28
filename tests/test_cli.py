"""CLI exit codes, renderers, and the synthetic samples."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from soclog.cli import analyse_path, main, sample_paths
from soclog.engine import load_rules
from soclog.render import render_markdown, render_terminal, use_color

ROOT = Path(__file__).resolve().parent.parent


def _run(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_help_missing_file_and_exit_codes(self) -> None:
        code, stdout, _stderr = _run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("analyse", stdout)

        code, _stdout, stderr = _run(["analyse", "no-such-log.txt"])
        self.assertEqual(code, 2)
        self.assertIn("file not found", stderr)

        with tempfile.TemporaryDirectory() as directory:
            benign = Path(directory) / "benign.log"
            benign.write_text(
                "2026-10-27T12:00:00Z web01 sshd[1]: Accepted password for deploy from 192.0.2.10 port 22 ssh2\n",
                encoding="utf-8",
            )
            night = Path(directory) / "night.log"
            night.write_text(
                "2026-10-27T23:10:00Z web01 sshd[1]: Accepted password for ops from 198.51.100.40 port 22 ssh2\n",
                encoding="utf-8",
            )
            brute = Path(directory) / "brute.log"
            lines = [
                f"2026-10-27T14:00:{second:02d}Z web01 sshd[{second}]: Failed password for root from 203.0.113.10 port 22 ssh2"
                for second in range(5)
            ]
            brute.write_text("\n".join(lines) + "\n", encoding="utf-8")
            report = Path(directory) / "out.md"

            code, stdout, _stderr = _run(["analyse", str(benign)])
            self.assertEqual(code, 0)
            self.assertIn("No alerts", stdout)
            self.assertNotIn("\033[", stdout)

            code, stdout, _stderr = _run(["analyse", str(night), "--min-severity", "medium"])
            self.assertEqual(code, 0)
            self.assertIn("No alerts", stdout)

            code, _stdout, _stderr = _run(["analyse", str(night), "--min-severity", "low"])
            self.assertEqual(code, 1)

            code, stdout, _stderr = _run(["analyse", str(brute), "--json", "--report", str(report), "--min-severity", "high"])
            self.assertEqual(code, 1)
            payload = json.loads(stdout)
            self.assertEqual(payload["tool"], "soclog")
            self.assertEqual(payload["alert_count"], 1)
            alert = payload["sources"][0]["alerts"][0]
            self.assertEqual(alert["id"], "SOC-001")
            self.assertEqual(alert["mitre"]["id"], "T1110.001")
            self.assertEqual(alert["mitre"]["name"], "Brute Force: Password Guessing")
            self.assertIn("what_to_do_next", alert)
            self.assertTrue(alert["evidence"])
            report_text = report.read_text(encoding="utf-8")
            self.assertIn("## Summary", report_text)
            self.assertIn("## Timeline", report_text)
            self.assertIn("## ATT&CK techniques seen", report_text)
            self.assertIn("### SOC-001", report_text)
            self.assertIn("What to do next", report_text)

            code, _stdout, _stderr = _run(["analyse", str(brute), "--min-severity", "critical"])
            self.assertEqual(code, 0)

    def test_colour_is_opt_in(self) -> None:
        rules = load_rules()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brute.log"
            lines = [
                f"2026-10-27T14:00:{second:02d}Z web01 sshd[{second}]: Failed password for root from 203.0.113.10 port 22 ssh2"
                for second in range(5)
            ]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            analysis = analyse_path(path, "linux-auth", rules)
            from soclog.cli import _finalise

            _finalise([analysis], "low")
            plain = render_terminal([analysis], min_severity="low", color=False)
            painted = render_terminal([analysis], min_severity="low", color=True)
        self.assertNotIn("\033[", plain)
        self.assertIn("\033[", painted)
        self.assertIn("T1110.001", plain)

        class Tty:
            def isatty(self) -> bool:
                return True

        previous = os.environ.pop("NO_COLOR", None)
        try:
            self.assertTrue(use_color(Tty()))
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(use_color(Tty()))
        finally:
            if previous is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = previous
        self.assertFalse(use_color(StringIO()))

    def test_report_creates_a_missing_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "one.log"
            log_path.write_text(
                "2026-10-27T12:00:00Z web01 sshd[1]: Accepted password for deploy from 192.0.2.10 port 22 ssh2\n",
                encoding="utf-8",
            )
            report = Path(directory) / "nested" / "out.md"
            code, _stdout, stderr = _run(["analyse", str(log_path), "--report", str(report)])
            self.assertEqual(code, 0, stderr)
            self.assertTrue(report.is_file())

    def test_samples_auto_detect_and_expected_rules(self) -> None:
        expected = {
            "linux-auth.log": {
                "auth-brute-force",
                "password-spray",
                "success-after-failures",
                "unusual-hours",
                "local-user-created",
                "privileged-group-add",
                "shell-pipe-download",
                "wget-to-tmp",
                "curl-to-tmp",
            },
            "web-access.log": {
                "web-sqli",
                "web-traversal",
                "web-xss",
                "web-scanner-ua",
                "web-404-burst",
            },
            "windows-security.json": {
                "success-after-failures",
                "windows-user-created",
                "privileged-group-add",
                "encoded-powershell",
                "certutil-download",
                "powershell-download",
                "audit-log-cleared",
                "unusual-hours",
            },
            "windows-security.csv": {"password-spray", "windows-user-created"},
        }
        rules = load_rules()
        for path in sample_paths():
            analysis = analyse_path(path, "auto", rules)
            found = {alert.rule_id for alert in analysis.alerts}
            self.assertEqual(found, expected[path.name], path.name)
            self.assertEqual(analysis.result.unparsed, 0, path.name)

        code, stdout, stderr = _run(["demo", "--min-severity", "low"])
        self.assertEqual(stderr, "")
        self.assertEqual(code, 1)
        self.assertIn("T1070.001", stdout)
        self.assertIn("T1190", stdout)
        self.assertIn("total alerts:", stdout)

    def test_markdown_mentions_synthetic_samples(self) -> None:
        rules = load_rules()
        analyses = [analyse_path(path, "auto", rules) for path in sample_paths()]
        from soclog.cli import _finalise

        _finalise(analyses, "low")
        text = render_markdown(analyses, generated=at_fixed(), min_severity="low")
        self.assertIn("synthetic samples", text)
        self.assertIn("not a declaration", text)


def at_fixed():
    from datetime import datetime

    return datetime(2026, 10, 28, 9, 0, 0)


class DocsTests(unittest.TestCase):
    def test_readme_and_example_report_match_the_rules(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        report = (ROOT / "docs" / "example-report.md").read_text(encoding="utf-8")
        for rule in load_rules():
            self.assertIn(rule["id"], readme)
            self.assertIn(rule["mitre_id"], readme)
            self.assertIn(rule["mitre_id"], report)
        for heading in ("## Summary", "## Timeline", "## ATT&CK techniques seen", "## Alerts"):
            self.assertIn(heading, report)
        self.assertIn("samples/linux-auth.log", report)
        self.assertNotIn("/workspace/", report)
        self.assertIn("What I learned", readme)
        self.assertIn("not a siem", readme.lower())


class StdlibOnlyTests(unittest.TestCase):
    def test_package_does_not_import_network_clients(self) -> None:
        banned = ("import requests", "urllib.request", "import socket", "import http.client")
        for path in (ROOT / "soclog").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for snippet in banned:
                self.assertNotIn(snippet, text, f"{path} contains {snippet}")


if __name__ == "__main__":
    unittest.main()
