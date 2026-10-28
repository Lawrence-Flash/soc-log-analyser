# Synthetic samples

These logs were written for this repository. They are not exports from a real system, and they do not describe real people.

Addresses come from the documentation ranges in RFC 5737:

- `192.0.2.0/24` is used as ordinary internal-looking traffic
- `198.51.100.0/24` is used as other external traffic
- `203.0.113.0/24` is used as the noisy external source

Account names are roles (`deploy`, `ops`, `svcbackup`, `analyst`) rather than names of people.

Each file mixes quiet activity with the cases the rules look for, so `python3 -m soclog demo` has something real to print. Thresholds are in `soclog/rules.json`. A single failed password, a few HTTP 404s, `Get-Date`, and adding an account to `Users` are in here on purpose and should stay quiet.
