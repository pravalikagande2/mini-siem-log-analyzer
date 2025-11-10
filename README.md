Mini SIEM Log Analyzer (Python)

This project is a lightweight Security Information and Event Management (SIEM) simulator built in Python.
It parses Windows Security Logs and detects basic security threats through simple correlation rules.

===========================================================================================

Features

Parses Windows-style security logs

Detects common security events:

Brute force login attempts (Event ID 4625)

Event log clearing (Event ID 1102)

New service installation (Event ID 7045)

Suspicious PowerShell execution (Event ID 4688)

Generates:

Console alert output with severity levels

Plain text report

HTML alert dashboard

===========================================================================================

Project Structure
mini-siem/
│
├── logs/
│   └── security.txt
│
├── detectors/
│   ├── brute_force.py
│   ├── powershell.py
│   ├── log_cleared.py
│   └── new_service.py
│
├── parser/
│   └── windows_parser.py
│
├── report/
│   └── alerts_report.html
│
├── siem.py
└── README.md

===========================================================================================

How to Run

Ensure Python 3 is installed

Install dependencies:

pip install colorama


Run the SIEM:

python siem.py

===========================================================================================

Output files generated:

alerts_report.txt

report/alerts_report.html

Sample Console Output
==== ALERTS ====

[HIGH] Possible Brute Force Attack from IP 192.168.1.20 (3 failed logins)
[HIGH] Suspicious PowerShell command: powershell -enc ...
[HIGH] Event Log Cleared at 2025-01-20 11:17:30
[MEDIUM] New Service Installed: UpdaterService

===========================================================================================

Technologies Used

Python

Regular expressions

HTML/CSS

Basic detection logic

Windows Event ID fundamentals

Colorama for CLI formatting

===========================================================================================

Why This Project Matters

This project demonstrates:

Understanding of Windows Security Event IDs

Log parsing and normalization

Implementation of basic SIEM-like detection rules

Generating meaningful alerts for security monitoring

Familiarity with attacker behaviors such as brute force attempts and malicious PowerShell
