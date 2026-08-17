# Simple Windows Forensics Data Collector

This script collects Windows data commonly used for forensic investigation during a suspected computer security incident.

## Overview

This script contains several functions to collect Windows system forensic data from a target machine.
The following information is collected:
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
- Browser data for Microsoft Edge and Google Chrome

Data is collected and stored to c:\IRStaging. From there you can zip it and extract it.

## Features

- Quick runtime
- Does not delete or remove files
- Saves files to staging directory for export to another machine for processing

## Requirements

- PowerShell 7+

## Usage

```powershell
.\Collect-WindowsForensicsData.ps1
```

## Output

Parent folder: C:\IRStaging
Contents:
- Chrome: Directory containing Chrome browsing data if present
- Edge: Directory containing Edge browsing data if present
- hkcu-comdlg32-data.csv
- hkcu-recent-docs.csv
- hkcu-run.csv
- hkcu-run-once.csv
- hkcu-typed-paths.csv
- userassist-reg-data.csv
- datalog.log

## Notes / Limitations

This tool was built to fill a specific gap: giving a small IT/security
team a fast, first-pass way to pull commonly referenced Windows forensic
artifacts during a suspected incident, without waiting on external
tooling or vendor engagement to get an initial read on scope.

- **Purpose is triage, not forensic analysis.** This script collects and
  parses artifacts to help a team quickly assess whether an incident
  warrants escalation — engaging cyber insurance, an IR retainer, or a
  forensics firm. It is not a substitute for formal forensic analysis,
  and its output should not be treated as a complete or evidentiary
  record on its own.

- **Designed for non-specialist operators.** The script is intentionally
  simple to run, with the goal that non-security IT staff at a remote
  site could execute it and ship the output back to the security team
  as a starting point, without prior forensics training.

- **Built on first-party tooling by design.** Everything here relies on
  native PowerShell and built-in Windows/registry access — no
  third-party agents, installers, or additional licensing. This was a
  deliberate choice to minimize deployment friction and avoid
  introducing new software (and new attack surface) onto a
  potentially-compromised host.

- **Not written by a DFIR specialist.** This was developed by a
  security generalist, not a dedicated forensics practitioner.
  Parsing logic (e.g. UserAssist and RecentDocs binary structures) is
  based on publicly documented formats and hands-on validation against
  test data, not formal forensic training. Findings from this tool
  should be treated as a starting point for triage decisions, not as
  a definitive interpretation of artifact data.

- **Known scope limits:**
  - RecentDocs filename extraction uses a printable-string sweep of
    each binary value rather than full shell-item-ID-list parsing, so
    embedded metadata beyond the filename (e.g. original folder paths
    within the shell item structure) is not currently extracted.
  - UserAssist parsing assumes the modern (Vista and later) 72-byte
    blob format; older XP-era 16-byte entries are not handled.
  - Feedback, corrections, and pull requests from anyone with deeper
    DFIR experience are welcome — this is offered as a practical
    starting point, not a finished or authoritative tool.

## Acknowledgments

PowerShell code development assisted by Anthropic's Claude (AI assistant) for code
review, debugging, and documentation drafting.

The following resources were very helpful in developing this tool:
- https://www.sans.org/blog/month-of-powershell-working-with-the-registry
- https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-keys?view=powershell-7.6
- https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-entries?view=powershell-7.6

## License

MIT