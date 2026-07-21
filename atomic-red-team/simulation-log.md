# Atomic Red Team Simulation Log

Invoke-AtomicRedTeam v2.1.0 installed on `minisoc-vm-win`. All techniques below were executed against real infrastructure to generate genuine telemetry. A blocked or failed technique is reported here exactly as honestly as a successful one, because both are valid, documentable outcomes in a real environment.

| Technique | Name | Outcome | Telemetry Generated |
|---|---|---|---|
| T1078.001 | Valid Accounts: Guest account abuse | ✅ Succeeded | EventID 4722 (account enabled), EventID 4732 (added to privileged group) |
| T1059.001 | PowerShell Execution: Mimikatz | 🛑 Blocked by Windows Defender | Exit code 2, no process ever launched, so no EventID 4688 generated |
| T1547.001 | Registry Run Key Persistence | ✅ Succeeded | EventID 4657 (registry value modified) |
| T1069.001 | Local Group Enumeration | ✅ Succeeded (5/6 sub-tests; deferred to Phase 7) | EventID 4799 (local group membership enumerated), across `net localgroup`, `Get-LocalGroup`, WMIC, and WMI Object methods. SharpHound sub-test skipped (external payload not downloaded, expected, not a failure). |
| T1021.002 | SMB / Windows Admin Shares | ⚠️ Environment constraint | Exit code 2, network path not found; expected in an isolated single-VM environment with no second host to target |

**Phase 4 total: 6 distinct EventID categories generated in Sentinel**, confirming the full attack-to-detection pipeline (Atomic Red Team → Sysmon/AMA → DCR → Sentinel) was operational end to end.

## Phase 7 additions: encoded execution and credential access

| Technique | Name | Outcome | Telemetry Generated |
|---|---|---|---|
| T1059.001 | Encoded PowerShell (`-EncodedCommand`) | ✅ Succeeded | EventID 4688 with a Base64-encoded payload visible in the `CommandLine` field, but only after command-line auditing was explicitly enabled (`ProcessCreationIncludeCmdLine_Enabled`), which was off by default. Without that fix, this event would have been invisible to the SIEM entirely, a real, documented misconfiguration finding. |
| T1003.001 | LSASS Credential Dumping (14 sub-tests: ProcDump, comsvcs.dll, Mimikatz, Out-Minidump, rdrleakdiag) | 🛑 Fully blocked | All 14 sub-tests returned "Access is denied" or "Script contains malicious content"; Windows Defender intercepted every attempt before process launch. No EventID 4688 generated. Two "Threats found" Defender alerts logged (8:15 PM, 8:21 PM), confirming real-time detection and blocking, not silent failure. External payload tools (NanoDump, pypykatz, xordump) were absent from the filesystem, which also limited full technique coverage, noted honestly rather than worked around. |

## Why the blocked techniques matter as much as the successful ones

A portfolio that only shows successful attacks looks staged. Windows Defender actively blocking Mimikatz and 14/14 LSASS-dump variants, with the alerts to prove it, demonstrates the endpoint protection layer is real and functioning, and that the lab environment behaves like production infrastructure rather than a permissive sandbox built to make detections look good.
