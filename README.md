# Azure Mini SOC Lab

A simulated cloud-based Security Operations Center built on Microsoft Azure's free tier, covering the full analyst workflow from multi-source log ingestion through detection engineering, attack simulation, threat hunting, and a complete incident response case file.

![Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4)
![KQL](https://img.shields.io/badge/Detections-KQL-blue)
![ATT&CK](https://img.shields.io/badge/Mapped-MITRE%20ATT%26CK-red)
![SOAR](https://img.shields.io/badge/Automation-Logic%20Apps%20SOAR-orange)
![ZeroTrust](https://img.shields.io/badge/Identity-Zero%20Trust-green)

---

## Objectives

- Gain hands-on SIEM/SOAR experience using Microsoft Sentinel on real (not simulated-on-paper) infrastructure.
- Build and validate custom detection rules mapped to MITRE ATT&CK, using genuine attack telemetry rather than manually-crafted fake logs.
- Practice the full analyst workflow: detect → hunt → investigate → contain → close, with a documented case file.
- Ingest and correlate logs across three heterogeneous sources: Windows, Linux, and Azure control-plane activity.

## Architecture

| Component | Purpose |
|---|---|
| Microsoft Sentinel | Core SIEM/SOAR: detections, incidents, automation, hunting |
| Log Analytics Workspace (`minisoc-ws`) | Central log repository for all three sources |
| Windows Server 2022 VM (`minisoc-vm-win`, B1s) | Primary log source + Atomic Red Team attack simulation host |
| Ubuntu 24.04 LTS VM (`minisoc-vm-linux`, B1s) | Secondary log source: Linux Syslog ingestion |
| Azure Monitor Agent (AMA) | Ships Windows Security Events + Sysmon telemetry to the workspace |
| Syslog Connector | Ships Linux auth/authpriv/cron/syslog/kern facilities to the workspace |
| Azure Activity Logs | Subscription-level control-plane operations, the third log source |
| Logic Apps (Playbooks) | SOAR automation: incident auto-triage and auto-close |
| Microsoft Entra ID | Identity plane: Security Defaults (Zero Trust baseline on a personal-tier account) |
| Azure Bastion | Browser-based RDP/SSH with no public IP on either VM |
| Azure NSGs | Explicit deny rules + Bastion-only access paths on both VM subnets |

**Note on Zero Trust:** this lab runs on a personal Gmail-based Azure account, which doesn't have access to Entra ID P2 (Conditional Access, Identity Protection). Security Defaults is used instead as the free-tier Zero Trust baseline, a deliberate, honest substitution rather than a gap.

## Detection Engineering

4 custom KQL rules mapped to MITRE ATT&CK, plus 3 built-in Sentinel analytics rule templates. Full queries in [`kql-queries/`](./kql-queries/):

| Rule | MITRE Technique | Severity | Source |
|---|---|---|---|
| Brute Force with Successful Logon | T1110 | Medium | Windows |
| Privilege Escalation via Group Modification | T1078 | High | Windows |
| Living-Off-the-Land Binary Execution | T1059 / T1218 | High | Windows |
| Linux SSH Brute Force | T1110 | Medium | Linux Syslog |

## Attack Simulation: Atomic Red Team

6 MITRE ATT&CK techniques executed against real infrastructure to generate genuine detection telemetry (not hand-crafted logs). Full outcomes in [`atomic-red-team/simulation-log.md`](./atomic-red-team/simulation-log.md). Results are reported honestly, including the ones that didn't fire, because a blocked/failed technique is still valid, documentable telemetry:

- 2 techniques succeeded and generated real telemetry
- 2 were blocked by Windows Defender (credential dumping) or hit a single-VM environment limitation
- 1 hit a missing prerequisite
- 1 hit an expected single-VM environment constraint

## Threat Hunting

3 hypothesis-driven hunts run in Defender Advanced Hunting: proactive searches for attacker behavior that hadn't triggered any automated rule yet.

- **Privilege Escalation Discovery** (T1069): validated with 84 group-enumeration events from the simulated host and 31 from the admin account.
- **Encoded PowerShell / LOTL Evasion** (T1059): initially returned 0 results, which led to discovering that Windows command-line auditing is off by default (`ProcessCreationIncludeCmdLine_Enabled` had to be explicitly enabled). This is a real, documented misconfiguration finding, not just a passed test.
- **Credential Harvesting Signals** (T1003): 0 results, confirming Windows Defender blocked all 14 LSASS-dump sub-tests before they could execute.

## SOAR Automation

Full workflow documented in [`playbooks/README.md`](./playbooks/README.md). A `SOC-AutoTriage` Logic App auto-comments and tags every new incident (`AUTO-TRIAGED`), paired with automation rules that run triage first and auto-close Informational-severity incidents to reduce analyst queue noise. **Honest limitation:** an AbuseIPDB IP-reputation enrichment step was attempted but is not functional, since the entity-extraction pattern it needs isn't supported by the current Logic Apps designer when triggered from a Sentinel incident. The core auto-triage workflow works; the IP-reputation lookup does not, and this repo doesn't claim otherwise.

## Incident Response

One incident worked end-to-end from alert to closure. Full case file: [`incident-reports/SOC-2026-001-case-file.md`](./incident-reports/SOC-2026-001-case-file.md).

**SOC-2026-001: Living-Off-the-Land Binary Execution.** 21 correlated High-severity alerts consolidated by Sentinel into one incident. Investigation via Advanced Hunting identified 9 LOLBin execution events: `rundll32.exe` and `cmd.exe` both spawned by `svchost.exe` over a 45-minute window, a parent-child relationship that `svchost.exe` should never legitimately produce. Closed as **True Positive**. Full activity trail of triage → investigation → containment → closure preserved as analyst comments.

## MITRE ATT&CK Coverage

<img width="700" alt="ATT&CK Navigator heatmap" src="https://github.com/user-attachments/assets/3b0de9ad-7631-4c21-a063-52b58bd6b97b" />

Detection rules and hunt queries currently cover **8 MITRE ATT&CK techniques across 6 tactics** (Credential Access, Privilege Escalation, Execution, Defense Evasion, Discovery, Lateral Movement): 5 fully detected by a custom or built-in rule, 2 covered by hunt-query-only visibility, and 1 attempted with a documented single-VM environment limitation (SMB lateral movement).

## Multi-Source Log Ingestion

Three independent log sources confirmed flowing into Sentinel: Windows Security Events (Sysmon + AMA), Linux Syslog (`minisoc-vm-linux`), and Azure Activity Logs (subscription-level control-plane operations). Getting there involved real cross-platform troubleshooting, documented in full in [`build-log.md`](./build-log.md) Phase 10, including a DCR severity-filter bug (Ubuntu 24.04 logs SSH auth failures at `LOG_INFO`, below a `LOG_WARNING` filter) and an NSG rule that initially blocked Bastion's own SSH path to the Linux VM.

## Cost Management

Both VMs run on the Azure free-tier B1s allowance. Azure Bastion (~$5/month) and its public IP are deleted at the end of every working session and recreated at the start of the next, rather than left running continuously. That's the single largest avoidable cost in a lab like this.

## What's Next

This lab is under active development. Completed so far: **Phases 1-10** (Zero Trust foundation through multi-source log ingestion). Planned next:

- **Investigation Query Library**: a set of reusable KQL queries for manual use during active investigations (distinct from automated detection rules).
- **Detection Tuning documentation**: false-positive analysis and threshold adjustments, backed by real observed data rather than assumptions.
- **Lessons Learned**: structured reflection, including operational lessons already learned the hard way (e.g., Log Analytics data retention defaults purging historical telemetry between multi-week lab sessions).

## Full Build Log

Every phase, with dated checkboxes and screenshots: [`build-log.md`](./build-log.md)
