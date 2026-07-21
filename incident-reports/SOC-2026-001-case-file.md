# Case File: SOC-2026-001

**Title:** Living-Off-the-Land Binary Execution
**Severity:** High
**Status:** Closed, True Positive (Malicious User Activity)
**MITRE Tactics:** Execution (TA0002), Defense Evasion (TA0005)
**Techniques:** T1059 (Command and Scripting Interpreter) | T1218 (System Binary Proxy Execution)
**Source Host:** `minisoc-vm-win`
**Source Alert:** Custom Rule 3 (Living-Off-the-Land Binary Execution)
**Detection Rule:** [`kql-queries/lotl-detection.kql`](../kql-queries/lotl-detection.kql)

---

## Triage

Incident assigned to analyst and set to **In Progress**. Severity confirmed High; classification held as Unclassified pending investigation.

Triage decision: 21 correlated High-severity alerts consolidated by Sentinel's correlation engine into this single incident, mapped to MITRE T1059 and T1218 on an active device (`minisoc-vm-win`). Assessed as a credible incident and escalated to investigation rather than dismissed as noise.

## Investigation

Ran an Advanced Hunting query to reconstruct what actually happened, the same underlying skill an investigation query library formalizes, applied here to a live incident instead of a canned template.

- **9 LOLBin execution events confirmed**, spanning a 45-minute window (3:19 PM to 4:04 PM).
- Two distinct Living-Off-the-Land patterns identified: `rundll32.exe` and `cmd.exe`, **both spawned by `svchost.exe`**.
- Account: `WORKGROUP\minisoc-vm-win$` (machine account) | Host: `minisoc-vm-win`.
- `svchost.exe` does not legitimately spawn command interpreters; this parent-child relationship is itself the indicator, independent of anything the command line contained.
- Evidence supports both techniques: T1218 (rundll32 proxy execution) and T1059 (cmd.exe execution).
- **UEBA was checked and found insufficient.** Microsoft Entra ID sync was enabled but Active Directory sync was not, and several identity data sources (AAD Managed Identity, Service Principal, Audit Logs) showed as "not ingested." No behavioral anomaly score was available for the `minisoc-vm-win$` account. This is documented here as a real lab limitation, not glossed over as a working control.
- No lateral movement detected; activity confirmed contained to `minisoc-vm-win`.

## Containment

Containment steps below are documented as the **theoretical production response**. This incident was a controlled single-VM simulation with no live threat, and the VM was already deallocated post-simulation, so these steps were not actually executed against a real compromise:

1. **Account containment:** disable `WORKGROUP\minisoc-vm-win$` in Entra ID to prevent further authenticated activity from the affected host.
2. **Host isolation:** NSG deny-all inbound/outbound on the host's subnet, preserving only Bastion access for forensic follow-up.
3. **Credential reset:** rotate local administrator credentials; rotate the machine account password via Group Policy.
4. **Evidence preservation:** capture a memory dump and process list before any remediation; export the relevant Sentinel KQL results as the case record.
5. **UEBA review:** flag the account for enhanced monitoring post-incident (acknowledging UEBA wasn't functional here, per the investigation finding above).

## Closure

**Classification:** True Positive, Malicious User Activity.
**Root cause:** Living-off-the-land technique. Legitimate system binaries (`rundll32.exe`, `cmd.exe`) abused via an anomalous parent process (`svchost.exe`) to blend in with normal system activity.
**Rule validation:** Custom Rule 3 (LOTL detection) confirmed correctly functioning; it caught exactly the behavior it was designed for.
**Lifecycle:** Alert → Triage → Investigation → Containment (theoretical) → Closure, with three analyst comments preserved in the Sentinel activity timeline as a full audit record of the investigation and decision points.
