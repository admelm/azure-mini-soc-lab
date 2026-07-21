# SOAR Playbooks

Two Logic Apps and two automation rules drive incident auto-triage in this lab. ARM/JSON exports aren't included here yet; this describes the actual configured workflow as built and validated in Sentinel.

## SOC-AutoTriage (working)

3-step Consumption-tier, stateful Logic App:

1. **Trigger:** Microsoft Sentinel incident trigger, starts automatically on every new incident.
2. **Add comment to incident:** pulls Incident Title, Severity, and Tactics from the Sentinel trigger's dynamic content and posts an auto-triage comment.
3. **Update incident:** sets status to Active, preserves the original severity, and tags the incident `AUTO-TRIAGED`.

This workflow is fully operational and validated against real incidents, including SOC-2026-001 (see [`incident-reports/SOC-2026-001-case-file.md`](../incident-reports/SOC-2026-001-case-file.md)).

## SOC-IP-Reputation-Check (partially working, honest limitation)

Deployed as a Consumption-tier stateful Logic App, triggered the same way on every new incident, intended to check the alert's source IP against AbuseIPDB and post the confidence score as an incident comment.

**This does not currently work end-to-end.** The entity-extraction step (a `For each` loop over the incident's IP entities) is not supported by the current Logic Apps designer when the trigger is a Sentinel incident trigger. This is a documented platform limitation encountered during the build, not a configuration mistake that was left unfixed. The Logic App exists as the intended foundation for IP-reputation enrichment, but the enrichment itself does not run. This repo does not claim AbuseIPDB integration as complete.

## Automation Rules

| Rule | Trigger | Action | Order |
|---|---|---|---|
| `Auto-Run-Triage` | Incident created | Run `SOC-IP-Reputation-Check` playbook | 1 (runs first) |
| `Auto-Close-Informational` | Incident created, Severity = Informational | Auto-close the incident | 2 (runs after triage) |

`Auto-Close-Informational` is what reduces analyst queue noise: Informational-severity incidents are closed automatically rather than requiring manual review, while anything Medium severity or above still reaches an analyst.
