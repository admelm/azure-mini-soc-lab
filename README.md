# Azure Mini SOC Lab (Free Tier)

A hands-on cloud SOC environment built using **Microsoft Azure** and **Sentinel**, designed to simulate real-world threat detection, investigation, and response — all on free-tier resources.

> 💡 Inspired by Jared Medeiros' Medium tutorial, this implementation expands with my own configurations, custom detections, automation rules, and documentation for learning and portfolio presentation.

---

## 🎯 Objectives
- Gain real-world **SIEM** experience using Microsoft Sentinel.
- Build a **working SOC** using only free Azure services.
- Develop **custom KQL detections**, playbooks, and hunting workflows.
- Showcase **incident response and automation** skills.

---


### Components
| Component | Purpose |
|------------|----------|
| **Azure Sentinel** | SIEM & SOAR analytics, incident management |
| **Log Analytics Workspace** | Central log ingestion and query engine |
| **Azure VM (honeypot)** | Generates logs and simulates attacks |
| **Threat Intelligence Connector** | Ingests external IOCs (Defender TI, OTX, etc.) |
| **Logic Apps (Playbooks)** | Automates alert triage and response |

---

## 🪜 Step-by-Step Setup

### Step 1. Azure Setup
- Create **free Azure account** → get $200 credits + free services.
- Create resource group: `minisoc-rg`.

### Step 2. Deploy Sentinel
- Create **Log Analytics Workspace** → `minisoc-ws`.
- Enable **Microsoft Sentinel** and attach workspace.

### Step 3. VM Log Ingestion
- Deploy free-tier VM (`Standard_B1s`, Windows or Ubuntu).
- Enable **Monitoring → Insights** and connect to `minisoc-ws`.
- Configure **Data Collection Rule** (`minisoc-dcr`) for Event Logs and Performance Counters.
- Simulate activity (logons, failed attempts, PowerShell commands).

### Step 4. Threat Intelligence Integration
- Install **Threat Intelligence Solution** via Content Hub.
- Enable **Microsoft Defender Threat Intelligence** connector.
- Deploy **Windows Security Events via AMA** solution and DCR (`minisoc-se`).

### Step 5. Detection Rules
- Use built-in template: _“Multiple authentication failures followed by success.”_
- Create **custom rule**: `GainedCodeExecutionADFSViaSMB`  
  (includes KQL query and MITRE ATT&CK mapping).
- Configure entity mapping for Account and Host entities.

### Step 6. Automation & Response
- **Logic App (Playbook)** — sends alert emails to analyst inbox.
- **Automation Rule** — auto-assign incidents to analyst.

### Step 7. Threat Hunting
- Create a Hunt: `Privilege Escalation`
- Use prebuilt queries:
  - “User account added to privileged group”
  - “Unauthorized permission grants”
- Run and interpret results manually to validate hypotheses.

---

## 🔍 Example Detection Query (KQL)
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account, bin(TimeGenerated, 1h)
| where FailedLogons > 5
