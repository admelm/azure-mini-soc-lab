## Phase 1 — Zero Trust Foundation
Date: [4/1/2026]

- [x] Resource group created (minisoc-rg) — East US
- [x] Security Defaults enabled — enforces MFA across all accounts in tenant. Equivalent zero trust baseline for a single tenant. — screenshot: 
<img width="434" height="405" alt="image" src="https://github.com/user-attachments/assets/f4daef26-20bf-4501-a050-aa5a69b8a715" />

- [x] soc-analyst user created in Entra ID
- [x] Sentinel Reader role assigned via IAM


## Phase 2 — SIEM Infrastructure
Date: [4/1/2026]

- [x] Log Analytics Workspace created (minisoc-ws) — screenshot: 
<img width="436" height="395" alt="image" src="https://github.com/user-attachments/assets/5ef67a81-74c3-4793-bcf7-7600ab376495" />

- [x] Sentinel enabled and connected to minisoc-ws — screenshot: 
<img width="2493" height="1221" alt="image" src="https://github.com/user-attachments/assets/d2da6b36-3007-445e-a3a7-afa26c204f84" />

- [x] Content Hub: 4 solutions installed — screenshot:
<img width="1652" height="681" alt="image" src="https://github.com/user-attachments/assets/9b7fa400-c157-4815-b93c-dec5f98692ed" />

- [x] UEBA enabled — Microsoft Entra ID selected as identity data source. Additional sources will show up as VMs and connectors are added in later phases. — screenshot:
<img width="1191" height="486" alt="image" src="https://github.com/user-attachments/assets/0d67e70a-26de-4dd7-b1d7-b9a4da75530b" />

## Phase 3 - Windows VM Setup And Log Ingestion
Date: [4/3/2026]

- [x] Windows VM configured — minisoc-vm-win, B1s, East US.
<img width="1045" height="875" alt="image" src="https://github.com/user-attachments/assets/5c27d342-33fb-4b9a-95bb-93f3244fe284" />

- [x] VM networking — no public IP, inbound ports none.
<img width="841" height="977" alt="image" src="https://github.com/user-attachments/assets/967929d5-af72-47a0-8d79-45aca676e754" />


- [x] Windows VM deployed successfully.
<img width="680" height="384" alt="image" src="https://github.com/user-attachments/assets/146ebb39-c10d-4dda-b8fa-926d998a6ecd" />

- [x] Bastion config - connected to VM's subnet
<img width="793" height="938" alt="image" src="https://github.com/user-attachments/assets/d6b360e8-ba7e-44b1-a4ca-1daa8bd0ae4b" />

- [x] Explicit Deny-RDP rule added at priority 100 — blocks port 3389 inbound from all internet sources. Recognizinng RDP as a common attack sector
<img width="1124" height="64" alt="image" src="https://github.com/user-attachments/assets/1da22284-0d74-471f-af13-6075fff4ed08" />
