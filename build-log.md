## Phase 1 — Zero Trust Foundation
Date: [4/1/2026]

- [x] Resource group created (minisoc-rg) — East US
- [x] Security Defaults enabled — enforces MFA across all accounts in tenant. Equivalent zero trust baseline for a single tenant. — screenshot: 
<img width="434" height="405" alt="image" src="https://github.com/user-attachments/assets/f4daef26-20bf-4501-a050-aa5a69b8a715" />

- [x] soc-analyst user created in Entra ID
- [x] Sentinel Reader role assigned via IAM — pending Phase 2 completion


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
