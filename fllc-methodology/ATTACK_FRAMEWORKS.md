# Attack Frameworks Quick Reference

> MITRE ATT&CK, PTES, OWASP, Cyber Kill Chain, Diamond Model.
> FLLC 2026 — FU PERSON

---

## MITRE ATT&CK — Tactics (Enterprise)

| ID | Tactic | Description |
|----|--------|-------------|
| TA0043 | Reconnaissance | Gathering target information |
| TA0042 | Resource Development | Establishing infrastructure |
| TA0001 | Initial Access | Getting into the network |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining access |
| TA0004 | Privilege Escalation | Getting higher permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Learning about the environment |
| TA0008 | Lateral Movement | Moving through the network |
| TA0009 | Collection | Gathering target data |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Disrupting availability/integrity |

### Most Common Techniques (2025-2026)
| Technique | ID | Prevalence |
|-----------|-----|------------|
| Phishing | T1566 | Very High |
| Valid Accounts | T1078 | Very High |
| Exploitation of Public-Facing App | T1190 | High |
| Command and Scripting Interpreter | T1059 | Very High |
| OS Credential Dumping | T1003 | High |
| Remote Services | T1021 | High |
| Ingress Tool Transfer | T1105 | High |
| Process Injection | T1055 | High |

---

## Cyber Kill Chain (Lockheed Martin)

| Phase | Description | Defender Action |
|-------|-------------|-----------------|
| 1. Reconnaissance | Research target | Monitor for scanning, OSINT exposure |
| 2. Weaponization | Create exploit/payload | Threat intel, sandbox analysis |
| 3. Delivery | Transmit to target | Email gateway, web filter, USB policy |
| 4. Exploitation | Trigger vulnerability | Patching, input validation, EDR |
| 5. Installation | Install persistence | Endpoint monitoring, file integrity |
| 6. C2 | Establish command channel | Network monitoring, DNS filtering |
| 7. Actions on Objectives | Achieve goal | DLP, segmentation, IR plan |

---

## PTES (Penetration Testing Execution Standard)

| Phase | Activities |
|-------|-----------|
| 1. Pre-engagement | Scope, rules of engagement, authorization |
| 2. Intelligence Gathering | OSINT, network recon, social engineering recon |
| 3. Threat Modeling | Identify assets, threats, attack vectors |
| 4. Vulnerability Analysis | Automated scanning, manual testing, validation |
| 5. Exploitation | Gain access, demonstrate impact |
| 6. Post-exploitation | Pivot, escalate, maintain access, collect data |
| 7. Reporting | Executive summary, technical details, remediation |

---

## OWASP Testing Guide

| Phase | Tests |
|-------|-------|
| Info Gathering | Web server fingerprinting, application discovery, content review |
| Configuration | SSL/TLS, HTTP methods, admin interfaces, file extensions |
| Identity | User registration, account enumeration, password policy |
| Authentication | Default creds, lockout, bypass, MFA |
| Authorization | Path traversal, privilege escalation, IDOR |
| Session | Cookie attributes, fixation, CSRF |
| Input Validation | SQLi, XSS, injection, file upload, SSRF |
| Error Handling | Error codes, stack traces, info disclosure |
| Cryptography | Weak ciphers, insufficient transport security |
| Business Logic | Workflow bypass, function abuse, race conditions |
| Client-side | DOM XSS, JavaScript analysis, WebSocket, postMessage |

---

## Diamond Model of Intrusion Analysis

```
        Adversary
           |
    Infrastructure --- Capability
           |
         Victim
```

| Element | Questions |
|---------|-----------|
| **Adversary** | Who? Attribution, motivation, sophistication |
| **Infrastructure** | How? C2 servers, domains, IPs, tools |
| **Capability** | What? Exploits, malware, TTPs |
| **Victim** | Target? Organization, system, data |

---

**FLLC 2026** — FU PERSON by PERSON FU
