# FLLC — TryHackMe Notes & Security Cheatsheets

<div align="center">

```
    ███████╗██╗     ██╗      ██████╗
    ██╔════╝██║     ██║     ██╔════╝
    █████╗  ██║     ██║     ██║
    ██╔══╝  ██║     ██║     ██║
    ██║     ███████╗███████╗╚██████╗
    ╚═╝     ╚══════╝╚══════╝ ╚═════╝
       SECURITY OPERATIONS LIBRARY
```

<img src="https://img.shields.io/badge/Rooms-992-00FFFF?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/KOTH-10-FF00FF?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/Cheatsheets-12-7B2FBE?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/FLLC-2026-00FFFF?style=for-the-badge&labelColor=0D0D2B"/>

</div>

---

## FLLC Cheatsheets

| Cheatsheet | Focus Area |
|------------|------------|
| [Pentest Methodology](fllc-cheatsheets/PENTEST_METHODOLOGY.md) | Full 6-phase penetration testing workflow |
| [Nmap](fllc-cheatsheets/NMAP_CHEATSHEET.md) | Scan types, NSE scripts, timing, output formats |
| [Linux PrivEsc](fllc-cheatsheets/LINUX_PRIVESC.md) | SUID, cron, capabilities, kernel, path hijacking |
| [Windows PrivEsc](fllc-cheatsheets/WINDOWS_PRIVESC.md) | Services, tokens, registry, DLL hijack, UAC bypass |
| [Active Directory](fllc-cheatsheets/ACTIVE_DIRECTORY.md) | Enumeration, Kerberoasting, lateral movement, persistence |
| [Web Exploitation](fllc-cheatsheets/WEB_EXPLOITATION.md) | OWASP Top 10, SQLi, XSS, SSRF, API security |
| [OSINT](fllc-cheatsheets/OSINT_CHEATSHEET.md) | Recon, social media, domain intel, geolocation |
| [Reverse Engineering](fllc-cheatsheets/REVERSE_ENGINEERING.md) | Ghidra, radare2, binary analysis, anti-RE bypass |
| [AI Red Teaming](fllc-cheatsheets/AI_RED_TEAMING.md) | LLM prompt injection, model extraction, adversarial ML |
| [Compliance Pentest](fllc-cheatsheets/COMPLIANCE_PENTEST.md) | NIST, PCI-DSS, SOC 2, HIPAA pentest mapping |
| [Cloud Security](fllc-cheatsheets/CLOUD_SECURITY.md) | AWS/Azure/GCP attack surface, IAM exploitation, defense |
| [Forensics & IR](fllc-cheatsheets/FORENSICS_IR.md) | Memory forensics, disk analysis, log triage, IR playbooks |

---

## FLLC Methodology

| Document | Description |
|----------|-------------|
| [Attack Frameworks](fllc-methodology/ATTACK_FRAMEWORKS.md) | MITRE ATT&CK, Cyber Kill Chain, Diamond Model mapping |
| [Medium Articles](fllc-methodology/MEDIUM_ARTICLES.md) | Curated security articles and research references |

---

## TryHackMe Room Notes (992 Rooms)

The `rooms/` directory contains notes and solutions organized by domain:

| Domain | Examples |
|--------|----------|
| **Offensive Security** | Buffer overflows, web exploitation, privilege escalation, post-exploitation |
| **Active Directory** | Domain enumeration, Kerberoasting, trust exploitation, persistence |
| **Cloud Security** | AWS IAM, S3 attacks, EC2 metadata, VPC exploitation, Lambda abuse |
| **Defensive Security** | SIEM, Splunk, ELK, incident response, threat hunting |
| **Forensics** | Memory analysis (Volatility), disk forensics, steganography |
| **Networking** | Protocols, firewall rules, VPN, DNS attacks, MITM |
| **Cryptography** | Hash cracking, encryption, PKI, attacking ECB |
| **OSINT** | Geolocation, social media, domain intel, recon |
| **Malware Analysis** | Static/dynamic analysis, reverse engineering, AV evasion |
| **Red Teaming** | C2 frameworks, lateral movement, data exfiltration |

---

## King of the Hill (10 Arenas)

The `koth/` directory contains strategies and notes for competitive THM KOTH arenas.

---

## Tool Quick Reference

| Tool | Use Case | Category |
|------|----------|----------|
| `nmap` | Port scanning, service detection, NSE scripts | Recon |
| `gobuster` | Directory and subdomain brute-force | Web |
| `ffuf` | Web fuzzing (dirs, params, vhosts) | Web |
| `sqlmap` | Automated SQL injection | Exploitation |
| `hydra` | Brute force authentication | Credential |
| `hashcat` | GPU-accelerated hash cracking | Credential |
| `john` | CPU hash cracking with rules | Credential |
| `burpsuite` | Web application proxy and scanner | Web |
| `metasploit` | Exploitation framework | Exploitation |
| `mimikatz` | Windows credential extraction | Post-Exploit |
| `BloodHound` | AD attack path analysis | AD |
| `Impacket` | Network protocol attacks, AD exploitation | AD/Network |
| `CrackMapExec` | AD/SMB/WinRM enumeration and exploitation | AD |
| `Wireshark` | Network packet analysis | Network |
| `tcpdump` | CLI packet capture | Network |
| `volatility` | Memory forensics framework | Forensics |
| `Autopsy` | Disk forensics platform | Forensics |
| `CyberChef` | Data encoding/decoding Swiss Army knife | Utility |
| `LinPEAS` | Linux privilege escalation enumeration | PrivEsc |
| `WinPEAS` | Windows privilege escalation enumeration | PrivEsc |
| `Ghidra` | Binary reverse engineering | RE |
| `radare2` | Binary analysis framework | RE |
| `Pacu` | AWS exploitation framework | Cloud |
| `ScoutSuite` | Multi-cloud security auditing | Cloud |

---

<div align="center">

**FLLC 2026** — FU PERSON by PERSON FU

Authorized security testing only.

</div>
