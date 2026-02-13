# Digital Forensics & Incident Response Cheatsheet

> Memory Forensics, Disk Analysis, Log Triage, IR Playbooks
> FLLC 2026 — FU PERSON

---

## Memory Forensics (Volatility 3)

```bash
# List processes
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree

# Hidden process detection
vol -f memory.raw windows.psscan

# Network connections
vol -f memory.raw windows.netscan

# Command history
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.consoles

# DLL injection detection
vol -f memory.raw windows.dlllist --pid <PID>
vol -f memory.raw windows.malfind

# Registry hive extraction
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Password hash extraction
vol -f memory.raw windows.hashdump

# File extraction from memory
vol -f memory.raw windows.dumpfiles --pid <PID>
vol -f memory.raw windows.filescan

# Process environment variables
vol -f memory.raw windows.envars --pid <PID>
```

---

## Disk Forensics

### Timeline Generation
```bash
# Plaso/log2timeline
log2timeline.py timeline.plaso disk_image.E01
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Autopsy
# Import E01 → Run Ingest Modules → Timeline Analysis

# fls (Sleuth Kit) — file listing with deleted files
fls -r -m "/" disk_image.dd
```

### Windows Artifacts
| Artifact | Location | Evidence Value |
|----------|----------|---------------|
| Prefetch | `C:\Windows\Prefetch\` | Program execution history |
| Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | Program install/execution |
| Shimcache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Program execution |
| NTFS $MFT | Root of NTFS volume | All file metadata, timestamps |
| USN Journal | `$Extend\$UsnJrnl` | File change log |
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Security, system, application events |
| Registry | `C:\Windows\System32\config\` | SAM, SYSTEM, SOFTWARE, SECURITY |
| User Registry | `C:\Users\<user>\NTUSER.DAT` | User preferences, recent files, typed URLs |
| Browser Data | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\` | History, downloads, cached creds |
| RDP Cache | `C:\Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache\` | RDP session bitmaps |

### Linux Artifacts
| Artifact | Location | Evidence Value |
|----------|----------|---------------|
| Auth logs | `/var/log/auth.log` | Login attempts, sudo usage |
| Syslog | `/var/log/syslog` | System events |
| Bash history | `~/.bash_history` | User command history |
| Crontab | `/var/spool/cron/`, `/etc/crontab` | Scheduled tasks (persistence) |
| SSH keys | `~/.ssh/` | Authentication material |
| /tmp and /dev/shm | Various | Attacker staging directories |
| systemd journals | `/var/log/journal/` | Structured system logs |

---

## Log Analysis

### Windows Event Log IDs (Critical)
| Event ID | Log | Meaning |
|----------|-----|---------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4732 | Security | User added to local group |
| 7045 | System | Service installed |
| 1102 | Security | Audit log cleared |
| 4104 | PowerShell | Script block logging |
| 4103 | PowerShell | Module logging |

### Logon Type Reference
| Type | Description |
|------|-------------|
| 2 | Interactive (console) |
| 3 | Network (SMB, share access) |
| 4 | Batch (scheduled task) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

### Sysmon Event IDs
| Event ID | Description |
|----------|-------------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded (DLL) |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess (credential dumping) |
| 11 | FileCreate |
| 12-14 | Registry events |
| 15 | FileCreateStreamHash (ADS) |
| 22 | DNSEvent |
| 23 | FileDelete |

---

## Incident Response Playbook

### Phase 1: Preparation
- [ ] IR team contact list and escalation matrix
- [ ] Forensic toolkit ready (USB with tools)
- [ ] Network diagram and asset inventory
- [ ] Log aggregation confirmed (SIEM ingestion)
- [ ] Backup integrity verified

### Phase 2: Detection & Analysis
- [ ] Alert triage — verify true positive
- [ ] Scope assessment — how many hosts affected?
- [ ] Preserve volatile evidence (memory dumps FIRST)
- [ ] Create forensic disk images (read-only)
- [ ] Timeline construction (earliest IOC to present)
- [ ] IOC extraction (hashes, IPs, domains, TTPs)

### Phase 3: Containment
- [ ] Network isolation of affected hosts
- [ ] Block IOCs at firewall/proxy/DNS
- [ ] Disable compromised accounts
- [ ] Revoke compromised credentials and tokens
- [ ] Monitor for lateral movement attempts

### Phase 4: Eradication
- [ ] Remove persistence mechanisms
- [ ] Patch exploited vulnerabilities
- [ ] Reimage compromised systems
- [ ] Verify clean state with EDR scan
- [ ] Rotate all potentially exposed secrets

### Phase 5: Recovery
- [ ] Restore from known-good backups
- [ ] Gradual reconnection with monitoring
- [ ] Verify business function restoration
- [ ] Enhanced monitoring for 72 hours minimum

### Phase 6: Lessons Learned
- [ ] Post-incident report (timeline, scope, impact)
- [ ] MITRE ATT&CK mapping of adversary TTPs
- [ ] Detection gap analysis — what was missed?
- [ ] Control improvement recommendations
- [ ] Updated runbooks and detection rules

---

## MITRE ATT&CK Quick Reference

| Tactic | Common Techniques |
|--------|-------------------|
| Initial Access | Phishing (T1566), Exploit Public App (T1190), Valid Accounts (T1078) |
| Execution | PowerShell (T1059.001), Cmd (T1059.003), Scheduled Task (T1053.005) |
| Persistence | Registry Run Keys (T1547.001), Scheduled Task, Service Creation (T1543.003) |
| Privilege Escalation | Token Manipulation (T1134), UAC Bypass (T1548.002), Exploitation (T1068) |
| Defense Evasion | Obfuscation (T1027), Timestomp (T1070.006), Process Injection (T1055) |
| Credential Access | LSASS Dump (T1003.001), Kerberoasting (T1558.003), Credential Files (T1552) |
| Discovery | Network Scan (T1046), Account Discovery (T1087), File Discovery (T1083) |
| Lateral Movement | PsExec (T1021.002), RDP (T1021.001), WMI (T1047) |
| Exfiltration | C2 Channel (T1041), Web Service (T1567), Automated (T1020) |
| Impact | Data Encryption (T1486), Service Stop (T1489), Data Destruction (T1485) |

---

**FLLC 2026** — Authorized forensic investigation only.
