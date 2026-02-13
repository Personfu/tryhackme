# FLLC Nmap Cheatsheet

## Scan Types

```bash
# Quick scan (top 1000 ports)
nmap target

# Full TCP scan
nmap -p- target

# Service version detection
nmap -sV target

# OS detection
nmap -O target

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A target

# UDP scan
nmap -sU target

# SYN stealth scan
nmap -sS target

# TCP connect scan
nmap -sT target

# Ping sweep (no port scan)
nmap -sn 192.168.1.0/24

# Skip host discovery
nmap -Pn target
```

## Script Categories

```bash
# Default scripts
nmap -sC target

# Vulnerability scan
nmap --script vuln target

# All scripts for a service
nmap --script "http-*" target

# Specific scripts
nmap --script http-enum target
nmap --script smb-vuln-* target
nmap --script ssh-brute target

# Script categories
nmap --script "auth,default,discovery" target
```

## Output

```bash
# All formats
nmap -oA scan_results target

# XML output
nmap -oX scan.xml target

# Grepable output
nmap -oG scan.gnmap target

# Normal output
nmap -oN scan.txt target
```

## Common Combinations

```bash
# Full pentest scan
nmap -sC -sV -O -p- -oA full_scan target

# Quick web scan
nmap -sV -p 80,443,8080,8443 --script "http-*" target

# SMB enumeration
nmap -p 139,445 --script smb-enum-shares,smb-enum-users target

# Firewall evasion
nmap -sS -T2 -f --data-length 200 target

# Subnet discovery
nmap -sn -PE -PA 192.168.1.0/24
```

## Timing

```
-T0  Paranoid   (IDS evasion, very slow)
-T1  Sneaky     (IDS evasion)
-T2  Polite     (less bandwidth)
-T3  Normal     (default)
-T4  Aggressive (faster, reliable networks)
-T5  Insane     (fastest, may miss ports)
```

---

*FLLC 2026*
