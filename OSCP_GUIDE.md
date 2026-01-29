# GoMap for OSCP - Complete Guide

**Your comprehensive network scanner and enumeration tool for OSCP labs and exam!**

## 🎯 Why GoMap for OSCP?

GoMap includes **50+ specialized scripts** focused on:
- **Service enumeration** - Detailed reconnaissance of all major services
- **Vulnerability detection** - Checks for known exploits (EternalBlue, Shellshock, etc.)
- **Misconfiguration identification** - Weak auth, missing security headers, etc.
- **Exploitation guidance** - Practical commands and Metasploit modules
- **OSCP-specific protocols** - SMB, RDP, NFS, SNMP, and more

## 🚀 Quick Start for OSCP

### Initial Network Scan
```bash
# Quick scan of all 65535 ports
./gomap -target 192.168.x.x -ports 1-65535 -threads 1000 -timeout 500ms

# Top 1000 ports with all features
./gomap -target 192.168.x.x -service -os -script -v
```

### OSCP Lab Enumeration Workflow

**Step 1: Discovery**
```bash
# Fast initial scan
./gomap -target 192.168.x.x -ports 1-1000 -threads 500

# Full TCP scan with scripts
./gomap -target 192.168.x.x -ports 1-65535 -service -script -v
```

**Step 2: Service-Specific Enumeration**
```bash
# Web servers (80, 443, 8080, 8000-9000)
./gomap -target 192.168.x.x -ports 80,443,8080,8000-9000 -script -script-category discovery -v

# SMB enumeration (139, 445)
./gomap -target 192.168.x.x -ports 139,445 -script -v

# Database services
./gomap -target 192.168.x.x -ports 3306,5432,1433,27017 -script -service -v
```

**Step 3: Vulnerability Scanning**
```bash
# Check for known vulnerabilities
./gomap -target 192.168.x.x -script -script-category vuln -v
```

## 📋 Service-by-Service Enumeration

### FTP (21)
```bash
./gomap -target 192.168.x.x -ports 21 -script -v
```
**What it checks:**
- Anonymous login (ftp-anon)
- Version detection
- FTP bounce vulnerability

**Next steps:**
```bash
ftp 192.168.x.x
# Try: anonymous / anonymous
# Try: anonymous / <blank>
```

### SSH (22)
```bash
./gomap -target 192.168.x.x -ports 22 -script -service -v
```
**What it checks:**
- SSH version and banner
- Authentication methods

**Next steps:**
```bash
# User enumeration
./ssh-user-enum.sh 192.168.x.x

# Brute force (if necessary)
hydra -L users.txt -P passwords.txt ssh://192.168.x.x
```

### Telnet (23) ⚠️
```bash
./gomap -target 192.168.x.x -ports 23 -script -v
```
**What it checks:**
- Unencrypted Telnet (HIGH PRIORITY!)
- Banner information

**Next steps:**
```bash
telnet 192.168.x.x
# Try default creds: admin/admin, root/root
```

### SMTP (25, 587)
```bash
./gomap -target 192.168.x.x -ports 25,587 -script -v
```
**What it checks:**
- SMTP commands (VRFY, EXPN)
- Supported features

**Next steps:**
```bash
# User enumeration
smtp-user-enum -M VRFY -U users.txt -t 192.168.x.x
```

### DNS (53)
```bash
./gomap -target 192.168.x.x -ports 53 -script -v
```
**What it checks:**
- DNS version
- Zone transfer vulnerability

**Next steps:**
```bash
# Zone transfer
dig @192.168.x.x domain.local AXFR

# Reverse lookup
dnsrecon -r 192.168.x.0/24 -n 192.168.x.x
```

### HTTP/HTTPS (80, 443, 8080, 8000-9000)
```bash
./gomap -target 192.168.x.x -ports 80,443,8080,8000-9000 -script -service -v
```
**What it checks:**
- HTTP methods (PUT, DELETE, etc.)
- robots.txt content
- Directory enumeration suggestions
- WebDAV detection
- Security headers
- SSL/TLS vulnerabilities
- WordPress detection
- Backup file patterns
- SQL injection guidance
- LFI/RFI guidance

**Next steps:**
```bash
# Directory brute force
gobuster dir -u http://192.168.x.x -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# Nikto scan
nikto -h http://192.168.x.x

# WordPress scan (if detected)
wpscan --url http://192.168.x.x --enumerate p,t,u

# Manual inspection
curl -i http://192.168.x.x
curl http://192.168.x.x/robots.txt
```

### NFS (111, 2049)
```bash
./gomap -target 192.168.x.x -ports 111,2049 -script -v
```
**What it checks:**
- NFS exports enumeration

**Next steps:**
```bash
# Show exports
showmount -e 192.168.x.x

# Mount share
mkdir /tmp/nfs
mount -t nfs 192.168.x.x:/share /tmp/nfs
```

### MSRPC (135)
```bash
./gomap -target 192.168.x.x -ports 135 -script -v
```
**What it checks:**
- MSRPC endpoint mapper

**Next steps:**
```bash
# Enumerate endpoints
rpcdump.py 192.168.x.x
```

### SMB (139, 445) - CRITICAL FOR OSCP!
```bash
./gomap -target 192.168.x.x -ports 139,445 -script -service -v
```
**What it checks:**
- SMB version/OS detection
- SMB signing requirements
- EternalBlue (MS17-010) check
- Share enumeration guidance
- User enumeration guidance
- NetBIOS information

**Next steps:**
```bash
# Enum4linux (comprehensive)
enum4linux -a 192.168.x.x

# SMB client
smbclient -L //192.168.x.x -N
smbclient //192.168.x.x/share -N

# Nmap SMB scripts
nmap -p 445 --script smb-vuln* 192.168.x.x

# CrackMapExec
crackmapexec smb 192.168.x.x -u '' -p ''
crackmapexec smb 192.168.x.x -u users.txt -p passwords.txt

# Check for EternalBlue
nmap -p 445 --script smb-vuln-ms17-010 192.168.x.x
```

### SNMP (161)
```bash
./gomap -target 192.168.x.x -ports 161 -script -v
```
**What it checks:**
- SNMP service detection
- Common community strings

**Next steps:**
```bash
# Brute force community strings
onesixtyone -c community.txt 192.168.x.x

# Walk the MIB
snmpwalk -v 2c -c public 192.168.x.x
```

### LDAP (389, 636, 3268)
```bash
./gomap -target 192.168.x.x -ports 389,636,3268 -script -v
```
**What it checks:**
- LDAP anonymous bind
- RootDSE information

**Next steps:**
```bash
# Anonymous bind query
ldapsearch -x -H ldap://192.168.x.x -s base namingcontexts

# Dump users
ldapsearch -x -H ldap://192.168.x.x -b "DC=domain,DC=local"

# Windapsearch
windapsearch.py -d domain.local --dc-ip 192.168.x.x -U
```

### MS SQL (1433, 1434)
```bash
./gomap -target 192.168.x.x -ports 1433,1434 -script -v
```
**What it checks:**
- MS SQL Server detection

**Next steps:**
```bash
# Connect
mssqlclient.py sa:password@192.168.x.x -windows-auth

# In SQL shell
xp_cmdshell 'whoami'
```

### MySQL (3306)
```bash
./gomap -target 192.168.x.x -ports 3306 -script -service -v
```
**What it checks:**
- MySQL version
- Protocol information

**Next steps:**
```bash
mysql -h 192.168.x.x -u root -p
```

### RDP (3389)
```bash
./gomap -target 192.168.x.x -ports 3389 -script -v
```
**What it checks:**
- RDP security settings
- NLA (Network Level Authentication) status

**Next steps:**
```bash
# Connect
xfreerdp /u:user /p:password /v:192.168.x.x

# Brute force
crowbar -b rdp -s 192.168.x.x/32 -u admin -C passwords.txt
```

### PostgreSQL (5432)
```bash
./gomap -target 192.168.x.x -ports 5432 -script -service -v
```

### VNC (5900, 5901, 5902)
```bash
./gomap -target 192.168.x.x -ports 5900,5901,5902 -script -v
```
**What it checks:**
- VNC protocol version
- Authentication requirements
- No-auth vulnerabilities

**Next steps:**
```bash
vncviewer 192.168.x.x:5900
```

### WinRM (5985, 5986)
```bash
./gomap -target 192.168.x.x -ports 5985,5986 -script -v
```
**What it checks:**
- WinRM service detection
- HTTP/HTTPS protocol

**Next steps:**
```bash
# Evil-WinRM
evil-winrm -i 192.168.x.x -u user -p password

# CrackMapExec
crackmapexec winrm 192.168.x.x -u user -p password
```

### Redis (6379)
```bash
./gomap -target 192.168.x.x -ports 6379 -script -service -v
```
**What it checks:**
- Redis version
- Authentication requirements

**Next steps:**
```bash
redis-cli -h 192.168.x.x
INFO
CONFIG GET dir
```

### Kerberos (88)
```bash
./gomap -target 192.168.x.x -ports 88 -script -v
```
**What it checks:**
- Kerberos KDC detection

**Next steps:**
```bash
# User enumeration
kerbrute userenum -d domain.local users.txt --dc 192.168.x.x

# ASREPRoast
GetNPUsers.py domain.local/ -dc-ip 192.168.x.x -request
```

## 🎓 OSCP Exam Strategy

### Time Management

**First 15 minutes:**
```bash
# Quick scan of all targets
for ip in 192.168.x.10 192.168.x.20 192.168.x.30; do
    ./gomap -target $ip -ports 1-1000 -threads 500 > scan_$ip.txt &
done
```

**Next 30 minutes:**
```bash
# Full scan with scripts on each target
for ip in 192.168.x.10 192.168.x.20 192.168.x.30; do
    ./gomap -target $ip -ports 1-65535 -service -script -v > detailed_$ip.txt &
done
```

**Review results and prioritize targets**

### Common OSCP Vulnerabilities to Check

1. **SMB Vulnerabilities**
   - EternalBlue (MS17-010)
   - Anonymous access
   - Weak permissions

2. **Web Applications**
   - SQL Injection
   - Local File Inclusion
   - Remote File Inclusion
   - File Upload vulnerabilities
   - Command Injection

3. **Weak Credentials**
   - Default passwords
   - Common passwords
   - No password required

4. **Misconfigurations**
   - Anonymous FTP
   - Open NFS shares
   - Public SNMP strings
   - Unauthenticated databases

5. **Kernel Exploits**
   - Check OS versions from service detection
   - Research kernel exploits after initial foothold

## 🔧 Integration with Other Tools

### Metasploit
```bash
# Use GoMap for initial recon, then:
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.x.x
run
```

### Nmap (for comparison/additional checks)
```bash
# After GoMap scan, use nmap for specific scripts:
nmap -p 445 --script smb-vuln-ms17-010 192.168.x.x
nmap -p 80 --script http-enum 192.168.x.x
```

### Enum4linux
```bash
# SMB enumeration after GoMap identifies SMB
enum4linux -a 192.168.x.x
```

## 💡 Pro Tips

1. **Always enumerate thoroughly** - More time in recon = less time stuck
2. **Try anonymous/guest access first** - Often overlooked
3. **Check ALL ports** - Not just the common ones
4. **Read script output carefully** - It provides exploitation commands
5. **Document everything** - Screenshots and commands for your report
6. **Use verbose mode (-v)** - See real-time progress
7. **Test credentials everywhere** - Reuse found creds on all services

## 🎯 OSCP Point Value Strategy

**10-point machines:** Start here, usually easier web apps
**20-point machines:** Medium difficulty, often Linux
**25-point machines:** Domain Controllers, Active Directory

Use GoMap's script engine to quickly identify:
- Entry points (web apps, SMB, NFS)
- Privilege escalation vectors
- Lateral movement opportunities

## 📝 Report Generation

Save your scans:
```bash
./gomap -target 192.168.x.x -ports 1-65535 -service -os -script -v | tee scan_results.txt
```

The output includes:
- Open ports and services
- Version information
- Security issues found
- Exploitation guidance
- Tools and commands to use

## ⚠️ Legal Notice

This tool is for use in the **OSCP labs and exam ONLY** or on systems you own/have permission to test. Unauthorized scanning is illegal.

## 🏆 Good Luck!

Remember: **Try Harder!** But also **Enumerate Smarter!**

---
*"The more you enumerate, the less you have to exploit"*
