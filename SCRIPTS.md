# GoMap Script Engine (NSE-like)

GoMap now includes a powerful script engine inspired by Nmap's NSE (Nmap Scripting Engine)!

## Overview

The script engine allows you to run specialized scripts against discovered services to:
- Detect vulnerabilities
- Gather detailed service information
- Check authentication methods
- Identify misconfigurations
- Extract SSL/TLS certificate details
- And much more!

## Available Scripts

### Authentication Scripts (auth)
- **http-auth** - Detects HTTP authentication methods
- **ftp-anon** - Checks for anonymous FTP login
- **ssh-auth-methods** - Detects SSH authentication methods
- **smb-security-mode** - Checks SMB security configuration and signing
- **rdp-nla** - Checks if RDP requires Network Level Authentication
- **vnc-info** - VNC authentication and version detection
- **ldap-rootdse** - LDAP anonymous bind and RootDSE enumeration
- **telnet-encryption** - Detects unencrypted Telnet (security risk)

### Discovery Scripts (discovery)
- **http-headers** - Captures HTTP response headers
- **http-title** - Extracts HTML page titles
- **http-robots-txt** - Retrieves and analyzes robots.txt
- **http-methods** - Checks allowed HTTP methods
- **http-enum** - Suggests HTTP directory enumeration techniques
- **http-wordpress-enum** - WordPress detection and enumeration
- **smtp-commands** - Enumerates SMTP commands and features
- **ssl-cert** - Extracts SSL/TLS certificate information
- **smb-os-discovery** - SMB version and OS detection
- **smb-enum-shares** - Enumerates SMB shares
- **smb-enum-users** - SMB user enumeration guidance
- **nbstat** - NetBIOS information gathering
- **rdp-enum-encryption** - RDP security configuration
- **msrpc-enum** - MSRPC endpoint enumeration
- **winrm-info** - WinRM service detection
- **krb5-enum-users** - Kerberos service and user enumeration
- **nfs-showmount** - Lists NFS exports
- **dns-version** - DNS version querying
- **ntp-monlist** - NTP service enumeration
- **tftp-enum** - TFTP service detection
- **rsync-list-modules** - Rsync module enumeration
- **snmp-info** - SNMP service and community strings
- **elasticsearch-info** - Elasticsearch detection

### Vulnerability Scripts (vuln)
- **http-vuln-check** - Checks for common HTTP security issues (missing headers)
- **http-webdav-scan** - WebDAV detection and testing
- **http-shellshock** - Shellshock (CVE-2014-6271) detection guidance
- **ssl-vuln** - Tests for SSL/TLS vulnerabilities (weak protocols/ciphers)
- **ftp-bounce** - Checks for FTP bounce vulnerability
- **smb-vuln-ms17-010** - EternalBlue vulnerability check
- **dns-zone-transfer** - DNS zone transfer vulnerability
- **rlogin-check** - Detects insecure rlogin/rsh services
- **rmi-vuln-classloader** - Java RMI deserialization vulnerabilities
- **distcc-cve2004-2687** - Vulnerable DistCC daemon detection

### Version Scripts (version)
- **ssh-version** - Extracts SSH version information
- **mysql-info** - Gathers MySQL server details
- **redis-info** - Collects Redis server information
- **mongodb-info** - MongoDB service information
- **ms-sql-info** - Microsoft SQL Server detection
- **cassandra-info** - Apache Cassandra detection

### Web Application Testing Guidance (safe)
- **http-sql-injection** - SQL injection testing guidance and payloads
- **http-xss** - XSS testing guidance and bypasses
- **http-lfi** - Local/Remote File Inclusion testing payloads
- **http-backup-finder** - Common backup file patterns to check

**Total Scripts: 52** covering all major services and OSCP scenarios!

## 🎓 OSCP-Specific Scripts

Many scripts are designed specifically for OSCP enumeration and exploitation:

**Windows/Active Directory:**
- SMB enumeration suite (smb-os-discovery, smb-enum-shares, smb-vuln-ms17-010)
- RDP detection (rdp-enum-encryption, rdp-nla)
- Kerberos enumeration (krb5-enum-users)
- LDAP anonymous binding (ldap-rootdse)
- WinRM detection (winrm-info)

**Web Applications:**
- SQL Injection guidance (http-sql-injection)
- LFI/RFI payloads (http-lfi)
- WebDAV file upload (http-webdav-scan)
- WordPress enumeration (http-wordpress-enum)

**Linux Services:**
- NFS exports (nfs-showmount)
- Rsync modules (rsync-list-modules)
- DistCC RCE (distcc-cve2004-2687)

**See [OSCP_GUIDE.md](OSCP_GUIDE.md) for complete OSCP enumeration workflows!**

## Usage

### Basic Script Scanning

Enable scripts with the `-script` flag:

```bash
./gomap -target example.com -script
```

### Run Specific Script Categories

Run only vulnerability scripts:
```bash
./gomap -target example.com -script -script-category vuln
```

Run authentication scripts:
```bash
./gomap -target example.com -script -script-category auth
```

Run discovery scripts:
```bash
./gomap -target example.com -script -script-category discovery
```

### List All Available Scripts

See all scripts and their descriptions:
```bash
./gomap -script-help
```

### Combined Scanning

Use scripts with service detection and OS detection:
```bash
./gomap -target example.com -service -os -script -v
```

Full featured scan:
```bash
./gomap -target example.com -ports 1-1000 -service -os -script -threads 50 -v
```

## Example Output

```
╔═══════════════════════════════════════╗
║         GoMap - Network Scanner       ║
║    Nmap-like tool written in Go       ║
╚═══════════════════════════════════════╝

Resolved example.com to 93.184.216.34
Scanning 1024 ports with 100 threads...

Running 3 scripts against 93.184.216.34:80...
  Running script: http-title
  Running script: http-headers
  Running script: http-vuln-check

Scan Results for example.com
Scan started at: 2024-01-28T10:30:00Z
Scan completed at: 2024-01-28T10:30:05Z
Duration: 5.2s

Host is up

Found 2 open port(s):

PORT     STATE    SERVICE
80       open     http
         Version: nginx/1.14.0
443      open     https
         Version: nginx/1.14.0

OS Detection: Linux (confidence: 6/10)

=== Script Results ===

[http-title]
Title: Example Domain

[http-headers]
HTTP Headers:
  Server: nginx/1.14.0
  Content-Type: text/html
  Content-Length: 1256
  Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT

[http-vuln-check]
Found 3 security issues:
  - Missing X-Frame-Options header (Clickjacking risk)
  - Missing X-Content-Type-Options header
  - Missing Content-Security-Policy header
  ⚠️  VULNERABLE

[ssl-cert]
SSL Certificate Information:
  Subject: example.com
  Issuer: Let's Encrypt Authority X3
  Valid from: 2024-01-01
  Valid until: 2024-04-01
  DNS Names: example.com, www.example.com

[ssl-vuln]
No SSL/TLS vulnerabilities detected
```

## Script Categories

| Category | Purpose | Risk Level |
|----------|---------|------------|
| **auth** | Authentication testing | Low |
| **discovery** | Service information gathering | Low |
| **version** | Version detection | Low |
| **safe** | Safe scripts (no impact) | None |
| **vuln** | Vulnerability detection | Low |
| **default** | Run by default with -script | Low |
| **intrusive** | May impact service | Medium |
| **exploit** | Exploit attempts | High |
| **brute** | Brute force attacks | High |
| **dos** | Denial of service | Critical |

**Note**: Currently only safe scripts are implemented. Intrusive/exploit scripts would require explicit user confirmation.

## Creating Custom Scripts

The script engine is extensible! Here's how to create a custom script:

```go
package main

import "fmt"

type MyCustomScript struct{}

func (s *MyCustomScript) Name() string {
    return "my-custom-check"
}

func (s *MyCustomScript) Description() string {
    return "Checks for my custom condition"
}

func (s *MyCustomScript) Categories() []ScriptCategory {
    return []ScriptCategory{CategoryDiscovery, CategorySafe}
}

func (s *MyCustomScript) PortRule(port int, service string) bool {
    return port == 8080 // Only run on port 8080
}

func (s *MyCustomScript) Execute(target ScriptTarget) (*ScriptResult, error) {
    // Your custom logic here
    result := &ScriptResult{
        ScriptName: s.Name(),
        Output:     "Custom check completed",
        Findings:   []string{"Finding 1", "Finding 2"},
        Vulnerable: false,
    }
    return result, nil
}
```

Then register it in `script_engine.go`:
```go
se.scripts = append(se.scripts, &MyCustomScript{})
```

## Architecture

The script engine consists of:

1. **script_engine.go** - Core engine and script management
2. **scripts_http.go** - HTTP-related scripts
3. **scripts_services.go** - SSH, FTP, SMTP scripts
4. **scripts_database.go** - Database and SSL/TLS scripts

Each script implements the `Script` interface:
- `Name()` - Script identifier
- `Description()` - What the script does
- `Categories()` - Script categories
- `PortRule()` - When to run the script
- `Execute()` - Script logic

## Performance Considerations

- Scripts run concurrently for each open port
- Each script has a 5-second timeout by default
- Verbose mode (`-v`) shows script execution progress
- Use `-script-category` to limit scripts for faster scans

## Common Use Cases

### Security Audit
```bash
./gomap -target myserver.com -script -script-category vuln -service
```

### Service Enumeration
```bash
./gomap -target 192.168.1.0/24 -script -script-category discovery
```

### SSL/TLS Assessment
```bash
./gomap -target example.com -ports 443 -script -v
```

### Authentication Check
```bash
./gomap -target ftp.example.com -ports 21,22 -script -script-category auth
```

## Comparison to Nmap NSE

| Feature | Nmap NSE | GoMap Scripts |
|---------|----------|---------------|
| Script Language | Lua | Native Go |
| Number of Scripts | 600+ | 15+ (extensible) |
| Performance | Fast | Very Fast (concurrent) |
| Customization | High | High |
| Dependencies | Lua interpreter | None (compiled) |
| Easy to extend | Yes | Yes (Go knowledge) |

## Future Enhancements

Potential additions:
- More scripts (targeting 50+ core scripts)
- Script arguments/parameters
- Script output formats (JSON, XML)
- Timing templates for script execution
- Script dependencies and chaining
- Pre-scanning scripts
- Post-scanning scripts

## Legal Notice

⚠️ Scripts should only be run against systems you own or have permission to test. Some scripts may trigger IDS/IPS systems or be considered intrusive.

Always use responsibly and legally!
