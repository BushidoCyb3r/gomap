# GoMap - Quick Start Guide

## What is GoMap?

GoMap is a full-featured network scanner written in pure Go, reimplementing core nmap functionality including:
- TCP/UDP/SYN port scanning
- Service version detection
- OS fingerprinting
- Concurrent scanning with configurable threads
- NSE-like script engine with 51 built-in scripts
- Vulnerability detection with ExploitDB integration
- Network scanning (CIDR notation support)
- Multiple output formats (JSON, XML, TXT)

## Building the Project

You need Go 1.21 or later installed. Download from https://golang.org/dl/

```bash
# Navigate to the project directory
cd gomap

# Build the binary
go build -o gomap .

# Run it
./gomap -target example.com
```

## Quick Examples

### 1. Basic Port Scan
```bash
./gomap -target scanme.nmap.org
```

### 2. Scan Specific Ports
```bash
./gomap -target example.com -ports 22,80,443,3306,8080
```

### 3. Scan Port Range
```bash
./gomap -target 192.168.1.1 -ports 1-1000
```

### 4. Service Detection
```bash
./gomap -target example.com -ports 1-1000 -service
```

### 5. OS Detection
```bash
./gomap -target example.com -os
```

### 6. Full Scan (All Features)
```bash
./gomap -target example.com -ports 1-1000 -service -os -script -v
```

### 7. UDP Scan
```bash
./gomap -target example.com -type udp -ports 53,67,161
```

### 8. Fast Scan
```bash
./gomap -target example.com -threads 500 -timeout 500ms
```

### 9. Host Discovery
```bash
./gomap -target example.com -ping
```

### 10. Network Scan (CIDR)
```bash
./gomap -target 192.168.1.0/24 -ping -host-threads 20
```

### 11. Vulnerability Scan
```bash
./gomap -target example.com -ports 1-1000 -service -vuln
```

### 12. Script Scanning
```bash
./gomap -target example.com -script -script-category vuln
```

### 13. Output to File
```bash
./gomap -target example.com -service -o results.json -oF json
```

## Command-Line Flags

### Core Options
```
-target, -t string      Target hostname, IP, or CIDR range (required)
-ports, -p string       Ports to scan: "80" or "1-1000" or "22,80,443" or "all" (default "1-1024")
-type string            Scan type: tcp, udp, syn (default "tcp")
-threads int            Concurrent threads (default 100)
-host-threads, -hT int  Concurrent hosts for subnet scans (default 10)
-timeout duration       Connection timeout (default 1s)
-ping-timeout duration  Host discovery timeout (default 500ms)
```

### Feature Flags
```
-service, -sV      Enable service version detection
-os                Enable OS fingerprinting
-ping              Host discovery only
-skip-down         Skip hosts that appear down (faster subnet scanning)
-vuln              Check services against vulnerability database
-script            Enable NSE-like script scanning
-script-category   Run scripts from category: auth, vuln, discovery, version
-script-help       List all 51 available scripts
-v                 Verbose output
```

### Output Options
```
-output, -o string        Output file path
-output-format, -oF string Output format: json, xml, txt (default "txt")
```

### Database Options
```
-searchsploit-update   Update the bundled exploit database
```

## Sample Output

```
   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗
  ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
  ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
  ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝

          Network Scanner & Exploitation Tool
          ═══════════════════════════════════════

Resolved example.com to 93.184.216.34

╔════════════════════════════════════════════════╗
║           SCAN RESULTS                         ║
╚════════════════════════════════════════════════╝
Target:   example.com
Started:  10:30:00
Finished: 10:30:03
Duration: 3.2s

[+] Host is UP

Found 2 open port(s):

PORT     STATE      SERVICE
────     ─────      ───────
80       open       http
         ↳ Version: nginx/1.14.0
443      open       https
         ↳ Version: nginx/1.14.0

OS Detection:
  ↳ Linux (confidence: 6/10)

════════════════════════════════════════════════
Scan complete!
```

## Architecture Overview

The project consists of 23 Go source files organized by functionality:

**Core (6 files):**
- `main.go` - CLI interface, argument parsing, result display
- `types.go` - Data structures (ScanConfig, ScanResults, PortResult, NetworkScanResults)
- `scanner.go` - Core scanning logic (TCP, UDP, host discovery)
- `service_detection.go` - Banner grabbing, service identification
- `utils.go` - Helper functions (port parsing, service name lookup)
- `output.go` - Result formatting and file output (JSON, XML, TXT)

**OS Fingerprinting (5 files):**
- `os_fingerprint.go`, `os_signatures.go`, `icmp_fingerprint.go`, `protocol_fingerprint.go`, `raw_socket.go`

**Script Engine (8 files, 51 scripts):**
- `script_engine.go` - Core engine
- `scripts_http.go`, `scripts_services.go`, `scripts_database.go`, `scripts_smb.go`, `scripts_win.go`, `scripts_enumeration.go`, `scripts_webapp.go`

**Vulnerability Database (4 files):**
- `exploit_db.go`, `exploit_update.go`, `vuln_data.go`, `vuln_db.go`

## Key Features Explained

### Concurrent Scanning
Uses goroutines with a semaphore pattern to limit concurrent connections:
```go
sem := make(chan struct{}, threads)
// Acquire semaphore before scanning
sem <- struct{}{}
defer func() { <-sem }()
```

### Service Detection
Connects to open ports and:
1. Sends probe packets (HTTP GET, empty line, HELP command)
2. Reads response banners
3. Parses version information from banners
4. Identifies services (HTTP, SSH, FTP, MySQL, etc.)

### OS Fingerprinting
Uses heuristics based on:
- Open port combinations (e.g., 135/139/445 = Windows)
- Service version strings (e.g., "OpenSSH" = Linux)
- Weighted scoring system for confidence

### Port Parsing
Flexible port specification:
- Single ports: `80`
- Multiple ports: `80,443,8080`
- Ranges: `1-1000`
- Combined: `20-25,80,443,8000-9000`

## Performance Tips

1. **Increase threads for faster scans**: `-threads 500`
2. **Reduce timeout for quicker results**: `-timeout 500ms`
3. **Scan smaller port ranges when testing**: `-ports 1-100`
4. **Use verbose mode to see progress**: `-v`

## Limitations vs. nmap

- 51 scripts vs nmap's 600+ NSE scripts (but easily extensible!)
- Basic OS detection (nmap has 1000+ fingerprints)
- SYN scan requires root (falls back to TCP connect)
- ICMP ping requires raw sockets (uses TCP fallback)
- No advanced evasion techniques
- Limited to IPv4

## Legal Notice

⚠️ **Only scan systems you own or have explicit permission to test.**

Unauthorized port scanning may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions
- Terms of Service agreements
- Network security policies

## Troubleshooting

**"connection refused" errors**: Normal for closed ports
**"timeout" errors**: Target may be filtering/dropping packets
**"permission denied"**: SYN scan requires root/admin privileges
**Slow scans**: Increase threads, decrease timeout, reduce port range
**No open ports found**: Target may be down or heavily firewalled

## Testing the Scanner

Test against legal scanning targets:
- `scanme.nmap.org` - Authorized test server
- `localhost` - Your own machine
- Your own servers/VMs

## Further Development Ideas

- Add IPv6 support
- Add more service fingerprints
- Implement rate limiting
- Add proxy support
- Create web UI
- Add more scripts to the engine

## Resources

- [nmap Documentation](https://nmap.org/book/)
- [Go net package](https://pkg.go.dev/net)
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)

---

Built with ❤️ in Go
