# GoMap - Network Scanner

A lightweight, fast network scanner written in Go, inspired by nmap. GoMap provides essential port scanning, service detection, and OS fingerprinting capabilities.

## Features

- **Multiple Scan Types**
  - TCP Connect Scan
  - UDP Scan (protocol-specific payloads for DNS, NTP, SNMP, NetBIOS)
  - SYN Scan (requires root, falls back to TCP)

- **Accurate Port States**
  - Distinguishes **open**, **closed** (RST), and **filtered** (no response)
  - Probe retransmission (`-retries`) so a single dropped packet no longer hides an open port
  - UDP closed-port detection via ICMP port-unreachable

- **Scan Control & Safety**
  - Timing templates `-T0`–`-T5` (paranoid → insane), like nmap
  - Global probe rate cap with `-max-rate` (probes/sec) to protect fragile/legacy devices and limit IDS footprint
  - Graceful cancellation: **Ctrl-C stops cleanly and returns partial results**

- **Host Discovery**
  - Combined **ICMP echo + TCP** probing (ICMP needs root; falls back to TCP)
  - `-Pn` to skip discovery and scan hosts that don't answer pings
  - **ARP sweep** (`-arp`, root/Linux) to enumerate live hosts on the local segment with **MAC address + vendor**
  - Reverse-DNS (PTR) enrichment on results

- **Targeting**
  - Single host, hostname, or CIDR range
  - `-iL` to read a list of targets/CIDRs from a file
  - `-exclude` / `-exclude-file` to carve out IPs/ranges (e.g. the gateway or fragile hosts)

- **Service Detection**
  - Banner grabbing
  - **TLS-aware**: completes a TLS handshake on HTTPS/SMTPS/IMAPS/etc., reads the certificate (CN/SAN/issuer/expiry), and grabs the banner inside the encrypted channel
  - Service version identification
  - Common service recognition

- **OS Fingerprinting**
  - Heuristic OS detection from TTL / TCP window / option ordering, plus service-banner hints
  - Requires corroborating signals before reporting a match; results are labelled as heuristic and flagged when ambiguous

- **Script Engine (NSE-like)**
  - 51 built-in scripts for vulnerability detection, service enumeration, and more
  - Categories: auth, discovery, vuln, version, safe
  - Extensible architecture for custom scripts
  - Concurrent script execution

- **Vulnerability Detection**
  - Built-in exploit database (ExploitDB integration)
  - CVE and EDB-ID identification
  - Version-aware matching; findings that can't be confirmed against a detected version are labelled `(unconfirmed: version not verified)` rather than asserted
  - Metasploit module references
  - Severity color-coding (critical, high, medium, low)
  - Automatic database updates with `-searchsploit-update`

- **Network Scanning**
  - CIDR notation support for subnet scanning
  - Configurable host concurrency with `-host-threads`
  - Skip unresponsive hosts with `-skip-down`

- **Output Options**
  - Multiple formats: JSON, XML, TXT, and nmap-style **greppable**
  - File output with `-output` flag
  - Live **progress bar with rate (items/sec) and ETA**

- **Resumable Scans**
  - `-resume <file>` records completed hosts and skips them when the same command is re-run, so an interrupted large scan can continue

- **Performance**
  - Concurrent scanning with configurable thread count
  - Customizable timeouts and per-scan timing templates
  - Fast scan times for large port ranges

## Installation

```bash
# Clone or download the source files
# Build the binary
go build -o gomap .

# Or run directly
go run .
```

## Usage

### Basic Scan

Scan the most common 1024 ports:
```bash
./gomap -target example.com
```

### Custom Port Range

Scan specific ports:
```bash
./gomap -target 192.168.1.1 -ports 80,443,8080
```

Scan a port range:
```bash
./gomap -target example.com -ports 1-1000
```

Scan multiple ranges and specific ports:
```bash
./gomap -target example.com -ports 20-25,80,443,8000-9000
```

### Service Detection

Enable service version detection:
```bash
./gomap -target example.com -service
```

### OS Detection

Enable OS fingerprinting:
```bash
./gomap -target example.com -os
```

### Full Scan

Comprehensive scan with all features:
```bash
./gomap -target example.com -ports 1-65535 -service -os -threads 200 -v
```

### Script Scanning (NSE-like)

Enable script scanning:
```bash
./gomap -target example.com -script
```

Run specific script category:
```bash
./gomap -target example.com -script -script-category vuln
```

List all available scripts:
```bash
./gomap -script-help
```

Full scan with scripts:
```bash
./gomap -target example.com -ports 1-1000 -service -os -script -v
```

### UDP Scan

Scan UDP ports (sends protocol-specific probes for DNS/NTP/SNMP/NetBIOS):
```bash
./gomap -target example.com -type udp -ports 53,67,68,69,161 -v
```

### Host Discovery Only

Check if a host is up (ping scan):
```bash
./gomap -target example.com -ping
```

Scan a host that doesn't respond to discovery probes (`-Pn`):
```bash
./gomap -target 192.168.1.50 -Pn -ports 1-1000
```

ARP-sweep a local subnet for live hosts, MAC addresses and vendors (root, Linux):
```bash
sudo ./gomap -target 192.168.1.0/24 -arp
```

### Target Lists & Exclusions

Scan a list of targets from a file (one host/CIDR per line, `#` for comments):
```bash
./gomap -iL targets.txt -ports 22,80,443 -sV
```

Exclude specific hosts or ranges (e.g. the gateway) from a sweep:
```bash
./gomap -target 10.0.0.0/24 -exclude 10.0.0.1,10.0.0.0/28
./gomap -target 10.0.0.0/24 -exclude-file do-not-scan.txt
```

### Network Scanning (CIDR)

Scan an entire subnet:
```bash
./gomap -target 192.168.1.0/24 -ping
```

Scan subnet with service detection:
```bash
./gomap -target 192.168.1.0/24 -ports 22,80,443 -service -host-threads 20
```

Skip unresponsive hosts for faster scanning:
```bash
./gomap -target 10.0.0.0/24 -skip-down -ports 1-1000
```

### Vulnerability Scanning

Check for known vulnerabilities:
```bash
./gomap -target example.com -ports 1-1000 -service -vuln
```

Update the exploit database:
```bash
./gomap -searchsploit-update
```

### Output to File

Save results in different formats:
```bash
# JSON output
./gomap -target example.com -service -output results.json -output-format json

# XML output
./gomap -target example.com -service -o results.xml -oF xml

# Text output (default)
./gomap -target example.com -service -o results.txt

# Greppable output (one line per host, easy to pipe into grep/awk/cut)
./gomap -target 10.0.0.0/24 -service -o results.gnmap -oF grep
```

### Resumable Scans

Record progress to a resume file; if the scan is interrupted (Ctrl-C, crash),
re-run the **same command** to skip already-completed hosts and continue:
```bash
./gomap -target 10.0.0.0/24 -ports 1-1000 -resume scan.state
# ... interrupted ... then simply run the same line again:
./gomap -target 10.0.0.0/24 -ports 1-1000 -resume scan.state
```

### Performance Tuning

Adjust timeout and thread count:
```bash
./gomap -target example.com -timeout 2s -threads 500
```

### Scan Control & Timing

Use a timing template (sets threads, timeout, retries, and rate cap together):
```bash
# Stealthy / gentle on fragile devices
./gomap -target 192.168.1.0/24 -ports 1-1000 -T1

# Aggressive
./gomap -target example.com -ports 1-65535 -T4
```

Cap the global probe rate (probes per second) regardless of thread count:
```bash
./gomap -target 10.0.0.0/24 -ports 1-1024 -max-rate 100
```

Add extra retransmissions on lossy networks to reduce false "filtered" results:
```bash
./gomap -target example.com -ports 1-1000 -retries 3
```

Explicit flags always override the timing template, e.g. `-T4 -threads 50`.
Press **Ctrl-C** at any time to stop the scan and print the partial results.

## Command-Line Options

### Core Options
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-target` | `-t` | Target IP address, hostname, or CIDR range | Required |
| `-ports` | `-p` | Ports to scan (e.g., "80,443" or "1-1000" or "all") | "1-1024" |
| `-timeout` | | Timeout for each connection | 1s |
| `-ping-timeout` | | Timeout for host discovery ping | 500ms |
| `-threads` | | Number of concurrent threads | 100 |
| `-host-threads` | `-hT` | Concurrent hosts to scan for subnet scans | 10 |
| `-type` | | Scan type: tcp, syn, udp | tcp |
| `-version` | `-V` | Print version and exit | false |

### Targeting & Discovery
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-iL` | | Read targets (one host/CIDR per line) from a file | "" |
| `-exclude` | | Comma-separated IPs/CIDRs to exclude | "" |
| `-exclude-file` | | File of IPs/CIDRs to exclude (one per line) | "" |
| `-ping` | | Ping scan only (host discovery) | false |
| `-Pn` | | Skip host discovery; treat all hosts as up | false |
| `-arp` | | ARP-sweep local subnet(s) for live hosts + MAC/vendor (root, Linux) | false |

### Scan Control & Timing
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-T` | | Timing template 0-5 (0=paranoid/slowest, 3=normal, 5=insane/fastest) | 3 |
| `-retries` | | Probe retransmissions before marking a port filtered | from `-T` |
| `-max-rate` | | Max probes per second across the scan (0 = unlimited) | from `-T` |

> Timing templates set `-threads`, `-timeout`, `-retries`, and `-max-rate` together. Any of those flags given explicitly overrides the template.

### Feature Flags
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-service` | `-sV` | Enable service version detection | false |
| `-os` | | Enable OS detection | false |
| `-skip-down` | | Skip hosts that appear down (faster scanning) | false |
| `-vuln` | | Check services against vulnerability database | false |
| `-script` | | Enable script scanning (NSE-like) | false |
| `-script-category` | | Run scripts from category (auth, vuln, discovery, version) | "" (all) |
| `-script-help` | | List all available scripts | false |
| `-v` | | Verbose output | false |

### Output Options
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-output` | `-o` | Output file path | "" |
| `-output-format` | `-oF` | Output format: json, xml, txt, grep | "txt" |
| `-resume` | | Resume file: skip already-completed hosts and record new ones | "" |

### Database Options
| Flag | Description | Default |
|------|-------------|---------|
| `-searchsploit-update` | Update the bundled exploit database | false |

## Examples

### Scan a Web Server
```bash
./gomap -target example.com -ports 80,443,8080,8443 -service -v
```

Output:
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
Scanning 4 ports with 100 threads...
Port 80 is open (http)
Port 443 is open (https)
Port states: 2 open, 2 closed, 0 filtered

Scan Results for example.com
Scan started at: 2024-01-28T10:30:00Z
Scan completed at: 2024-01-28T10:30:02Z
Duration: 2.1s

Host is up

Found 2 open port(s):

PORT     STATE    SERVICE
80       open     http
         Version: nginx/1.14.0
443      open     https
         Version: nginx/1.14.0
```

### Scan Local Network Host
```bash
./gomap -target 192.168.1.1 -ports 1-1000 -threads 200 -v
```

### Check Common Database Ports
```bash
./gomap -target db.example.com -ports 3306,5432,27017,6379 -service
```

## Architecture

The scanner is organized into 29 Go source files (plus a test suite):

**Core Components:**
- **main.go** - CLI interface, argument parsing, result display, ARP discovery mode
- **types.go** - Data structures (ScanConfig, ScanResults, PortResult, NetworkScanResults)
- **scanner.go** - Core scanning logic (TCP, UDP, host discovery, port-state classification)
- **ratelimit.go** - Rate limiter, timing templates, UDP probe payloads, error classification
- **service_detection.go** - Banner grabbing, TLS handshake/cert inspection, service identification
- **discovery.go** - Reverse DNS, ARP frame build/parse, MAC vendor (OUI) lookup
- **arp_linux.go** / **arp_other.go** - ARP sweep via AF_PACKET (Linux), graceful stub elsewhere
- **exclude.go** - Target-list file reading and IP/CIDR exclusion matching
- **resume.go** - Append-only resume log for skipping completed hosts
- **utils.go** - Helper functions (port parsing, service name lookup, progress bar)
- **output.go** - Result formatting and file output (JSON, XML, TXT, greppable)

**OS Fingerprinting:**
- **os_fingerprint.go** - OS detection implementation
- **os_signatures.go** - OS signature database
- **icmp_fingerprint.go** - ICMP-based fingerprinting
- **protocol_fingerprint.go** - Protocol-level analysis
- **raw_socket.go** - Raw socket implementation for advanced scanning

**Script Engine (51 scripts):**
- **script_engine.go** - Core engine and script management
- **scripts_http.go** - HTTP-related scripts
- **scripts_services.go** - SSH, FTP, SMTP scripts
- **scripts_database.go** - Database and SSL/TLS scripts
- **scripts_smb.go** - SMB enumeration scripts
- **scripts_win.go** - Windows-specific scripts
- **scripts_enumeration.go** - Various enumeration scripts
- **scripts_webapp.go** - Web application testing scripts

**Vulnerability & Exploit Database:**
- **exploit_db.go** - ExploitDB integration
- **exploit_update.go** - Database update mechanism
- **vuln_data.go** - Vulnerability data storage
- **vuln_db.go** - Vulnerability database interface

**Tests:**
- **gomap_test.go**, **limitations_test.go**, **scanner_test.go** - Unit tests for port parsing, CIDR expansion, version comparison, OS-match scoring, vuln labelling, rate limiting, timing templates, and error classification. Run with `go test ./...`.

## How It Works

1. **Target Resolution**: Resolves hostname to IP address and performs a reverse-DNS (PTR) lookup
2. **Host Discovery**: Checks reachability via ICMP echo + TCP probes (or skips it with `-Pn`; ARP sweep with `-arp`)
3. **Port Scanning**: Probes ports concurrently, retransmits on no-response, and classifies each as open/closed/filtered
4. **Service Detection**: Grabs banners (TLS-aware: handshake + certificate on TLS ports) and identifies services
5. **OS Detection**: Analyzes TTL/window/options and service versions (heuristic, labelled as such)

## Limitations

- SYN scanning requires root privileges (raw sockets); without it, falls back to TCP connect
- OS detection is heuristic (small static signature set) and far less comprehensive than nmap's; matches are explicitly labelled and flagged when ambiguous
- UDP scanning is inherently slower/less certain than TCP; ports with no known probe payload may report `open|filtered`
- Script engine has 51 scripts vs nmap's 600+ NSE scripts (but easily extensible!)
- ICMP-based ping requires raw sockets (falls back to TCP)
- **IPv4 only — no IPv6 support**
- ARP discovery requires root and only works on the local Ethernet segment (Linux)
- ICMP echo discovery requires root; without it, discovery falls back to TCP probes only
- Vulnerability data is a curated subset, not a full CVE feed; treat findings as leads to confirm, especially any labelled `unconfirmed`

## Script Engine

See [SCRIPTS.md](SCRIPTS.md) for detailed documentation on the NSE-like script engine, including:
- Available scripts and categories
- How to use scripts
- Creating custom scripts
- Script output examples

## Performance Considerations

- Default thread count (100) is conservative; increase for faster scans or use `-T4`/`-T5`
- Use `-T0`/`-T1` or `-max-rate` to scan gently — important for fragile/legacy/OT devices and to reduce IDS noise
- **For high port ranges (32768-65535)**, the scanner automatically reduces concurrency to avoid ephemeral port exhaustion
- Higher timeouts may be needed for slow or congested networks; add `-retries` on lossy links
- Shorter timeouts (e.g., 500ms) help avoid source port exhaustion when scanning many ports

### Ephemeral Port Exhaustion
When scanning high ports (32768+), your OS uses these same ports as **source ports** for outgoing connections. With high concurrency, you can run out of available source ports. The scanner mitigates this by:
- Automatically limiting threads to 50 when scanning high ports
- Using `SetLinger(0)` to send RST packets for faster port release
- Disabling TCP keepalive to close connections immediately
- If you still have issues, reduce `-threads` or increase `-timeout`

## Legal and Ethical Use

**Important**: Only scan networks and systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction and could violate terms of service or computer fraud laws.

## Contributing

This is a demonstration project. For production use, consider using the original nmap tool which has decades of development and comprehensive features.

## License

MIT License - feel free to use and modify

## Acknowledgments

Inspired by nmap (Network Mapper) created by Gordon Lyon (Fyodor)
