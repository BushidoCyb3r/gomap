# GoMap - Network Scanner

A lightweight, fast network scanner written in Go, inspired by nmap. GoMap provides essential port scanning, service detection, and OS fingerprinting capabilities.

## Features

- **Multiple Scan Types**
  - TCP Connect Scan
  - UDP Scan
  - SYN Scan (requires root, falls back to TCP)

- **Host Discovery**
  - Ping scan to check if hosts are up
  - TCP-based host discovery

- **Service Detection**
  - Banner grabbing
  - Service version identification
  - Common service recognition

- **OS Fingerprinting**
  - Basic OS detection based on open ports and service versions

- **Script Engine (NSE-like)**
  - 51 built-in scripts for vulnerability detection, service enumeration, and more
  - Categories: auth, discovery, vuln, version, safe
  - Extensible architecture for custom scripts
  - Concurrent script execution

- **Vulnerability Detection**
  - Built-in exploit database (ExploitDB integration)
  - CVE and EDB-ID identification
  - Metasploit module references
  - Severity color-coding (critical, high, medium, low)
  - Automatic database updates with `-searchsploit-update`

- **Network Scanning**
  - CIDR notation support for subnet scanning
  - Configurable host concurrency with `-host-threads`
  - Skip unresponsive hosts with `-skip-down`

- **Output Options**
  - Multiple formats: JSON, XML, TXT
  - File output with `-output` flag

- **Performance**
  - Concurrent scanning with configurable thread count
  - Customizable timeouts
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

Scan UDP ports:
```bash
./gomap -target example.com -type udp -ports 53,67,68,69,161
```

### Host Discovery Only

Check if a host is up (ping scan):
```bash
./gomap -target example.com -ping
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
```

### Performance Tuning

Adjust timeout and thread count:
```bash
./gomap -target example.com -timeout 2s -threads 500
```

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

### Feature Flags
| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `-service` | `-sV` | Enable service version detection | false |
| `-os` | | Enable OS detection | false |
| `-ping` | | Ping scan only (host discovery) | false |
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
| `-output-format` | `-oF` | Output format: json, xml, txt | "txt" |

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

The scanner is organized into 23 Go source files:

**Core Components:**
- **main.go** - CLI interface, argument parsing, result display
- **types.go** - Data structures (ScanConfig, ScanResults, PortResult, NetworkScanResults)
- **scanner.go** - Core scanning logic (TCP, UDP, host discovery)
- **service_detection.go** - Banner grabbing, service identification
- **utils.go** - Helper functions (port parsing, service name lookup)
- **output.go** - Result formatting and file output (JSON, XML, TXT)

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

## How It Works

1. **Target Resolution**: Resolves hostname to IP address
2. **Host Discovery**: Checks if the target is reachable
3. **Port Scanning**: Connects to specified ports concurrently
4. **Service Detection**: Grabs banners and identifies services
5. **OS Detection**: Analyzes open ports and service versions

## Limitations

- SYN scanning requires root privileges (raw sockets)
- OS detection is basic compared to nmap's comprehensive fingerprinting
- UDP scanning is less reliable due to the nature of UDP protocol
- Script engine has 51 scripts vs nmap's 600+ NSE scripts (but easily extensible!)
- ICMP-based ping requires raw sockets (falls back to TCP)
- Limited to IPv4 (no IPv6 support)

## Script Engine

See [SCRIPTS.md](SCRIPTS.md) for detailed documentation on the NSE-like script engine, including:
- Available scripts and categories
- How to use scripts
- Creating custom scripts
- Script output examples

## Performance Considerations

- Default thread count (100) is conservative; increase for faster scans
- **For high port ranges (32768-65535)**, the scanner automatically reduces concurrency to avoid ephemeral port exhaustion
- Higher timeouts may be needed for slow or congested networks
- Large port ranges with many threads can trigger rate limiting or IDS
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
