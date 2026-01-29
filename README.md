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
  - 15+ built-in scripts for vulnerability detection, service enumeration, and more
  - Categories: auth, discovery, vuln, version
  - Extensible architecture for custom scripts
  - Concurrent script execution

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

### Performance Tuning

Adjust timeout and thread count:
```bash
./gomap -target example.com -timeout 2s -threads 500
```

## Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-target` | Target IP address or hostname | Required |
| `-ports` | Ports to scan (e.g., "80,443" or "1-1000") | "1-1024" |
| `-timeout` | Timeout for each connection | 1s |
| `-threads` | Number of concurrent threads | 100 |
| `-type` | Scan type: tcp, syn, udp | tcp |
| `-service` | Enable service version detection | false |
| `-os` | Enable OS detection | false |
| `-script` | Enable script scanning (NSE-like) | false |
| `-script-category` | Run scripts from category (auth, vuln, discovery) | "" (all) |
| `-script-help` | List all available scripts | false |
| `-v` | Verbose output | false |
| `-ping` | Ping scan only (host discovery) | false |

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

The scanner is organized into several modules:

- **main.go** - CLI interface and result formatting
- **types.go** - Data structures and configuration
- **scanner.go** - Core scanning logic (TCP, UDP, ping)
- **service_detection.go** - Service identification and OS fingerprinting
- **utils.go** - Port parsing and service name lookup
- **script_engine.go** - NSE-like script engine core
- **scripts_http.go** - HTTP-related vulnerability and discovery scripts
- **scripts_services.go** - SSH, FTP, SMTP scripts
- **scripts_database.go** - Database and SSL/TLS scripts

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
- Script engine has 15+ scripts vs nmap's 600+ NSE scripts (but easily extensible!)
- ICMP-based ping requires raw sockets (falls back to TCP)

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
