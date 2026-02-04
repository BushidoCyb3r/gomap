# Build Troubleshooting Guide

## Quick Fix

If you got compilation errors, the files have been updated. Simply re-download all the `.go` files and run:

```bash
chmod +x build.sh
./build.sh
```

## Common Errors and Fixes

### Error: "min redeclared in this block"

**Fixed!** The `min` function was renamed to `minInt` in both `service_detection.go` and `scripts_webapp.go`.

### Error: "undefined: RDPSecurityScript" (and similar)

**This means the files aren't being compiled together.**

Make sure ALL 23 Go files are in the same directory:

**Core files:**
- main.go
- types.go
- scanner.go
- utils.go
- service_detection.go
- output.go

**OS Fingerprinting:**
- os_fingerprint.go
- os_signatures.go
- icmp_fingerprint.go
- protocol_fingerprint.go
- raw_socket.go

**Script Engine:**
- script_engine.go
- scripts_http.go
- scripts_services.go
- scripts_database.go
- scripts_smb.go
- scripts_win.go
- scripts_enumeration.go
- scripts_webapp.go

**Vulnerability Database:**
- exploit_db.go
- exploit_update.go
- vuln_data.go
- vuln_db.go

Then run: `go build -o gomap .`

The `.` at the end is important - it tells Go to compile all `.go` files in the current directory.

### Error: "package main is not in GOROOT"

Make sure you're in the directory containing all the `.go` files:
```bash
cd /path/to/gomap
ls *.go  # Should show all 23 files
go build -o gomap .
```

### Error: "go: cannot find main module"

You don't need a `go.mod` for this project, but if Go insists:
```bash
go mod init gomap
go build -o gomap .
```

### Error: Go version too old

You need Go 1.21 or later:
```bash
go version  # Should show 1.21 or higher
```

If too old, update from https://golang.org/dl/

## Verification Steps

1. **Count your files:**
   ```bash
   ls *.go | wc -l
   # Should output: 23
   ```

2. **Check all files are in main package:**
   ```bash
   grep "package main" *.go | wc -l
   # Should output: 23
   ```

3. **Verify script types exist:**
   ```bash
   grep -h "Name().*string" scripts_*.go | wc -l
   # Should output: 51 (one for each script)
   ```

## Manual Build Process

If the automatic build fails, try these steps:

```bash
# Clean any old builds
rm -f gomap

# Format all Go files
go fmt *.go

# Check for syntax errors
go vet *.go

# Build with verbose output
go build -v -o gomap .

# If it works, test it
./gomap -script-help
```

## Still Having Issues?

### Check File Integrity

```bash
# List all Go files to verify they exist:
ls *.go
```

Expected files (23 total):
```
exploit_db.go        os_fingerprint.go     scripts_database.go   scripts_webapp.go    utils.go
exploit_update.go    os_signatures.go      scripts_enumeration.go scripts_win.go      vuln_data.go
icmp_fingerprint.go  output.go             scripts_http.go       service_detection.go vuln_db.go
main.go              protocol_fingerprint.go scripts_services.go  types.go
                     raw_socket.go         scripts_smb.go        scanner.go
```

### Rebuild from Scratch

```bash
# Remove everything
rm *.go gomap

# Re-download ALL files
# Make sure you get all 23 .go files

# Then build
go build -o gomap .
```

## Success Indicators

When the build succeeds, you should see:
```bash
$ ./gomap -script-help

   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗
  ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
  ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
  ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝

          Network Scanner & Exploitation Tool
          ═══════════════════════════════════════

Available Scripts (51 total):
=============================

auth Scripts:
  - http-auth: Detects HTTP authentication methods
  - ftp-anon: Checks for anonymous FTP login
  - ssh-auth-methods: Enumerates SSH authentication methods
  [... and more ...]

vuln Scripts:
  - http-vuln-cve2017-5638: Checks for Apache Struts RCE
  - ssl-heartbleed: Checks for Heartbleed vulnerability
  [... and more ...]

discovery Scripts:
  - http-title: Extracts HTTP page titles
  - http-headers: Analyzes HTTP response headers
  [... and more ...]
```

## Getting Help

If you're still stuck:
1. Make sure you have Go 1.21+
2. Make sure ALL 23 .go files are present
3. Try the manual build process above
4. Check that files weren't corrupted during download

## Quick Test After Build

```bash
# Test basic scanning
./gomap -target scanme.nmap.org -ports 80,443

# Test with scripts
./gomap -target scanme.nmap.org -ports 80,443 -script

# Test vulnerability scanning
./gomap -target scanme.nmap.org -ports 80,443 -service -vuln

# Test JSON output
./gomap -target scanme.nmap.org -ports 80 -o test.json -oF json

# Test network scanning (use your own network)
./gomap -target 192.168.1.0/24 -ping -host-threads 20 -skip-down
```

## Common Runtime Issues

### "Permission denied" for SYN scan
SYN scanning requires root privileges:
```bash
sudo ./gomap -target example.com -type syn
```

### Vulnerability database not found
Update the exploit database:
```bash
./gomap -searchsploit-update
```

### Network scan too slow
Increase host threads and skip down hosts:
```bash
./gomap -target 10.0.0.0/24 -host-threads 50 -skip-down -timeout 500ms
```

### Ephemeral port exhaustion on high-port scans
The scanner automatically handles this, but if you still see issues:
```bash
./gomap -target example.com -ports 32768-65535 -threads 30 -timeout 2s
```
