#!/bin/bash

echo "════════════════════════════════════════════════"
echo "  GoMap Build Script"
echo "════════════════════════════════════════════════"
echo ""

# Clean previous build
rm -f gomap

# Check for Go
if ! command -v go &> /dev/null; then
    echo "✗ Go is not installed!"
    echo "  Install with: sudo apt install golang-go"
    exit 1
fi

echo "[*] Go version: $(go version | cut -d' ' -f3)"
echo ""

# Build with all source files
echo "[*] Building GoMap..."
go build -ldflags="-s -w" -o gomap .

if [ $? -eq 0 ]; then
    echo ""
    echo "════════════════════════════════════════════════"
    echo "  ✓ BUILD SUCCESSFUL!"
    echo "════════════════════════════════════════════════"
    echo ""
    ls -lh gomap
    echo ""

    # Show capabilities
    echo "[*] Features:"
    echo "    - TCP/UDP port scanning"
    echo "    - Service version detection (-sV)"
    echo "    - OS fingerprinting (-os)"
    echo "    - Vulnerability checking (-vuln)"
    echo "    - 50+ enumeration scripts (-script)"
    echo "    - Exploit database (-searchsploit-update)"
    echo ""

    # Quick test
    echo "[*] Quick test:"
    ./gomap -h 2>&1 | grep -E "^\s+-(os|vuln|searchsploit)" | head -5
    echo ""

    echo "════════════════════════════════════════════════"
    echo "  Usage Examples:"
    echo "════════════════════════════════════════════════"
    echo ""
    echo "  # Basic scan"
    echo "  ./gomap -t 192.168.1.1 -p 1-1000"
    echo ""
    echo "  # Full scan with OS detection and vuln check"
    echo "  sudo ./gomap -t 192.168.1.1 -p 1-1000 -sV -os -vuln"
    echo ""
    echo "  # Update exploit database"
    echo "  ./gomap -searchsploit-update"
    echo ""
    echo "  # Network scan"
    echo "  ./gomap -t 192.168.1.0/24 -p 22,80,443 -sV -vuln"
    echo ""
else
    echo ""
    echo "════════════════════════════════════════════════"
    echo "  ✗ BUILD FAILED"
    echo "════════════════════════════════════════════════"
    echo ""
    echo "Trying verbose build..."
    go build -v -o gomap . 2>&1
    exit 1
fi
