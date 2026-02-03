#!/bin/bash

echo "════════════════════════════════════════════════"
echo "  GoMap System-Wide Installation"
echo "════════════════════════════════════════════════"
echo ""

# Check if running as root for system-wide install
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    DATA_DIR="/usr/local/share/gomap"
    echo "[*] Installing system-wide to $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/.local/bin"
    DATA_DIR="$HOME/.gomap"
    echo "[*] Installing to user directory: $INSTALL_DIR"
    echo "[*] (Run with sudo for system-wide install)"
fi

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR/exploitdb"

# Check for Go
if ! command -v go &> /dev/null; then
    echo ""
    echo "✗ Go is not installed!"
    echo "  Install with: sudo apt install golang-go"
    exit 1
fi

# Build the binary
echo ""
echo "[1/4] Building GoMap..."
go build -ldflags="-s -w" -o gomap .

if [ $? -ne 0 ]; then
    echo "✗ Build failed!"
    exit 1
fi
echo "✓ Build successful!"

# Copy binary to install directory
echo ""
echo "[2/4] Installing binary..."
cp gomap "$INSTALL_DIR/gomap"
chmod +x "$INSTALL_DIR/gomap"
echo "✓ Installed to: $INSTALL_DIR/gomap"

# Copy exploit database if it exists
echo ""
echo "[3/4] Setting up exploit database..."
if [ -d "exploitdb" ] && [ -f "exploitdb/files_exploits.csv" ]; then
    cp -r exploitdb/* "$DATA_DIR/exploitdb/"
    echo "✓ Exploit database copied to: $DATA_DIR/exploitdb"
else
    echo "[*] No exploit database found locally"
    echo "    Run 'gomap -searchsploit-update' after installation"
fi

# Check if install directory is in PATH
echo ""
echo "[4/4] Checking PATH..."
if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo "✓ $INSTALL_DIR is in your PATH"
else
    echo "⚠ $INSTALL_DIR is NOT in your PATH"
    echo ""
    echo "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
    echo "Then run: source ~/.bashrc"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  ✓ Installation Complete!"
echo "════════════════════════════════════════════════"
echo ""
echo "Quick Start:"
echo ""
echo "  # Update exploit database (recommended)"
echo "  gomap -searchsploit-update"
echo ""
echo "  # Basic scan"
echo "  gomap -t <target> -p 1-1000 -sV"
echo ""
echo "  # Full scan with OS detection + vulnerabilities"
echo "  sudo gomap -t <target> -p 1-1000 -sV -os -vuln"
echo ""
echo "  # List scripts"
echo "  gomap -script-help"
echo ""
