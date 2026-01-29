#!/bin/bash

echo "════════════════════════════════════════════════"
echo "  GoMap System-Wide Installation"
echo "════════════════════════════════════════════════"
echo ""

# Check if running as root for system-wide install
if [ "$EUID" -eq 0 ]; then 
    INSTALL_DIR="/usr/local/bin"
    echo "[*] Installing system-wide to $INSTALL_DIR"
else
    INSTALL_DIR="$HOME/.local/bin"
    echo "[*] Installing to user directory: $INSTALL_DIR"
    echo "[*] (Run with sudo for system-wide install)"
fi

# Create directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Build the binary
echo ""
echo "[1/3] Building GoMap..."
go build -o gomap \
    types.go \
    utils.go \
    script_engine.go \
    scripts_http.go \
    scripts_services.go \
    scripts_database.go \
    scripts_smb.go \
    scripts_windows.go \
    scripts_enumeration.go \
    scripts_webapp.go \
    service_detection.go \
    scanner.go \
    output.go \
    main.go

if [ $? -ne 0 ]; then
    echo "✗ Build failed!"
    exit 1
fi

echo "✓ Build successful!"

# Copy to install directory
echo ""
echo "[2/3] Installing binary..."
cp gomap "$INSTALL_DIR/gomap"
chmod +x "$INSTALL_DIR/gomap"
echo "✓ Installed to: $INSTALL_DIR/gomap"

# Check if install directory is in PATH
echo ""
echo "[3/3] Checking PATH..."
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
echo "✓ Installation Complete!"
echo "════════════════════════════════════════════════"
echo ""
echo "Usage: gomap -target <target> -script"
echo ""
echo "Try it: gomap -script-help"
echo ""
