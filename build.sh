#!/bin/bash

echo "=== GoMap Build Verification ==="
echo ""

# Check Go version
echo "Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed!"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

go version
echo ""

# Check all required files
echo "Checking required files..."
REQUIRED_FILES=(
    "main.go"
    "types.go"
    "scanner.go"
    "utils.go"
    "service_detection.go"
    "script_engine.go"
    "scripts_http.go"
    "scripts_services.go"
    "scripts_database.go"
    "scripts_smb.go"
    "scripts_windows.go"
    "scripts_enumeration.go"
    "scripts_webapp.go"
)

MISSING=0
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing $file"
        MISSING=1
    else
        echo "✓ Found $file"
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "ERROR: Some required files are missing!"
    exit 1
fi

echo ""
echo "All files present. Attempting to build..."
echo ""

# Try to build
go build -o gomap .

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ BUILD SUCCESSFUL!"
    echo ""
    echo "GoMap binary created: ./gomap"
    echo ""
    echo "Quick test:"
    ./gomap -script-help | head -20
    echo ""
    echo "Ready to scan! Try:"
    echo "  ./gomap -target scanme.nmap.org -script"
else
    echo ""
    echo "✗ BUILD FAILED!"
    echo ""
    echo "Please check the error messages above."
    echo "Common issues:"
    echo "  1. Go version too old (need Go 1.21+)"
    echo "  2. Files corrupted during download"
    echo "  3. Missing dependencies"
    exit 1
fi
