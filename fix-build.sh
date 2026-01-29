#!/bin/bash

echo "=== GoMap Build Fixer ==="
echo ""
echo "This script will fix common build issues..."
echo ""

# Step 1: Clean old builds
echo "[1/4] Cleaning old builds..."
rm -f gomap
echo "  ✓ Cleaned"

# Step 2: Format all Go files
echo "[2/4] Formatting Go code..."
go fmt *.go > /dev/null 2>&1
echo "  ✓ Formatted"

# Step 3: Check for syntax issues
echo "[3/4] Checking for issues..."
go vet *.go > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  ⚠ Some warnings found (may be ok)"
else
    echo "  ✓ No issues found"
fi

# Step 4: Build with clear output
echo "[4/4] Building..."
echo ""

go build -o gomap . 2>&1 | tee build.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo "════════════════════════════════════"
    echo "✓ BUILD SUCCESSFUL!"
    echo "════════════════════════════════════"
    echo ""
    echo "Binary created:"
    ls -lh gomap
    echo ""
    echo "Quick test:"
    echo ""
    ./gomap -script-help 2>&1 | head -30
    echo ""
    echo "Ready! Try: ./gomap -target scanme.nmap.org -script"
else
    echo ""
    echo "════════════════════════════════════"
    echo "✗ BUILD FAILED"
    echo "════════════════════════════════════"
    echo ""
    echo "Error summary:"
    grep "error:" build.log
    echo ""
    echo "Possible fixes:"
    echo ""
    
    if grep -q "redeclared" build.log; then
        echo "• Duplicate function: Re-download the fixed files"
    fi
    
    if grep -q "undefined:" build.log; then
        echo "• Missing types: Make sure ALL 13 .go files are in this directory"
        echo "  Run: ls *.go | wc -l"
        echo "  Should output: 13"
    fi
    
    echo ""
    echo "Full error log saved to: build.log"
fi
