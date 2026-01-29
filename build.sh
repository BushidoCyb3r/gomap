#!/bin/bash

echo "=== Building GoMap ==="
echo ""

# Clean
rm -f gomap

# Build with explicit file list to ensure proper compilation order
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
    main.go

if [ $? -eq 0 ]; then
    echo ""
    echo "✓✓✓ BUILD SUCCESSFUL! ✓✓✓"
    echo ""
    ls -lh gomap
    echo ""
    echo "Testing..."
    ./gomap -script-help | head -20
    echo ""
    echo "🎉 Ready to scan! Try: ./gomap -target 192.168.1.1 -script"
else
    echo ""
    echo "✗ Build failed"
    echo "Trying alternative method..."
    echo ""
    
    # Alternative: use go build with all files explicitly
    go build -v -o gomap *.go
fi
