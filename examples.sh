#!/bin/bash

# GoMap Example Usage Script
# Demonstrates various scanning scenarios

echo "=== GoMap Scanner Examples ==="
echo ""

# Build the project
echo "Building GoMap..."
go build -o gomap .
echo "Build complete!"
echo ""

# Example 1: Quick scan of common ports
echo "Example 1: Quick scan of google.com (common ports)"
./gomap -target google.com -ports 80,443
echo ""

# Example 2: Scan with service detection
echo "Example 2: Scan localhost with service detection"
./gomap -target localhost -ports 1-1000 -service -threads 200
echo ""

# Example 3: Verbose scan
echo "Example 3: Verbose scan of a specific service"
./gomap -target localhost -ports 22,80,443,3306,5432 -v
echo ""

# Example 4: Host discovery
echo "Example 4: Check if host is up"
./gomap -target 8.8.8.8 -ping
echo ""

# Example 5: Custom timeout and threads
echo "Example 5: Fast scan with custom settings"
./gomap -target localhost -ports 1-100 -timeout 500ms -threads 50
echo ""

echo "Examples complete!"
