#!/bin/bash

echo "════════════════════════════════════════════════"
echo "  GoMap Uninstall"
echo "════════════════════════════════════════════════"
echo ""

REMOVED=0

# Check common installation locations
LOCATIONS=(
    "/usr/local/bin/gomap"
    "/usr/bin/gomap"
    "$HOME/.local/bin/gomap"
    "$HOME/bin/gomap"
    "/opt/gomap"
)

echo "Searching for gomap installations..."
echo ""

for location in "${LOCATIONS[@]}"; do
    if [ -f "$location" ]; then
        echo "[*] Found: $location"
        
        # Check if we need sudo
        if [[ "$location" == /usr/* ]] || [[ "$location" == /opt/* ]]; then
            echo "    Requires sudo to remove..."
            sudo rm -f "$location"
        else
            rm -f "$location"
        fi
        
        if [ $? -eq 0 ]; then
            echo "    ✓ Removed"
            REMOVED=$((REMOVED + 1))
        else
            echo "    ✗ Failed to remove"
        fi
        echo ""
    fi
done

# Search for any other gomap binaries in PATH
echo "Checking PATH for other installations..."
WHICH_RESULT=$(which gomap 2>/dev/null)
if [ -n "$WHICH_RESULT" ]; then
    echo "[*] Found in PATH: $WHICH_RESULT"
    
    # Check if it's in a location we haven't covered
    ALREADY_HANDLED=0
    for location in "${LOCATIONS[@]}"; do
        if [ "$WHICH_RESULT" == "$location" ]; then
            ALREADY_HANDLED=1
            break
        fi
    done
    
    if [ $ALREADY_HANDLED -eq 0 ]; then
        echo "    Attempting to remove..."
        if [[ "$WHICH_RESULT" == /usr/* ]] || [[ "$WHICH_RESULT" == /opt/* ]]; then
            sudo rm -f "$WHICH_RESULT"
        else
            rm -f "$WHICH_RESULT"
        fi
        
        if [ $? -eq 0 ]; then
            echo "    ✓ Removed"
            REMOVED=$((REMOVED + 1))
        fi
    fi
fi

echo ""
echo "════════════════════════════════════════════════"

if [ $REMOVED -gt 0 ]; then
    echo "✓ Removed $REMOVED gomap installation(s)"
    echo ""
    echo "Verify removal:"
    echo "  which gomap"
    echo ""
    echo "Should output: (nothing)"
else
    echo "No gomap installations found"
fi

echo "════════════════════════════════════════════════"
echo ""

# Check if gomap is still accessible
if command -v gomap &> /dev/null; then
    echo "⚠ Warning: gomap is still in PATH"
    echo ""
    echo "Location: $(which gomap)"
    echo ""
    echo "This might be a copy we couldn't find."
    echo "Remove it manually with:"
    echo "  sudo rm $(which gomap)"
else
    echo "✓ gomap successfully uninstalled from system"
fi

echo ""
