//go:build !linux

package main

import (
	"fmt"
	"net"
	"time"
)

// arpScan is only implemented on Linux (AF_PACKET). On other platforms it
// returns an explanatory error so callers degrade gracefully.
func arpScan(targets []string, timeout time.Duration) (map[string]net.HardwareAddr, error) {
	return nil, fmt.Errorf("ARP scan is only supported on Linux")
}
