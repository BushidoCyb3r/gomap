//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// arpScan sends ARP requests for each target on the local segment and returns a
// map of responding IP -> MAC. Requires root (CAP_NET_RAW) and a target subnet
// that is directly attached to one of this host's interfaces.
func arpScan(targets []string, timeout time.Duration) (map[string]net.HardwareAddr, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	first := net.ParseIP(targets[0])
	if first == nil {
		return nil, fmt.Errorf("invalid target %q", targets[0])
	}
	iface, srcIP, err := localInterfaceFor(first)
	if err != nil {
		return nil, err
	}

	proto := int(htons(ethPARP))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (ARP scan needs root): %v", err)
	}
	defer syscall.Close(fd)

	ll := &syscall.SockaddrLinklayer{Protocol: htons(ethPARP), Ifindex: iface.Index}
	if err := syscall.Bind(fd, ll); err != nil {
		return nil, fmt.Errorf("bind AF_PACKET: %v", err)
	}

	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil || ip.To4() == nil {
			continue
		}
		want[ip.String()] = true
		frame := buildARPRequest(iface.HardwareAddr, srcIP, ip)
		_ = syscall.Sendto(fd, frame, 0, ll)
	}

	// Bound the receive loop with a socket timeout so it can't hang.
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	results := make(map[string]net.HardwareAddr)
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			break // timeout or error
		}
		ip, mac, ok := parseARPReply(buf[:n])
		if !ok {
			continue
		}
		ipStr := ip.String()
		if want[ipStr] {
			if _, seen := results[ipStr]; !seen {
				results[ipStr] = mac
			}
		}
		if len(results) == len(want) {
			break
		}
	}
	return results, nil
}
