package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// ICMPFingerprint contains ICMP-based OS detection data
type ICMPFingerprint struct {
	TTL            int    `json:"ttl"`
	ResponseTime   int64  `json:"response_time_ms"`
	ReplyReceived  bool   `json:"reply_received"`
	ICMPCode       uint8  `json:"icmp_code"`
	ReplyTTL       int    `json:"reply_ttl"`
	IPIDPattern    string `json:"ip_id_pattern"`   // "incremental", "random", "zero"
	DFBit          bool   `json:"df_bit"`
	ResponseQuoted int    `json:"response_quoted"` // Bytes quoted in error messages
}

// ICMP types and codes
const (
	ICMPEchoReply      = 0
	ICMPDestUnreach    = 3
	ICMPEchoRequest    = 8
	ICMPTimeExceeded   = 11
	ICMPTimestamp      = 13
	ICMPTimestampReply = 14
	ICMPAddressMask    = 17
	ICMPAddressMaskReply = 18
)

// ICMPProbe sends ICMP echo requests and analyzes responses
func ICMPProbe(targetIP string, timeout time.Duration) (*ICMPFingerprint, error) {
	cap := CheckRawSocketCapability()
	if !cap.Available {
		return nil, fmt.Errorf("ICMP probing requires root: %s", cap.Reason)
	}

	// Parse target IP
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return nil, fmt.Errorf("IPv6 not supported for ICMP fingerprinting")
	}

	// Create ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("cannot create ICMP socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set receive timeout
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		return nil, fmt.Errorf("cannot set receive timeout: %v", err)
	}

	result := &ICMPFingerprint{}

	// Send multiple echo requests to analyze IP ID pattern
	var ipIDs []uint16
	for i := 0; i < 3; i++ {
		// Build ICMP echo request
		icmpPacket := buildICMPEchoRequest(uint16(os.Getpid()&0xFFFF), uint16(i+1))

		// Send
		dstAddr := syscall.SockaddrInet4{}
		copy(dstAddr.Addr[:], dstIP)

		startTime := time.Now()
		err = syscall.Sendto(fd, icmpPacket, 0, &dstAddr)
		if err != nil {
			continue
		}

		// Receive
		buf := make([]byte, 1500)
		deadline := time.Now().Add(timeout)

		for time.Now().Before(deadline) {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				break
			}

			if n < 28 { // IP header (20) + ICMP header (8)
				continue
			}

			// Parse IP header
			if buf[0]>>4 != 4 {
				continue
			}
			ipHeaderLen := int(buf[0]&0x0F) * 4

			// Check source IP
			pktSrcIP := net.IP(buf[12:16])
			if !pktSrcIP.Equal(dstIP) {
				continue
			}

			// Extract IP header info
			ttl := buf[8]
			flags := binary.BigEndian.Uint16(buf[6:8])
			dfBit := (flags & 0x4000) != 0
			ipID := binary.BigEndian.Uint16(buf[4:6])

			// Parse ICMP
			icmpData := buf[ipHeaderLen:]
			icmpType := icmpData[0]
			icmpCode := icmpData[1]

			if icmpType == ICMPEchoReply {
				result.ReplyReceived = true
				result.TTL = int(ttl)
				result.ReplyTTL = int(ttl)
				result.DFBit = dfBit
				result.ICMPCode = icmpCode
				result.ResponseTime = time.Since(startTime).Milliseconds()

				ipIDs = append(ipIDs, ipID)
				break
			}
		}

		time.Sleep(50 * time.Millisecond) // Brief delay between probes
	}

	// Analyze IP ID pattern
	if len(ipIDs) >= 2 {
		result.IPIDPattern = analyzeIPIDPattern(ipIDs)
	}

	if !result.ReplyReceived {
		return nil, fmt.Errorf("no ICMP echo reply received")
	}

	return result, nil
}

// buildICMPEchoRequest creates an ICMP echo request packet
func buildICMPEchoRequest(id, seq uint16) []byte {
	packet := make([]byte, 64)

	packet[0] = ICMPEchoRequest // Type
	packet[1] = 0               // Code
	// Checksum at [2:4] - calculated below
	binary.BigEndian.PutUint16(packet[4:6], id)
	binary.BigEndian.PutUint16(packet[6:8], seq)

	// Payload (timestamp)
	binary.BigEndian.PutUint64(packet[8:16], uint64(time.Now().UnixNano()))

	// Fill rest with pattern
	for i := 16; i < 64; i++ {
		packet[i] = byte(i)
	}

	// Calculate checksum
	checksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)

	return packet
}

// icmpChecksum calculates ICMP checksum
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// analyzeIPIDPattern determines the IP ID generation pattern
func analyzeIPIDPattern(ids []uint16) string {
	if len(ids) < 2 {
		return "unknown"
	}

	// Check if all zeros
	allZero := true
	for _, id := range ids {
		if id != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "zero"
	}

	// Check for incremental pattern
	incremental := true
	for i := 1; i < len(ids); i++ {
		diff := int(ids[i]) - int(ids[i-1])
		// Allow for wraparound and small increments
		if diff < 0 {
			diff += 65536
		}
		if diff < 1 || diff > 100 {
			incremental = false
			break
		}
	}
	if incremental {
		return "incremental"
	}

	return "random"
}

// ICMPTimestampProbe sends ICMP timestamp request (often blocked)
func ICMPTimestampProbe(targetIP string, timeout time.Duration) (bool, error) {
	cap := CheckRawSocketCapability()
	if !cap.Available {
		return false, fmt.Errorf("ICMP probing requires root: %s", cap.Reason)
	}

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return false, fmt.Errorf("invalid target IP")
	}
	dstIP = dstIP.To4()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Build ICMP timestamp request
	packet := make([]byte, 20)
	packet[0] = ICMPTimestamp // Type
	packet[1] = 0             // Code
	binary.BigEndian.PutUint16(packet[4:6], uint16(os.Getpid()&0xFFFF))
	binary.BigEndian.PutUint16(packet[6:8], 1) // Sequence

	// Originate timestamp (milliseconds since midnight UTC)
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	ms := uint32(now.Sub(midnight).Milliseconds())
	binary.BigEndian.PutUint32(packet[8:12], ms)

	checksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)

	dstAddr := syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP)

	err = syscall.Sendto(fd, packet, 0, &dstAddr)
	if err != nil {
		return false, err
	}

	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return false, nil // Timeout = no response
		}

		if n < 28 {
			continue
		}

		ipHeaderLen := int(buf[0]&0x0F) * 4
		icmpData := buf[ipHeaderLen:]

		if icmpData[0] == ICMPTimestampReply {
			return true, nil
		}
	}

	return false, nil
}

// ICMPAddressMaskProbe sends ICMP address mask request (usually blocked)
func ICMPAddressMaskProbe(targetIP string, timeout time.Duration) (bool, error) {
	cap := CheckRawSocketCapability()
	if !cap.Available {
		return false, fmt.Errorf("ICMP probing requires root: %s", cap.Reason)
	}

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return false, fmt.Errorf("invalid target IP")
	}
	dstIP = dstIP.To4()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Build ICMP address mask request
	packet := make([]byte, 12)
	packet[0] = ICMPAddressMask
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(os.Getpid()&0xFFFF))
	binary.BigEndian.PutUint16(packet[6:8], 1)

	checksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)

	dstAddr := syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP)

	err = syscall.Sendto(fd, packet, 0, &dstAddr)
	if err != nil {
		return false, err
	}

	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return false, nil
		}

		if n < 28 {
			continue
		}

		ipHeaderLen := int(buf[0]&0x0F) * 4
		icmpData := buf[ipHeaderLen:]

		if icmpData[0] == ICMPAddressMaskReply {
			return true, nil
		}
	}

	return false, nil
}

// GetICMPOSHints returns OS hints based on ICMP behavior
func GetICMPOSHints(fp *ICMPFingerprint) []OSMatch {
	matches := make([]OSMatch, 0)

	if fp == nil || !fp.ReplyReceived {
		return matches
	}

	// TTL-based hints
	ttlFamilies := GuessOSFromTTL(fp.TTL)

	for _, family := range ttlFamilies {
		match := OSMatch{
			Family:     family,
			Confidence: 0.6,
			Method:     "icmp",
		}

		// Refine based on IP ID pattern
		switch fp.IPIDPattern {
		case "zero":
			// Linux 4.x+ or some BSD
			if family == "Linux" {
				match.Name = "Linux 4.x+ (IP ID=0)"
				match.Confidence = 0.7
			}
		case "incremental":
			// Windows typically uses incremental IP IDs
			if family == "Windows" {
				match.Name = "Windows"
				match.Confidence = 0.75
			}
		case "random":
			// Modern Linux or BSD with randomization
			if family == "Linux" || family == "BSD" {
				match.Name = family + " (randomized IP ID)"
				match.Confidence = 0.65
			}
		}

		if match.Name == "" {
			match.Name = family
		}

		matches = append(matches, match)
	}

	return matches
}
