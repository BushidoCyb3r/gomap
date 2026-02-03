package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// RawSocketCapability indicates whether raw sockets can be used
type RawSocketCapability struct {
	Available bool
	Reason    string
}

// CheckRawSocketCapability tests if raw sockets can be used
func CheckRawSocketCapability() *RawSocketCapability {
	// Check if running as root
	if os.Geteuid() != 0 {
		return &RawSocketCapability{
			Available: false,
			Reason:    "Raw sockets require root privileges (run with sudo)",
		}
	}

	// Try to create a raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return &RawSocketCapability{
			Available: false,
			Reason:    fmt.Sprintf("Cannot create raw socket: %v", err),
		}
	}
	syscall.Close(fd)

	return &RawSocketCapability{
		Available: true,
		Reason:    "Raw sockets available",
	}
}

// TCPPacket represents a captured TCP packet with IP header info
type TCPPacket struct {
	SrcIP      net.IP
	DstIP      net.IP
	TTL        uint8
	DFBit      bool
	IPOptions  []byte
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	TCPOptions []TCPOption
}

// TCPOption represents a TCP header option
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
	Name   string
}

// TCP Option kinds
const (
	TCPOptEnd       = 0
	TCPOptNOP       = 1
	TCPOptMSS       = 2
	TCPOptWScale    = 3
	TCPOptSACKPerm  = 4
	TCPOptSACK      = 5
	TCPOptTimestamp = 8
)

// TCP Flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// ParseTCPOptions parses TCP options from raw bytes
func ParseTCPOptions(data []byte) []TCPOption {
	options := make([]TCPOption, 0)
	i := 0

	for i < len(data) {
		kind := data[i]

		switch kind {
		case TCPOptEnd:
			options = append(options, TCPOption{Kind: kind, Name: "EOL"})
			return options
		case TCPOptNOP:
			options = append(options, TCPOption{Kind: kind, Name: "NOP"})
			i++
		case TCPOptMSS:
			if i+3 < len(data) {
				opt := TCPOption{Kind: kind, Length: data[i+1], Name: "MSS"}
				opt.Data = data[i+2 : i+4]
				options = append(options, opt)
				i += 4
			} else {
				return options
			}
		case TCPOptWScale:
			if i+2 < len(data) {
				opt := TCPOption{Kind: kind, Length: data[i+1], Name: "WS"}
				opt.Data = data[i+2 : i+3]
				options = append(options, opt)
				i += 3
			} else {
				return options
			}
		case TCPOptSACKPerm:
			options = append(options, TCPOption{Kind: kind, Length: 2, Name: "SACK"})
			i += 2
		case TCPOptTimestamp:
			if i+9 < len(data) {
				opt := TCPOption{Kind: kind, Length: data[i+1], Name: "TS"}
				opt.Data = data[i+2 : i+10]
				options = append(options, opt)
				i += 10
			} else {
				return options
			}
		default:
			// Unknown option
			if i+1 < len(data) && data[i+1] > 0 {
				length := int(data[i+1])
				opt := TCPOption{Kind: kind, Length: uint8(length), Name: fmt.Sprintf("OPT%d", kind)}
				if i+length <= len(data) {
					opt.Data = data[i+2 : i+length]
					i += length
				} else {
					return options
				}
				options = append(options, opt)
			} else {
				return options
			}
		}
	}

	return options
}

// GetTCPOptionsString returns a canonical string representation
func GetTCPOptionsString(options []TCPOption) string {
	names := make([]string, 0, len(options))
	for _, opt := range options {
		if opt.Name != "EOL" { // Skip EOL in string representation
			names = append(names, opt.Name)
		}
	}
	return strings.Join(names, ",")
}

// GetMSSValue extracts MSS value from TCP options
func GetMSSValue(options []TCPOption) int {
	for _, opt := range options {
		if opt.Kind == TCPOptMSS && len(opt.Data) >= 2 {
			return int(binary.BigEndian.Uint16(opt.Data))
		}
	}
	return 0
}

// GetWindowScale extracts window scale value from TCP options
func GetWindowScale(options []TCPOption) int {
	for _, opt := range options {
		if opt.Kind == TCPOptWScale && len(opt.Data) >= 1 {
			return int(opt.Data[0])
		}
	}
	return 0
}

// HasSACK checks if SACK permitted option is present
func HasSACK(options []TCPOption) bool {
	for _, opt := range options {
		if opt.Kind == TCPOptSACKPerm {
			return true
		}
	}
	return false
}

// HasTimestamp checks if timestamp option is present
func HasTimestamp(options []TCPOption) bool {
	for _, opt := range options {
		if opt.Kind == TCPOptTimestamp {
			return true
		}
	}
	return false
}

// TCPSYNProbe sends a TCP SYN and captures the SYN-ACK response for fingerprinting
func TCPSYNProbe(targetIP string, port int, timeout time.Duration) (*OSFingerprint, error) {
	cap := CheckRawSocketCapability()
	if !cap.Available {
		return nil, fmt.Errorf("raw sockets not available: %s", cap.Reason)
	}

	// Parse target IP
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return nil, fmt.Errorf("IPv6 not supported for raw socket fingerprinting")
	}

	// Get local IP for source
	conn, err := net.Dial("udp", fmt.Sprintf("%s:80", targetIP))
	if err != nil {
		return nil, fmt.Errorf("cannot determine local IP: %v", err)
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()
	srcIP := localAddr.IP.To4()

	// Create raw socket for sending
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("cannot create send socket: %v", err)
	}
	defer syscall.Close(sendFd)

	// Set IP_HDRINCL to include our own IP header
	err = syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot set IP_HDRINCL: %v", err)
	}

	// Create raw socket for receiving
	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("cannot create receive socket: %v", err)
	}
	defer syscall.Close(recvFd)

	// Set receive timeout
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	err = syscall.SetsockoptTimeval(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		return nil, fmt.Errorf("cannot set receive timeout: %v", err)
	}

	// Build SYN packet
	srcPort := uint16(40000 + (time.Now().UnixNano() % 20000)) // Random source port
	synPacket := buildTCPSYNPacket(srcIP, dstIP, srcPort, uint16(port))

	// Send SYN
	dstAddr := syscall.SockaddrInet4{Port: port}
	copy(dstAddr.Addr[:], dstIP)

	err = syscall.Sendto(sendFd, synPacket, 0, &dstAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot send SYN: %v", err)
	}

	// Receive response
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(recvFd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return nil, fmt.Errorf("receive error: %v", err)
		}

		if n < 40 { // Minimum IP + TCP header
			continue
		}

		// Parse IP header
		if buf[0]>>4 != 4 { // IPv4 only
			continue
		}
		ipHeaderLen := int(buf[0]&0x0F) * 4
		if ipHeaderLen < 20 || n < ipHeaderLen+20 {
			continue
		}

		// Check if it's from our target
		pktSrcIP := net.IP(buf[12:16])
		pktDstIP := net.IP(buf[16:20])
		if !pktSrcIP.Equal(dstIP) || !pktDstIP.Equal(srcIP) {
			continue
		}

		// Extract TTL and DF bit
		ttl := buf[8]
		flags := binary.BigEndian.Uint16(buf[6:8])
		dfBit := (flags & 0x4000) != 0

		// Parse TCP header
		tcpHeader := buf[ipHeaderLen:]
		pktSrcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		pktDstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

		if pktSrcPort != uint16(port) || pktDstPort != srcPort {
			continue
		}

		tcpFlags := tcpHeader[13]
		if tcpFlags&(TCPFlagSYN|TCPFlagACK) != (TCPFlagSYN | TCPFlagACK) {
			// Not a SYN-ACK
			if tcpFlags&TCPFlagRST != 0 {
				return nil, fmt.Errorf("port %d is closed (RST received)", port)
			}
			continue
		}

		// Parse TCP header length and options
		tcpHeaderLen := int(tcpHeader[12]>>4) * 4
		windowSize := binary.BigEndian.Uint16(tcpHeader[14:16])

		var tcpOptions []TCPOption
		if tcpHeaderLen > 20 && len(tcpHeader) >= tcpHeaderLen {
			tcpOptions = ParseTCPOptions(tcpHeader[20:tcpHeaderLen])
		}

		// Send RST to close connection cleanly
		rstPacket := buildTCPRSTPacket(srcIP, dstIP, srcPort, uint16(port),
			binary.BigEndian.Uint32(tcpHeader[8:12])+1)
		syscall.Sendto(sendFd, rstPacket, 0, &dstAddr)

		// Build fingerprint
		fp := &OSFingerprint{
			TTL:           int(ttl),
			WindowSize:    int(windowSize),
			DFBit:         dfBit,
			TCPOptions:    make([]string, 0),
			MSS:           GetMSSValue(tcpOptions),
			WindowScale:   GetWindowScale(tcpOptions),
			SACKPermitted: HasSACK(tcpOptions),
			Timestamp:     HasTimestamp(tcpOptions),
		}

		for _, opt := range tcpOptions {
			fp.TCPOptions = append(fp.TCPOptions, opt.Name)
		}
		fp.TCPOptionsStr = GetTCPOptionsString(tcpOptions)

		return fp, nil
	}

	return nil, fmt.Errorf("timeout waiting for SYN-ACK")
}

// buildTCPSYNPacket creates a raw TCP SYN packet with IP header
func buildTCPSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	// IP Header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                                        // Version 4, IHL 5
	ipHeader[1] = 0x00                                        // TOS
	binary.BigEndian.PutUint16(ipHeader[2:4], 60)             // Total length (IP + TCP + options)
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(12345))  // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)         // Flags (DF) + Fragment offset
	ipHeader[8] = 64                                          // TTL
	ipHeader[9] = syscall.IPPROTO_TCP                         // Protocol
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)
	// Checksum calculated by kernel with IP_HDRINCL

	// TCP Header (20 bytes base + 20 bytes options = 40 bytes)
	tcpHeader := make([]byte, 40)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], uint32(time.Now().UnixNano()&0xFFFFFFFF)) // Seq
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)                                        // Ack
	tcpHeader[12] = 0xA0                                                                  // Data offset (10 * 4 = 40 bytes)
	tcpHeader[13] = TCPFlagSYN                                                            // SYN flag
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)                                   // Window size

	// TCP Options (20 bytes)
	// MSS (4 bytes)
	tcpHeader[20] = TCPOptMSS
	tcpHeader[21] = 4
	binary.BigEndian.PutUint16(tcpHeader[22:24], 1460)
	// SACK Permitted (2 bytes)
	tcpHeader[24] = TCPOptSACKPerm
	tcpHeader[25] = 2
	// Timestamp (10 bytes)
	tcpHeader[26] = TCPOptTimestamp
	tcpHeader[27] = 10
	binary.BigEndian.PutUint32(tcpHeader[28:32], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(tcpHeader[32:36], 0)
	// NOP (1 byte)
	tcpHeader[36] = TCPOptNOP
	// Window Scale (3 bytes)
	tcpHeader[37] = TCPOptWScale
	tcpHeader[38] = 3
	tcpHeader[39] = 7 // Scale factor

	// Calculate TCP checksum
	checksum := tcpChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	// Combine headers
	packet := make([]byte, 60)
	copy(packet[0:20], ipHeader)
	copy(packet[20:60], tcpHeader)

	return packet
}

// buildTCPRSTPacket creates a TCP RST packet
func buildTCPRSTPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum uint32) []byte {
	// IP Header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(12346))
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = syscall.IPPROTO_TCP
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)

	// TCP Header (20 bytes, no options)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seqNum)
	tcpHeader[12] = 0x50 // Data offset (5 * 4 = 20 bytes)
	tcpHeader[13] = TCPFlagRST | TCPFlagACK

	checksum := tcpChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	packet := make([]byte, 40)
	copy(packet[0:20], ipHeader)
	copy(packet[20:40], tcpHeader)

	return packet
}

// tcpChecksum calculates TCP checksum including pseudo-header
func tcpChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	// Pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpHeader)))

	// Combine pseudo-header and TCP header
	data := append(pseudoHeader, tcpHeader...)

	// Calculate checksum
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

// FingerprintWithFallback attempts raw socket fingerprinting, falls back to connect-based
func FingerprintWithFallback(target string, port int, timeout time.Duration) (*OSFingerprint, bool, error) {
	// Try raw socket first
	cap := CheckRawSocketCapability()
	if cap.Available {
		fp, err := TCPSYNProbe(target, port, timeout)
		if err == nil {
			return fp, true, nil
		}
		// Fall through to connect-based if raw socket probe fails
	}

	// Fallback: Use regular TCP connection to get limited info
	fp, err := connectFingerprint(target, port, timeout)
	return fp, false, err
}

// connectFingerprint uses a regular TCP connection to get what limited info we can
func connectFingerprint(target string, port int, timeout time.Duration) (*OSFingerprint, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// We can't get TTL or TCP options from a regular connection,
	// but we note that the port is open
	fp := &OSFingerprint{
		TTL:        0, // Unknown
		WindowSize: 0, // Unknown
	}

	return fp, nil
}
