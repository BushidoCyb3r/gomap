package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProtocolFingerprint contains service-specific OS detection data
type ProtocolFingerprint struct {
	Protocol string            `json:"protocol"`
	OSHints  []string          `json:"os_hints"`
	Details  map[string]string `json:"details"`
}

// SSHFingerprint contains SSH key exchange analysis
type SSHFingerprint struct {
	ProtocolVersion string   `json:"protocol_version"`
	SoftwareVersion string   `json:"software_version"`
	KexAlgorithms   []string `json:"kex_algorithms"`
	HostKeyTypes    []string `json:"host_key_types"`
	CiphersC2S      []string `json:"ciphers_client_to_server"`
	CiphersS2C      []string `json:"ciphers_server_to_client"`
	MACsC2S         []string `json:"macs_client_to_server"`
	MACsS2C         []string `json:"macs_server_to_client"`
	Compression     []string `json:"compression"`
	OSHint          string   `json:"os_hint"`
}

// HTTPFingerprint contains HTTP server behavior analysis
type HTTPFingerprint struct {
	ServerHeader     string            `json:"server_header"`
	HeaderOrder      []string          `json:"header_order"`
	PoweredBy        string            `json:"powered_by"`
	AllowedMethods   []string          `json:"allowed_methods"`
	ErrorPagePattern string            `json:"error_page_pattern"`
	Features         []string          `json:"features"`
	CustomHeaders    map[string]string `json:"custom_headers"`
	OSHint           string            `json:"os_hint"`
}

// TLSFingerprint contains TLS handshake analysis
type TLSFingerprint struct {
	JA3S            string   `json:"ja3s"`
	Version         string   `json:"tls_version"`
	CipherSuite     string   `json:"cipher_suite"`
	Extensions      []string `json:"extensions"`
	ALPN            []string `json:"alpn"`
	CertIssuer      string   `json:"cert_issuer"`
	CertSubject     string   `json:"cert_subject"`
	CertExpiry      string   `json:"cert_expiry"`
	OSHint          string   `json:"os_hint"`
}

// SSHKexInit message parsing constants
const (
	SSHMsgKexInit = 20
)

// SSHFingerprinting performs SSH protocol analysis for OS detection
func SSHFingerprinting(target string, port int, timeout time.Duration) (*ProtocolFingerprint, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 2))

	result := &ProtocolFingerprint{
		Protocol: "ssh",
		OSHints:  make([]string, 0),
		Details:  make(map[string]string),
	}

	// Read SSH banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	banner = strings.TrimSpace(banner)
	result.Details["banner"] = banner

	// Parse SSH version
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) >= 3 {
			result.Details["protocol_version"] = parts[1]
			result.Details["software_version"] = parts[2]

			// OS detection from software version
			softwareLower := strings.ToLower(parts[2])

			switch {
			case strings.Contains(softwareLower, "ubuntu"):
				result.OSHints = append(result.OSHints, "Ubuntu Linux")
				result.Details["os_family"] = "Linux"
			case strings.Contains(softwareLower, "debian"):
				result.OSHints = append(result.OSHints, "Debian Linux")
				result.Details["os_family"] = "Linux"
			case strings.Contains(softwareLower, "centos"):
				result.OSHints = append(result.OSHints, "CentOS Linux")
				result.Details["os_family"] = "Linux"
			case strings.Contains(softwareLower, "rhel") || strings.Contains(softwareLower, "red hat"):
				result.OSHints = append(result.OSHints, "RHEL")
				result.Details["os_family"] = "Linux"
			case strings.Contains(softwareLower, "freebsd"):
				result.OSHints = append(result.OSHints, "FreeBSD")
				result.Details["os_family"] = "BSD"
			case strings.Contains(softwareLower, "openbsd"):
				result.OSHints = append(result.OSHints, "OpenBSD")
				result.Details["os_family"] = "BSD"
			case strings.Contains(softwareLower, "for_windows") || strings.Contains(softwareLower, "windows"):
				result.OSHints = append(result.OSHints, "Windows")
				result.Details["os_family"] = "Windows"
			case strings.Contains(softwareLower, "cisco"):
				result.OSHints = append(result.OSHints, "Cisco IOS")
				result.Details["os_family"] = "Cisco"
			case strings.Contains(softwareLower, "dropbear"):
				result.OSHints = append(result.OSHints, "Embedded Linux (Dropbear)")
				result.Details["os_family"] = "Linux"
			case strings.Contains(softwareLower, "openssh"):
				// Try to get version for more specific OS hint
				versionMatch := regexp.MustCompile(`OpenSSH[_\s]+(\d+\.\d+)`).FindStringSubmatch(parts[2])
				if len(versionMatch) > 1 {
					result.Details["openssh_version"] = versionMatch[1]
				}
				result.OSHints = append(result.OSHints, "Linux/Unix (OpenSSH)")
				result.Details["os_family"] = "Linux"
			}
		}
	}

	// Send our SSH banner
	conn.Write([]byte("SSH-2.0-GoMap_Scanner\r\n"))

	// Try to read KEX_INIT (often not needed but provides extra fingerprinting data)
	kexBuf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := reader.Read(kexBuf)
	if err == nil && n > 5 {
		// Try to parse KEX_INIT for algorithm fingerprinting
		parseSSHKexInit(kexBuf[:n], result)
	}

	return result, nil
}

// parseSSHKexInit extracts algorithms from SSH KEX_INIT message
func parseSSHKexInit(data []byte, result *ProtocolFingerprint) {
	// SSH packet format: length (4) + padding (1) + type (1) + data
	if len(data) < 6 {
		return
	}

	// Find KEX_INIT message (may be after version exchange)
	for i := 0; i < len(data)-5; i++ {
		// Look for packet with type 20 (KEX_INIT)
		if data[i] == SSHMsgKexInit && i >= 5 {
			// Parse from here
			offset := i + 1 + 16 // Skip type and cookie (16 bytes)
			if offset >= len(data) {
				return
			}

			// Read name-lists
			algNames := []string{
				"kex_algorithms",
				"server_host_key_algorithms",
				"encryption_algorithms_c2s",
				"encryption_algorithms_s2c",
				"mac_algorithms_c2s",
				"mac_algorithms_s2c",
				"compression_algorithms_c2s",
				"compression_algorithms_s2c",
			}

			for _, name := range algNames {
				if offset+4 > len(data) {
					break
				}
				length := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
				offset += 4
				if offset+length > len(data) || length > 10000 {
					break
				}
				if length > 0 {
					algorithms := string(data[offset : offset+length])
					result.Details[name] = algorithms
				}
				offset += length
			}
			break
		}
	}
}

// HTTPFingerprinting performs HTTP server behavior analysis
func HTTPFingerprinting(target string, port int, timeout time.Duration) (*ProtocolFingerprint, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 2))

	result := &ProtocolFingerprint{
		Protocol: "http",
		OSHints:  make([]string, 0),
		Details:  make(map[string]string),
	}

	// Send HTTP request
	request := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: GoMap/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", target)
	conn.Write([]byte(request))

	// Read response
	reader := bufio.NewReader(conn)
	response := make([]byte, 0)
	headerOrder := make([]string, 0)

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		response = append(response, []byte(line)...)

		// Parse header
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			headerName := strings.TrimSpace(line[:colonIdx])
			headerValue := strings.TrimSpace(line[colonIdx+1:])
			headerOrder = append(headerOrder, headerName)

			switch strings.ToLower(headerName) {
			case "server":
				result.Details["server"] = headerValue
				osHint := identifyOSFromServerHeader(headerValue)
				if osHint != "" {
					result.OSHints = append(result.OSHints, osHint)
				}
			case "x-powered-by":
				result.Details["powered_by"] = headerValue
			case "x-aspnet-version":
				result.OSHints = append(result.OSHints, "Windows (ASP.NET)")
				result.Details["aspnet_version"] = headerValue
			case "x-aspnetmvc-version":
				result.OSHints = append(result.OSHints, "Windows (ASP.NET MVC)")
			}
		}
	}

	// Store header order for fingerprinting
	result.Details["header_order"] = strings.Join(headerOrder, ",")

	// Check for allowed methods
	methodConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err == nil {
		defer methodConn.Close()
		methodConn.SetDeadline(time.Now().Add(timeout))
		optionsRequest := fmt.Sprintf("OPTIONS / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		methodConn.Write([]byte(optionsRequest))

		methodReader := bufio.NewReader(methodConn)
		for {
			line, err := methodReader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
			if strings.HasPrefix(strings.ToLower(line), "allow:") {
				result.Details["allowed_methods"] = strings.TrimSpace(line[6:])
				break
			}
		}
	}

	return result, nil
}

// identifyOSFromServerHeader extracts OS hints from HTTP Server header
func identifyOSFromServerHeader(header string) string {
	headerLower := strings.ToLower(header)

	patterns := []struct {
		pattern string
		os      string
	}{
		{"microsoft-iis", "Windows Server"},
		{"microsoft-httpapi", "Windows"},
		{"win32", "Windows"},
		{"win64", "Windows"},
		{"(ubuntu)", "Ubuntu Linux"},
		{"(debian)", "Debian Linux"},
		{"(centos)", "CentOS Linux"},
		{"(red hat)", "RHEL"},
		{"(fedora)", "Fedora Linux"},
		{"(freebsd)", "FreeBSD"},
		{"(openbsd)", "OpenBSD"},
		{"(unix)", "Unix"},
		{"(linux)", "Linux"},
		{"openresty", "Linux (OpenResty)"},
		{"nginx", "Linux (likely)"},
		{"apache", "Linux/Unix (likely)"},
		{"lighttpd", "Linux"},
	}

	for _, p := range patterns {
		if strings.Contains(headerLower, p.pattern) {
			return p.os
		}
	}

	return ""
}

// TLSFingerprinting performs TLS handshake analysis
func TLSFingerprinting(target string, port int, timeout time.Duration) (*ProtocolFingerprint, error) {
	result := &ProtocolFingerprint{
		Protocol: "tls",
		OSHints:  make([]string, 0),
		Details:  make(map[string]string),
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target, port), tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get connection state
	state := conn.ConnectionState()

	// TLS Version
	switch state.Version {
	case tls.VersionTLS10:
		result.Details["tls_version"] = "TLS 1.0"
	case tls.VersionTLS11:
		result.Details["tls_version"] = "TLS 1.1"
	case tls.VersionTLS12:
		result.Details["tls_version"] = "TLS 1.2"
	case tls.VersionTLS13:
		result.Details["tls_version"] = "TLS 1.3"
	default:
		result.Details["tls_version"] = fmt.Sprintf("0x%04x", state.Version)
	}

	// Cipher suite
	result.Details["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)

	// Generate JA3S-like fingerprint (simplified)
	// JA3S = TLSVersion,CipherSuite,Extensions
	ja3sComponents := []string{
		fmt.Sprintf("%d", state.Version),
		fmt.Sprintf("%d", state.CipherSuite),
	}
	ja3sString := strings.Join(ja3sComponents, ",")
	hash := md5.Sum([]byte(ja3sString))
	result.Details["ja3s"] = hex.EncodeToString(hash[:])

	// Certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Details["cert_subject"] = cert.Subject.String()
		result.Details["cert_issuer"] = cert.Issuer.String()
		result.Details["cert_expiry"] = cert.NotAfter.Format(time.RFC3339)
		result.Details["cert_not_before"] = cert.NotBefore.Format(time.RFC3339)

		// Check for OS hints in certificate
		subjectLower := strings.ToLower(cert.Subject.String())
		issuerLower := strings.ToLower(cert.Issuer.String())

		if strings.Contains(subjectLower, "microsoft") || strings.Contains(issuerLower, "microsoft") {
			result.OSHints = append(result.OSHints, "Windows (Microsoft certificate)")
		}
		if strings.Contains(subjectLower, "apple") || strings.Contains(issuerLower, "apple") {
			result.OSHints = append(result.OSHints, "macOS/iOS (Apple certificate)")
		}
	}

	// ALPN
	if state.NegotiatedProtocol != "" {
		result.Details["alpn"] = state.NegotiatedProtocol
	}

	return result, nil
}

// SMBEnhancedFingerprint performs enhanced SMB analysis for OS detection
func SMBEnhancedFingerprint(target string, port int, timeout time.Duration) (*ProtocolFingerprint, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 2))

	result := &ProtocolFingerprint{
		Protocol: "smb",
		OSHints:  make([]string, 0),
		Details:  make(map[string]string),
	}

	// SMB2 Negotiate Request
	smb2NegotiateRequest := []byte{
		// NetBIOS Session Service Header
		0x00,                   // Message Type
		0x00, 0x00, 0x66,       // Length (102 bytes)

		// SMB2 Header (64 bytes)
		0xFE, 0x53, 0x4D, 0x42, // Protocol ID (0xFE 'SMB')
		0x40, 0x00,             // Header Length (64)
		0x00, 0x00,             // Credit Charge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00,             // Command (NEGOTIATE)
		0x00, 0x00,             // Credits Requested
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next Command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature

		// SMB2 NEGOTIATE Request (38 bytes)
		0x24, 0x00,             // Structure Size (36)
		0x05, 0x00,             // Dialect Count (5)
		0x01, 0x00,             // Security Mode
		0x00, 0x00,             // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID

		// Dialects
		0x02, 0x02, // SMB 2.0.2
		0x10, 0x02, // SMB 2.1
		0x00, 0x03, // SMB 3.0
		0x02, 0x03, // SMB 3.0.2
		0x11, 0x03, // SMB 3.1.1
	}

	_, err = conn.Write(smb2NegotiateRequest)
	if err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	if n < 70 { // Minimum valid response
		return result, nil
	}

	// Skip NetBIOS header (4 bytes), check SMB2 signature
	if n > 4 && buf[4] == 0xFE && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		// SMB2 response
		result.Details["smb_version"] = "SMB2"

		// Parse SMB2 Negotiate Response
		if n > 72 {
			dialectRevision := uint16(buf[68]) | uint16(buf[69])<<8
			switch dialectRevision {
			case 0x0202:
				result.Details["dialect"] = "SMB 2.0.2"
			case 0x0210:
				result.Details["dialect"] = "SMB 2.1"
			case 0x0300:
				result.Details["dialect"] = "SMB 3.0"
			case 0x0302:
				result.Details["dialect"] = "SMB 3.0.2"
			case 0x0311:
				result.Details["dialect"] = "SMB 3.1.1"
			default:
				result.Details["dialect"] = fmt.Sprintf("0x%04x", dialectRevision)
			}

			// Security mode
			securityMode := buf[70]
			if securityMode&0x01 != 0 {
				result.Details["signing_enabled"] = "true"
			}
			if securityMode&0x02 != 0 {
				result.Details["signing_required"] = "true"
			}
		}

		// OS hints based on SMB capabilities
		result.OSHints = append(result.OSHints, "Windows (SMB2)")
	} else if n > 4 && buf[4] == 0xFF && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		// SMB1 response
		result.Details["smb_version"] = "SMB1"
		result.OSHints = append(result.OSHints, "Windows (SMB1) or Samba")
	}

	return result, nil
}

// ConvertProtocolFingerprintToOSMatch converts protocol fingerprint to OS matches
func ConvertProtocolFingerprintToOSMatch(fp *ProtocolFingerprint) []OSMatch {
	matches := make([]OSMatch, 0)

	if fp == nil {
		return matches
	}

	for _, hint := range fp.OSHints {
		match := OSMatch{
			Name:       hint,
			Family:     GetOSFamily(hint),
			Confidence: 0.7,
			Method:     fp.Protocol,
		}
		matches = append(matches, match)
	}

	return matches
}

// CombineFingerprints aggregates results from multiple fingerprinting methods
func CombineFingerprints(tcpFP *OSFingerprint, icmpFP *ICMPFingerprint, protocolFPs []*ProtocolFingerprint) *OSDetectionResult {
	result := NewOSDetectionResult()

	// Add TCP fingerprint results
	if tcpFP != nil {
		result.Fingerprint = tcpFP
		result.RawSocketUsed = true
		result.Methods = append(result.Methods, "tcp")

		tcpMatches := MatchFingerprint(tcpFP)
		for _, m := range tcpMatches {
			result.AddMatch(m)
		}
	}

	// Add ICMP fingerprint results
	if icmpFP != nil && icmpFP.ReplyReceived {
		result.ICMPUsed = true
		result.Methods = append(result.Methods, "icmp")

		icmpMatches := GetICMPOSHints(icmpFP)
		for _, m := range icmpMatches {
			result.AddMatch(m)
		}
	}

	// Add protocol fingerprint results
	for _, pfp := range protocolFPs {
		if pfp != nil {
			result.Methods = append(result.Methods, pfp.Protocol)

			protoMatches := ConvertProtocolFingerprintToOSMatch(pfp)
			for _, m := range protoMatches {
				result.AddMatch(m)
			}
		}
	}

	// Combine and deduplicate matches
	result.consolidateMatches()
	result.SelectBestMatch()

	return result
}

// consolidateMatches merges duplicate OS matches and adjusts confidence
func (r *OSDetectionResult) consolidateMatches() {
	if len(r.Matches) <= 1 {
		return
	}

	// Group matches by OS family
	familyScores := make(map[string]float64)
	familyNames := make(map[string]string)
	familyMethods := make(map[string][]string)

	for _, m := range r.Matches {
		family := m.Family
		if family == "" {
			family = m.Name
		}

		familyScores[family] += m.Confidence
		if _, exists := familyNames[family]; !exists || len(m.Name) > len(familyNames[family]) {
			familyNames[family] = m.Name
		}
		familyMethods[family] = append(familyMethods[family], m.Method)
	}

	// Rebuild matches with consolidated scores
	newMatches := make([]OSMatch, 0)
	for family, score := range familyScores {
		// Normalize score (multiple methods increase confidence, max 0.95)
		normalizedScore := score
		methodCount := len(familyMethods[family])
		if methodCount > 1 {
			normalizedScore = score * (1 + float64(methodCount-1)*0.1)
		}
		if normalizedScore > 0.95 {
			normalizedScore = 0.95
		}

		newMatches = append(newMatches, OSMatch{
			Name:       familyNames[family],
			Family:     family,
			Confidence: normalizedScore,
			Method:     "combined",
		})
	}

	// Sort by confidence
	sort.Slice(newMatches, func(i, j int) bool {
		return newMatches[i].Confidence > newMatches[j].Confidence
	})

	r.Matches = newMatches
}

// GetPortsForProtocolFingerprinting suggests which ports to use for protocol fingerprinting
func GetPortsForProtocolFingerprinting(openPorts []PortResult) map[string]int {
	suggestions := make(map[string]int)

	for _, port := range openPorts {
		switch port.Port {
		case 22:
			suggestions["ssh"] = 22
		case 80:
			if _, exists := suggestions["http"]; !exists {
				suggestions["http"] = 80
			}
		case 443:
			suggestions["tls"] = 443
		case 8080, 8443:
			if _, exists := suggestions["http"]; !exists {
				suggestions["http"] = port.Port
			}
		case 445:
			suggestions["smb"] = 445
		case 139:
			if _, exists := suggestions["smb"]; !exists {
				suggestions["smb"] = 139
			}
		}

		// Check service names
		serviceLower := strings.ToLower(port.Service)
		if strings.Contains(serviceLower, "ssh") && suggestions["ssh"] == 0 {
			suggestions["ssh"] = port.Port
		}
		if strings.Contains(serviceLower, "http") && suggestions["http"] == 0 {
			suggestions["http"] = port.Port
		}
		if strings.Contains(serviceLower, "ssl") || strings.Contains(serviceLower, "https") {
			if suggestions["tls"] == 0 {
				suggestions["tls"] = port.Port
			}
		}
		if strings.Contains(serviceLower, "smb") || strings.Contains(serviceLower, "microsoft-ds") {
			if suggestions["smb"] == 0 {
				suggestions["smb"] = port.Port
			}
		}
	}

	return suggestions
}

// ExtractVersionFromBanner tries to extract version numbers from service banners
func ExtractVersionFromBanner(banner string) string {
	// Common version patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(\d+\.\d+\.\d+[a-zA-Z0-9\-\.]*)`),
		regexp.MustCompile(`(\d+\.\d+[a-zA-Z0-9\-\.]*)`),
		regexp.MustCompile(`[vV]ersion[:\s]+([0-9][0-9a-zA-Z\.\-]+)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(banner)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// CompareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(strings.TrimLeft(parts1[i], "0"))
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(strings.TrimLeft(parts2[i], "0"))
		}

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}
