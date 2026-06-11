package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// detectServices attempts to identify services and versions on open ports
func (s *Scanner) detectServices(target string, ports *[]PortResult) {
	if s.config.Verbose {
		fmt.Println("\n" + ColorCyan + "[*] " + ColorReset + "Performing service detection...")
	}

	// Create progress bar for service detection
	progressBar := NewProgressBarWithLabel(len(*ports), "services")

	for i := range *ports {
		port := &(*ports)[i]
		address := fmt.Sprintf("%s:%d", target, port.Port)

		// For TLS ports, complete a TLS handshake first: read the certificate
		// and grab the real banner from inside the encrypted channel. Sending
		// cleartext probes to a TLS port (the old behaviour) only ever returns
		// encrypted noise.
		var banner string
		if isTLSPort(port.Port) {
			banner, port.TLSInfo = grabTLSBanner(address, port.Port, s.config.Timeout)
			if s.config.Verbose && port.TLSInfo != "" {
				fmt.Printf("\n"+ColorGreen+"  [+] "+ColorReset+"Port "+ColorPurple+"%d"+ColorReset+" TLS: "+ColorTeal+"%s"+ColorReset, port.Port, port.TLSInfo)
			}
		}

		// Fall back to a plain-text banner grab if TLS did not apply or yielded nothing.
		if banner == "" {
			banner = grabBanner(address, s.config.Timeout)
		}

		if banner != "" {
			version := parseVersion(banner, port.Service)
			port.Version = version

			if s.config.Verbose {
				fmt.Printf("\n"+ColorGreen+"  [+] "+ColorReset+"Port "+ColorPurple+"%d"+ColorReset+": "+ColorTeal+"%s"+ColorReset, port.Port, version)
			}
		}

		// Update progress
		progressBar.Update(i + 1)
	}
	progressBar.Finish(false)
}

// grabBanner connects to a port and attempts to read a banner
func grabBanner(address string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send common probes
	probes := []string{
		"GET / HTTP/1.0\r\n\r\n",
		"\r\n",
		"HELP\r\n",
	}

	for _, probe := range probes {
		conn.Write([]byte(probe))

		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return string(buffer[:n])
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Try reading without sending anything
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return string(buffer[:n])
	}

	return ""
}

// tlsPorts lists ports that speak TLS immediately (not STARTTLS).
var tlsPorts = map[int]bool{
	443:  true, // https
	465:  true, // smtps
	563:  true, // nntps
	636:  true, // ldaps
	853:  true, // dns-over-tls
	989:  true, // ftps-data
	990:  true, // ftps
	993:  true, // imaps
	995:  true, // pop3s
	5986: true, // winrm-https
	8443: true, // https-alt
	9443: true, // https-alt
}

// isTLSPort reports whether a port is expected to speak TLS directly.
func isTLSPort(port int) bool { return tlsPorts[port] }

// httpOverTLSPorts are TLS ports where an HTTP request elicits a useful banner.
var httpOverTLSPorts = map[int]bool{443: true, 8443: true, 9443: true, 5986: true}

// grabTLSBanner performs a TLS handshake, summarises the server certificate, and
// reads whatever banner the service exposes inside the encrypted channel.
// Returns (banner, tlsInfo). Certificate validation is intentionally skipped so
// self-signed / expired certs are still inspected.
func grabTLSBanner(address string, port int, timeout time.Duration) (string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tlsInfo := summariseTLS(conn.ConnectionState())

	// Coax a banner out: HTTP ports need a request; mail/other TLS services send
	// a greeting on connect.
	if httpOverTLSPorts[port] {
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n]), tlsInfo
	}
	return "", tlsInfo
}

// summariseTLS renders a one-line summary of a TLS connection state and its
// leaf certificate.
func summariseTLS(state tls.ConnectionState) string {
	parts := []string{tlsVersionName(state.Version)}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if cert.Subject.CommonName != "" {
			parts = append(parts, "CN="+cert.Subject.CommonName)
		}
		if len(cert.DNSNames) > 0 {
			sans := cert.DNSNames
			if len(sans) > 4 {
				sans = sans[:4]
			}
			parts = append(parts, "SAN="+strings.Join(sans, ","))
		}
		if cert.Issuer.CommonName != "" {
			parts = append(parts, "Issuer="+cert.Issuer.CommonName)
		}
		parts = append(parts, "Expires="+cert.NotAfter.Format("2006-01-02"))
	}
	return strings.Join(parts, "; ")
}

// tlsVersionName maps a TLS version constant to a human-readable name.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// parseVersion extracts version information from a banner
func parseVersion(banner, service string) string {
	lines := strings.Split(banner, "\n")
	if len(lines) == 0 {
		return "unknown"
	}

	firstLine := strings.TrimSpace(lines[0])

	// HTTP detection
	if strings.Contains(firstLine, "HTTP/") {
		scanner := bufio.NewScanner(strings.NewReader(banner))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Server:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			}
		}
		return "HTTP server"
	}

	// SSH detection
	if strings.HasPrefix(firstLine, "SSH-") {
		return firstLine
	}

	// FTP detection
	if strings.Contains(firstLine, "FTP") {
		return firstLine
	}

	// SMTP detection
	if strings.Contains(firstLine, "SMTP") || strings.HasPrefix(firstLine, "220") {
		return firstLine
	}

	// MySQL detection
	if strings.Contains(banner, "mysql") || strings.Contains(strings.ToLower(banner), "mariadb") {
		return "MySQL/MariaDB"
	}

	// PostgreSQL detection
	if strings.Contains(banner, "postgres") {
		return "PostgreSQL"
	}

	// Redis detection
	if strings.HasPrefix(firstLine, "-ERR") || strings.HasPrefix(firstLine, "+PONG") {
		return "Redis"
	}

	// RPC/MSRPC detection
	if strings.Contains(strings.ToLower(banner), "rpc") ||
		(len(banner) > 10 && banner[0] == 0x05) { // DCE/RPC header
		return "Microsoft Windows RPC"
	}

	// SMB detection
	if len(banner) > 4 && banner[0] == 0xFF && banner[1] == 'S' && banner[2] == 'M' && banner[3] == 'B' {
		return "Microsoft Windows SMB"
	}

	// NetBIOS detection
	if len(banner) > 0 && (banner[0] == 0x82 || banner[0] == 0x83) {
		return "NetBIOS Session Service"
	}

	// Kerberos detection
	if len(banner) > 10 && strings.Contains(strings.ToLower(banner), "krb") {
		return "Kerberos"
	}

	// LDAP detection
	if len(banner) > 5 && banner[0] == 0x30 { // ASN.1 SEQUENCE
		return "LDAP"
	}

	// RDP detection (minimal)
	if len(banner) > 10 && banner[0] == 0x03 {
		return "Microsoft Terminal Services"
	}

	// WinRM/WS-Management detection
	if strings.Contains(strings.ToLower(banner), "wsman") ||
		strings.Contains(strings.ToLower(banner), "ws-management") {
		return "WS-Management (WinRM)"
	}

	if firstLine != "" && len(firstLine) < 200 {
		return firstLine
	}

	return "unknown"
}

// detectOS attempts basic OS fingerprinting
func (s *Scanner) detectOS(target string, openPorts []PortResult) string {
	if s.config.Verbose {
		fmt.Println("\n" + ColorCyan + "[*] " + ColorReset + "Attempting OS detection...")
	}

	// This is a simplified OS detection
	// Real OS detection would use TCP/IP stack fingerprinting

	signatures := make(map[string]int)

	for _, port := range openPorts {
		switch port.Port {
		case 22: // SSH
			if strings.Contains(port.Version, "OpenSSH") {
				signatures["Linux/Unix"]++
			}
		case 135, 139, 445: // Windows SMB/RPC
			signatures["Windows"]++
		case 3389: // RDP
			signatures["Windows"]++
		case 548: // AFP (Apple Filing Protocol)
			signatures["macOS"]++
		case 5900: // VNC
			signatures["Linux/Unix"]++
		}

		// Check version strings
		versionLower := strings.ToLower(port.Version)
		if strings.Contains(versionLower, "microsoft") || strings.Contains(versionLower, "windows") {
			signatures["Windows"] += 2
		} else if strings.Contains(versionLower, "ubuntu") || strings.Contains(versionLower, "debian") {
			signatures["Linux (Debian-based)"] += 2
		} else if strings.Contains(versionLower, "centos") || strings.Contains(versionLower, "rhel") {
			signatures["Linux (RedHat-based)"] += 2
		} else if strings.Contains(versionLower, "linux") {
			signatures["Linux"]++
		} else if strings.Contains(versionLower, "unix") {
			signatures["Unix"]++
		}
	}

	// Find OS with highest score
	maxScore := 0
	detectedOS := "Unknown"

	for os, score := range signatures {
		if score > maxScore {
			maxScore = score
			detectedOS = os
		}
	}

	if maxScore > 0 {
		return fmt.Sprintf("%s (confidence: %d/10)", detectedOS, minInt(maxScore*2, 10))
	}

	return "Unknown"
}
