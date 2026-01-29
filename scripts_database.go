package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLCertScript extracts SSL certificate information
type SSLCertScript struct{}

func (s *SSLCertScript) Name() string        { return "ssl-cert" }
func (s *SSLCertScript) Description() string { return "Extracts SSL/TLS certificate information" }
func (s *SSLCertScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *SSLCertScript) PortRule(port int, service string) bool {
	return port == 443 || port == 8443 || port == 465 || port == 993 || port == 995 || strings.Contains(service, "https") || strings.Contains(service, "ssl")
}

func (s *SSLCertScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", target.Host, target.Port),
		config,
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &ScriptResult{
			ScriptName: s.Name(),
			Output:     "No certificates found",
		}, nil
	}

	cert := certs[0]
	result := &ScriptResult{ScriptName: s.Name()}

	var output strings.Builder
	output.WriteString("SSL Certificate Information:\n")
	output.WriteString(fmt.Sprintf("  Subject: %s\n", cert.Subject.CommonName))
	output.WriteString(fmt.Sprintf("  Issuer: %s\n", cert.Issuer.CommonName))
	output.WriteString(fmt.Sprintf("  Valid from: %s\n", cert.NotBefore.Format("2006-01-02")))
	output.WriteString(fmt.Sprintf("  Valid until: %s\n", cert.NotAfter.Format("2006-01-02")))

	if len(cert.DNSNames) > 0 {
		output.WriteString(fmt.Sprintf("  DNS Names: %s\n", strings.Join(cert.DNSNames, ", ")))
	}

	// Check if expired
	if time.Now().After(cert.NotAfter) {
		output.WriteString("  WARNING: Certificate has expired!\n")
		result.Vulnerable = true
		result.Findings = append(result.Findings, "Expired certificate")
	}

	// Check if self-signed
	if cert.Issuer.CommonName == cert.Subject.CommonName {
		output.WriteString("  Note: Self-signed certificate\n")
		result.Findings = append(result.Findings, "Self-signed certificate")
	}

	result.Output = output.String()
	result.Findings = append(result.Findings, cert.Subject.CommonName)

	return result, nil
}

// SSLVulnScript checks for SSL/TLS vulnerabilities
type SSLVulnScript struct{}

func (s *SSLVulnScript) Name() string        { return "ssl-vuln" }
func (s *SSLVulnScript) Description() string { return "Checks for SSL/TLS vulnerabilities" }
func (s *SSLVulnScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *SSLVulnScript) PortRule(port int, service string) bool {
	return port == 443 || port == 8443 || strings.Contains(service, "https") || strings.Contains(service, "ssl")
}

func (s *SSLVulnScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	var findings []string

	// Test for weak protocols (SSLv3, TLS 1.0, TLS 1.1)
	weakProtocols := []uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
	}

	for _, version := range weakProtocols {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		}

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp",
			fmt.Sprintf("%s:%d", target.Host, target.Port),
			config,
		)

		if err == nil {
			conn.Close()
			versionName := "Unknown"
			switch version {
			case tls.VersionSSL30:
				versionName = "SSLv3"
			case tls.VersionTLS10:
				versionName = "TLS 1.0"
			case tls.VersionTLS11:
				versionName = "TLS 1.1"
			}
			findings = append(findings, fmt.Sprintf("Weak protocol supported: %s", versionName))
		}
	}

	// Check current connection for cipher suite strength
	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", target.Host, target.Port),
		config,
	)

	if err == nil {
		defer conn.Close()
		state := conn.ConnectionState()

		// Get cipher suite name
		cipherName := tls.CipherSuiteName(state.CipherSuite)
		if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "DES") {
			findings = append(findings, fmt.Sprintf("Weak cipher suite: %s", cipherName))
		}
	}

	result.Findings = findings
	result.Vulnerable = len(findings) > 0

	if len(findings) > 0 {
		result.Output = fmt.Sprintf("Found %d SSL/TLS issues:\n  - %s", len(findings), strings.Join(findings, "\n  - "))
	} else {
		result.Output = "No SSL/TLS vulnerabilities detected"
	}

	return result, nil
}

// MySQLInfoScript extracts MySQL server information
type MySQLInfoScript struct{}

func (s *MySQLInfoScript) Name() string        { return "mysql-info" }
func (s *MySQLInfoScript) Description() string { return "Extracts MySQL server information" }
func (s *MySQLInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDefault, CategorySafe}
}
func (s *MySQLInfoScript) PortRule(port int, service string) bool {
	return port == 3306 || strings.Contains(service, "mysql")
}

func (s *MySQLInfoScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read MySQL greeting packet
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	result := &ScriptResult{ScriptName: s.Name()}

	if n > 5 {
		// Parse protocol version (byte 0)
		protocolVersion := buffer[0]

		// Parse server version string (null-terminated after protocol version)
		versionStart := 1
		versionEnd := versionStart
		for versionEnd < n && buffer[versionEnd] != 0 {
			versionEnd++
		}

		if versionEnd > versionStart {
			version := string(buffer[versionStart:versionEnd])
			result.Output = fmt.Sprintf("MySQL Server Information:\n  Protocol: %d\n  Version: %s", protocolVersion, version)
			result.Findings = append(result.Findings, fmt.Sprintf("MySQL %s", version))
		} else {
			result.Output = "MySQL server detected (version string not parsed)"
		}
	} else {
		result.Output = "MySQL server detected (minimal response)"
	}

	return result, nil
}

// RedisInfoScript extracts Redis server information
type RedisInfoScript struct{}

func (s *RedisInfoScript) Name() string        { return "redis-info" }
func (s *RedisInfoScript) Description() string { return "Extracts Redis server information" }
func (s *RedisInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDefault, CategorySafe}
}
func (s *RedisInfoScript) PortRule(port int, service string) bool {
	return port == 6379 || strings.Contains(service, "redis")
}

func (s *RedisInfoScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send INFO command
	conn.Write([]byte("INFO\r\n"))

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := string(buffer[:n])

	result := &ScriptResult{ScriptName: s.Name()}

	if strings.HasPrefix(response, "$") || strings.Contains(response, "redis_version") {
		// Parse Redis INFO response
		lines := strings.Split(response, "\n")
		var version, mode string

		for _, line := range lines {
			if strings.HasPrefix(line, "redis_version:") {
				version = strings.TrimPrefix(line, "redis_version:")
				version = strings.TrimSpace(version)
			}
			if strings.HasPrefix(line, "redis_mode:") {
				mode = strings.TrimPrefix(line, "redis_mode:")
				mode = strings.TrimSpace(mode)
			}
		}

		if version != "" {
			result.Output = fmt.Sprintf("Redis Server Information:\n  Version: %s\n  Mode: %s", version, mode)
			result.Findings = append(result.Findings, fmt.Sprintf("Redis %s", version))
		} else {
			result.Output = "Redis server detected (version not parsed)"
		}

		// Check if authentication is required
		if !strings.Contains(response, "NOAUTH") {
			result.Findings = append(result.Findings, "No authentication required - potential security risk")
			result.Vulnerable = true
		}
	} else {
		result.Output = "Redis server detected"
	}

	return result, nil
}
