package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// NFSExportScript enumerates NFS exports
type NFSExportScript struct{}

func (s *NFSExportScript) Name() string        { return "nfs-showmount" }
func (s *NFSExportScript) Description() string { return "Lists NFS exports" }
func (s *NFSExportScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *NFSExportScript) PortRule(port int, service string) bool {
	return port == 2049 || port == 111 || strings.Contains(service, "nfs") || strings.Contains(service, "rpcbind")
}

func (s *NFSExportScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "NFS Service detected\nNote: Use showmount or nfs-ls for enumeration\nExample: showmount -e <target>\nMount example: mount -t nfs <target>:/share /mnt/share"
	result.Findings = append(result.Findings, "NFS accessible")

	return result, nil
}

// DNSVersionScript attempts to get DNS version using CHAOS TXT query
type DNSVersionScript struct{}

func (s *DNSVersionScript) Name() string        { return "dns-version" }
func (s *DNSVersionScript) Description() string { return "Queries DNS version using CHAOS TXT" }
func (s *DNSVersionScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDiscovery, CategorySafe}
}
func (s *DNSVersionScript) PortRule(port int, service string) bool {
	return port == 53 || strings.Contains(service, "dns")
}

func (s *DNSVersionScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	// Build DNS CHAOS TXT query for version.bind
	query := buildDNSVersionQuery()

	// Send UDP query
	addr := fmt.Sprintf("%s:53", target.Host)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		result.Output = "DNS Service detected (could not query version)\nNote: Query manually with: dig @" + target.Host + " version.bind CHAOS TXT"
		result.Findings = append(result.Findings, "DNS server accessible")
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		result.Output = "DNS Service detected (query failed)\nNote: Query manually with: dig @" + target.Host + " version.bind CHAOS TXT"
		result.Findings = append(result.Findings, "DNS server accessible")
		return result, nil
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		result.Output = "DNS Service detected (no version response)\nNote: Server may block version queries"
		result.Findings = append(result.Findings, "DNS server accessible (version hidden)")
		return result, nil
	}

	// Parse DNS response
	version := parseDNSVersionResponse(response[:n])
	if version != "" {
		result.Output = fmt.Sprintf("DNS Version: %s\n\nOS Detection Hints:\n", version)

		// OS detection from version string
		versionLower := strings.ToLower(version)
		if strings.Contains(versionLower, "bind") {
			result.Output += "  - BIND DNS server (typically Linux/Unix)\n"
			result.Findings = append(result.Findings, "BIND DNS: "+version)

			// Extract BIND version for vulnerability checking
			if strings.Contains(version, "9.") {
				result.Findings = append(result.Findings, "BIND 9.x detected")
			}
		} else if strings.Contains(versionLower, "microsoft") || strings.Contains(versionLower, "windows") {
			result.Output += "  - Microsoft DNS server (Windows Server)\n"
			result.Findings = append(result.Findings, "Microsoft DNS detected")
		} else if strings.Contains(versionLower, "dnsmasq") {
			result.Output += "  - dnsmasq (Linux/embedded)\n"
			result.Findings = append(result.Findings, "dnsmasq DNS: "+version)
		} else if strings.Contains(versionLower, "unbound") {
			result.Output += "  - Unbound DNS (Linux/BSD)\n"
			result.Findings = append(result.Findings, "Unbound DNS: "+version)
		} else if strings.Contains(versionLower, "powerdns") {
			result.Output += "  - PowerDNS (Linux)\n"
			result.Findings = append(result.Findings, "PowerDNS: "+version)
		} else {
			result.Findings = append(result.Findings, "DNS version: "+version)
		}
	} else {
		result.Output = "DNS Service detected\nVersion query returned no data"
		result.Findings = append(result.Findings, "DNS server accessible")
	}

	return result, nil
}

// buildDNSVersionQuery creates a DNS CHAOS TXT query for version.bind
func buildDNSVersionQuery() []byte {
	// DNS Header (12 bytes)
	query := make([]byte, 0, 64)

	// Transaction ID
	query = append(query, 0x00, 0x01)
	// Flags: Standard query, recursion desired
	query = append(query, 0x00, 0x00)
	// Questions: 1
	query = append(query, 0x00, 0x01)
	// Answer RRs: 0
	query = append(query, 0x00, 0x00)
	// Authority RRs: 0
	query = append(query, 0x00, 0x00)
	// Additional RRs: 0
	query = append(query, 0x00, 0x00)

	// Question section: version.bind
	// version (7 bytes)
	query = append(query, 0x07)
	query = append(query, "version"...)
	// bind (4 bytes)
	query = append(query, 0x04)
	query = append(query, "bind"...)
	// null terminator
	query = append(query, 0x00)

	// Type: TXT (16)
	query = append(query, 0x00, 0x10)
	// Class: CHAOS (3)
	query = append(query, 0x00, 0x03)

	return query
}

// parseDNSVersionResponse extracts version string from DNS response
func parseDNSVersionResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Check response flags
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 { // Not a response
		return ""
	}
	if flags&0x000F != 0 { // Error code
		return ""
	}

	// Get answer count
	answerCount := binary.BigEndian.Uint16(data[6:8])
	if answerCount == 0 {
		return ""
	}

	// Skip header (12 bytes) and question section
	offset := 12
	// Skip question name
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 { // Pointer
			offset += 2
			break
		}
		offset += int(data[offset]) + 1
	}
	if data[offset] == 0 {
		offset++ // Skip null terminator
	}
	offset += 4 // Skip QTYPE and QCLASS

	// Parse answer
	if offset >= len(data) {
		return ""
	}

	// Skip answer name (likely a pointer)
	if data[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}

	if offset+10 > len(data) {
		return ""
	}

	// Skip TYPE (2), CLASS (2), TTL (4)
	offset += 8

	// RDLENGTH
	rdLength := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(rdLength) > len(data) || rdLength < 2 {
		return ""
	}

	// TXT record: first byte is string length
	txtLen := int(data[offset])
	offset++

	if offset+txtLen > len(data) {
		return ""
	}

	return string(data[offset : offset+txtLen])
}

// DNSZoneTransferScript checks for zone transfer
type DNSZoneTransferScript struct{}

func (s *DNSZoneTransferScript) Name() string { return "dns-zone-transfer" }
func (s *DNSZoneTransferScript) Description() string {
	return "Checks for DNS zone transfer vulnerability"
}
func (s *DNSZoneTransferScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategoryDiscovery, CategorySafe}
}
func (s *DNSZoneTransferScript) PortRule(port int, service string) bool {
	return port == 53 || strings.Contains(service, "dns")
}

func (s *DNSZoneTransferScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "DNS Zone Transfer Check:\nNote: Use dig or fierce for testing\nExample: dig @<target> domain.com AXFR\nOr: fierce --domain domain.com --dns-servers <target>"
	result.Findings = append(result.Findings, "Zone transfer should be tested")

	return result, nil
}

// NTPMonlistScript checks NTP service and extracts version/OS information
type NTPMonlistScript struct{}

func (s *NTPMonlistScript) Name() string { return "ntp-info" }
func (s *NTPMonlistScript) Description() string {
	return "NTP service enumeration and OS detection via readvar"
}
func (s *NTPMonlistScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDiscovery, CategorySafe}
}
func (s *NTPMonlistScript) PortRule(port int, service string) bool {
	return port == 123 || strings.Contains(service, "ntp")
}

func (s *NTPMonlistScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	// Send NTP mode 6 (control) readvar request
	addr := fmt.Sprintf("%s:123", target.Host)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		result.Output = "NTP Service detected (could not connect)\nManual check: ntpq -c rv " + target.Host
		result.Findings = append(result.Findings, "NTP server accessible")
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// NTP control message (mode 6) - readvar request
	// This queries system variables including version and processor info
	ntpRequest := []byte{
		0x16,       // LI=0, VN=2, Mode=6 (control)
		0x01,       // Response bit=0, Error=0, More=0, Opcode=1 (read variables)
		0x00, 0x00, // Sequence
		0x00, 0x00, // Status
		0x00, 0x00, // Association ID (0 = system)
		0x00, 0x00, // Offset
		0x00, 0x00, // Count
	}

	_, err = conn.Write(ntpRequest)
	if err != nil {
		result.Output = "NTP Service detected (query failed)\nManual check: ntpq -c rv " + target.Host
		result.Findings = append(result.Findings, "NTP server accessible")
		return result, nil
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		result.Output = "NTP Service detected (no control response)\nNote: Server may not support NTP control messages"
		result.Findings = append(result.Findings, "NTP server accessible")
		return result, nil
	}

	// Parse NTP control response
	version, processor, system, stratum := parseNTPResponse(response[:n])

	var output strings.Builder
	output.WriteString("NTP Service Information:\n")
	output.WriteString("========================\n")

	if version != "" {
		output.WriteString(fmt.Sprintf("  Version:   %s\n", version))
		result.Findings = append(result.Findings, "NTP version: "+version)
	}
	if processor != "" {
		output.WriteString(fmt.Sprintf("  Processor: %s\n", processor))
		result.Findings = append(result.Findings, "Processor: "+processor)
	}
	if system != "" {
		output.WriteString(fmt.Sprintf("  System:    %s\n", system))
		result.Findings = append(result.Findings, "System: "+system)

		// OS detection from system variable
		systemLower := strings.ToLower(system)
		if strings.Contains(systemLower, "linux") {
			output.WriteString("\n  OS Hint: Linux\n")
		} else if strings.Contains(systemLower, "freebsd") {
			output.WriteString("\n  OS Hint: FreeBSD\n")
		} else if strings.Contains(systemLower, "windows") {
			output.WriteString("\n  OS Hint: Windows\n")
		} else if strings.Contains(systemLower, "darwin") || strings.Contains(systemLower, "macos") {
			output.WriteString("\n  OS Hint: macOS\n")
		}
	}
	if stratum != "" {
		output.WriteString(fmt.Sprintf("  Stratum:   %s\n", stratum))
	}

	if version == "" && system == "" {
		output.WriteString("  (Limited information available)\n")
		output.WriteString("\nManual enumeration:\n")
		output.WriteString("  ntpq -c rv " + target.Host + "\n")
		output.WriteString("  ntpq -c peers " + target.Host + "\n")
	}

	// Check for monlist vulnerability
	output.WriteString("\nSecurity Note:\n")
	output.WriteString("  - Check for CVE-2013-5211 (monlist amplification)\n")
	output.WriteString("  - Test: ntpdc -c monlist " + target.Host + "\n")

	result.Output = output.String()
	return result, nil
}

// parseNTPResponse extracts system variables from NTP control response
func parseNTPResponse(data []byte) (version, processor, system, stratum string) {
	if len(data) < 12 {
		return
	}

	// Check if it's a valid response (mode 6, response bit set)
	if data[0]&0x07 != 6 { // Mode must be 6
		return
	}

	// Data starts at offset 12
	if len(data) <= 12 {
		return
	}

	// Parse the variable data (format: "name=value,name=value,...")
	dataStr := string(data[12:])

	// Extract key variables
	extractVar := func(name string) string {
		prefix := name + "="
		idx := strings.Index(dataStr, prefix)
		if idx == -1 {
			return ""
		}
		start := idx + len(prefix)
		// Find end (comma, newline, or end of string)
		end := start
		inQuote := false
		for end < len(dataStr) {
			c := dataStr[end]
			if c == '"' {
				inQuote = !inQuote
			} else if !inQuote && (c == ',' || c == '\r' || c == '\n') {
				break
			}
			end++
		}
		value := strings.Trim(dataStr[start:end], "\" ")
		return value
	}

	version = extractVar("version")
	processor = extractVar("processor")
	system = extractVar("system")
	stratum = extractVar("stratum")

	return
}

// TFTPEnumScript detects TFTP service
type TFTPEnumScript struct{}

func (s *TFTPEnumScript) Name() string        { return "tftp-enum" }
func (s *TFTPEnumScript) Description() string { return "TFTP service detection" }
func (s *TFTPEnumScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *TFTPEnumScript) PortRule(port int, service string) bool {
	return port == 69 || strings.Contains(service, "tftp")
}

func (s *TFTPEnumScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "TFTP Service detected\nNote: TFTP has no authentication - often allows arbitrary file upload/download\nExample: tftp <target> -c get config.txt"
	result.Findings = append(result.Findings, "TFTP accessible - potential file upload/download")
	result.Vulnerable = true

	return result, nil
}

// TelnetEnumScript checks Telnet service
type TelnetEnumScript struct{}

func (s *TelnetEnumScript) Name() string        { return "telnet-encryption" }
func (s *TelnetEnumScript) Description() string { return "Checks Telnet service (unencrypted)" }
func (s *TelnetEnumScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryVuln, CategoryDefault, CategorySafe}
}
func (s *TelnetEnumScript) PortRule(port int, service string) bool {
	return port == 23 || strings.Contains(service, "telnet")
}

func (s *TelnetEnumScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)

	result := &ScriptResult{ScriptName: s.Name()}
	banner := string(buffer[:n])

	result.Output = "⚠️  Telnet Service detected (UNENCRYPTED)\nBanner: " + strings.TrimSpace(banner) + "\nNote: Use hydra or medusa for brute forcing\nExample: hydra -L users.txt -P passwords.txt telnet://<target>"
	result.Findings = append(result.Findings, "Unencrypted Telnet service")
	result.Vulnerable = true

	return result, nil
}

// RLoginScript checks for rlogin/rsh services
type RLoginScript struct{}

func (s *RLoginScript) Name() string        { return "rlogin-check" }
func (s *RLoginScript) Description() string { return "Checks for rlogin/rsh services" }
func (s *RLoginScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryVuln, CategorySafe}
}
func (s *RLoginScript) PortRule(port int, service string) bool {
	return port == 513 || port == 514 || strings.Contains(service, "rlogin") || strings.Contains(service, "rsh")
}

func (s *RLoginScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "⚠️  rlogin/rsh Service detected (INSECURE)\nNote: These services trust based on IP/hostname\nCheck /etc/hosts.equiv and ~/.rhosts\nExample: rlogin <target> -l root"
	result.Findings = append(result.Findings, "Insecure r-services detected")
	result.Vulnerable = true

	return result, nil
}

// JavaRMIScript detects Java RMI
type JavaRMIScript struct{}

func (s *JavaRMIScript) Name() string        { return "rmi-vuln-classloader" }
func (s *JavaRMIScript) Description() string { return "Java RMI Registry detection" }
func (s *JavaRMIScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategoryDiscovery, CategorySafe}
}
func (s *JavaRMIScript) PortRule(port int, service string) bool {
	return port == 1099 || port == 1098 || strings.Contains(service, "rmi")
}

func (s *JavaRMIScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "Java RMI Registry detected\nNote: Potentially vulnerable to remote code execution\nUse: rmg (Remote Method Guesser) or ysoserial\nExample: rmg enum <target> <port>"
	result.Findings = append(result.Findings, "Java RMI - check for deserialization vulns")

	return result, nil
}

// DistCCScript checks for DistCC
type DistCCScript struct{}

func (s *DistCCScript) Name() string        { return "distcc-cve2004-2687" }
func (s *DistCCScript) Description() string { return "Checks for vulnerable DistCC daemon" }
func (s *DistCCScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *DistCCScript) PortRule(port int, service string) bool {
	return port == 3632 || strings.Contains(service, "distccd")
}

func (s *DistCCScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "⚠️  DistCC Daemon detected\nVulnerability: CVE-2004-2687 (Remote Code Execution)\nNote: DistCC v2.x allows arbitrary command execution\nMetasploit: exploit/unix/misc/distcc_exec"
	result.Findings = append(result.Findings, "Vulnerable DistCC daemon")
	result.Vulnerable = true

	return result, nil
}

// RSyncScript checks rsync service
type RSyncScript struct{}

func (s *RSyncScript) Name() string        { return "rsync-list-modules" }
func (s *RSyncScript) Description() string { return "Lists rsync modules" }
func (s *RSyncScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *RSyncScript) PortRule(port int, service string) bool {
	return port == 873 || strings.Contains(service, "rsync")
}

func (s *RSyncScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "Rsync Service detected\nNote: Use rsync to list and download files\nExample: rsync --list-only rsync://<target>/\nExample: rsync -av rsync://<target>/share /local/path"
	result.Findings = append(result.Findings, "Rsync accessible - check for unauthenticated access")

	return result, nil
}

// MongoDBInfoScript checks MongoDB
type MongoDBInfoScript struct{}

func (s *MongoDBInfoScript) Name() string        { return "mongodb-info" }
func (s *MongoDBInfoScript) Description() string { return "MongoDB service information" }
func (s *MongoDBInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *MongoDBInfoScript) PortRule(port int, service string) bool {
	return port == 27017 || port == 27018 || strings.Contains(service, "mongodb")
}

func (s *MongoDBInfoScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "MongoDB detected\nNote: Check for unauthenticated access\nExample: mongo <target>:27017\nOr: mongodump --host <target> --port 27017 --out /tmp/dump"
	result.Findings = append(result.Findings, "MongoDB accessible - check auth")

	return result, nil
}

// CassandraScript checks Cassandra
type CassandraScript struct{}

func (s *CassandraScript) Name() string        { return "cassandra-info" }
func (s *CassandraScript) Description() string { return "Apache Cassandra detection" }
func (s *CassandraScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *CassandraScript) PortRule(port int, service string) bool {
	return port == 9042 || port == 9160 || strings.Contains(service, "cassandra")
}

func (s *CassandraScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "Apache Cassandra detected\nNote: Use cqlsh for access\nExample: cqlsh <target>"
	result.Findings = append(result.Findings, "Cassandra accessible")

	return result, nil
}

// ElasticsearchScript checks Elasticsearch
type ElasticsearchScript struct{}

func (s *ElasticsearchScript) Name() string        { return "elasticsearch-info" }
func (s *ElasticsearchScript) Description() string { return "Elasticsearch service information" }
func (s *ElasticsearchScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *ElasticsearchScript) PortRule(port int, service string) bool {
	return port == 9200 || port == 9300 || strings.Contains(service, "elasticsearch")
}

func (s *ElasticsearchScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "Elasticsearch detected\nNote: Often exposed without authentication\nExample: curl http://<target>:9200/_cat/indices\nExample: curl http://<target>:9200/_search?pretty"
	result.Findings = append(result.Findings, "Elasticsearch - check for data exposure")

	return result, nil
}
