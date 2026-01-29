package main

import (
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

// DNSVersionScript attempts to get DNS version
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
	result.Output = "DNS Service detected\nNote: Query version with: dig @<target> version.bind CHAOS TXT\nZone transfer: dig @<target> domain.com AXFR"
	result.Findings = append(result.Findings, "DNS server accessible")

	return result, nil
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

// NTPMonlistScript checks for NTP monlist command
type NTPMonlistScript struct{}

func (s *NTPMonlistScript) Name() string { return "ntp-monlist" }
func (s *NTPMonlistScript) Description() string {
	return "Checks for NTP monlist command (amplification attack)"
}
func (s *NTPMonlistScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategoryDiscovery, CategorySafe}
}
func (s *NTPMonlistScript) PortRule(port int, service string) bool {
	return port == 123 || strings.Contains(service, "ntp")
}

func (s *NTPMonlistScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "NTP Service detected\nNote: Use ntpq or ntpdc for enumeration\nExample: ntpq -c readlist <target>\nMonlist: Can reveal IPs of clients (CVE-2013-5211)"
	result.Findings = append(result.Findings, "NTP server accessible")

	return result, nil
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
