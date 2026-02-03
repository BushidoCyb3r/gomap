package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RDPSecurityScript checks RDP security configuration
type RDPSecurityScript struct{}

func (s *RDPSecurityScript) Name() string { return "rdp-enum-encryption" }
func (s *RDPSecurityScript) Description() string {
	return "Checks RDP encryption and security settings"
}
func (s *RDPSecurityScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *RDPSecurityScript) PortRule(port int, service string) bool {
	return port == 3389 || strings.Contains(service, "ms-wbt-server") || strings.Contains(service, "rdp")
}

func (s *RDPSecurityScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "RDP Service detected\nSecurity: Requires RDP protocol handshake for detailed analysis\nNote: Use ncrack, hydra, or crowbar for brute forcing"
	result.Findings = append(result.Findings, "RDP accessible")

	return result, nil
}

// RDPNLAScript checks if Network Level Authentication is enabled
type RDPNLAScript struct{}

func (s *RDPNLAScript) Name() string { return "rdp-nla" }
func (s *RDPNLAScript) Description() string {
	return "Checks if NLA (Network Level Authentication) is required"
}
func (s *RDPNLAScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategorySafe}
}
func (s *RDPNLAScript) PortRule(port int, service string) bool {
	return port == 3389 || strings.Contains(service, "rdp")
}

func (s *RDPNLAScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "RDP NLA Check:\nNote: NLA disabled = easier to exploit\nUse xfreerdp or rdesktop to test connection"
	result.Findings = append(result.Findings, "RDP service active")
	return result, nil
}

// VNCAuthScript checks VNC authentication
type VNCAuthScript struct{}

func (s *VNCAuthScript) Name() string { return "vnc-info" }
func (s *VNCAuthScript) Description() string {
	return "Gathers VNC server information and auth requirements"
}
func (s *VNCAuthScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *VNCAuthScript) PortRule(port int, service string) bool {
	return port == 5900 || port == 5901 || port == 5902 || strings.Contains(service, "vnc")
}

func (s *VNCAuthScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read VNC protocol version
	buffer := make([]byte, 12)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	result := &ScriptResult{ScriptName: s.Name()}

	if n >= 12 && string(buffer[:3]) == "RFB" {
		version := strings.TrimSpace(string(buffer[:12]))
		result.Output = fmt.Sprintf("VNC Server detected:\n  Protocol: %s", version)
		result.Findings = append(result.Findings, version)

		// Send back version
		conn.Write(buffer[:12])
		time.Sleep(100 * time.Millisecond)

		// Read security types
		secBuffer := make([]byte, 256)
		n, err := conn.Read(secBuffer)
		if err == nil && n > 0 {
			result.Output += "\n  Authentication: Required"
			if n == 4 && secBuffer[3] == 1 {
				result.Output += "\n  WARNING: No authentication (security type 1)"
				result.Vulnerable = true
				result.Findings = append(result.Findings, "No authentication required!")
			}
		}
	} else {
		result.Output = "VNC-like service detected"
	}

	return result, nil
}

// MSRPCEndpointScript enumerates MSRPC endpoints
type MSRPCEndpointScript struct{}

func (s *MSRPCEndpointScript) Name() string        { return "msrpc-enum" }
func (s *MSRPCEndpointScript) Description() string { return "Enumerates MSRPC endpoints" }
func (s *MSRPCEndpointScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *MSRPCEndpointScript) PortRule(port int, service string) bool {
	return port == 135 || port == 593 || strings.Contains(service, "msrpc")
}

func (s *MSRPCEndpointScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "MSRPC Endpoint Mapper detected\nNote: Use rpcdump.py or rpcinfo for detailed enumeration\nExample: rpcdump.py <target>"
	result.Findings = append(result.Findings, "MSRPC accessible")

	return result, nil
}

// WinRMScript checks for WinRM service
type WinRMScript struct{}

func (s *WinRMScript) Name() string        { return "winrm-info" }
func (s *WinRMScript) Description() string { return "Detects Windows Remote Management service" }
func (s *WinRMScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *WinRMScript) PortRule(port int, service string) bool {
	return port == 5985 || port == 5986 || strings.Contains(service, "winrm")
}

func (s *WinRMScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	scheme := "http"
	if target.Port == 5986 {
		scheme = "https"
	}

	result.Output = fmt.Sprintf("WinRM Service detected:\n  Protocol: %s\n  Port: %d\n  Note: Use evil-winrm or crackmapexec for exploitation",
		scheme, target.Port)
	result.Findings = append(result.Findings, "WinRM accessible")

	return result, nil
}

// LDAPAnonBindScript checks for anonymous LDAP bind
type LDAPAnonBindScript struct{}

func (s *LDAPAnonBindScript) Name() string        { return "ldap-rootdse" }
func (s *LDAPAnonBindScript) Description() string { return "Checks LDAP RootDSE and anonymous bind" }
func (s *LDAPAnonBindScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *LDAPAnonBindScript) PortRule(port int, service string) bool {
	return port == 389 || port == 636 || port == 3268 || strings.Contains(service, "ldap")
}

func (s *LDAPAnonBindScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "LDAP Service detected\nNote: Use ldapsearch or windapsearch for enumeration\nExample: ldapsearch -x -H ldap://<target> -s base namingcontexts"
	result.Findings = append(result.Findings, "LDAP accessible")

	return result, nil
}

// KerberosEnumScript checks Kerberos service
type KerberosEnumScript struct{}

func (s *KerberosEnumScript) Name() string { return "krb5-enum-users" }
func (s *KerberosEnumScript) Description() string {
	return "Kerberos service detection and user enumeration"
}
func (s *KerberosEnumScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryAuth, CategorySafe}
}
func (s *KerberosEnumScript) PortRule(port int, service string) bool {
	return port == 88 || strings.Contains(service, "kerberos")
}

func (s *KerberosEnumScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "Kerberos Service (KDC) detected\nNote: Use kerbrute for user enumeration\nExample: kerbrute userenum -d domain.local users.txt --dc <target>\nASREPRoast: Look for users without Kerberos pre-auth"
	result.Findings = append(result.Findings, "Kerberos KDC accessible")

	return result, nil
}

// MSQLServerInfoScript enumerates MS SQL Server
type MSQLServerInfoScript struct{}

func (s *MSQLServerInfoScript) Name() string { return "ms-sql-info" }
func (s *MSQLServerInfoScript) Description() string {
	return "Microsoft SQL Server information gathering"
}
func (s *MSQLServerInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *MSQLServerInfoScript) PortRule(port int, service string) bool {
	return port == 1433 || port == 1434 || strings.Contains(service, "ms-sql")
}

func (s *MSQLServerInfoScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "MS SQL Server detected\nNote: Use sqsh, mssqlclient.py, or nmap's ms-sql-* scripts\nDefault creds: sa:(blank) or sa:sa\nExample: mssqlclient.py sa@<target> -windows-auth"
	result.Findings = append(result.Findings, "MS SQL Server accessible")

	return result, nil
}

// SNMPEnumScript enumerates SNMP service and retrieves sysDescr for OS detection
type SNMPEnumScript struct{}

func (s *SNMPEnumScript) Name() string        { return "snmp-sysdescr" }
func (s *SNMPEnumScript) Description() string { return "SNMP sysDescr enumeration for OS detection" }
func (s *SNMPEnumScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *SNMPEnumScript) PortRule(port int, service string) bool {
	return port == 161 || port == 162 || strings.Contains(service, "snmp")
}

func (s *SNMPEnumScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	// Try common community strings
	communities := []string{"public", "private", "community"}

	for _, community := range communities {
		sysDescr, err := snmpGetSysDescr(target.Host, community)
		if err == nil && sysDescr != "" {
			result.Output = fmt.Sprintf("SNMP sysDescr (community: %s):\n%s\n\n", community, sysDescr)
			result.Findings = append(result.Findings, "SNMP community '"+community+"' accessible")
			result.Findings = append(result.Findings, "sysDescr: "+sysDescr)

			// OS detection from sysDescr
			sysDescrLower := strings.ToLower(sysDescr)
			osHint := ""
			switch {
			case strings.Contains(sysDescrLower, "linux"):
				osHint = "Linux"
				if strings.Contains(sysDescrLower, "ubuntu") {
					osHint = "Ubuntu Linux"
				} else if strings.Contains(sysDescrLower, "debian") {
					osHint = "Debian Linux"
				} else if strings.Contains(sysDescrLower, "centos") {
					osHint = "CentOS Linux"
				} else if strings.Contains(sysDescrLower, "red hat") || strings.Contains(sysDescrLower, "rhel") {
					osHint = "RHEL"
				}
			case strings.Contains(sysDescrLower, "windows"):
				osHint = "Windows"
				if strings.Contains(sysDescrLower, "server 2022") {
					osHint = "Windows Server 2022"
				} else if strings.Contains(sysDescrLower, "server 2019") {
					osHint = "Windows Server 2019"
				} else if strings.Contains(sysDescrLower, "server 2016") {
					osHint = "Windows Server 2016"
				}
			case strings.Contains(sysDescrLower, "cisco"):
				osHint = "Cisco IOS"
			case strings.Contains(sysDescrLower, "juniper") || strings.Contains(sysDescrLower, "junos"):
				osHint = "Juniper JunOS"
			case strings.Contains(sysDescrLower, "freebsd"):
				osHint = "FreeBSD"
			case strings.Contains(sysDescrLower, "hp-ux"):
				osHint = "HP-UX"
			case strings.Contains(sysDescrLower, "aix"):
				osHint = "AIX"
			case strings.Contains(sysDescrLower, "solaris") || strings.Contains(sysDescrLower, "sunos"):
				osHint = "Solaris"
			case strings.Contains(sysDescrLower, "vmware"):
				osHint = "VMware ESXi"
			}

			if osHint != "" {
				result.Output += fmt.Sprintf("OS Detection: %s\n", osHint)
				result.Findings = append(result.Findings, "OS detected: "+osHint)
			}

			result.Output += "\nFurther enumeration:\n"
			result.Output += "  snmpwalk -v 2c -c " + community + " " + target.Host + " system\n"
			result.Output += "  snmpwalk -v 2c -c " + community + " " + target.Host + " interfaces\n"
			return result, nil
		}
	}

	// No community string worked
	result.Output = "SNMP Service detected\nNo common community strings worked (public, private, community)\n\n"
	result.Output += "Brute force communities:\n"
	result.Output += "  onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt " + target.Host + "\n"
	result.Output += "  hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt " + target.Host + " snmp\n"
	result.Findings = append(result.Findings, "SNMP accessible (community unknown)")

	return result, nil
}

// snmpGetSysDescr queries SNMP sysDescr OID (1.3.6.1.2.1.1.1.0)
func snmpGetSysDescr(host, community string) (string, error) {
	addr := fmt.Sprintf("%s:161", host)
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build SNMP v2c GET request for sysDescr (1.3.6.1.2.1.1.1.0)
	request := buildSNMPGetRequest(community, []byte{0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00})

	_, err = conn.Write(request)
	if err != nil {
		return "", err
	}

	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}

	return parseSNMPResponse(response[:n])
}

// buildSNMPGetRequest creates an SNMP v2c GET request
func buildSNMPGetRequest(community string, oid []byte) []byte {
	// This is a simplified SNMP GET request builder
	// OID: 1.3.6.1.2.1.1.1.0 = sysDescr

	// VarBind: OID + NULL value
	varBind := []byte{0x30} // SEQUENCE
	oidEncoded := append([]byte{0x06, byte(len(oid))}, oid...)
	nullValue := []byte{0x05, 0x00} // NULL
	varBindContent := append(oidEncoded, nullValue...)
	varBind = append(varBind, byte(len(varBindContent)))
	varBind = append(varBind, varBindContent...)

	// VarBindList: SEQUENCE of VarBind
	varBindList := []byte{0x30}
	varBindList = append(varBindList, byte(len(varBind)))
	varBindList = append(varBindList, varBind...)

	// PDU: GetRequest-PDU (0xA0)
	pdu := []byte{0xA0}
	requestID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01} // INTEGER request-id
	errorStatus := []byte{0x02, 0x01, 0x00}                  // INTEGER 0
	errorIndex := []byte{0x02, 0x01, 0x00}                   // INTEGER 0
	pduContent := append(requestID, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varBindList...)
	pdu = append(pdu, byte(len(pduContent)))
	pdu = append(pdu, pduContent...)

	// Community string
	communityEncoded := []byte{0x04, byte(len(community))}
	communityEncoded = append(communityEncoded, []byte(community)...)

	// Version: SNMPv2c (1)
	version := []byte{0x02, 0x01, 0x01}

	// Message
	messageContent := append(version, communityEncoded...)
	messageContent = append(messageContent, pdu...)

	message := []byte{0x30}
	message = append(message, byte(len(messageContent)))
	message = append(message, messageContent...)

	return message
}

// parseSNMPResponse extracts the string value from SNMP response
func parseSNMPResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("response too short")
	}

	// Very basic ASN.1 BER parsing to find the OCTET STRING value
	// Look for the response value after the OID

	// Find OCTET STRING (0x04) after the OID
	for i := 0; i < len(data)-2; i++ {
		// Look for our OID followed by OCTET STRING
		if data[i] == 0x04 && i > 10 { // OCTET STRING tag
			length := int(data[i+1])
			if length > 127 {
				// Long form length encoding
				numBytes := length & 0x7F
				if numBytes == 1 && i+2 < len(data) {
					length = int(data[i+2])
					i++
				} else if numBytes == 2 && i+3 < len(data) {
					length = int(data[i+2])<<8 | int(data[i+3])
					i += 2
				} else {
					continue
				}
			}
			if i+2+length <= len(data) {
				return string(data[i+2 : i+2+length]), nil
			}
		}
	}

	return "", fmt.Errorf("no string value found")
}
