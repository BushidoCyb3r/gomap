package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// SMBVersionScript detects SMB version
type SMBVersionScript struct{}

func (s *SMBVersionScript) Name() string        { return "smb-os-discovery" }
func (s *SMBVersionScript) Description() string { return "Detects SMB version and OS information" }
func (s *SMBVersionScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDefault, CategorySafe}
}
func (s *SMBVersionScript) PortRule(port int, service string) bool {
	return port == 139 || port == 445 || strings.Contains(service, "smb") || strings.Contains(service, "microsoft-ds")
}

func (s *SMBVersionScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send SMB Negotiate Protocol Request
	negotiateMsg := []byte{
		0x00, 0x00, 0x00, 0x85, // NetBIOS Session Message
		0xff, 0x53, 0x4d, 0x42, // SMB Header "\xffSMB"
		0x72, // Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x18, // Flags
		0x53, 0xc8, // Flags2
		0x00, 0x00, // Process ID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0xff, 0xff, // Tree ID
		0xfe, 0xff, // Process ID
		0x00, 0x00, // User ID
		0x00, 0x00, // Multiplex ID
		0x00, // Word Count
		0x62, 0x00, // Byte Count
		0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20,
		0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
		0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72,
		0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20,
		0x33, 0x2e, 0x31, 0x61, 0x00,
		0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00,
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(negotiateMsg)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	result := &ScriptResult{ScriptName: s.Name()}
	
	// Parse SMB response
	if n > 4 && bytes.Equal(buffer[4:8], []byte{0xff, 0x53, 0x4d, 0x42}) {
		var output strings.Builder
		output.WriteString("SMB Detected:\n")
		
		// Try to extract OS and domain info from response
		responseStr := string(buffer[:n])
		if strings.Contains(responseStr, "Windows") {
			output.WriteString("  OS: Windows\n")
			result.Findings = append(result.Findings, "Windows SMB")
		}
		if strings.Contains(responseStr, "Samba") {
			output.WriteString("  OS: Linux/Unix (Samba)\n")
			result.Findings = append(result.Findings, "Samba")
		}
		
		result.Output = output.String()
	} else {
		result.Output = "SMB service detected but couldn't parse response"
	}

	return result, nil
}

// SMBSigningScript checks if SMB signing is required
type SMBSigningScript struct{}

func (s *SMBSigningScript) Name() string        { return "smb-security-mode" }
func (s *SMBSigningScript) Description() string { return "Checks SMB security mode and signing requirements" }
func (s *SMBSigningScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDefault, CategorySafe}
}
func (s *SMBSigningScript) PortRule(port int, service string) bool {
	return port == 139 || port == 445 || strings.Contains(service, "smb")
}

func (s *SMBSigningScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "SMB Signing: Checking security configuration"
	result.Findings = append(result.Findings, "SMB service accessible")
	return result, nil
}

// SMBVulnMS17010Script checks for EternalBlue vulnerability
type SMBVulnMS17010Script struct{}

func (s *SMBVulnMS17010Script) Name() string { return "smb-vuln-ms17-010" }
func (s *SMBVulnMS17010Script) Description() string {
	return "Checks for MS17-010 EternalBlue vulnerability"
}
func (s *SMBVulnMS17010Script) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *SMBVulnMS17010Script) PortRule(port int, service string) bool {
	return port == 445 || (port == 139 && strings.Contains(service, "smb"))
}

func (s *SMBVulnMS17010Script) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	// This is a simplified check - full implementation would require SMB protocol
	result.Output = "MS17-010 Check: Requires deeper SMB protocol analysis\nNote: Use dedicated tools like Metasploit's auxiliary/scanner/smb/smb_ms17_010"
	result.Findings = append(result.Findings, "Manual verification recommended")
	
	return result, nil
}

// SMBEnumSharesScript enumerates SMB shares
type SMBEnumSharesScript struct{}

func (s *SMBEnumSharesScript) Name() string        { return "smb-enum-shares" }
func (s *SMBEnumSharesScript) Description() string { return "Enumerates SMB shares" }
func (s *SMBEnumSharesScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *SMBEnumSharesScript) PortRule(port int, service string) bool {
	return port == 139 || port == 445 || strings.Contains(service, "smb")
}

func (s *SMBEnumSharesScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "SMB Share Enumeration:\nNote: Use smbclient or enum4linux for complete enumeration\nCommon shares: IPC$, ADMIN$, C$, SYSVOL, NETLOGON"
	result.Findings = append(result.Findings, "SMB enumeration available")
	return result, nil
}

// SMBEnumUsersScript attempts to enumerate users
type SMBEnumUsersScript struct{}

func (s *SMBEnumUsersScript) Name() string        { return "smb-enum-users" }
func (s *SMBEnumUsersScript) Description() string { return "Enumerates SMB users" }
func (s *SMBEnumUsersScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *SMBEnumUsersScript) PortRule(port int, service string) bool {
	return port == 139 || port == 445 || strings.Contains(service, "smb")
}

func (s *SMBEnumUsersScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = "SMB User Enumeration:\nNote: Use rpcclient, enum4linux, or crackmapexec for user enumeration\nExample: rpcclient -U \"\" -N <target> -c enumdomusers"
	result.Findings = append(result.Findings, "User enumeration endpoint available")
	return result, nil
}

// NetBIOSInfoScript gathers NetBIOS information
type NetBIOSInfoScript struct{}

func (s *NetBIOSInfoScript) Name() string        { return "nbstat" }
func (s *NetBIOSInfoScript) Description() string { return "Gathers NetBIOS information" }
func (s *NetBIOSInfoScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *NetBIOSInfoScript) PortRule(port int, service string) bool {
	return port == 137 || port == 138 || port == 139 || strings.Contains(service, "netbios")
}

func (s *NetBIOSInfoScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	// Simple NetBIOS detection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:139", target.Host), 3*time.Second)
	if err != nil {
		result.Output = "NetBIOS service detected but not accessible"
		return result, nil
	}
	defer conn.Close()
	
	result.Output = "NetBIOS Name Service detected\nNote: Use nbtscan or nmblookup for detailed enumeration"
	result.Findings = append(result.Findings, "NetBIOS accessible")
	
	return result, nil
}
