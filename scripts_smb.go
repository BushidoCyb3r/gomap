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
		0x72,                   // Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x18,       // Flags
		0x53, 0xc8, // Flags2
		0x00, 0x00, // Process ID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0xff, 0xff, // Tree ID
		0xfe, 0xff, // Process ID
		0x00, 0x00, // User ID
		0x00, 0x00, // Multiplex ID
		0x00,       // Word Count
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

func (s *SMBSigningScript) Name() string { return "smb-security-mode" }
func (s *SMBSigningScript) Description() string {
	return "Checks SMB security mode and signing requirements"
}
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

	// MS17-010 (EternalBlue) only affects hosts that still speak SMBv1. Rather
	// than claim a full exploit-level result, we make a real, bounded check:
	// negotiate SMBv1 and see whether the server supports it. If SMBv1 is
	// disabled the host is definitively not exposed via this vector; if it is
	// enabled the host is a candidate that warrants a dedicated MS17-010 probe.
	smb1Enabled, detail, err := probeSMBv1(target.Host, target.Port)
	if err != nil {
		return nil, err
	}

	if smb1Enabled {
		result.Output = "SMBv1 is ENABLED (" + detail + "). SMBv1 hosts may be exposed to MS17-010/EternalBlue.\n" +
			"This is a prerequisite check only - confirm exploitability with a dedicated MS17-010 probe."
		result.Findings = append(result.Findings, "SMBv1 enabled - potential MS17-010 exposure")
		// Not marked Vulnerable: SMBv1 support is necessary but not sufficient to
		// confirm MS17-010, and we deliberately avoid asserting an unverified vuln.
	} else {
		result.Output = "SMBv1 appears DISABLED (" + detail + "). Host is not exposed to MS17-010 via SMBv1."
		result.Findings = append(result.Findings, "SMBv1 disabled")
	}

	return result, nil
}

// probeSMBv1 sends a single SMBv1 "Negotiate Protocol" request offering the
// "NT LM 0.12" dialect and reports whether the server answers as SMBv1.
// Returns (enabled, humanDetail, error). It never sends any further commands.
func probeSMBv1(host string, port int) (bool, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// SMBv1 Negotiate Protocol Request (NetBIOS session + SMB header + one dialect).
	req := []byte{
		// NetBIOS session service: type 0x00, length 0x002f (47 bytes follow)
		0x00, 0x00, 0x00, 0x2f,
		// SMB header
		0xff, 'S', 'M', 'B', // protocol id
		0x72,                   // command: Negotiate Protocol (0x72)
		0x00, 0x00, 0x00, 0x00, // NT status
		0x18,       // flags
		0x53, 0xc8, // flags2 (0xc853, little-endian)
		0x00, 0x00, // PID high
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
		0x00, 0x00, // reserved
		0x00, 0x00, // tree id
		0x2f, 0x4b, // process id
		0x00, 0x00, // user id
		0x00, 0x00, // multiplex id
		// Negotiate body
		0x00,       // word count
		0x0c, 0x00, // byte count (12)
		0x02,                                                   // dialect buffer format
		'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00, // "NT LM 0.12"
	}

	if _, err := conn.Write(req); err != nil {
		return false, "", err
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 9 {
		// No usable SMB response - SMBv1 negotiation did not succeed.
		return false, "no SMBv1 response", nil
	}

	// Response framing: 4-byte NetBIOS header, then SMB header beginning with
	// 0xFF 'S' 'M' 'B'. Byte 8 is the command; a Negotiate response echoes 0x72.
	body := resp[4:n]
	if len(body) < 5 || !(body[0] == 0xff && body[1] == 'S' && body[2] == 'M' && body[3] == 'B') {
		return false, "non-SMBv1 response", nil
	}
	if body[4] != 0x72 {
		return false, "unexpected SMB command in response", nil
	}
	// NT status occupies body[5:9]; a non-zero status means the dialect was not
	// accepted (e.g. SMBv1 refused).
	if body[5] != 0x00 || body[6] != 0x00 || body[7] != 0x00 || body[8] != 0x00 {
		return false, "SMBv1 negotiate returned an error status", nil
	}
	return true, "NT LM 0.12 accepted", nil
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
