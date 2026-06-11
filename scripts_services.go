package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SSHAuthMethodsScript detects SSH authentication methods
type SSHAuthMethodsScript struct{}

func (s *SSHAuthMethodsScript) Name() string        { return "ssh-auth-methods" }
func (s *SSHAuthMethodsScript) Description() string { return "Detects SSH authentication methods" }
func (s *SSHAuthMethodsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDefault, CategorySafe}
}
func (s *SSHAuthMethodsScript) PortRule(port int, service string) bool {
	return port == 22 || strings.Contains(service, "ssh")
}

func (s *SSHAuthMethodsScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	if target.Banner != "" && strings.HasPrefix(target.Banner, "SSH-") {
		result.Output = fmt.Sprintf("SSH Banner: %s", strings.TrimSpace(target.Banner))
		result.Findings = append(result.Findings, target.Banner)

		// Extract SSH version
		if strings.Contains(target.Banner, "OpenSSH") {
			result.Findings = append(result.Findings, "OpenSSH detected")
		}
	} else {
		result.Output = "SSH service detected but no detailed banner available"
	}

	return result, nil
}

// SSHVersionScript extracts SSH version information
type SSHVersionScript struct{}

func (s *SSHVersionScript) Name() string        { return "ssh-version" }
func (s *SSHVersionScript) Description() string { return "Extracts SSH version information" }
func (s *SSHVersionScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVersion, CategoryDefault, CategorySafe}
}
func (s *SSHVersionScript) PortRule(port int, service string) bool {
	return port == 22 || strings.Contains(service, "ssh")
}

func (s *SSHVersionScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = fmt.Sprintf("SSH Version: %s", banner)
	result.Findings = append(result.Findings, banner)

	return result, nil
}

// FTPAnonScript checks for anonymous FTP access
type FTPAnonScript struct{}

func (s *FTPAnonScript) Name() string        { return "ftp-anon" }
func (s *FTPAnonScript) Description() string { return "Checks for anonymous FTP login" }
func (s *FTPAnonScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDefault, CategorySafe}
}
func (s *FTPAnonScript) PortRule(port int, service string) bool {
	return port == 21 || strings.Contains(service, "ftp")
}

func (s *FTPAnonScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	banner := string(buffer[:n])

	// Try anonymous login
	conn.Write([]byte("USER anonymous\r\n"))
	time.Sleep(500 * time.Millisecond)

	n, err = conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := string(buffer[:n])

	result := &ScriptResult{ScriptName: s.Name()}

	if strings.Contains(response, "230") || strings.Contains(response, "331") {
		result.Output = "Anonymous FTP login allowed"
		result.Findings = append(result.Findings, "Anonymous access enabled")
		result.Vulnerable = true
	} else {
		result.Output = "Anonymous FTP login not allowed"
	}

	result.Findings = append(result.Findings, fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)))

	return result, nil
}

// FTPBounceScript checks for FTP bounce vulnerability
type FTPBounceScript struct{}

func (s *FTPBounceScript) Name() string        { return "ftp-bounce" }
func (s *FTPBounceScript) Description() string { return "Checks for FTP bounce vulnerability" }
func (s *FTPBounceScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *FTPBounceScript) PortRule(port int, service string) bool {
	return port == 21 || strings.Contains(service, "ftp")
}

func (s *FTPBounceScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	readResp := func() string {
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		return strings.TrimSpace(string(buf[:n]))
	}

	// Greeting banner
	banner := readResp()
	result.Findings = append(result.Findings, fmt.Sprintf("Banner: %s", banner))

	// The PORT command generally requires an authenticated session; attempt an
	// anonymous login first.
	conn.Write([]byte("USER anonymous\r\n"))
	userResp := readResp()
	conn.Write([]byte("PASS anonymous@example.com\r\n"))
	passResp := readResp()
	loggedIn := strings.Contains(userResp, "230") || strings.Contains(passResp, "230")

	// Direct the data connection at a foreign address (loopback:80 here). We only
	// observe whether the server *accepts* the PORT command; no data-transfer
	// command is ever sent, so no third party is actually contacted. A server
	// that accepts a foreign PORT can be abused to proxy/scan other hosts.
	conn.Write([]byte("PORT 127,0,0,1,0,80\r\n"))
	portResp := readResp()

	switch {
	case strings.HasPrefix(portResp, "2"): // 200 PORT command successful
		result.Output = "Server accepted a foreign PORT command - vulnerable to FTP bounce"
		result.Findings = append(result.Findings, "FTP bounce: foreign PORT accepted ("+portResp+")")
		result.Vulnerable = true
	case strings.HasPrefix(portResp, "5"): // 5xx rejected
		result.Output = "Server rejected the foreign PORT command - not vulnerable to FTP bounce"
	case !loggedIn:
		result.Output = "Anonymous login refused; FTP bounce could not be conclusively tested"
	case portResp == "":
		result.Output = "No response to PORT command; FTP bounce could not be conclusively tested"
	default:
		result.Output = "Inconclusive PORT response: " + portResp
	}

	return result, nil
}

// SMTPCommandsScript enumerates SMTP commands
type SMTPCommandsScript struct{}

func (s *SMTPCommandsScript) Name() string        { return "smtp-commands" }
func (s *SMTPCommandsScript) Description() string { return "Enumerates supported SMTP commands" }
func (s *SMTPCommandsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *SMTPCommandsScript) PortRule(port int, service string) bool {
	return port == 25 || port == 587 || port == 465 || strings.Contains(service, "smtp")
}

func (s *SMTPCommandsScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	// Send EHLO command
	conn.Write([]byte("EHLO test\r\n"))
	time.Sleep(500 * time.Millisecond)

	n, err = conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := string(buffer[:n])

	result := &ScriptResult{ScriptName: s.Name()}
	result.Output = fmt.Sprintf("SMTP Banner: %s\n\nSupported features:\n%s", banner, response)
	result.Findings = append(result.Findings, banner)

	// Parse EHLO response for features
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && len(line) > 4 {
			result.Findings = append(result.Findings, line[4:])
		}
	}

	return result, nil
}
