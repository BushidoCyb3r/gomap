package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// isHTTPService checks if a port is running an HTTP/web service
func isHTTPService(port int, service string) bool {
	// Common HTTP ports
	commonHTTPPorts := []int{80, 443, 8000, 8008, 8080, 8081, 8180, 8181, 8443, 8888, 9000, 9090}
	for _, p := range commonHTTPPorts {
		if port == p {
			return true
		}
	}
	
	// Check service name for HTTP indicators
	serviceLower := strings.ToLower(service)
	return strings.Contains(serviceLower, "http") || 
	       strings.Contains(serviceLower, "web") ||
	       strings.Contains(serviceLower, "www") ||
	       strings.Contains(serviceLower, "apache") ||
	       strings.Contains(serviceLower, "nginx") ||
	       strings.Contains(serviceLower, "iis")
}

// HTTPAuthScript detects HTTP authentication methods
type HTTPAuthScript struct{}

func (s *HTTPAuthScript) Name() string        { return "http-auth" }
func (s *HTTPAuthScript) Description() string { return "Detects HTTP authentication methods" }
func (s *HTTPAuthScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryAuth, CategoryDefault, CategorySafe}
}
func (s *HTTPAuthScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPAuthScript) Execute(target ScriptTarget) (*ScriptResult, error) {
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
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	result := &ScriptResult{ScriptName: s.Name()}
	
	if resp.StatusCode == 401 {
		authHeader := resp.Header.Get("WWW-Authenticate")
		if authHeader != "" {
			result.Output = fmt.Sprintf("HTTP authentication detected: %s", authHeader)
			result.Findings = append(result.Findings, authHeader)
		}
	} else {
		result.Output = "No HTTP authentication detected"
	}
	
	return result, nil
}

// HTTPHeadersScript captures and analyzes HTTP headers
type HTTPHeadersScript struct{}

func (s *HTTPHeadersScript) Name() string        { return "http-headers" }
func (s *HTTPHeadersScript) Description() string { return "Captures HTTP response headers" }
func (s *HTTPHeadersScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *HTTPHeadersScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPHeadersScript) Execute(target ScriptTarget) (*ScriptResult, error) {
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
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	result := &ScriptResult{ScriptName: s.Name()}
	
	var output strings.Builder
	output.WriteString("HTTP Headers:\n")
	
	for key, values := range resp.Header {
		for _, value := range values {
			output.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
			result.Findings = append(result.Findings, fmt.Sprintf("%s: %s", key, value))
		}
	}
	
	result.Output = output.String()
	return result, nil
}

// HTTPTitleScript extracts the HTML title
type HTTPTitleScript struct{}

func (s *HTTPTitleScript) Name() string        { return "http-title" }
func (s *HTTPTitleScript) Description() string { return "Extracts HTML title from web pages" }
func (s *HTTPTitleScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryDiscovery, CategoryDefault, CategorySafe}
}
func (s *HTTPTitleScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPTitleScript) Execute(target ScriptTarget) (*ScriptResult, error) {
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
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	result := &ScriptResult{ScriptName: s.Name()}
	
	// Extract title
	bodyStr := string(body)
	titleStart := strings.Index(strings.ToLower(bodyStr), "<title>")
	titleEnd := strings.Index(strings.ToLower(bodyStr), "</title>")
	
	if titleStart != -1 && titleEnd != -1 && titleEnd > titleStart {
		title := bodyStr[titleStart+7 : titleEnd]
		title = strings.TrimSpace(title)
		result.Output = fmt.Sprintf("Title: %s", title)
		result.Findings = append(result.Findings, title)
	} else {
		result.Output = "No title found"
	}
	
	return result, nil
}

// HTTPVulnScript checks for common HTTP vulnerabilities
type HTTPVulnScript struct{}

func (s *HTTPVulnScript) Name() string        { return "http-vuln-check" }
func (s *HTTPVulnScript) Description() string { return "Checks for common HTTP vulnerabilities" }
func (s *HTTPVulnScript) Categories() []ScriptCategory {
	return []ScriptCategory{CategoryVuln, CategorySafe}
}
func (s *HTTPVulnScript) PortRule(port int, service string) bool {
	return isHTTPService(port, service)
}

func (s *HTTPVulnScript) Execute(target ScriptTarget) (*ScriptResult, error) {
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
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	result := &ScriptResult{ScriptName: s.Name()}
	var findings []string
	
	// Check for missing security headers
	if resp.Header.Get("X-Frame-Options") == "" {
		findings = append(findings, "Missing X-Frame-Options header (Clickjacking risk)")
	}
	if resp.Header.Get("X-Content-Type-Options") == "" {
		findings = append(findings, "Missing X-Content-Type-Options header")
	}
	if resp.Header.Get("Strict-Transport-Security") == "" && (target.Port == 443 || target.Port == 8443) {
		findings = append(findings, "Missing HSTS header")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		findings = append(findings, "Missing Content-Security-Policy header")
	}
	
	// Check for information disclosure
	server := resp.Header.Get("Server")
	if server != "" && (strings.Contains(server, "/") || strings.Contains(server, "(")) {
		findings = append(findings, fmt.Sprintf("Server version disclosed: %s", server))
	}
	
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		findings = append(findings, fmt.Sprintf("Technology disclosed: %s", xPoweredBy))
	}
	
	result.Findings = findings
	result.Vulnerable = len(findings) > 0
	
	if len(findings) > 0 {
		result.Output = fmt.Sprintf("Found %d security issues:\n  - %s", len(findings), strings.Join(findings, "\n  - "))
	} else {
		result.Output = "No common vulnerabilities detected"
	}
	
	return result, nil
}
