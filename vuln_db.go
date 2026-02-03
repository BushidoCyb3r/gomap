package main

// VulnerabilityInfo contains CVE and exploit information for a vulnerable service
type VulnerabilityInfo struct {
	CVE         string  `json:"cve" xml:"cve,attr"`
	EDBID       string  `json:"edb_id" xml:"edb_id,attr"`
	Title       string  `json:"title" xml:"title"`
	Severity    string  `json:"severity" xml:"severity,attr"` // critical, high, medium, low
	CVSS        float64 `json:"cvss" xml:"cvss,attr"`
	Metasploit  string  `json:"metasploit,omitempty" xml:"metasploit,omitempty"`
	ExploitPath string  `json:"exploit_path,omitempty" xml:"exploit_path,omitempty"`
	Description string  `json:"description,omitempty" xml:"description,omitempty"`
	Verified    bool    `json:"verified" xml:"verified,attr"`
}

// VulnSummary aggregates vulnerability statistics for a scan
type VulnSummary struct {
	TotalVulns int `json:"total_vulns" xml:"total_vulns"`
	Critical   int `json:"critical" xml:"critical"`
	High       int `json:"high" xml:"high"`
	Medium     int `json:"medium" xml:"medium"`
	Low        int `json:"low" xml:"low"`
}

// VulnEntry maps version patterns to known vulnerabilities for a service
type VulnEntry struct {
	MinVersion     string              `json:"min_version,omitempty"`
	MaxVersion     string              `json:"max_version,omitempty"`
	VersionPattern string              `json:"version_pattern,omitempty"` // regex pattern
	Vulns          []VulnerabilityInfo `json:"vulnerabilities"`
}

// ComputeVulnSummary calculates vulnerability statistics from port results
func ComputeVulnSummary(ports []PortResult) *VulnSummary {
	summary := &VulnSummary{}

	for _, port := range ports {
		if !port.Vulnerable {
			continue
		}
		for _, vuln := range port.Vulnerabilities {
			summary.TotalVulns++
			switch vuln.Severity {
			case "critical":
				summary.Critical++
			case "high":
				summary.High++
			case "medium":
				summary.Medium++
			case "low":
				summary.Low++
			}
		}
	}

	return summary
}

// GetSeverityWeight returns a numeric weight for sorting by severity
func GetSeverityWeight(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
