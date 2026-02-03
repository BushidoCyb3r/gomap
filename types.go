package main

import (
	"time"
)

// ScanConfig holds the configuration for the scan
type ScanConfig struct {
	Target         string
	Ports          string
	Timeout        time.Duration
	PingTimeout    time.Duration
	Threads        int
	HostThreads    int
	ScanType       string
	OSDetect       bool
	ServiceDetect  bool
	VulnCheck      bool
	Verbose        bool
	PingOnly       bool
	SkipDown       bool
	ScriptScan     bool
	ScriptCategory ScriptCategory
	Output         string
	OutputFormat   string
}

// ScanResults holds the results of a scan
type ScanResults struct {
	Target        string             `json:"target" xml:"target"`
	HostUp        bool               `json:"host_up" xml:"host_up"`
	OpenPorts     []PortResult       `json:"open_ports" xml:"open_ports>port"`
	OS            string             `json:"os,omitempty" xml:"os,omitempty"`
	OSDetection   *OSDetectionResult `json:"os_detection,omitempty" xml:"os_detection,omitempty"`
	VulnSummary   *VulnSummary       `json:"vuln_summary,omitempty" xml:"vuln_summary,omitempty"`
	ScriptResults []ScriptResult     `json:"script_results,omitempty" xml:"script_results>script,omitempty"`
	StartTime     time.Time          `json:"start_time" xml:"start_time"`
	EndTime       time.Time          `json:"end_time" xml:"end_time"`
	Duration      time.Duration      `json:"duration_ns" xml:"duration_ns"`
	DurationStr   string             `json:"duration" xml:"duration"`
}

// PortResult represents a scanned port
type PortResult struct {
	Port            int                 `json:"port" xml:"number,attr"`
	State           string              `json:"state" xml:"state,attr"`
	Service         string              `json:"service" xml:"service,attr"`
	Version         string              `json:"version,omitempty" xml:"version,attr,omitempty"`
	Vulnerable      bool                `json:"vulnerable" xml:"vulnerable,attr"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vuln,omitempty"`
}

// NetworkScanResults holds results for multiple hosts in a subnet scan
type NetworkScanResults struct {
	Network     string         `json:"network" xml:"network"`
	TotalHosts  int            `json:"total_hosts" xml:"total_hosts"`
	HostsUp     int            `json:"hosts_up" xml:"hosts_up"`
	HostsDown   int            `json:"hosts_down" xml:"hosts_down"`
	HostResults []*ScanResults `json:"host_results" xml:"host_results>host"`
	StartTime   time.Time      `json:"start_time" xml:"start_time"`
	EndTime     time.Time      `json:"end_time" xml:"end_time"`
	Duration    time.Duration  `json:"duration_ns" xml:"duration_ns"`
	DurationStr string         `json:"duration" xml:"duration"`
}

// Scanner performs network scans
type Scanner struct {
	config *ScanConfig
}

// NewScanner creates a new scanner with the given configuration
func NewScanner(config *ScanConfig) *Scanner {
	return &Scanner{
		config: config,
	}
}
