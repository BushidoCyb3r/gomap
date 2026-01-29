package main

import (
	"time"
)

// ScanConfig holds the configuration for the scan
type ScanConfig struct {
	Target         string
	Ports          string
	Timeout        time.Duration
	Threads        int
	ScanType       string
	OSDetect       bool
	ServiceDetect  bool
	Verbose        bool
	PingOnly       bool
	ScriptScan     bool
	ScriptCategory ScriptCategory
}

// ScanResults holds the results of a scan
type ScanResults struct {
	Target        string
	HostUp        bool
	OpenPorts     []PortResult
	OS            string
	ScriptResults []ScriptResult
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
}

// PortResult represents a scanned port
type PortResult struct {
	Port    int
	State   string
	Service string
	Version string
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
