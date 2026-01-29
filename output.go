package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// writeOutput writes scan results to a file in the specified format
func writeOutput(results interface{}, filename, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(results, filename)
	case "xml":
		return writeXML(results, filename)
	case "txt":
		return writeTXT(results, filename)
	default:
		return fmt.Errorf("unsupported output format: %s (supported: json, xml, txt)", format)
	}
}

// writeJSON writes results as formatted JSON
func writeJSON(results interface{}, filename string) error {
	// Prepare results for JSON output
	prepareForOutput(results)

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	return nil
}

// XMLScanResults wraps ScanResults for proper XML output
type XMLScanResults struct {
	XMLName xml.Name `xml:"scan_results"`
	*ScanResults
}

// XMLNetworkScanResults wraps NetworkScanResults for proper XML output
type XMLNetworkScanResults struct {
	XMLName xml.Name `xml:"network_scan_results"`
	*NetworkScanResults
}

// writeXML writes results as formatted XML
func writeXML(results interface{}, filename string) error {
	// Prepare results for output
	prepareForOutput(results)

	var data []byte
	var err error

	// Wrap results for proper XML root element
	switch v := results.(type) {
	case *ScanResults:
		wrapped := XMLScanResults{ScanResults: v}
		data, err = xml.MarshalIndent(wrapped, "", "  ")
	case *NetworkScanResults:
		wrapped := XMLNetworkScanResults{NetworkScanResults: v}
		data, err = xml.MarshalIndent(wrapped, "", "  ")
	default:
		data, err = xml.MarshalIndent(results, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal XML: %v", err)
	}

	// Add XML header
	xmlHeader := []byte(xml.Header)
	fullData := append(xmlHeader, data...)

	if err := os.WriteFile(filename, fullData, 0644); err != nil {
		return fmt.Errorf("failed to write XML file: %v", err)
	}

	return nil
}

// writeTXT writes results as human-readable plain text
func writeTXT(results interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create TXT file: %v", err)
	}
	defer file.Close()

	switch v := results.(type) {
	case *ScanResults:
		writeSingleHostTXT(file, v)
	case *NetworkScanResults:
		writeNetworkTXT(file, v)
	default:
		return fmt.Errorf("unknown result type for TXT output")
	}

	return nil
}

// writeSingleHostTXT writes a single host scan result to text
func writeSingleHostTXT(file *os.File, results *ScanResults) {
	fmt.Fprintf(file, "GOMAP SCAN RESULTS\n")
	fmt.Fprintf(file, "==================\n\n")
	fmt.Fprintf(file, "Target:   %s\n", results.Target)
	fmt.Fprintf(file, "Started:  %s\n", results.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Finished: %s\n", results.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Duration: %v\n\n", results.Duration)

	if !results.HostUp {
		fmt.Fprintf(file, "Host Status: DOWN\n")
		return
	}

	fmt.Fprintf(file, "Host Status: UP\n\n")

	if len(results.OpenPorts) == 0 {
		fmt.Fprintf(file, "No open ports found\n")
	} else {
		fmt.Fprintf(file, "Open Ports: %d\n\n", len(results.OpenPorts))
		fmt.Fprintf(file, "%-8s %-12s %-15s %s\n", "PORT", "STATE", "SERVICE", "VERSION")
		fmt.Fprintf(file, "%-8s %-12s %-15s %s\n", "----", "-----", "-------", "-------")

		for _, port := range results.OpenPorts {
			version := port.Version
			if version == "" {
				version = "-"
			}
			fmt.Fprintf(file, "%-8d %-12s %-15s %s\n", port.Port, port.State, port.Service, version)
		}
	}

	if results.OS != "" {
		fmt.Fprintf(file, "\nOS Detection: %s\n", results.OS)
	}

	if len(results.ScriptResults) > 0 {
		fmt.Fprintf(file, "\nScript Results:\n")
		fmt.Fprintf(file, "---------------\n")
		for _, script := range results.ScriptResults {
			fmt.Fprintf(file, "\n[%s]\n", script.ScriptName)
			if script.Error != nil {
				fmt.Fprintf(file, "  Error: %v\n", script.Error)
			} else {
				// Indent output lines
				lines := strings.Split(script.Output, "\n")
				for _, line := range lines {
					if line != "" {
						fmt.Fprintf(file, "  %s\n", line)
					}
				}
				if script.Vulnerable {
					fmt.Fprintf(file, "  [!] VULNERABLE\n")
				}
			}
		}
	}
}

// writeNetworkTXT writes network scan results to text
func writeNetworkTXT(file *os.File, results *NetworkScanResults) {
	fmt.Fprintf(file, "GOMAP NETWORK SCAN RESULTS\n")
	fmt.Fprintf(file, "==========================\n\n")
	fmt.Fprintf(file, "Network:     %s\n", results.Network)
	fmt.Fprintf(file, "Total Hosts: %d\n", results.TotalHosts)
	fmt.Fprintf(file, "Hosts Up:    %d\n", results.HostsUp)
	fmt.Fprintf(file, "Hosts Down:  %d\n", results.HostsDown)
	fmt.Fprintf(file, "Started:     %s\n", results.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Finished:    %s\n", results.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Duration:    %v\n", results.Duration)

	if len(results.HostResults) == 0 {
		fmt.Fprintf(file, "\nNo hosts responded.\n")
		return
	}

	fmt.Fprintf(file, "\n")
	fmt.Fprintf(file, "================================================================================\n")
	fmt.Fprintf(file, "HOST DETAILS\n")
	fmt.Fprintf(file, "================================================================================\n")

	for _, host := range results.HostResults {
		fmt.Fprintf(file, "\n--- %s ---\n", host.Target)

		if len(host.OpenPorts) == 0 {
			fmt.Fprintf(file, "No open ports found\n")
		} else {
			fmt.Fprintf(file, "%-8s %-12s %-15s %s\n", "PORT", "STATE", "SERVICE", "VERSION")
			for _, port := range host.OpenPorts {
				version := port.Version
				if version == "" {
					version = "-"
				}
				fmt.Fprintf(file, "%-8d %-12s %-15s %s\n", port.Port, port.State, port.Service, version)
			}
		}

		if host.OS != "" {
			fmt.Fprintf(file, "OS: %s\n", host.OS)
		}
	}

	fmt.Fprintf(file, "\n================================================================================\n")
}

// prepareForOutput prepares results for output by populating string fields
func prepareForOutput(results interface{}) {
	switch v := results.(type) {
	case *ScanResults:
		v.DurationStr = v.Duration.String()
		// Convert script errors to strings
		for i := range v.ScriptResults {
			if v.ScriptResults[i].Error != nil {
				v.ScriptResults[i].ErrorStr = v.ScriptResults[i].Error.Error()
			}
		}
	case *NetworkScanResults:
		v.DurationStr = v.Duration.String()
		for _, host := range v.HostResults {
			host.DurationStr = host.Duration.String()
			for i := range host.ScriptResults {
				if host.ScriptResults[i].Error != nil {
					host.ScriptResults[i].ErrorStr = host.ScriptResults[i].Error.Error()
				}
			}
		}
	}
}
