package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	// Command line flags with shortcuts
	target := flag.String("target", "", "Target IP or hostname to scan")
	flag.StringVar(target, "t", "", "Target IP or hostname to scan (shorthand)")
	
	ports := flag.String("ports", "1-1024", "Port range to scan (e.g., 80,443 or 1-1000 or 'all')")
	flag.StringVar(ports, "p", "1-1024", "Port range to scan (shorthand)")
	
	timeout := flag.Duration("timeout", 1*time.Second, "Timeout for each port")
	threads := flag.Int("threads", 100, "Number of concurrent threads")
	scanType := flag.String("type", "tcp", "Scan type: tcp, syn, udp")
	osDetect := flag.Bool("os", false, "Enable OS detection")
	
	serviceDetect := flag.Bool("service", false, "Enable service version detection")
	flag.BoolVar(serviceDetect, "sV", false, "Enable service version detection (shorthand)")
	
	verbose := flag.Bool("v", false, "Verbose output")
	pingOnly := flag.Bool("ping", false, "Ping scan only (host discovery)")
	skipDown := flag.Bool("skip-down", false, "Skip hosts that appear down (faster scanning)")
	pingTimeout := flag.Duration("ping-timeout", 500*time.Millisecond, "Timeout for host discovery ping")
	scriptScan := flag.Bool("script", false, "Enable script scanning")
	scriptCategory := flag.String("script-category", "", "Run scripts from specific category (auth, vuln, discovery, etc.)")
	listScripts := flag.Bool("script-help", false, "List all available scripts")

	// Output options
	output := flag.String("output", "", "Output file path")
	flag.StringVar(output, "o", "", "Output file path (shorthand)")

	outputFormat := flag.String("output-format", "txt", "Output format: json, xml, txt")
	flag.StringVar(outputFormat, "oF", "txt", "Output format (shorthand)")

	// Network scanning options
	hostThreads := flag.Int("host-threads", 10, "Concurrent hosts to scan for subnet scans")
	flag.IntVar(hostThreads, "hT", 10, "Concurrent hosts to scan (shorthand)")

	flag.Parse()

	// Print banner
	printBanner()

	// List scripts if requested
	if *listScripts {
		engine := NewScriptEngine(true, "", false)
		engine.ListScripts()
		os.Exit(0)
	}

	// Validate target
	if *target == "" {
		fmt.Println(ColorRed + "Error: target is required" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}
	
	// Handle "all" ports option
	if *ports == "all" {
		*ports = "1-65535"
		if *verbose {
			fmt.Printf(ColorCyan+"[*] "+ColorReset+"Scanning all 65535 ports\n")
		}
	}

	// Create scanner configuration
	config := &ScanConfig{
		Target:         *target,
		Ports:          *ports,
		Timeout:        *timeout,
		PingTimeout:    *pingTimeout,
		Threads:        *threads,
		HostThreads:    *hostThreads,
		ScanType:       *scanType,
		OSDetect:       *osDetect,
		ServiceDetect:  *serviceDetect,
		Verbose:        *verbose,
		PingOnly:       *pingOnly,
		SkipDown:       *skipDown,
		ScriptScan:     *scriptScan,
		ScriptCategory: ScriptCategory(*scriptCategory),
		Output:         *output,
		OutputFormat:   *outputFormat,
	}

	// Create scanner
	scanner := NewScanner(config)

	// Check if target is CIDR notation for network scanning
	if isCIDR(*target) {
		// Network scan
		networkResults, err := scanner.ScanNetwork(*target)
		if err != nil {
			fmt.Printf(ColorRed+"Error during network scan: %v\n"+ColorReset, err)
			os.Exit(1)
		}

		// Print results
		printNetworkResults(networkResults, config)

		// Write to file if output specified
		if *output != "" {
			if err := writeOutput(networkResults, *output, *outputFormat); err != nil {
				fmt.Printf(ColorRed+"Error writing output: %v\n"+ColorReset, err)
				os.Exit(1)
			}
			fmt.Printf(ColorGreen+"[+] "+ColorReset+"Results written to "+ColorPurple+"%s"+ColorReset+" (%s)\n", *output, *outputFormat)
		}
	} else {
		// Single host scan
		results, err := scanner.Scan()
		if err != nil {
			fmt.Printf(ColorRed+"Error during scan: %v\n"+ColorReset, err)
			os.Exit(1)
		}

		// Print results
		printResults(results, config)

		// Write to file if output specified
		if *output != "" {
			if err := writeOutput(results, *output, *outputFormat); err != nil {
				fmt.Printf(ColorRed+"Error writing output: %v\n"+ColorReset, err)
				os.Exit(1)
			}
			fmt.Printf(ColorGreen+"[+] "+ColorReset+"Results written to "+ColorPurple+"%s"+ColorReset+" (%s)\n", *output, *outputFormat)
		}
	}
}

func printBanner() {
	banner := ColorPurple + ColorBold + `
   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
  ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
  ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
  ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
` + ColorReset + ColorTeal + `
          Network Scanner & Exploitation Tool
` + ColorReset + ColorPurple + `          ═══════════════════════════════════════
` + ColorReset
	fmt.Println(banner)
}

func printResults(results *ScanResults, config *ScanConfig) {
	fmt.Printf("\n"+ColorCyan+ColorBold+"╔════════════════════════════════════════════════╗\n")
	fmt.Printf("║           SCAN RESULTS                         ║\n")
	fmt.Printf("╚════════════════════════════════════════════════╝\n"+ColorReset)
	
	fmt.Printf(ColorTeal+"Target:   "+ColorReset+ColorBold+"%s\n"+ColorReset, results.Target)
	fmt.Printf(ColorTeal+"Started:  "+ColorReset+"%s\n", results.StartTime.Format("15:04:05"))
	fmt.Printf(ColorTeal+"Finished: "+ColorReset+"%s\n", results.EndTime.Format("15:04:05"))
	fmt.Printf(ColorTeal+"Duration: "+ColorReset+ColorPurple+"%v\n"+ColorReset, results.Duration)

	if !results.HostUp {
		fmt.Println(ColorRed + "\n[!] Host appears to be DOWN" + ColorReset)
		return
	}

	fmt.Println(ColorGreen + "\n[+] Host is UP" + ColorReset)
	
	if config.PingOnly {
		return
	}

	if len(results.OpenPorts) == 0 {
		fmt.Println(ColorYellow + "\n[!] No open ports found" + ColorReset)
		return
	}

	fmt.Printf("\n"+ColorCyan+ColorBold+"Found %d open port(s):\n\n"+ColorReset, len(results.OpenPorts))
	fmt.Printf(ColorPurple+"%-8s %-10s %s\n"+ColorReset, "PORT", "STATE", "SERVICE")
	fmt.Printf(ColorPurple+"%-8s %-10s %s\n"+ColorReset, "────", "─────", "───────")
	
	for _, port := range results.OpenPorts {
		service := port.Service
		if service == "" {
			service = "unknown"
		}
		
		// Color code by port type
		portColor := ColorCyan
		if port.Port == 21 || port.Port == 23 || port.Port == 69 {
			portColor = ColorRed // Insecure services
		} else if port.Port == 80 || port.Port == 443 || port.Port == 8080 {
			portColor = ColorGreen // HTTP services
		} else if port.Port == 139 || port.Port == 445 {
			portColor = ColorYellow // SMB services
		}
		
		fmt.Printf(portColor+"%-8d "+ColorReset+ColorGreen+"%-10s "+ColorReset+ColorTeal+"%s\n"+ColorReset, 
			port.Port, port.State, service)
		
		if config.ServiceDetect && port.Version != "" {
			fmt.Printf(ColorPurple+"         ↳ "+ColorReset+"Version: %s\n", port.Version)
		}
	}

	if config.OSDetect && results.OS != "" {
		fmt.Printf("\n"+ColorCyan+ColorBold+"OS Detection:\n"+ColorReset)
		fmt.Printf(ColorPurple+"  ↳ "+ColorReset+"%s\n", results.OS)
	}

	// Print script results
	if len(results.ScriptResults) > 0 {
		fmt.Printf("\n"+ColorCyan+ColorBold+"╔════════════════════════════════════════════════╗\n")
		fmt.Printf("║           SCRIPT RESULTS                       ║\n")
		fmt.Printf("╚════════════════════════════════════════════════╝\n"+ColorReset)
		
		for _, scriptResult := range results.ScriptResults {
			fmt.Printf("\n"+ColorPurple+ColorBold+"[%s]\n"+ColorReset, scriptResult.ScriptName)
			if scriptResult.Error != nil {
				fmt.Printf(ColorRed+"  ✗ Error: %v\n"+ColorReset, scriptResult.Error)
			} else {
				// Add indentation to output
				lines := splitLines(scriptResult.Output)
				for _, line := range lines {
					fmt.Printf(ColorTeal+"  "+ColorReset+"%s\n", line)
				}
				if scriptResult.Vulnerable {
					fmt.Printf(ColorRed+ColorBold+"  [!] VULNERABLE\n"+ColorReset)
				}
			}
		}
	}
	
	fmt.Printf("\n"+ColorCyan+ColorBold+"════════════════════════════════════════════════\n"+ColorReset)
	fmt.Printf(ColorGreen+"Scan complete!"+ColorReset+"\n")
}

func printNetworkResults(results *NetworkScanResults, config *ScanConfig) {
	fmt.Printf("\n"+ColorCyan+ColorBold+"╔════════════════════════════════════════════════╗\n")
	fmt.Printf("║         NETWORK SCAN RESULTS                   ║\n")
	fmt.Printf("╚════════════════════════════════════════════════╝\n"+ColorReset)

	fmt.Printf(ColorTeal+"Network:    "+ColorReset+ColorBold+"%s\n"+ColorReset, results.Network)
	fmt.Printf(ColorTeal+"Total Hosts:"+ColorReset+" %d\n", results.TotalHosts)
	fmt.Printf(ColorTeal+"Hosts Up:   "+ColorReset+ColorGreen+"%d\n"+ColorReset, results.HostsUp)
	fmt.Printf(ColorTeal+"Hosts Down: "+ColorReset+ColorRed+"%d\n"+ColorReset, results.HostsDown)
	fmt.Printf(ColorTeal+"Started:    "+ColorReset+"%s\n", results.StartTime.Format("15:04:05"))
	fmt.Printf(ColorTeal+"Finished:   "+ColorReset+"%s\n", results.EndTime.Format("15:04:05"))
	fmt.Printf(ColorTeal+"Duration:   "+ColorReset+ColorPurple+"%v\n"+ColorReset, results.Duration)

	if len(results.HostResults) == 0 {
		fmt.Println(ColorYellow + "\n[!] No hosts responded" + ColorReset)
		return
	}

	// Print summary of all hosts with open ports
	fmt.Printf("\n"+ColorCyan+ColorBold+"╔════════════════════════════════════════════════╗\n")
	fmt.Printf("║         DISCOVERED HOSTS                       ║\n")
	fmt.Printf("╚════════════════════════════════════════════════╝\n"+ColorReset)

	for _, host := range results.HostResults {
		if !host.HostUp {
			continue
		}

		fmt.Printf("\n"+ColorPurple+ColorBold+"┌─ %s\n"+ColorReset, host.Target)

		if config.PingOnly {
			fmt.Printf(ColorGreen+"│  Host is UP\n"+ColorReset)
			continue
		}

		if len(host.OpenPorts) == 0 {
			fmt.Printf(ColorYellow+"│  No open ports found\n"+ColorReset)
			continue
		}

		fmt.Printf(ColorCyan+"│  Open ports: %d\n"+ColorReset, len(host.OpenPorts))
		fmt.Printf(ColorPurple+"│  %-8s %-10s %s\n"+ColorReset, "PORT", "STATE", "SERVICE")

		for _, port := range host.OpenPorts {
			service := port.Service
			if service == "" {
				service = "unknown"
			}

			// Color code by port type
			portColor := ColorCyan
			if port.Port == 21 || port.Port == 23 || port.Port == 69 {
				portColor = ColorRed
			} else if port.Port == 80 || port.Port == 443 || port.Port == 8080 {
				portColor = ColorGreen
			} else if port.Port == 139 || port.Port == 445 {
				portColor = ColorYellow
			}

			fmt.Printf("│  "+portColor+"%-8d "+ColorReset+ColorGreen+"%-10s "+ColorReset+ColorTeal+"%s"+ColorReset, port.Port, port.State, service)

			if config.ServiceDetect && port.Version != "" {
				fmt.Printf(" (%s)", port.Version)
			}
			fmt.Println()
		}

		if config.OSDetect && host.OS != "" {
			fmt.Printf(ColorCyan+"│  OS: "+ColorReset+"%s\n", host.OS)
		}
	}

	fmt.Printf("\n"+ColorCyan+ColorBold+"════════════════════════════════════════════════\n"+ColorReset)
	fmt.Printf(ColorGreen+"Network scan complete!"+ColorReset+"\n")
}

func splitLines(s string) []string {
	result := []string{}
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			result = append(result, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
