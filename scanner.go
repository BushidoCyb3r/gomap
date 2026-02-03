package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Scan performs the network scan
func (s *Scanner) Scan() (*ScanResults, error) {
	results := &ScanResults{
		Target:    s.config.Target,
		StartTime: time.Now(),
	}

	// Resolve target hostname to IP
	ips, err := net.LookupIP(s.config.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %v", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for target")
	}

	targetIP := ips[0].String()
	if s.config.Verbose {
		fmt.Printf(ColorCyan+"[*] "+ColorReset+"Resolved "+ColorPurple+"%s"+ColorReset+" to "+ColorTeal+"%s\n"+ColorReset, s.config.Target, targetIP)
	}

	// Check if host is up
	results.HostUp = s.pingHost(targetIP)
	if !results.HostUp {
		if s.config.SkipDown {
			if s.config.Verbose {
				fmt.Println(ColorYellow + "[!] Host appears down, skipping (use without -skip-down to scan anyway)" + ColorReset)
			}
			results.EndTime = time.Now()
			results.Duration = results.EndTime.Sub(results.StartTime)
			return results, nil
		}
		if s.config.Verbose {
			fmt.Println(ColorYellow + "[!] Warning: Host appears down, continuing scan anyway..." + ColorReset)
		}
	}

	// If ping only, return early
	if s.config.PingOnly {
		results.EndTime = time.Now()
		results.Duration = results.EndTime.Sub(results.StartTime)
		return results, nil
	}

	// Parse port range
	ports, err := parsePorts(s.config.Ports)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ports: %v", err)
	}

	if s.config.Verbose {
		fmt.Printf(ColorCyan+"[*] "+ColorReset+"Scanning "+ColorPurple+"%d"+ColorReset+" ports with "+ColorTeal+"%d"+ColorReset+" threads...\n", len(ports), s.config.Threads)
	}

	// Scan ports based on scan type
	var openPorts []PortResult
	switch s.config.ScanType {
	case "tcp":
		openPorts = s.tcpScan(targetIP, ports)
	case "syn":
		fmt.Println("SYN scan requires root privileges, falling back to TCP connect scan")
		openPorts = s.tcpScan(targetIP, ports)
	case "udp":
		openPorts = s.udpScan(targetIP, ports)
	default:
		return nil, fmt.Errorf("unknown scan type: %s", s.config.ScanType)
	}

	results.OpenPorts = openPorts

	// Service detection if enabled
	if s.config.ServiceDetect && len(openPorts) > 0 {
		s.detectServices(targetIP, &results.OpenPorts)
	}

	// Vulnerability checking if enabled (requires service detection)
	if s.config.VulnCheck && len(results.OpenPorts) > 0 {
		s.checkVulnerabilities(&results.OpenPorts)
		results.VulnSummary = ComputeVulnSummary(results.OpenPorts)
	}

	// OS detection if enabled (now with TCP/IP fingerprinting)
	if s.config.OSDetect {
		results.OSDetection = s.performOSDetection(targetIP, results.OpenPorts)
		if results.OSDetection != nil && results.OSDetection.BestMatch != nil {
			results.OS = results.OSDetection.BestMatch.String()
		} else {
			results.OS = s.detectOS(targetIP, results.OpenPorts)
		}
	}

	// Run scripts if enabled
	if s.config.ScriptScan && len(openPorts) > 0 {
		engine := NewScriptEngine(true, s.config.ScriptCategory, s.config.Verbose)
		
		for _, port := range openPorts {
			target := ScriptTarget{
				Host:    targetIP,
				Port:    port.Port,
				Service: port.Service,
				Version: port.Version,
				Banner:  "", // Could be populated from service detection
			}
			
			scriptResults := engine.RunScripts(target)
			results.ScriptResults = append(results.ScriptResults, scriptResults...)
		}
	}

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)

	return results, nil
}

// tcpScan performs a TCP connect scan
func (s *Scanner) tcpScan(target string, ports []int) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a semaphore to limit concurrent connections
	// For high ports, reduce concurrency to avoid ephemeral port exhaustion
	maxThreads := s.config.Threads
	if len(ports) > 0 && ports[len(ports)-1] > 32768 {
		// Scanning high ephemeral ports - use fewer threads
		if maxThreads > 50 {
			maxThreads = 50
		}
	}
	sem := make(chan struct{}, maxThreads)

	// Create progress bar for port scanning
	progressBar := NewProgressBarWithLabel(len(ports), "ports")
	scannedCount := 0

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			address := fmt.Sprintf("%s:%d", target, p)

			// Use custom dialer to disable keepalive and close faster
			dialer := &net.Dialer{
				Timeout:   s.config.Timeout,
				KeepAlive: -1, // Disable keepalive
			}

			conn, err := dialer.Dial("tcp", address)

			if err == nil {
				// Immediately close the connection and set linger to 0
				// This releases the local port faster
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetLinger(0) // RST instead of FIN for faster close
				}
				conn.Close()

				service := getServiceName(p)

				mu.Lock()
				results = append(results, PortResult{
					Port:    p,
					State:   "open",
					Service: service,
				})
				mu.Unlock()

				if s.config.Verbose {
					fmt.Printf("\n"+ColorGreen+"[+] "+ColorReset+"Port "+ColorPurple+"%d"+ColorReset+" is "+ColorGreen+"open"+ColorReset+" (%s)", p, service)
				}
			}

			// Update progress
			mu.Lock()
			scannedCount++
			progressBar.Update(scannedCount)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	progressBar.Finish(false)
	return results
}

// udpScan performs a UDP scan
func (s *Scanner) udpScan(target string, ports []int) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, s.config.Threads)

	// Create progress bar for UDP port scanning
	progressBar := NewProgressBarWithLabel(len(ports), "ports")
	scannedCount := 0

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("udp", address, s.config.Timeout)

			if err == nil {
				// Send a probe packet
				conn.Write([]byte("probe"))

				// Set read deadline
				conn.SetReadDeadline(time.Now().Add(s.config.Timeout))

				buffer := make([]byte, 1024)
				_, err := conn.Read(buffer)
				conn.Close()

				// If we get a response or timeout (not connection refused), port might be open
				if err == nil {
					service := getServiceName(p)
					mu.Lock()
					results = append(results, PortResult{
						Port:    p,
						State:   "open|filtered",
						Service: service,
					})
					mu.Unlock()

					if s.config.Verbose {
						fmt.Printf("\n"+ColorYellow+"[+] "+ColorReset+"UDP Port "+ColorPurple+"%d"+ColorReset+" is "+ColorYellow+"open|filtered"+ColorReset+" (%s)", p, service)
					}
				}
			}

			// Update progress
			mu.Lock()
			scannedCount++
			progressBar.Update(scannedCount)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	progressBar.Finish(false)
	return results
}

// pingHost checks if the host is up using parallel TCP connection attempts
func (s *Scanner) pingHost(target string) bool {
	// Try TCP connection to common ports in parallel for faster detection
	commonPorts := []int{80, 443, 22, 21, 25, 8080, 3389}

	// Use configurable ping timeout, default to 500ms if not set
	timeout := s.config.PingTimeout
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	// Channel to signal host is up (first successful connection wins)
	found := make(chan bool, 1)
	done := make(chan struct{})

	var wg sync.WaitGroup
	var closeOnce sync.Once

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			select {
			case <-done:
				// Another goroutine already found the host is up
				return
			default:
			}

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				conn.Close()
				select {
				case found <- true:
					closeOnce.Do(func() { close(done) }) // Signal other goroutines to stop
				default:
				}
			}
		}(port)
	}

	// Wait for all goroutines in a separate goroutine
	go func() {
		wg.Wait()
		select {
		case found <- false:
		default:
		}
	}()

	return <-found
}

// ScanNetwork performs a scan across all hosts in a CIDR range
func (s *Scanner) ScanNetwork(cidr string) (*NetworkScanResults, error) {
	results := &NetworkScanResults{
		Network:   cidr,
		StartTime: time.Now(),
	}

	// Expand CIDR to list of IPs
	hosts, err := expandCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to expand CIDR: %v", err)
	}

	results.TotalHosts = len(hosts)

	fmt.Printf(ColorCyan+"[*] "+ColorReset+"Scanning network "+ColorPurple+"%s"+ColorReset+" (%d hosts)\n\n", cidr, len(hosts))

	// Use semaphore to limit concurrent host scans
	hostThreads := s.config.HostThreads
	if hostThreads <= 0 {
		hostThreads = 10
	}
	sem := make(chan struct{}, hostThreads)

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create progress bar
	progressBar := NewProgressBar(len(hosts))

	// Track scanned count
	scannedCount := 0

	for _, host := range hosts {
		wg.Add(1)
		go func(targetHost string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			// Create a new scanner config for this host
			hostConfig := &ScanConfig{
				Target:         targetHost,
				Ports:          s.config.Ports,
				Timeout:        s.config.Timeout,
				PingTimeout:    s.config.PingTimeout,
				Threads:        s.config.Threads,
				ScanType:       s.config.ScanType,
				OSDetect:       s.config.OSDetect,
				ServiceDetect:  s.config.ServiceDetect,
				VulnCheck:      s.config.VulnCheck,
				Verbose:        false, // Suppress per-host verbose output for network scans
				PingOnly:       s.config.PingOnly,
				SkipDown:       s.config.SkipDown,
				ScriptScan:     s.config.ScriptScan,
				ScriptCategory: s.config.ScriptCategory,
			}

			hostScanner := NewScanner(hostConfig)
			hostResults, err := hostScanner.Scan()

			mu.Lock()
			scannedCount++
			progressBar.Update(scannedCount)

			if err != nil {
				if s.config.Verbose {
					fmt.Printf("\n"+ColorRed+"[!] "+ColorReset+"Error scanning %s: %v\n", targetHost, err)
				}
				mu.Unlock()
				return
			}

			// Set duration string
			hostResults.DurationStr = hostResults.Duration.String()

			if hostResults.HostUp {
				results.HostsUp++
				results.HostResults = append(results.HostResults, hostResults)
			} else {
				results.HostsDown++
			}
			mu.Unlock()
		}(host)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	progressBar.Finish(false)

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.DurationStr = results.Duration.String()

	return results, nil
}

// checkVulnerabilities checks open ports against the vulnerability database
func (s *Scanner) checkVulnerabilities(ports *[]PortResult) {
	if s.config.Verbose {
		fmt.Println("\n" + ColorCyan + "[*] " + ColorReset + "Checking for known vulnerabilities...")
	}

	for i := range *ports {
		port := &(*ports)[i]

		// Get service and version
		service := port.Service
		version := port.Version

		// Check for vulnerabilities
		vulns := CheckServiceVulnerabilities(service, version, port.Port)

		if len(vulns) > 0 {
			port.Vulnerable = true
			port.Vulnerabilities = vulns

			if s.config.Verbose {
				fmt.Printf(ColorRed+"  [!] "+ColorReset+"Port %d (%s): %d potential vulnerabilities\n",
					port.Port, service, len(vulns))
			}
		}
	}
}

// performOSDetection performs advanced OS detection using multiple methods
func (s *Scanner) performOSDetection(target string, openPorts []PortResult) *OSDetectionResult {
	if s.config.Verbose {
		fmt.Println("\n" + ColorCyan + "[*] " + ColorReset + "Performing advanced OS detection...")
	}

	result := NewOSDetectionResult()

	// Try TCP/IP stack fingerprinting first (requires root)
	if len(openPorts) > 0 {
		// Pick a port for fingerprinting (prefer 80, 443, 22)
		fpPort := openPorts[0].Port
		for _, p := range openPorts {
			if p.Port == 80 || p.Port == 443 || p.Port == 22 {
				fpPort = p.Port
				break
			}
		}

		fp, rawSocketUsed, err := FingerprintWithFallback(target, fpPort, s.config.Timeout)
		if err == nil && fp != nil {
			result.Fingerprint = fp
			result.RawSocketUsed = rawSocketUsed

			if rawSocketUsed {
				result.Methods = append(result.Methods, "tcp")
				// Match against known signatures
				matches := MatchFingerprint(fp)
				for _, m := range matches {
					result.AddMatch(m)
				}

				if s.config.Verbose {
					fmt.Printf(ColorGreen+"  [+] "+ColorReset+"TCP fingerprint: %s\n", fp.String())
				}
			}
		} else if s.config.Verbose && err != nil {
			fmt.Printf(ColorYellow+"  [!] "+ColorReset+"TCP fingerprinting: %v\n", err)
		}
	}

	// Try ICMP fingerprinting (requires root)
	icmpFP, err := ICMPProbe(target, s.config.Timeout)
	if err == nil && icmpFP != nil {
		result.ICMPUsed = true
		result.Methods = append(result.Methods, "icmp")

		icmpMatches := GetICMPOSHints(icmpFP)
		for _, m := range icmpMatches {
			result.AddMatch(m)
		}

		if s.config.Verbose {
			fmt.Printf(ColorGreen+"  [+] "+ColorReset+"ICMP TTL: %d, IP ID pattern: %s\n",
				icmpFP.TTL, icmpFP.IPIDPattern)
		}
	}

	// Try protocol-specific fingerprinting
	protoSuggestions := GetPortsForProtocolFingerprinting(openPorts)

	// SSH fingerprinting
	if sshPort, ok := protoSuggestions["ssh"]; ok {
		pfp, err := SSHFingerprinting(target, sshPort, s.config.Timeout)
		if err == nil && pfp != nil {
			result.Methods = append(result.Methods, "ssh")
			for _, match := range ConvertProtocolFingerprintToOSMatch(pfp) {
				result.AddMatch(match)
			}
			if s.config.Verbose && len(pfp.OSHints) > 0 {
				fmt.Printf(ColorGreen+"  [+] "+ColorReset+"SSH hints: %s\n", pfp.OSHints[0])
			}
		}
	}

	// HTTP fingerprinting
	if httpPort, ok := protoSuggestions["http"]; ok {
		pfp, err := HTTPFingerprinting(target, httpPort, s.config.Timeout)
		if err == nil && pfp != nil {
			result.Methods = append(result.Methods, "http")
			for _, match := range ConvertProtocolFingerprintToOSMatch(pfp) {
				result.AddMatch(match)
			}
		}
	}

	// SMB fingerprinting
	if smbPort, ok := protoSuggestions["smb"]; ok {
		pfp, err := SMBEnhancedFingerprint(target, smbPort, s.config.Timeout)
		if err == nil && pfp != nil {
			result.Methods = append(result.Methods, "smb")
			for _, match := range ConvertProtocolFingerprintToOSMatch(pfp) {
				result.AddMatch(match)
			}
		}
	}

	// Fall back to banner-based detection if no matches yet
	if len(result.Matches) == 0 {
		result.Methods = append(result.Methods, "banner")
		for _, port := range openPorts {
			if match := MatchServiceVersion(port.Version); match != nil {
				result.AddMatch(*match)
			}
		}
	}

	// Select best match
	result.SelectBestMatch()

	return result
}
