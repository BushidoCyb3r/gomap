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
	if !results.HostUp && s.config.Verbose {
		fmt.Println(ColorYellow + "[!] Warning: Host appears down, continuing scan anyway..." + ColorReset)
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

	// OS detection if enabled
	if s.config.OSDetect {
		results.OS = s.detectOS(targetIP, openPorts)
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
					fmt.Printf(ColorGreen+"[+] "+ColorReset+"Port "+ColorPurple+"%d"+ColorReset+" is "+ColorGreen+"open"+ColorReset+" (%s)\n", p, service)
				}
			}
		}(port)
	}

	wg.Wait()
	return results
}

// udpScan performs a UDP scan
func (s *Scanner) udpScan(target string, ports []int) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, s.config.Threads)

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
						fmt.Printf(ColorYellow+"[+] "+ColorReset+"UDP Port "+ColorPurple+"%d"+ColorReset+" is "+ColorYellow+"open|filtered"+ColorReset+" (%s)\n", p, service)
					}
				}
			}
		}(port)
	}

	wg.Wait()
	return results
}

// pingHost checks if the host is up using ICMP or TCP fallback
func (s *Scanner) pingHost(target string) bool {
	// Try TCP connection to common ports as a ping alternative
	commonPorts := []int{80, 443, 22, 21, 25}
	
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	
	return false
}
