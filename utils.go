package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

// ProgressBar represents a terminal progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	mu        sync.Mutex
	cancelled bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total: total,
		width: 40,
	}
}

// Update updates the progress bar with the current count
func (p *ProgressBar) Update(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	p.render()
}

// Increment increments the progress bar by 1
func (p *ProgressBar) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.render()
}

// SetCancelled marks the progress bar as cancelled
func (p *ProgressBar) SetCancelled() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancelled = true
}

// render draws the progress bar
func (p *ProgressBar) render() {
	percent := float64(p.current) / float64(p.total)
	filled := int(percent * float64(p.width))
	if filled > p.width {
		filled = p.width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	status := ""
	if p.cancelled {
		status = ColorYellow + " [STOPPING]" + ColorReset
	}

	fmt.Printf("\r"+ColorCyan+"[*] "+ColorReset+"Progress: "+ColorPurple+"%s"+ColorReset+" %d/%d (%.1f%%)%s    ",
		bar, p.current, p.total, percent*100, status)
}

// Finish completes the progress bar
func (p *ProgressBar) Finish(cancelled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cancelled {
		fmt.Printf("\r"+ColorYellow+"[!] "+ColorReset+"Scan terminated early: "+ColorPurple+"%d/%d"+ColorReset+" hosts scanned                    \n", p.current, p.total)
	} else {
		fmt.Printf("\r"+ColorGreen+"[+] "+ColorReset+"Scan complete: "+ColorPurple+"%d/%d"+ColorReset+" hosts scanned                         \n", p.current, p.total)
	}
}

// ANSI color codes - defined once for the entire project
const (
	ColorReset  = "\033[0m"
	ColorPurple = "\033[95m"
	ColorCyan   = "\033[96m"
	ColorTeal   = "\033[38;5;51m"
	ColorBold   = "\033[1m"
	ColorGreen  = "\033[92m"
	ColorYellow = "\033[93m"
	ColorRed    = "\033[91m"
	ColorBlue   = "\033[94m"
)

// parsePorts parses port specifications like "80,443" or "1-1000"
func parsePorts(portSpec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Check if it's a range
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("start port must be less than end port: %d-%d", start, end)
			}

			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("ports must be between 1 and 65535")
			}

			for i := start; i <= end; i++ {
				if !seen[i] {
					ports = append(ports, i)
					seen[i] = true
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be between 1 and 65535: %d", port)
			}

			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports, nil
}

// getServiceName returns the common service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		67:    "dhcp",
		68:    "dhcp",
		69:    "tftp",
		80:    "http",
		88:    "kerberos",
		110:   "pop3",
		111:   "rpcbind",
		119:   "nntp",
		123:   "ntp",
		135:   "msrpc",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		139:   "netbios-ssn",
		143:   "imap",
		161:   "snmp",
		162:   "snmptrap",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		464:   "kpasswd",
		465:   "smtps",
		514:   "syslog",
		515:   "printer",
		548:   "afp",
		587:   "submission",
		593:   "http-rpc-epmap",
		631:   "ipp",
		636:   "ldaps",
		873:   "rsync",
		989:   "ftps-data",
		990:   "ftps",
		993:   "imaps",
		995:   "pop3s",
		1025:  "msrpc",
		1026:  "msrpc",
		1027:  "msrpc",
		1028:  "msrpc",
		1029:  "msrpc",
		1080:  "socks",
		1099:  "java-rmi",
		1433:  "ms-sql-s",
		1434:  "ms-sql-m",
		1521:  "oracle",
		1723:  "pptp",
		2049:  "nfs",
		2121:  "ccproxy-ftp",
		2181:  "zookeeper",
		3000:  "ppp",
		3268:  "globalcatLDAP",
		3269:  "globalcatLDAPssl",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		3632:  "distccd",
		4369:  "epmd",
		4786:  "cisco-smart-install",
		5000:  "upnp",
		5060:  "sip",
		5357:  "wsdapi",
		5432:  "postgresql",
		5555:  "freeciv",
		5631:  "pcanywhere",
		5666:  "nrpe",
		5672:  "amqp",
		5800:  "vnc-http",
		5900:  "vnc",
		5901:  "vnc-1",
		5902:  "vnc-2",
		5985:  "winrm",
		5986:  "winrm-https",
		6000:  "x11",
		6379:  "redis",
		6660:  "irc",
		6661:  "irc",
		6662:  "irc",
		6663:  "irc",
		6664:  "irc",
		6665:  "irc",
		6666:  "irc",
		6667:  "irc",
		6668:  "irc",
		6669:  "irc",
		7001:  "afs3-callback",
		8000:  "http-alt",
		8008:  "http",
		8009:  "ajp13",
		8080:  "http-proxy",
		8081:  "http-alt",
		8089:  "splunkd",
		8181:  "http-alt",
		8443:  "https-alt",
		8888:  "sun-answerbook",
		9000:  "cslistener",
		9001:  "tor-orport",
		9042:  "cassandra",
		9090:  "zeus-admin",
		9100:  "jetdirect",
		9200:  "elasticsearch",
		9418:  "git",
		10000: "snet-sensor-mgmt",
		10050: "zabbix-agent",
		11211: "memcache",
		27017: "mongod",
		27018: "mongod",
		47001: "winrm",
		49152: "unknown",
		49153: "unknown",
		49154: "unknown",
		49155: "unknown",
		49156: "unknown",
		49157: "unknown",
		50000: "ibm-db2",
	}

	if service, ok := services[port]; ok {
		return service
	}

	return "unknown"
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isCIDR checks if the target string is in CIDR notation (e.g., 192.168.1.0/24)
func isCIDR(target string) bool {
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

// expandCIDR expands a CIDR notation to a list of all host IP addresses
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %v", err)
	}

	var ips []string

	// Get the network size
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	totalHosts := 1 << hostBits

	// For IPv4, skip network address and broadcast for /31 and larger networks
	// /32 is a single host, /31 is point-to-point link (both hosts usable)
	skipFirst := false
	skipLast := false
	if bits == 32 && hostBits >= 2 {
		skipFirst = true // Skip network address
		skipLast = true  // Skip broadcast address
	}

	// Convert IP to uint32 for easy iteration (IPv4 only)
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR notation is supported")
	}

	startIP := binary.BigEndian.Uint32(ip)

	// Ensure we start at the network address
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	startIP = startIP & mask

	for i := 0; i < totalHosts; i++ {
		if skipFirst && i == 0 {
			continue
		}
		if skipLast && i == totalHosts-1 {
			continue
		}

		currentIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(currentIP, startIP+uint32(i))
		ips = append(ips, currentIP.String())
	}

	return ips, nil
}

// getCIDRHostCount returns the number of usable hosts in a CIDR range
func getCIDRHostCount(cidr string) (int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	totalHosts := 1 << hostBits

	// Subtract network and broadcast addresses for /30 and larger
	if hostBits >= 2 {
		return totalHosts - 2, nil
	}
	return totalHosts, nil
}
