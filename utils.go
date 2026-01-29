package main

import (
	"fmt"
	"strconv"
	"strings"
)

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
