package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ExcludeMatcher decides whether a target IP should be skipped. It holds both
// exact IPs and CIDR ranges so an operator can carve out e.g. the gateway or a
// fragile host from a wider scan.
type ExcludeMatcher struct {
	nets []*net.IPNet
	ips  map[string]bool
}

// NewExcludeMatcher builds a matcher from a list of IPs and/or CIDR strings.
func NewExcludeMatcher(specs []string) (*ExcludeMatcher, error) {
	m := &ExcludeMatcher{ips: make(map[string]bool)}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if strings.Contains(spec, "/") {
			_, n, err := net.ParseCIDR(spec)
			if err != nil {
				return nil, fmt.Errorf("invalid exclude CIDR %q: %v", spec, err)
			}
			m.nets = append(m.nets, n)
		} else {
			ip := net.ParseIP(spec)
			if ip == nil {
				return nil, fmt.Errorf("invalid exclude IP %q", spec)
			}
			m.ips[ip.String()] = true
		}
	}
	return m, nil
}

// Empty reports whether the matcher would never exclude anything.
func (m *ExcludeMatcher) Empty() bool {
	return m == nil || (len(m.nets) == 0 && len(m.ips) == 0)
}

// Contains reports whether the given IP string is excluded.
func (m *ExcludeMatcher) Contains(ipStr string) bool {
	if m == nil {
		return false
	}
	if m.ips[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// filterExcluded returns hosts with any excluded IPs removed, plus the count removed.
func filterExcluded(hosts []string, m *ExcludeMatcher) ([]string, int) {
	if m.Empty() {
		return hosts, 0
	}
	kept := make([]string, 0, len(hosts))
	removed := 0
	for _, h := range hosts {
		if m.Contains(h) {
			removed++
			continue
		}
		kept = append(kept, h)
	}
	return kept, removed
}

// readTargetList reads targets (hosts or CIDRs), one per line, from a file.
// Blank lines and lines beginning with '#' are ignored. Inline whitespace lets a
// single line hold several targets.
func readTargetList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, strings.Fields(line)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// readExcludeFile reads exclusion specs (IPs or CIDRs) one per line from a file.
func readExcludeFile(path string) ([]string, error) {
	return readTargetList(path) // same format
}
