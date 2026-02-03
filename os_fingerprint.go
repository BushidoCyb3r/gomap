package main

import (
	"fmt"
	"strings"
)

// OSFingerprint holds TCP/IP stack characteristics extracted from packets
type OSFingerprint struct {
	TTL           int      `json:"ttl" xml:"ttl"`
	WindowSize    int      `json:"window_size" xml:"window_size"`
	MSS           int      `json:"mss" xml:"mss"`
	WindowScale   int      `json:"window_scale" xml:"window_scale"`
	TCPOptions    []string `json:"tcp_options" xml:"tcp_options>option"`
	TCPOptionsStr string   `json:"tcp_options_str" xml:"tcp_options_str"`
	DFBit         bool     `json:"df_bit" xml:"df_bit"`
	SACKPermitted bool     `json:"sack_permitted" xml:"sack_permitted"`
	Timestamp     bool     `json:"timestamp" xml:"timestamp"`
	NOP           bool     `json:"nop" xml:"nop"`
	ECN           bool     `json:"ecn" xml:"ecn"`
}

// OSMatch represents a potential OS match with confidence score
type OSMatch struct {
	Name       string  `json:"name" xml:"name"`
	Family     string  `json:"family" xml:"family"`     // Windows, Linux, BSD, macOS, etc.
	Version    string  `json:"version" xml:"version"`   // Specific version if known
	Confidence float64 `json:"confidence" xml:"confidence"` // 0.0 to 1.0
	Method     string  `json:"method" xml:"method"`     // tcp, icmp, smb, ssh, banner, combined
}

// OSDetectionResult holds all OS detection data from various methods
type OSDetectionResult struct {
	Fingerprint   *OSFingerprint `json:"fingerprint,omitempty" xml:"fingerprint,omitempty"`
	Matches       []OSMatch      `json:"matches" xml:"matches>match"`
	BestMatch     *OSMatch       `json:"best_match,omitempty" xml:"best_match,omitempty"`
	RawSocketUsed bool           `json:"raw_socket_used" xml:"raw_socket_used"`
	ICMPUsed      bool           `json:"icmp_used" xml:"icmp_used"`
	Methods       []string       `json:"methods_used" xml:"methods_used>method"`
}

// NewOSFingerprint creates a new empty fingerprint
func NewOSFingerprint() *OSFingerprint {
	return &OSFingerprint{
		TCPOptions: make([]string, 0),
	}
}

// NewOSDetectionResult creates a new detection result
func NewOSDetectionResult() *OSDetectionResult {
	return &OSDetectionResult{
		Matches: make([]OSMatch, 0),
		Methods: make([]string, 0),
	}
}

// AddMatch adds an OS match to the detection result
func (r *OSDetectionResult) AddMatch(match OSMatch) {
	r.Matches = append(r.Matches, match)
}

// SelectBestMatch chooses the best OS match based on confidence and method priority
func (r *OSDetectionResult) SelectBestMatch() {
	if len(r.Matches) == 0 {
		return
	}

	// Priority order for methods (raw socket methods are most reliable)
	methodPriority := map[string]int{
		"tcp":      5,
		"icmp":     4,
		"smb":      3,
		"ssh":      3,
		"http":     2,
		"banner":   1,
		"combined": 5,
	}

	var best *OSMatch
	bestScore := 0.0

	for i := range r.Matches {
		match := &r.Matches[i]
		priority := float64(methodPriority[match.Method])
		score := match.Confidence * (1 + priority/10)

		if score > bestScore {
			bestScore = score
			best = match
		}
	}

	r.BestMatch = best
}

// MergeResults combines multiple OS detection results
func (r *OSDetectionResult) MergeResults(other *OSDetectionResult) {
	if other == nil {
		return
	}

	// Add matches from other result
	r.Matches = append(r.Matches, other.Matches...)

	// Merge methods used
	for _, method := range other.Methods {
		found := false
		for _, existing := range r.Methods {
			if existing == method {
				found = true
				break
			}
		}
		if !found {
			r.Methods = append(r.Methods, method)
		}
	}

	// Use fingerprint if we don't have one
	if r.Fingerprint == nil && other.Fingerprint != nil {
		r.Fingerprint = other.Fingerprint
	}

	// Update flags
	r.RawSocketUsed = r.RawSocketUsed || other.RawSocketUsed
	r.ICMPUsed = r.ICMPUsed || other.ICMPUsed
}

// GetTCPOptionsString returns a canonical string representation of TCP options
func (f *OSFingerprint) GetTCPOptionsString() string {
	if f.TCPOptionsStr != "" {
		return f.TCPOptionsStr
	}
	if len(f.TCPOptions) > 0 {
		return strings.Join(f.TCPOptions, ",")
	}
	return ""
}

// String returns a human-readable summary of the fingerprint
func (f *OSFingerprint) String() string {
	var parts []string

	if f.TTL > 0 {
		parts = append(parts, fmt.Sprintf("TTL=%d", f.TTL))
	}
	if f.WindowSize > 0 {
		parts = append(parts, fmt.Sprintf("Win=%d", f.WindowSize))
	}
	if f.MSS > 0 {
		parts = append(parts, fmt.Sprintf("MSS=%d", f.MSS))
	}
	if f.DFBit {
		parts = append(parts, "DF")
	}
	if opts := f.GetTCPOptionsString(); opts != "" {
		parts = append(parts, fmt.Sprintf("Opts=%s", opts))
	}

	return strings.Join(parts, " ")
}

// String returns a human-readable summary of the OS match
func (m *OSMatch) String() string {
	if m.Version != "" {
		return fmt.Sprintf("%s %s (%.0f%% confidence via %s)",
			m.Name, m.Version, m.Confidence*100, m.Method)
	}
	return fmt.Sprintf("%s (%.0f%% confidence via %s)",
		m.Name, m.Confidence*100, m.Method)
}

// GetOSFamily returns the OS family for classification
func GetOSFamily(osName string) string {
	lower := strings.ToLower(osName)

	switch {
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "ubuntu"):
		return "Linux"
	case strings.Contains(lower, "debian"):
		return "Linux"
	case strings.Contains(lower, "centos"):
		return "Linux"
	case strings.Contains(lower, "rhel"):
		return "Linux"
	case strings.Contains(lower, "fedora"):
		return "Linux"
	case strings.Contains(lower, "macos"), strings.Contains(lower, "mac os"), strings.Contains(lower, "darwin"):
		return "macOS"
	case strings.Contains(lower, "freebsd"):
		return "BSD"
	case strings.Contains(lower, "openbsd"):
		return "BSD"
	case strings.Contains(lower, "netbsd"):
		return "BSD"
	case strings.Contains(lower, "solaris"):
		return "Solaris"
	case strings.Contains(lower, "cisco"):
		return "Cisco"
	case strings.Contains(lower, "juniper"):
		return "Juniper"
	default:
		return "Unknown"
	}
}
