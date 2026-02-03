package main

import (
	"regexp"
	"strings"
)

// OSSignature defines a known OS fingerprint pattern
type OSSignature struct {
	Name        string
	Family      string
	TTLMin      int
	TTLMax      int
	WindowSizes []int
	TCPOptions  string // Canonical options order like "MSS,NOP,WS,SACK,TS"
	DFBit       *bool  // nil means don't care
	MSS         int    // 0 means don't care
}

// boolPtr is a helper to create *bool for DFBit
func boolPtr(b bool) *bool {
	return &b
}

// KnownOSSignatures contains fingerprints for common operating systems
var KnownOSSignatures = []OSSignature{
	// Windows signatures
	{
		Name:        "Windows 10/11",
		Family:      "Windows",
		TTLMin:      127,
		TTLMax:      128,
		WindowSizes: []int{65535, 64240, 65535},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Windows Server 2016/2019/2022",
		Family:      "Windows",
		TTLMin:      127,
		TTLMax:      128,
		WindowSizes: []int{65535, 8192},
		TCPOptions:  "MSS,NOP,WS,SACK,TS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Windows 7/8/8.1",
		Family:      "Windows",
		TTLMin:      127,
		TTLMax:      128,
		WindowSizes: []int{8192, 65535},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,SACK",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Windows XP/2003",
		Family:      "Windows",
		TTLMin:      127,
		TTLMax:      128,
		WindowSizes: []int{65535, 16384},
		TCPOptions:  "MSS,NOP,NOP,SACK",
		DFBit:       boolPtr(true),
	},

	// Linux signatures
	{
		Name:        "Linux 5.x/6.x (Modern)",
		Family:      "Linux",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{29200, 65535, 65483, 64240},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Linux 4.x",
		Family:      "Linux",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{29200, 5840, 65535},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Linux 3.x",
		Family:      "Linux",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{14600, 5840, 29200},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Linux 2.6.x",
		Family:      "Linux",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{5840, 5792, 16384},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       boolPtr(true),
	},

	// macOS signatures
	{
		Name:        "macOS 12+ (Monterey/Ventura/Sonoma)",
		Family:      "macOS",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{65535, 131072},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,TS,SACK,EOL",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "macOS 10.x/11.x",
		Family:      "macOS",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{65535},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,TS,SACK,EOL",
		DFBit:       boolPtr(true),
	},

	// BSD signatures
	{
		Name:        "FreeBSD 13+",
		Family:      "BSD",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{65535},
		TCPOptions:  "MSS,NOP,WS,SACK,TS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "FreeBSD 11/12",
		Family:      "BSD",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{65535, 65228},
		TCPOptions:  "MSS,NOP,WS,SACK,TS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "OpenBSD 6.x/7.x",
		Family:      "BSD",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{16384},
		TCPOptions:  "MSS,NOP,NOP,SACK,NOP,WS,NOP,NOP,TS",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "NetBSD",
		Family:      "BSD",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{32768, 65535},
		TCPOptions:  "MSS,NOP,WS,SACK,TS",
		DFBit:       boolPtr(true),
	},

	// Network device signatures
	{
		Name:        "Cisco IOS",
		Family:      "Cisco",
		TTLMin:      254,
		TTLMax:      255,
		WindowSizes: []int{4128, 16384},
		TCPOptions:  "MSS",
		DFBit:       nil,
	},
	{
		Name:        "Cisco IOS-XE",
		Family:      "Cisco",
		TTLMin:      254,
		TTLMax:      255,
		WindowSizes: []int{4128, 16384, 65535},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       nil,
	},
	{
		Name:        "Juniper JunOS",
		Family:      "Juniper",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{65535, 16384},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,TS",
		DFBit:       boolPtr(true),
	},

	// Other Unix signatures
	{
		Name:        "Solaris 11",
		Family:      "Solaris",
		TTLMin:      254,
		TTLMax:      255,
		WindowSizes: []int{49640, 32768},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,SACK",
		DFBit:       boolPtr(true),
	},
	{
		Name:        "Solaris 10",
		Family:      "Solaris",
		TTLMin:      254,
		TTLMax:      255,
		WindowSizes: []int{49232, 32850},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,SACK",
		DFBit:       nil,
	},
	{
		Name:        "AIX",
		Family:      "AIX",
		TTLMin:      59,
		TTLMax:      60,
		WindowSizes: []int{16384, 65535},
		TCPOptions:  "MSS,NOP,WS,NOP,NOP,TS,SACK,EOL",
		DFBit:       nil,
	},
	{
		Name:        "HP-UX",
		Family:      "HP-UX",
		TTLMin:      254,
		TTLMax:      255,
		WindowSizes: []int{32768},
		TCPOptions:  "MSS",
		DFBit:       nil,
	},

	// Embedded/IoT
	{
		Name:        "Linux Embedded (BusyBox)",
		Family:      "Linux",
		TTLMin:      63,
		TTLMax:      64,
		WindowSizes: []int{5840, 14600},
		TCPOptions:  "MSS,SACK,TS,NOP,WS",
		DFBit:       nil,
	},
}

// TTLFamilyHints maps initial TTL values to likely OS families
var TTLFamilyHints = map[int][]string{
	255: {"Solaris", "Cisco", "HP-UX"},
	254: {"Solaris", "Cisco", "HP-UX"},
	128: {"Windows"},
	127: {"Windows"},
	64:  {"Linux", "macOS", "BSD", "Juniper"},
	63:  {"Linux", "macOS", "BSD"},
	60:  {"AIX"},
	59:  {"AIX"},
	32:  {"Windows 95/98"},
	30:  {"Windows 95/98"},
}

// MatchFingerprint compares a captured fingerprint against known signatures
func MatchFingerprint(fp *OSFingerprint) []OSMatch {
	if fp == nil {
		return nil
	}

	matches := make([]OSMatch, 0)

	for _, sig := range KnownOSSignatures {
		score := 0.0
		maxScore := 0.0

		// TTL matching (weight: 30%)
		maxScore += 30
		if fp.TTL >= sig.TTLMin && fp.TTL <= sig.TTLMax {
			score += 30
		} else if fp.TTL >= sig.TTLMin-2 && fp.TTL <= sig.TTLMax+2 {
			// Close match (within 2 hops)
			score += 15
		}

		// Window size matching (weight: 25%)
		maxScore += 25
		for _, ws := range sig.WindowSizes {
			if fp.WindowSize == ws {
				score += 25
				break
			} else if fp.WindowSize > 0 && ws > 0 {
				// Partial match if within 10%
				diff := float64(fp.WindowSize-ws) / float64(ws)
				if diff >= -0.1 && diff <= 0.1 {
					score += 10
					break
				}
			}
		}

		// TCP options order matching (weight: 30%)
		maxScore += 30
		if sig.TCPOptions != "" && fp.TCPOptionsStr != "" {
			if fp.TCPOptionsStr == sig.TCPOptions {
				score += 30
			} else if strings.Contains(fp.TCPOptionsStr, "MSS") && strings.Contains(sig.TCPOptions, "MSS") {
				// Partial match - check how many options match in order
				fpOpts := strings.Split(fp.TCPOptionsStr, ",")
				sigOpts := strings.Split(sig.TCPOptions, ",")
				matchCount := 0
				for i := 0; i < len(fpOpts) && i < len(sigOpts); i++ {
					if fpOpts[i] == sigOpts[i] {
						matchCount++
					}
				}
				score += float64(matchCount) * 30 / float64(len(sigOpts))
			}
		}

		// DF bit matching (weight: 15%)
		if sig.DFBit != nil {
			maxScore += 15
			if *sig.DFBit == fp.DFBit {
				score += 15
			}
		}

		// Calculate confidence
		confidence := score / maxScore

		// Only include if confidence > 50%
		if confidence > 0.5 {
			matches = append(matches, OSMatch{
				Name:       sig.Name,
				Family:     sig.Family,
				Confidence: confidence,
				Method:     "tcp",
			})
		}
	}

	// Sort by confidence (highest first)
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].Confidence > matches[i].Confidence {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	return matches
}

// GuessOSFromTTL provides a quick OS family guess based on TTL value
func GuessOSFromTTL(ttl int) []string {
	// Find the likely original TTL
	originalTTL := 0
	if ttl <= 32 {
		originalTTL = 32
	} else if ttl <= 64 {
		originalTTL = 64
	} else if ttl <= 128 {
		originalTTL = 128
	} else {
		originalTTL = 255
	}

	if families, ok := TTLFamilyHints[originalTTL]; ok {
		return families
	}

	return []string{"Unknown"}
}

// ServiceVersionPatterns maps service banners to OS hints
var ServiceVersionPatterns = []struct {
	Pattern  *regexp.Regexp
	OS       string
	Family   string
	Priority int
}{
	// SSH patterns
	{regexp.MustCompile(`(?i)OpenSSH[_\s]+(\d+\.\d+).*Ubuntu`), "Ubuntu Linux", "Linux", 3},
	{regexp.MustCompile(`(?i)OpenSSH[_\s]+(\d+\.\d+).*Debian`), "Debian Linux", "Linux", 3},
	{regexp.MustCompile(`(?i)OpenSSH[_\s]+(\d+\.\d+).*\+FreeBSD`), "FreeBSD", "BSD", 3},
	{regexp.MustCompile(`(?i)OpenSSH[_\s]+for_Windows`), "Windows Server", "Windows", 3},
	{regexp.MustCompile(`(?i)OpenSSH[_\s]+(\d+\.\d+)`), "Linux/Unix", "Linux", 1},

	// HTTP Server patterns
	{regexp.MustCompile(`(?i)Microsoft-IIS/(\d+\.\d+)`), "Windows Server", "Windows", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(Ubuntu\)`), "Ubuntu Linux", "Linux", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(Debian\)`), "Debian Linux", "Linux", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(CentOS\)`), "CentOS Linux", "Linux", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(Red Hat\)`), "RHEL", "Linux", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(Win\d+\)`), "Windows", "Windows", 3},
	{regexp.MustCompile(`(?i)Apache/[\d.]+\s+\(FreeBSD\)`), "FreeBSD", "BSD", 3},
	{regexp.MustCompile(`(?i)nginx`), "Linux/Unix", "Linux", 1},

	// FTP patterns
	{regexp.MustCompile(`(?i)Microsoft FTP Service`), "Windows Server", "Windows", 3},
	{regexp.MustCompile(`(?i)vsFTPd\s+(\d+\.\d+)`), "Linux", "Linux", 2},
	{regexp.MustCompile(`(?i)ProFTPD`), "Linux/Unix", "Linux", 1},
	{regexp.MustCompile(`(?i)Pure-FTPd`), "Linux/Unix", "Linux", 1},

	// SMB patterns
	{regexp.MustCompile(`(?i)Windows\s+Server\s+(\d{4})`), "Windows Server", "Windows", 3},
	{regexp.MustCompile(`(?i)Windows\s+(\d+)`), "Windows", "Windows", 2},
	{regexp.MustCompile(`(?i)Samba\s+(\d+\.\d+)`), "Linux/Unix (Samba)", "Linux", 2},

	// RDP patterns
	{regexp.MustCompile(`(?i)Microsoft Terminal`), "Windows", "Windows", 2},
}

// MatchServiceVersion tries to identify OS from service version strings
func MatchServiceVersion(version string) *OSMatch {
	if version == "" {
		return nil
	}

	var bestMatch *OSMatch
	bestPriority := 0

	for _, pattern := range ServiceVersionPatterns {
		if pattern.Pattern.MatchString(version) {
			if pattern.Priority > bestPriority {
				bestPriority = pattern.Priority
				bestMatch = &OSMatch{
					Name:       pattern.OS,
					Family:     pattern.Family,
					Confidence: float64(pattern.Priority) * 0.3, // Max 0.9 for priority 3
					Method:     "banner",
				}
			}
		}
	}

	return bestMatch
}
