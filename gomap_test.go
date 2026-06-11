package main

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{"single", "80", []int{80}, false},
		{"list", "80,443", []int{80, 443}, false},
		{"range", "1-3", []int{1, 2, 3}, false},
		{"mixed", "80,90-92", []int{80, 90, 91, 92}, false},
		{"dedup", "22,22,22", []int{22}, false},
		{"spaces", " 80 , 443 ", []int{80, 443}, false},
		{"min/max bounds", "1,65535", []int{1, 65535}, false},
		{"not a number", "abc", nil, true},
		{"zero port", "0", nil, true},
		{"too large", "70000", nil, true},
		{"reversed range", "5-1", nil, true},
		{"range out of bounds", "1-70000", nil, true},
		{"malformed range", "1-2-3", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePorts(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePorts(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"1.0", "1.0", 0},
		{"2.0", "1.0", 1},
		{"1.0", "2.0", -1},
		{"1.2.3", "1.2", 1},
		{"1.2", "1.2.3", -1},
		// Numeric (not lexical) comparison of components.
		{"10.0", "9.0", 1},
		{"1.10", "1.9", 1},
		// OpenSSH-style patch suffixes: 8.2p1 is newer than 8.2.
		{"8.2p1", "8.2", 1},
		{"8.2", "8.2p1", -1},
		{"7.7", "7.8", -1},
		{"7.7p1", "7.7", 1},
		// Trailing-letter patch levels (e.g. ProFTPD 1.3.3c).
		{"1.3.3c", "1.3.3", 1},
		{"1.3.3", "1.3.3c", -1},
		// Pre-release markers rank below the final release.
		{"1.0-rc1", "1.0", -1},
		{"2.4.49-beta", "2.4.49", -1},
		{"1.0", "1.0-rc1", 1},
	}
	for _, tt := range tests {
		got := CompareVersions(tt.v1, tt.v2)
		if got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
		}
	}
}

func TestSplitNumericPrefix(t *testing.T) {
	tests := []struct {
		in    string
		wantN int
		wantS string
	}{
		{"12", 12, ""},
		{"12p3", 12, "p3"},
		{"3c", 3, "c"},
		{"rc1", 0, "rc1"},
		{"", 0, ""},
		{"007", 7, ""},
	}
	for _, tt := range tests {
		n, s := splitNumericPrefix(tt.in)
		if n != tt.wantN || s != tt.wantS {
			t.Errorf("splitNumericPrefix(%q) = (%d, %q), want (%d, %q)", tt.in, n, s, tt.wantN, tt.wantS)
		}
	}
}

func TestGetServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{6379, "redis"},
		{1, "unknown"},
		{99999, "unknown"},
	}
	for _, tt := range tests {
		if got := getServiceName(tt.port); got != tt.want {
			t.Errorf("getServiceName(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	// /30 has 4 addresses; network and broadcast are skipped.
	got, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("expandCIDR error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expandCIDR(/30) = %v, want %v", got, want)
	}

	// /24 yields 254 usable hosts (256 - network - broadcast).
	got24, err := expandCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("expandCIDR error: %v", err)
	}
	if len(got24) != 254 {
		t.Errorf("expandCIDR(/24) returned %d hosts, want 254", len(got24))
	}
	if got24[0] != "10.0.0.1" || got24[len(got24)-1] != "10.0.0.254" {
		t.Errorf("expandCIDR(/24) bounds = [%s..%s], want [10.0.0.1..10.0.0.254]", got24[0], got24[len(got24)-1])
	}

	if _, err := expandCIDR("not-a-cidr"); err == nil {
		t.Error("expandCIDR(invalid) expected error, got nil")
	}
	if _, err := expandCIDR("2001:db8::/64"); err == nil {
		t.Error("expandCIDR(IPv6) expected error (IPv4-only), got nil")
	}
}

func TestGetCIDRHostCount(t *testing.T) {
	tests := []struct {
		cidr string
		want int
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/31", 2}, // point-to-point: both usable
		{"10.0.0.1/32", 1}, // single host
		{"172.16.0.0/16", 65534},
	}
	for _, tt := range tests {
		got, err := getCIDRHostCount(tt.cidr)
		if err != nil {
			t.Fatalf("getCIDRHostCount(%q) error: %v", tt.cidr, err)
		}
		if got != tt.want {
			t.Errorf("getCIDRHostCount(%q) = %d, want %d", tt.cidr, got, tt.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		service string
		want    string
	}{
		{"http server header", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "http", "nginx/1.18.0"},
		{"ssh banner", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3", "ssh", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"},
		{"ftp banner", "220 ProFTPD 1.3.5 Server ready", "ftp", "220 ProFTPD 1.3.5 Server ready"},
		{"empty banner", "", "", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVersion(tt.banner, tt.service); got != tt.want {
				t.Errorf("parseVersion(%q) = %q, want %q", tt.banner, got, tt.want)
			}
		})
	}
}

func TestScriptEngineRegistration(t *testing.T) {
	engine := NewScriptEngine(true, "", false)
	if len(engine.scripts) == 0 {
		t.Fatal("no scripts registered")
	}
	// Every registered script must have a non-empty name and at least one
	// category, and names must be unique.
	seen := make(map[string]bool)
	for _, s := range engine.scripts {
		name := s.Name()
		if name == "" {
			t.Error("script with empty name registered")
		}
		if seen[name] {
			t.Errorf("duplicate script registered: %q", name)
		}
		seen[name] = true
		if len(s.Categories()) == 0 {
			t.Errorf("script %q has no categories", name)
		}
	}
	// ftp-bounce was defined but historically not registered; guard against
	// regressing that fix.
	if !seen["ftp-bounce"] {
		t.Error("ftp-bounce script is not registered")
	}
}
