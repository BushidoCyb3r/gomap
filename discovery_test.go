package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestARPRequestRoundTrip(t *testing.T) {
	srcMAC, _ := net.ParseMAC("de:ad:be:ef:00:01")
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("192.168.1.20")

	req := buildARPRequest(srcMAC, srcIP, dstIP)
	if len(req) != 42 {
		t.Fatalf("ARP request should be 42 bytes, got %d", len(req))
	}
	// EtherType ARP and opcode request.
	if req[12] != 0x08 || req[13] != 0x06 {
		t.Error("EtherType is not ARP (0x0806)")
	}
	if req[21] != 0x01 {
		t.Error("opcode should be request (1)")
	}

	// Forge a reply (opcode 2) from dstIP and confirm we parse it back.
	reply := make([]byte, 42)
	copy(reply[12:14], []byte{0x08, 0x06})
	reply[21] = 0x02 // reply
	replyMAC, _ := net.ParseMAC("ca:fe:00:00:00:02")
	copy(reply[22:28], replyMAC)
	copy(reply[28:32], dstIP.To4())

	ip, mac, ok := parseARPReply(reply)
	if !ok {
		t.Fatal("parseARPReply should accept a valid reply")
	}
	if !ip.Equal(dstIP) {
		t.Errorf("parsed IP = %v, want %v", ip, dstIP)
	}
	if mac.String() != replyMAC.String() {
		t.Errorf("parsed MAC = %v, want %v", mac, replyMAC)
	}

	// A request frame (opcode 1) must not parse as a reply.
	if _, _, ok := parseARPReply(req); ok {
		t.Error("parseARPReply should reject a request frame")
	}
	// Too-short frames are rejected.
	if _, _, ok := parseARPReply(req[:10]); ok {
		t.Error("parseARPReply should reject a short frame")
	}
}

func TestLookupVendor(t *testing.T) {
	mac, _ := net.ParseMAC("00:0c:29:ab:cd:ef") // VMware OUI
	if v := lookupVendor(mac); v != "VMware" {
		t.Errorf("lookupVendor(VMware OUI) = %q, want VMware", v)
	}
	unknown, _ := net.ParseMAC("ff:ff:ff:00:00:00")
	if v := lookupVendor(unknown); v != "" {
		t.Errorf("unknown OUI should return empty, got %q", v)
	}
}

func TestExcludeMatcher(t *testing.T) {
	m, err := NewExcludeMatcher([]string{"192.168.1.5", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Contains("192.168.1.5") {
		t.Error("exact IP should be excluded")
	}
	if !m.Contains("10.0.0.99") {
		t.Error("IP inside excluded CIDR should be excluded")
	}
	if m.Contains("172.16.0.1") {
		t.Error("unrelated IP should not be excluded")
	}
	if m.Empty() {
		t.Error("matcher with entries should not be Empty")
	}

	if _, err := NewExcludeMatcher([]string{"nope"}); err == nil {
		t.Error("invalid spec should error")
	}

	var nilM *ExcludeMatcher
	if !nilM.Empty() || nilM.Contains("1.2.3.4") {
		t.Error("nil matcher should be empty and exclude nothing")
	}
}

func TestFilterExcluded(t *testing.T) {
	hosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	m, _ := NewExcludeMatcher([]string{"10.0.0.2"})
	kept, removed := filterExcluded(hosts, m)
	if removed != 1 || len(kept) != 2 {
		t.Errorf("expected 1 removed/2 kept, got %d removed/%d kept", removed, len(kept))
	}
	for _, h := range kept {
		if h == "10.0.0.2" {
			t.Error("excluded host leaked through filter")
		}
	}
}

func TestReadTargetList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "# comment\n192.168.1.1\n\n10.0.0.0/30  example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readTargetList(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.1", "10.0.0.0/30", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOutputPathFor(t *testing.T) {
	// Single target: unchanged.
	if got := outputPathFor("out.json", "1.2.3.4", false); got != "out.json" {
		t.Errorf("single-target path = %q, want out.json", got)
	}
	// Multiple targets: sanitized target inserted before extension.
	if got := outputPathFor("out.json", "10.0.0.0/24", true); got != "out_10_0_0_0_24.json" {
		t.Errorf("multi-target path = %q, want out_10_0_0_0_24.json", got)
	}
	// No output: stays empty.
	if got := outputPathFor("", "1.2.3.4", true); got != "" {
		t.Errorf("empty output should stay empty, got %q", got)
	}
}

func TestIsTLSPort(t *testing.T) {
	for _, p := range []int{443, 993, 465, 8443} {
		if !isTLSPort(p) {
			t.Errorf("port %d should be a TLS port", p)
		}
	}
	for _, p := range []int{22, 80, 21} {
		if isTLSPort(p) {
			t.Errorf("port %d should not be a TLS port", p)
		}
	}
}
