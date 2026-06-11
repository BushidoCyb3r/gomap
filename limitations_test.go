package main

import (
	"strings"
	"testing"
)

// --- OS fingerprint confidence honesty ---

func TestMatchFingerprintRejectsEmpty(t *testing.T) {
	// A connect-scan fingerprint carries no TTL/window/options signal.
	if got := MatchFingerprint(&OSFingerprint{}); len(got) != 0 {
		t.Errorf("expected no matches for empty fingerprint, got %d", len(got))
	}
}

func TestMatchFingerprintRequiresCorroboration(t *testing.T) {
	// TTL alone (64) is shared by Linux/macOS/BSD and must not produce a match.
	fp := &OSFingerprint{TTL: 64}
	if got := MatchFingerprint(fp); len(got) != 0 {
		t.Errorf("single-feature (TTL only) should not match any OS, got %d matches", len(got))
	}
}

func TestMatchFingerprintConfidenceBounds(t *testing.T) {
	// Any reported match must clear the raised confidence threshold.
	fp := &OSFingerprint{
		TTL:           128,
		WindowSize:    65535,
		TCPOptionsStr: "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK",
		DFBit:         true,
	}
	for _, m := range MatchFingerprint(fp) {
		if m.Confidence < 0.6 {
			t.Errorf("match %q reported below threshold: %.2f", m.Name, m.Confidence)
		}
	}
}

func TestOSDetectionIsAmbiguous(t *testing.T) {
	r := NewOSDetectionResult()
	r.AddMatch(OSMatch{Name: "Linux 5.x", Family: "Linux", Confidence: 0.70})
	r.AddMatch(OSMatch{Name: "FreeBSD", Family: "BSD", Confidence: 0.66})
	if !r.IsAmbiguous() {
		t.Error("two near-tied families across different families should be ambiguous")
	}

	r2 := NewOSDetectionResult()
	r2.AddMatch(OSMatch{Name: "Windows 10", Family: "Windows", Confidence: 0.90})
	r2.AddMatch(OSMatch{Name: "Linux", Family: "Linux", Confidence: 0.50})
	if r2.IsAmbiguous() {
		t.Error("a clear leader should not be ambiguous")
	}
}

func TestOSSummaryIsLabelled(t *testing.T) {
	r := NewOSDetectionResult()
	r.AddMatch(OSMatch{Name: "Linux", Family: "Linux", Confidence: 0.65, Method: "tcp"})
	r.SelectBestMatch()
	s := r.OSSummary()
	if !strings.Contains(s, "heuristic") {
		t.Errorf("OS summary should be labelled heuristic, got %q", s)
	}
}

// --- Vulnerability match honesty ---

func TestMatchVulnEntriesVersionVerified(t *testing.T) {
	entries := []ServiceVulnEntry{
		{
			MaxVersion: "7.7",
			Vulns:      []VulnerabilityInfo{{CVE: "CVE-2018-15473", Title: "OpenSSH < 7.7 - User Enumeration", Verified: true}},
		},
	}

	// In range, with an observed version -> verified, no "unconfirmed" tag.
	got := matchVulnEntries(entries, "7.6")
	if len(got) != 1 {
		t.Fatalf("expected 1 match for 7.6, got %d", len(got))
	}
	if !got[0].Verified || strings.Contains(got[0].Title, "unconfirmed") {
		t.Errorf("in-range match should stay verified: %+v", got[0])
	}

	// Above range -> no match (patched).
	if got := matchVulnEntries(entries, "7.8"); len(got) != 0 {
		t.Errorf("7.8 is patched and should not match, got %d", len(got))
	}

	// OpenSSH suffix handling: 7.7p1 is above MaxVersion 7.7 -> no match.
	if got := matchVulnEntries(entries, "7.7p1"); len(got) != 0 {
		t.Errorf("7.7p1 should be above MaxVersion 7.7, got %d matches", len(got))
	}

	// Unknown version against a version-constrained entry -> no match at all.
	if got := matchVulnEntries(entries, ""); len(got) != 0 {
		t.Errorf("version-constrained entry must not match when version is unknown, got %d", len(got))
	}
}

func TestMatchVulnEntriesUnconfirmedLabelling(t *testing.T) {
	entries := []ServiceVulnEntry{
		{
			// No version constraints at all.
			Vulns: []VulnerabilityInfo{{CVE: "CVE-0000-0000", Title: "Generic SMB issue", Verified: true}},
		},
	}
	// With no observed version, a constraint-less entry matches but must be
	// labelled unconfirmed and flipped to Verified=false.
	got := matchVulnEntries(entries, "")
	if len(got) != 1 {
		t.Fatalf("expected 1 broad match, got %d", len(got))
	}
	if got[0].Verified {
		t.Error("constraint-less match without a version must be Verified=false")
	}
	if !strings.Contains(got[0].Title, "unconfirmed") {
		t.Errorf("constraint-less match should be labelled unconfirmed, got %q", got[0].Title)
	}
}

func TestVsftpdBackdoorPattern(t *testing.T) {
	entries := ServiceVulnDB["vsftpd"]
	if got := matchVulnEntries(entries, "2.3.4"); len(got) == 0 {
		t.Error("vsftpd 2.3.4 should match the backdoor entry")
	}
	if got := matchVulnEntries(entries, "2.3.5"); len(got) != 0 {
		t.Errorf("vsftpd 2.3.5 should not match the 2.3.4-only pattern, got %d", len(got))
	}
}

// --- SMBv1 probe packet construction (honest MS17-010 prerequisite check) ---

func TestSMBv1RequestWellFormed(t *testing.T) {
	// Re-derive the request the way probeSMBv1 builds it and assert the NetBIOS
	// length field matches the actual payload length, so the packet is valid.
	req := []byte{
		0x00, 0x00, 0x00, 0x2f,
		0xff, 'S', 'M', 'B',
		0x72,
		0x00, 0x00, 0x00, 0x00,
		0x18,
		0x53, 0xc8,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x2f, 0x4b,
		0x00, 0x00,
		0x00, 0x00,
		0x00,
		0x0c, 0x00,
		0x02,
		'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
	}
	nbLen := int(req[1])<<16 | int(req[2])<<8 | int(req[3])
	if nbLen != len(req)-4 {
		t.Errorf("NetBIOS length %d does not match payload length %d", nbLen, len(req)-4)
	}
	if !(req[4] == 0xff && req[5] == 'S' && req[6] == 'M' && req[7] == 'B') {
		t.Error("SMB protocol id header is malformed")
	}
}
