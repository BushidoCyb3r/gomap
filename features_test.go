package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResumeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.state")

	r, err := OpenResumeLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if r.Done("10.0.0.1") {
		t.Error("nothing should be done in a fresh log")
	}
	r.Mark("10.0.0.1")
	r.Mark("10.0.0.2")
	r.Mark("10.0.0.1") // duplicate should be a no-op
	if !r.Done("10.0.0.1") || !r.Done("10.0.0.2") {
		t.Error("marked hosts should be Done")
	}
	if r.CompletedCount() != 2 {
		t.Errorf("CompletedCount = %d, want 2", r.CompletedCount())
	}
	r.Close()

	// Reopening must reload the persisted keys.
	r2, err := OpenResumeLog(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer r2.Close()
	if !r2.Done("10.0.0.1") || !r2.Done("10.0.0.2") {
		t.Error("reopened log should remember completed hosts")
	}
	if r2.CompletedCount() != 2 {
		t.Errorf("reopened CompletedCount = %d, want 2", r2.CompletedCount())
	}

	// The file should contain exactly the two keys.
	data, _ := os.ReadFile(path)
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("resume file has %d lines, want 2", lines)
	}
}

func TestResumeLogNilSafe(t *testing.T) {
	var r *ResumeLog // -resume not set
	if r.Done("x") {
		t.Error("nil ResumeLog.Done should be false")
	}
	if r.CompletedCount() != 0 {
		t.Error("nil ResumeLog.CompletedCount should be 0")
	}
	r.Mark("x") // must not panic
	r.Close()   // must not panic
}

func TestGrepHost(t *testing.T) {
	var b strings.Builder
	r := &ScanResults{
		Target:   "192.168.1.10",
		Hostname: "host.local",
		HostUp:   true,
		OS:       "Linux (heuristic)",
		OpenPorts: []PortResult{
			{Port: 22, State: "open", Service: "ssh", Version: "OpenSSH 8.2"},
			{Port: 80, State: "open", Service: "http"},
		},
	}
	grepHost(&b, r)
	out := b.String()

	if !strings.Contains(out, "Host: 192.168.1.10 (host.local)\tStatus: Up") {
		t.Errorf("missing status line:\n%s", out)
	}
	if !strings.Contains(out, "22/open/ssh//OpenSSH 8.2/") {
		t.Errorf("missing port 22 entry:\n%s", out)
	}
	if !strings.Contains(out, "80/open/http///") {
		t.Errorf("missing port 80 entry:\n%s", out)
	}
	if !strings.Contains(out, "OS: Linux (heuristic)") {
		t.Errorf("missing OS field:\n%s", out)
	}
}

func TestGrepHostDown(t *testing.T) {
	var b strings.Builder
	grepHost(&b, &ScanResults{Target: "10.0.0.9", HostUp: false})
	out := b.String()
	if !strings.Contains(out, "Status: Down") {
		t.Errorf("down host should report Status: Down, got:\n%s", out)
	}
	if strings.Contains(out, "Ports:") {
		t.Errorf("down host with no ports should have no Ports line:\n%s", out)
	}
}
