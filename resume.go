package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// ResumeLog records which targets/hosts have finished scanning so an interrupted
// run can be continued by re-invoking the same command with the same -resume
// file. It is a simple append-only list of completed keys (one per line), loaded
// on open and flushed to disk as each key completes.
type ResumeLog struct {
	mu   sync.Mutex
	f    *os.File
	done map[string]bool
}

// OpenResumeLog opens (creating if needed) a resume file and loads any keys
// already recorded in it.
func OpenResumeLog(path string) (*ResumeLog, error) {
	done := make(map[string]bool)
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				done[line] = true
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &ResumeLog{f: f, done: done}, nil
}

// Done reports whether a key was already completed in a previous run.
func (r *ResumeLog) Done(key string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done[key]
}

// Mark records a key as completed and flushes it to disk immediately so progress
// survives a crash or Ctrl-C.
func (r *ResumeLog) Mark(key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done[key] {
		return
	}
	r.done[key] = true
	fmt.Fprintln(r.f, key)
	_ = r.f.Sync()
}

// CompletedCount returns how many keys were already done when the log was opened
// (and since marked).
func (r *ResumeLog) CompletedCount() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.done)
}

// Close closes the underlying file.
func (r *ResumeLog) Close() {
	if r == nil || r.f == nil {
		return
	}
	_ = r.f.Close()
}
