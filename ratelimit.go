package main

import (
	"context"
	"strings"
	"sync"
	"time"
)

// RateLimiter paces outgoing probes to at most N per second using a simple
// leaky-bucket: each Wait() reserves the next evenly-spaced slot. A nil
// *RateLimiter means "unlimited" so callers can use it unconditionally.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewRateLimiter returns a limiter capping probes to perSecond. A value <= 0
// disables rate limiting (returns nil).
func NewRateLimiter(perSecond int) *RateLimiter {
	if perSecond <= 0 {
		return nil
	}
	return &RateLimiter{interval: time.Second / time.Duration(perSecond)}
}

// Wait blocks until the next probe slot is available, or until ctx is done.
// It returns ctx.Err() if the context was cancelled while waiting.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	wait := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TimingProfile holds the tunables a timing template (-T) sets.
type TimingProfile struct {
	Threads int
	Timeout time.Duration
	Retries int
	MaxRate int // probes/sec, 0 = unlimited
}

// timingProfiles mirrors the familiar T0-T5 ladder: slower and stealthier at the
// low end, faster and louder at the high end.
var timingProfiles = map[int]TimingProfile{
	0: {Threads: 1, Timeout: 5000 * time.Millisecond, Retries: 2, MaxRate: 1},    // paranoid
	1: {Threads: 5, Timeout: 3000 * time.Millisecond, Retries: 2, MaxRate: 10},   // sneaky
	2: {Threads: 20, Timeout: 2000 * time.Millisecond, Retries: 1, MaxRate: 100}, // polite
	3: {Threads: 100, Timeout: 1000 * time.Millisecond, Retries: 1, MaxRate: 0},  // normal
	4: {Threads: 300, Timeout: 800 * time.Millisecond, Retries: 1, MaxRate: 0},   // aggressive
	5: {Threads: 600, Timeout: 500 * time.Millisecond, Retries: 0, MaxRate: 0},   // insane
}

// GetTimingProfile returns the profile for a timing template, clamping out-of-range
// values to the nearest valid template.
func GetTimingProfile(level int) TimingProfile {
	if level < 0 {
		level = 0
	}
	if level > 5 {
		level = 5
	}
	return timingProfiles[level]
}

// classifyDialError maps a TCP dial error to a port state. A "connection
// refused" is a definitive RST (closed); anything else (timeout, unreachable)
// is treated as filtered.
func classifyDialError(err error) string {
	if err == nil {
		return "open"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") {
		return "closed"
	}
	return "filtered"
}

// udpPayloads holds protocol-specific UDP probes keyed by destination port.
// A meaningful payload is far more likely to elicit a reply than a generic one,
// which is the difference between "open" and "open|filtered".
var udpPayloads = map[int][]byte{
	53: { // DNS standard query A for version.bind (CHAOS) / root
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
	},
	123: { // NTP v3 client request (mode 3)
		0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	161: { // SNMPv1 get-request for sysDescr.0, community "public"
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x05, 0x00,
	},
	137: { // NetBIOS name query (node status)
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
	},
}

// udpProbeFor returns the best probe payload for a UDP port: a protocol-specific
// one when known, otherwise a minimal generic payload.
func udpProbeFor(port int) []byte {
	if p, ok := udpPayloads[port]; ok {
		return p
	}
	return []byte{0x00}
}
