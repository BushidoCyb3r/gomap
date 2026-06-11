package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil is open", nil, "open"},
		{"refused is closed", errors.New("dial tcp 127.0.0.1:80: connect: connection refused"), "closed"},
		{"timeout is filtered", errors.New("dial tcp 10.0.0.1:80: i/o timeout"), "filtered"},
		{"unreachable is filtered", errors.New("connect: no route to host"), "filtered"},
	}
	for _, tt := range tests {
		if got := classifyDialError(tt.err); got != tt.want {
			t.Errorf("classifyDialError(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestGetTimingProfile(t *testing.T) {
	// Slower templates must retry more and cap the rate; faster ones must not.
	p0 := GetTimingProfile(0)
	p5 := GetTimingProfile(5)
	if p0.Retries < p5.Retries {
		t.Errorf("T0 retries (%d) should be >= T5 retries (%d)", p0.Retries, p5.Retries)
	}
	if p0.Threads >= p5.Threads {
		t.Errorf("T0 threads (%d) should be < T5 threads (%d)", p0.Threads, p5.Threads)
	}
	if p0.MaxRate == 0 {
		t.Error("T0 should impose a rate cap")
	}
	if p5.MaxRate != 0 {
		t.Error("T5 should be unlimited (MaxRate 0)")
	}
	// Out-of-range values clamp instead of panicking.
	if GetTimingProfile(-3) != GetTimingProfile(0) {
		t.Error("negative timing should clamp to T0")
	}
	if GetTimingProfile(99) != GetTimingProfile(5) {
		t.Error("oversized timing should clamp to T5")
	}
}

func TestRateLimiterPaces(t *testing.T) {
	// 20 tokens at 50/sec should take at least ~ (20-1)/50 = 0.38s.
	r := NewRateLimiter(50)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 20; i++ {
		if err := r.Wait(ctx); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Errorf("rate limiter too fast: 20 tokens at 50/s took %v, expected >= ~380ms", elapsed)
	}
}

func TestRateLimiterNilUnlimited(t *testing.T) {
	var r *RateLimiter // NewRateLimiter(0) returns nil
	if NewRateLimiter(0) != nil {
		t.Error("NewRateLimiter(0) should be nil (unlimited)")
	}
	if err := r.Wait(context.Background()); err != nil {
		t.Errorf("nil limiter Wait should be a no-op, got %v", err)
	}
}

func TestRateLimiterHonorsCancellation(t *testing.T) {
	r := NewRateLimiter(1) // 1/sec: the second Wait must block ~1s
	ctx, cancel := context.WithCancel(context.Background())
	_ = r.Wait(ctx) // first token is immediate
	cancel()
	if err := r.Wait(ctx); err == nil {
		t.Error("Wait should return an error once the context is cancelled")
	}
}

func TestUDPProbeFor(t *testing.T) {
	// Known ports get a non-trivial protocol payload; unknown ports get a fallback.
	for _, port := range []int{53, 123, 161, 137} {
		if len(udpProbeFor(port)) < 8 {
			t.Errorf("port %d should have a protocol-specific payload", port)
		}
	}
	if got := udpProbeFor(40000); len(got) == 0 {
		t.Error("unknown port should still get a (generic) payload")
	}
}
