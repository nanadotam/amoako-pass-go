package services

import (
	"testing"
	"time"
)

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)

	if !limiter.Allow("user@example.com") {
		t.Fatal("first attempt should be allowed")
	}
	limiter.RecordFailure("user@example.com")
	if !limiter.Allow("user@example.com") {
		t.Fatal("second attempt should be allowed")
	}
	limiter.RecordFailure("user@example.com")
	if limiter.Allow("user@example.com") {
		t.Fatal("third attempt should be blocked")
	}
}
