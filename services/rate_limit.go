package services

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string][]time.Time),
	}
}

func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	recent := r.pruneLocked(key, now)
	if len(recent) >= r.limit {
		r.entries[key] = recent
		return false
	}
	return true
}

func (r *RateLimiter) RecordFailure(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	recent := r.pruneLocked(key, now)
	recent = append(recent, now)
	r.entries[key] = recent
}

func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
}

func (r *RateLimiter) pruneLocked(key string, now time.Time) []time.Time {
	attempts := r.entries[key]
	cutoff := now.Add(-r.window)
	kept := attempts[:0]
	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	return kept
}
