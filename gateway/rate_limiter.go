package gateway

import (
	"context"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiter *rate.Limiter
}

func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), 1),
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}
