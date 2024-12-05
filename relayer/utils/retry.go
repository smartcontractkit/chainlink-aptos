package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/jpillora/backoff"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Exponential backoff (default) is used to handle retries with increasing wait times in case of errors
var BackoffStrategyDefault = backoff.Backoff{
	Min:    100 * time.Millisecond,
	Max:    3 * time.Second,
	Factor: 2,
}

// WithRetryStrategy applies a retry strategy to a given function.
func WithRetryStrategy[R any](ctx context.Context, lggr logger.Logger, strategy backoff.Backoff, fn func(ctx context.Context) (R, error)) (R, error) {
	for {
		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}

		wait := strategy.Duration()
		lggr.Warnw(fmt.Sprintf("Failed to execute function, retrying in %s ...", wait), "wait", wait, "err", err)

		select {
		case <-ctx.Done():
			return result, fmt.Errorf("context done while executing function: %w", ctx.Err())
		case <-time.After(wait):
		}
	}
}

// WithRetry applies a default retry strategy to a given function.
func WithRetry[R any](ctx context.Context, lggr logger.Logger, fn func(ctx context.Context) (R, error)) (R, error) {
	return WithRetryStrategy(ctx, lggr, BackoffStrategyDefault, fn)
}
