package logpoller

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func httpErr(status int, body string) *aptos.HttpError {
	return &aptos.HttpError{StatusCode: status, Status: fmt.Sprintf("%d", status), Body: []byte(body)}
}

func TestClassifyEventsRPCError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want EventsRPCErrorClass
	}{
		{
			name: "nil error is fatal",
			err:  nil,
			want: ErrorClassFatal,
		},
		{
			name: "HTTP 410 Gone is pruned",
			err:  httpErr(http.StatusGone, `{"error_code":"gone"}`),
			want: ErrorClassPruned,
		},
		{
			name: "HTTP 200 with pruned body is pruned",
			err:  httpErr(http.StatusOK, `{"message":"data pruned from node"}`),
			want: ErrorClassPruned,
		},
		{
			name: "body containing gone (lowercase) is pruned",
			err:  httpErr(http.StatusOK, `{"error":"gone"}`),
			want: ErrorClassPruned,
		},
		{
			name: "HTTP 429 is transient",
			err:  httpErr(http.StatusTooManyRequests, `{"error_code":"rate_limit"}`),
			want: ErrorClassTransient,
		},
		{
			name: "HTTP 500 is transient",
			err:  httpErr(http.StatusInternalServerError, `{"error":"internal"}`),
			want: ErrorClassTransient,
		},
		{
			name: "HTTP 503 is transient",
			err:  httpErr(http.StatusServiceUnavailable, `{"error":"unavailable"}`),
			want: ErrorClassTransient,
		},
		{
			name: "HTTP 404 is fatal",
			err:  httpErr(http.StatusNotFound, `{"error_code":"not_found"}`),
			want: ErrorClassFatal,
		},
		{
			name: "HTTP 400 is fatal",
			err:  httpErr(http.StatusBadRequest, `{"error_code":"bad_request"}`),
			want: ErrorClassFatal,
		},
		{
			name: "non-HttpError with pruned in message is pruned",
			err:  errors.New("event data pruned from ledger"),
			want: ErrorClassPruned,
		},
		{
			name: "non-HttpError with 410 gone in message is pruned",
			err:  errors.New("request failed: 410 gone"),
			want: ErrorClassPruned,
		},
		{
			name: "plain network error is transient",
			err:  errors.New("connection refused"),
			want: ErrorClassTransient,
		},
		{
			name: "wrapped HttpError 410 is pruned",
			err:  fmt.Errorf("get events api err: %w", httpErr(http.StatusGone, `{}`)),
			want: ErrorClassPruned,
		},
		{
			name: "wrapped HttpError 500 is transient",
			err:  fmt.Errorf("get events api err: %w", httpErr(http.StatusInternalServerError, `{}`)),
			want: ErrorClassTransient,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyEventsRPCError(tc.err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsPrunedOffset(t *testing.T) {
	t.Parallel()

	require.True(t, IsPrunedOffset(ErrPrunedOffset))
	require.True(t, IsPrunedOffset(fmt.Errorf("wrapped: %w", ErrPrunedOffset)))
	require.False(t, IsPrunedOffset(nil))
	require.False(t, IsPrunedOffset(errors.New("other error")))
}
