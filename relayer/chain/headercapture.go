package chain

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// HeaderCapturingRoundTripper wraps an http.RoundTripper and captures the
// X-APTOS-LEDGER-OLDEST-VERSION response header from Aptos events API responses.
//
// Background: the aptos-go-sdk (v1.13.0) discards HTTP response headers on successful
// (2xx) responses — it only populates HttpError.Header on error (>=400) responses. The
// pruned event offset can return HTTP 200 + non-empty events with no error, so the
// LogPoller needs the oldest-ledger-version signal on the success path too. This round
// tripper intercepts responses to /events/ requests and atomically stores the header value
// so syncEvent can compare event.Version against it and detect pruning on the non-empty
// path.
//
// Concurrency: EventsByCreationNumber issues a single HTTP request when limit <= 100
// (the default EventBatchSize). When limit > 100 it fans out into concurrent goroutines,
// each hitting /events/. The header is node-wide (identical across pages from the same
// node), so "last writer wins" via atomic store is semantically correct. The capture is
// therefore safe regardless of fan-out.
//
// The captured value is shared across all callers using this transport. The LogPoller
// reads it immediately after an EventsByCreationNumber call on the same goroutine, before
// any other events call can overwrite it — which is sufficient because syncEvent's
// eventLoop is sequential (one EventsByCreationNumber call at a time per handle).
type HeaderCapturingRoundTripper struct {
	base http.RoundTripper

	// oldestLedgerVersion holds the last captured X-APTOS-LEDGER-OLDEST-VERSION value.
	// hasValue is 1 when a valid value has been captured, 0 otherwise.
	oldestLedgerVersion atomic.Uint64
	hasValue            atomic.Bool
}

// NewHeaderCapturingRoundTripper wraps base (falling back to http.DefaultTransport if nil)
// and returns a round tripper that captures X-APTOS-LEDGER-OLDEST-VERSION from /events/
// responses.
func NewHeaderCapturingRoundTripper(base http.RoundTripper) *HeaderCapturingRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &HeaderCapturingRoundTripper{base: base}
}

// RoundTrip implements http.RoundTripper. It forwards the request and, for responses to
// /events/ paths, captures the X-APTOS-LEDGER-OLDEST-VERSION header if present.
func (rt *HeaderCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Only capture from events API responses (path contains "/events/"). This avoids
	// attributing headers from unrelated RPC calls (Info, AccountResource, BlockByVersion)
	// that share the same transport via GetClient's per-URL client cache.
	if !strings.Contains(req.URL.Path, "/events/") {
		return resp, nil
	}
	if v := resp.Header.Get("X-APTOS-LEDGER-OLDEST-VERSION"); v == "" {
		return resp, nil
	} else if parsed, perr := parseUint64(v); perr == nil {
		rt.oldestLedgerVersion.Store(parsed)
		rt.hasValue.Store(true)
	}

	return resp, nil
}

// LastOldestLedgerVersion returns the most recently captured X-APTOS-LEDGER-OLDEST-VERSION
// header value and whether a valid value has been captured since construction.
func (rt *HeaderCapturingRoundTripper) LastOldestLedgerVersion() (uint64, bool) {
	return rt.oldestLedgerVersion.Load(), rt.hasValue.Load()
}

// parseUint64 parses a decimal uint64 string. Returns an error on invalid/empty input.
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, errInvalidUint64
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errInvalidUint64
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

var errInvalidUint64 = &parseError{msg: "invalid uint64"}

type parseError struct{ msg string }

func (e *parseError) Error() string { return e.msg }
