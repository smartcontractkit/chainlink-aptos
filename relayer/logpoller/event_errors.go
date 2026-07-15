package logpoller

import (
	"errors"
	"net/http"
	"strings"

	aptos "github.com/aptos-labs/aptos-go-sdk"
)

// ErrPrunedOffset is returned when an Aptos event offset falls in the pruned ledger range.
// This is a non-retriable, operator-intervention error — the poller halts until resolved.
var ErrPrunedOffset = errors.New("event offset pruned on Aptos node")

// EventsRPCErrorClass classifies errors returned by EventsByCreationNumber.
type EventsRPCErrorClass int

const (
	// ErrorClassFatal covers 4xx errors (other than 410 Gone) and unrecoverable parse errors.
	// The poller returns the error; same retry semantics as today.
	ErrorClassFatal EventsRPCErrorClass = iota
	// ErrorClassTransient covers 5xx, 429, timeouts, and connection resets.
	// The poller returns the error and retries on the next tick.
	ErrorClassTransient
	// ErrorClassPruned indicates the requested event data has been pruned (HTTP 410 or
	// equivalent). The poller halts and emits a pruned_offset_total metric.
	ErrorClassPruned
)

// ClassifyEventsRPCError categorises an error from EventsByCreationNumber.
//
// Classification rules (from PRUNED_RPC.md §"aptos-go-sdk v1.13.0"):
//   - HTTP 410 Gone           → Pruned   (documented; not observed on localnet v1.42.1 but
//     expected on production nodes)
//   - body contains "pruned"  → Pruned   (belt-and-suspenders)
//   - HTTP 429 / 5xx          → Transient
//   - other 4xx / parse error → Fatal
//   - unknown / network error → Transient (safe: lets the poller retry)
func ClassifyEventsRPCError(err error) EventsRPCErrorClass {
	if err == nil {
		return ErrorClassFatal
	}

	var httpErr *aptos.HttpError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode == http.StatusGone { // 410
			return ErrorClassPruned
		}
		// Belt-and-suspenders: check body for pruned/gone strings even on non-410 status.
		body := strings.ToLower(string(httpErr.Body))
		if strings.Contains(body, "pruned") || strings.Contains(body, "gone") {
			return ErrorClassPruned
		}
		if httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= http.StatusInternalServerError {
			return ErrorClassTransient
		}
		return ErrorClassFatal
	}

	// Non-HttpError: last-resort string check on the error message itself.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "pruned") || strings.Contains(msg, "410 gone") {
		return ErrorClassPruned
	}

	// Treat unrecognised errors (network, context, etc.) as transient so the poller retries.
	return ErrorClassTransient
}

// IsPrunedOffset reports whether err (or any error in its chain) is ErrPrunedOffset.
func IsPrunedOffset(err error) bool {
	return errors.Is(err, ErrPrunedOffset)
}
