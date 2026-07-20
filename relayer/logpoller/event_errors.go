package logpoller

import (
	"errors"
	"net/http"
	"strings"

	aptos "github.com/aptos-labs/aptos-go-sdk"
)

// ErrPrunedOffset is returned when an Aptos event offset falls in the pruned ledger range.
// The CR does NOT halt on this: it stays operational, raises a pruned-warning gauge
// (aptos_log_poller_pruned_warning_active) so the NOP can act (switch to archive node),
// and auto-recovers once the NOP fixes the node. See PRUNED_RPC.md.
var ErrPrunedOffset = errors.New("event offset pruned on Aptos node")

// ErrSequenceGap is returned when a gap is detected between the stored offset and the
// first event in a batch (missing events). The CR does NOT halt: it inserts the events it
// did receive, advances past the gap, and raises a warning so the NOP can reindex the
// missing events from an archive node. See PRUNED_RPC.md.
var ErrSequenceGap = errors.New("event sequence gap detected — possible missing CCIP events")

// EventsRPCErrorClass classifies errors returned by EventsByCreationNumber.
type EventsRPCErrorClass int

const (
	// ErrorClassFatal covers 4xx errors (other than 410 Gone) and unrecoverable parse errors.
	// The poller returns the error and logs at Error; the CR does not halt.
	ErrorClassFatal EventsRPCErrorClass = iota
	// ErrorClassTransient covers 5xx, 429, timeouts, and connection resets.
	// The poller returns the error and retries on the next tick.
	ErrorClassTransient
	// ErrorClassPruned indicates the requested event data has been pruned (HTTP 410 or
	// equivalent). The poller raises a warning gauge (paging signal) and stays operational;
	// it auto-recovers once the NOP switches to an archive node.
	ErrorClassPruned
)

// ClassifyEventsRPCError categorises an error from EventsByCreationNumber.
//
// Classification rules (from PRUNED_RPC.md §"aptos-go-sdk v1.13.0"):
//   - HTTP 410 Gone           → Pruned   (documented; not observed on localnet v1.42.1 but
//     expected on production nodes)
//   - X-APTOS-LEDGER-OLDEST-VERSION header present on an error response → Pruned (corroborating)
//   - body contains "pruned"  → Pruned   (belt-and-suspenders)
//   - body contains structured Aptos error_code "gone"/"pruned" → Pruned
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
		// Corroborating signal: the Aptos node exposes X-APTOS-LEDGER-OLDEST-VERSION on
		// error responses (available via HttpError.Header on the SDK error path). Its
		// presence on a non-2xx response is a strong pruned indicator.
		if httpErr.Header != nil {
			if v := httpErr.Header.Get("X-APTOS-LEDGER-OLDEST-VERSION"); v != "" {
				return ErrorClassPruned
			}
		}
		// Structured Aptos error_code check (preferred over bare substring matching).
		// Avoids false positives where an unrelated error body happens to contain "gone".
		body := strings.ToLower(string(httpErr.Body))
		if strings.Contains(body, `"error_code":"pruned"`) ||
			strings.Contains(body, `"error_code":"gone"`) ||
			strings.Contains(body, "pruned") ||
			strings.Contains(body, "410 gone") {
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

// IsSequenceGap reports whether err (or any error in its chain) is ErrSequenceGap.
func IsSequenceGap(err error) bool {
	return errors.Is(err, ErrSequenceGap)
}
