package logpoller

import (
	"encoding/json"
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
// Classification rules (from PRUNED_RPC.md §"aptos-go-sdk v1.13.0"), checked in order:
//   - HTTP 410 Gone           → Pruned   (documented; not observed on localnet v1.42.1 but
//     expected on production nodes). Cheapest and most reliable signal, checked first.
//   - HTTP 429 / 5xx           → Transient (checked before the header/body signals so a
//     transient error is never misclassified as Pruned, regardless of whether the node
//     attaches X-APTOS-LEDGER-OLDEST-VERSION to every response).
//   - X-APTOS-LEDGER-OLDEST-VERSION header present on the error response → Pruned
//     (corroborating signal, available via HttpError.Header on the SDK error path).
//   - body JSON error_code "gone"/"pruned" → Pruned (decoded via encoding/json so it is
//     robust to whitespace/formatting variations; preferred over substring matching).
//   - body contains bare "pruned" substring → Pruned (belt-and-suspenders fallback for
//     non-JSON bodies).
//   - other 4xx / parse error → Fatal
//   - unknown / network error → Transient (safe: lets the poller retry)
func ClassifyEventsRPCError(err error) EventsRPCErrorClass {
	if err == nil {
		return ErrorClassFatal
	}

	var httpErr *aptos.HttpError
	if errors.As(err, &httpErr) {
		// Cheapest, most reliable signal first.
		if httpErr.StatusCode == http.StatusGone { // 410
			return ErrorClassPruned
		}
		// Transient errors must be classified before the header/body pruned signals so
		// they are never misclassified as Pruned (the X-APTOS-LEDGER-OLDEST-VERSION header
		// may be present on every response, including 429/5xx).
		if httpErr.StatusCode == http.StatusTooManyRequests || httpErr.StatusCode >= http.StatusInternalServerError {
			return ErrorClassTransient
		}
		// Corroborating signal: the Aptos node exposes X-APTOS-LEDGER-OLDEST-VERSION on
		// error responses (available via HttpError.Header on the SDK error path). Its
		// presence on a non-transient error response is a strong pruned indicator.
		if httpErr.Header != nil {
			if v := httpErr.Header.Get("X-APTOS-LEDGER-OLDEST-VERSION"); v != "" {
				return ErrorClassPruned
			}
		}
		// Structured Aptos error_code check via JSON decode (robust to whitespace and
		// formatting variations, unlike literal substring matching). Aptos REST errors
		// return a JSON body with an "error_code" string field.
		var parsed struct {
			ErrorCode string `json:"error_code"`
		}
		if err := json.Unmarshal(httpErr.Body, &parsed); err == nil {
			code := strings.ToLower(parsed.ErrorCode)
			if code == "pruned" || code == "gone" {
				return ErrorClassPruned
			}
		}
		// Belt-and-suspenders fallback for non-JSON bodies that still mention pruning.
		// Bare "gone" is intentionally NOT matched to avoid false positives (an unrelated
		// error body containing the word "gone").
		if body := strings.ToLower(string(httpErr.Body)); strings.Contains(body, "pruned") || strings.Contains(body, "410 gone") {
			return ErrorClassPruned
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
