package chain
package chain

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderCapturingRoundTripper_CapturesEventsHeader(t *testing.T) {
	t.Parallel()

	var capturedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		if strings.Contains(r.URL.Path, "/events/") {
			w.Header().Set("X-APTOS-LEDGER-OLDEST-VERSION", "515")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	rt := NewHeaderCapturingRoundTripper(nil)
	client := &http.Client{Transport: rt}

	// Non-events request: should NOT capture.
	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1", nil)
	resp1, err := client.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	_, ok := rt.LastOldestLedgerVersion()
	assert.False(t, ok, "non-events request must not capture the header")

	// Events request: should capture.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/accounts/0x1/events/3", nil)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()

	assert.Contains(t, capturedPath, "/events/")
	v, ok := rt.LastOldestLedgerVersion()
	require.True(t, ok, "events request must capture the header")
	assert.Equal(t, uint64(515), v)
}

func TestHeaderCapturingRoundTripper_NoHeader(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No X-APTOS-LEDGER-OLDEST-VERSION header set.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	rt := NewHeaderCapturingRoundTripper(nil)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/accounts/0x1/events/3", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	_, ok := rt.LastOldestLedgerVersion()
	assert.False(t, ok, "no header present → hasValue must be false")
}

func TestHeaderCapturingRoundTripper_InvalidHeader(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-APTOS-LEDGER-OLDEST-VERSION", "not-a-number")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	rt := NewHeaderCapturingRoundTripper(nil)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/accounts/0x1/events/3", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	_, ok := rt.LastOldestLedgerVersion()
	assert.False(t, ok, "invalid header value must not be captured")
}

func TestParseUint64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"0", 0, true},
		{"515", 515, true},
		{"18446744073709551615", 18446744073709551615, true},
		{"", 0, false},
		{"abc", 0, false},
		{"12x", 0, false},
		{"-1", 0, false},
	}
	for _, tc := range tests {
		got, err := parseUint64(tc.in)
		if tc.ok {
			require.NoError(t, err, "input %q", tc.in)
			assert.Equal(t, tc.want, got, "input %q", tc.in)
		} else {
			assert.Error(t, err, "input %q should error", tc.in)
		}
	}
}
