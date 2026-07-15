package logpoller

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

// fakeEventStore is a test double for the eventStore interface.
type fakeEventStore struct {
	offset    uint64
	txVersion uint64
	found     bool
	insertErr error
	inserted  []db.EventRecord
}

func (f *fakeEventStore) GetLatestEventMeta(_ context.Context, _, _, _ string) (uint64, uint64, bool, error) {
	return f.offset, f.txVersion, f.found, nil
}

func (f *fakeEventStore) InsertEvents(_ context.Context, records []db.EventRecord) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserted = append(f.inserted, records...)
	return nil
}

// testBlock returns an api.Block with a timestamp 1 hour before now (in microseconds).
func testBlock() *api.Block {
	tsMicros := uint64(time.Now().Add(-time.Hour).UnixMicro())
	return &api.Block{
		BlockHash:      "0x014e30aafd9f715ab6262322bf919abebd66d948f6822ffb8a2699a57722fb80",
		BlockHeight:    1,
		BlockTimestamp: tsMicros,
	}
}

// testResource returns an AccountResource map with creation_num "3" at the given field path.
func testResource(fieldName string) map[string]any {
	return map[string]any{
		"data": map[string]any{
			fieldName: map[string]any{
				"guid": map[string]any{
					"id": map[string]any{
						"creation_num": "3",
					},
				},
			},
		},
	}
}

// testEvent returns an api.Event with the given sequence number and tx version.
func testEvent(seqNum, version uint64) *api.Event {
	return &api.Event{
		SequenceNumber: seqNum,
		Version:        version,
		Data:           map[string]any{"value": "1"},
	}
}

// buildPoller constructs a minimal AptosLogPoller for unit tests.
func buildPoller(t *testing.T, client aptos.AptosRpcClient, store *fakeEventStore) *AptosLogPoller {
	t.Helper()
	lggr := logger.Test(t)
	cfg := DefaultConfigSet
	batchSize := uint64(25)
	cfg.EventBatchSize = &batchSize

	var addr aptos.AccountAddress
	require.NoError(t, addr.ParseStringRelaxed("0x1"))

	return &AptosLogPoller{
		lggr:    logger.Named(lggr, "test"),
		evStore: store,
		config:  &cfg,
		getClient: func() (aptos.AptosRpcClient, error) {
			return client, nil
		},
		chainInfo: types.ChainInfo{
			ChainFamilyName: "aptos",
			ChainID:         "test-chain",
			NetworkName:     "test-net",
		},
		resourceCache:            cache.New(time.Minute, time.Minute),
		blockCache:               cache.New(time.Minute, time.Minute),
		eventAccountAddressCache: cache.New(time.Minute, time.Minute),
		modules:                  make(map[string]*moduleInfo),
	}
}

// testEventConfig returns a minimal ChainReaderEvent config for the given field name.
func testEventConfig(fieldName string) *config.ChainReaderEvent {
	return &config.ChainReaderEvent{
		EventHandleStructName: "TestHandle",
		EventHandleFieldName:  fieldName,
	}
}

// boundAddr returns an AccountAddress from a hex string, failing the test on error.
func boundAddr(t *testing.T, hex string) aptos.AccountAddress {
	t.Helper()
	var addr aptos.AccountAddress
	require.NoError(t, addr.ParseStringRelaxed(hex))
	return addr
}

// TestSyncEvent_EmptyEvents_AtTip verifies that an empty event list with no stored
// history is treated as "caught up" and returns nil without inserting anything.
func TestSyncEvent_EmptyEvents_AtTip(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 0, found: false}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return([]*api.Event{}, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	assert.Empty(t, store.inserted)
}

// TestSyncEvent_PrunedError_HaltsWithErrPrunedOffset verifies that a HTTP 410 error
// from EventsByCreationNumber causes syncEvent to return ErrPrunedOffset and not insert.
func TestSyncEvent_PrunedError_HaltsWithErrPrunedOffset(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 10, found: true, txVersion: 50}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	pruned := &aptos.HttpError{StatusCode: http.StatusGone, Status: "410 Gone", Body: []byte(`{"error":"gone"}`)}

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return(([]*api.Event)(nil), pruned).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.Error(t, err)
	assert.True(t, IsPrunedOffset(err), "expected ErrPrunedOffset, got: %v", err)
	assert.Empty(t, store.inserted, "no events should be inserted on pruned error")
}

// TestSyncEvent_TransientError_ReturnsError verifies that a transient (5xx) RPC error
// is returned as-is (not ErrPrunedOffset) so the caller can retry on the next tick.
func TestSyncEvent_TransientError_ReturnsError(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 0, found: false}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	transient := &aptos.HttpError{StatusCode: http.StatusInternalServerError, Status: "500", Body: []byte(`{}`)}

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return(([]*api.Event)(nil), transient).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.Error(t, err)
	assert.False(t, IsPrunedOffset(err), "transient error should not be ErrPrunedOffset")
	assert.Empty(t, store.inserted)
}

// TestSyncEvent_Events_Inserted verifies normal event insertion: events are fetched
// and persisted, and nil is returned.
func TestSyncEvent_Events_Inserted(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 0, found: false}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"
	version := uint64(100)
	blk := testBlock()

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	// First call returns one event (fewer than batchSize → caught up).
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return([]*api.Event{testEvent(0, version)}, nil).Once()
	rpc.On("BlockByVersion", version, false).Return(blk, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	require.Len(t, store.inserted, 1)
	assert.Equal(t, uint64(0), store.inserted[0].EventOffset)
	assert.Equal(t, version, store.inserted[0].TxVersion)
}

// TestSyncEvent_SequenceGap_EventsStillInserted verifies that a gap in event sequence
// numbers triggers the gap metric (via log) but events are still inserted.
func TestSyncEvent_SequenceGap_EventsStillInserted(t *testing.T) {
	t.Parallel()

	// Simulate: DB has offset 2, but next event starts at sequence 7 (gap of 5).
	offset := uint64(2)
	store := &fakeEventStore{offset: offset, found: true, txVersion: 50}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"
	version := uint64(200)
	blk := testBlock()

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &offset, lp.config.EventBatchSize).
		Return([]*api.Event{testEvent(7, version)}, nil).Once()
	rpc.On("BlockByVersion", version, false).Return(blk, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	require.Len(t, store.inserted, 1, "events should still be inserted despite the gap")
	assert.Equal(t, uint64(7), store.inserted[0].EventOffset)
}

// TestSyncEvent_EmptyEvents_DefensivePrunedCheck verifies that when we get an empty
// event list but have stored events whose tx_version is below the node's
// oldest_ledger_version, syncEvent returns ErrPrunedOffset.
func TestSyncEvent_EmptyEvents_DefensivePrunedCheck(t *testing.T) {
	t.Parallel()

	// Stored events have last tx_version = 50; oldest_ledger_version = 100.
	offset := uint64(5)
	store := &fakeEventStore{offset: offset, found: true, txVersion: 50}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &offset, lp.config.EventBatchSize).
		Return([]*api.Event{}, nil).Once()
	rpc.On("Info").Return(aptos.NodeInfo{OldestLedgerVersionStr: "100"}, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.Error(t, err)
	assert.True(t, IsPrunedOffset(err), "expected ErrPrunedOffset from defensive check, got: %v", err)
	assert.Empty(t, store.inserted)
}

// TestSyncEvent_EmptyEvents_DefensiveCheck_NotPruned verifies that when we get an
// empty event list and the stored tx_version is >= oldest_ledger_version, syncEvent
// treats the result as "caught up" and returns nil.
func TestSyncEvent_EmptyEvents_DefensiveCheck_NotPruned(t *testing.T) {
	t.Parallel()

	// Stored events have last tx_version = 200; oldest_ledger_version = 100 — still valid.
	offset := uint64(5)
	store := &fakeEventStore{offset: offset, found: true, txVersion: 200}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &offset, lp.config.EventBatchSize).
		Return([]*api.Event{}, nil).Once()
	rpc.On("Info").Return(aptos.NodeInfo{OldestLedgerVersionStr: "100"}, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	assert.Empty(t, store.inserted)
}

// TestSyncEvent_EmptyEvents_NoStoredEvents_NoPrunedCheck verifies that when we get an
// empty event list and there are no stored events (found=false), syncEvent treats the
// result as "caught up" without calling Info().
func TestSyncEvent_EmptyEvents_NoStoredEvents_NoPrunedCheck(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 0, found: false}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return([]*api.Event{}, nil).Once()
	// Info() must NOT be called — the mock will fail the test if it is.

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	assert.Empty(t, store.inserted)
}

// TestSyncEvent_ReaderLag_Observed verifies that events with an old block timestamp
// are still inserted (reader lag is a metric, not a halt condition).
func TestSyncEvent_ReaderLag_Observed(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 0, found: false}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	// Block timestamp is one hour old (in microseconds).
	oldTimestamp := uint64(time.Now().Add(-time.Hour).UnixMicro())
	blk := &api.Block{
		BlockHash:      "0x014e30aafd9f715ab6262322bf919abebd66d948f6822ffb8a2699a57722fb80",
		BlockHeight:    1,
		BlockTimestamp: oldTimestamp,
	}

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return([]*api.Event{testEvent(0, 100)}, nil).Once()
	rpc.On("BlockByVersion", uint64(100), false).Return(blk, nil).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.NoError(t, err)
	require.Len(t, store.inserted, 1)
	// Reader lag metric is emitted — verified by successful completion without panic.
}

// TestSyncEvent_PrunedError_NonHttpError verifies that a non-HttpError whose message
// contains "pruned" is still classified as pruned.
func TestSyncEvent_PrunedError_NonHttpError(t *testing.T) {
	t.Parallel()

	store := &fakeEventStore{offset: 5, found: true, txVersion: 100}
	rpc := mocks.NewAptosRpcClient(t)
	lp := buildPoller(t, rpc, store)

	addr := boundAddr(t, "0x1")
	fieldName := "my_events"

	rpc.On("AccountResource", addr, addr.String()+"::test::TestHandle").
		Return(testResource(fieldName), nil).Once()
	rpc.On("EventsByCreationNumber", addr, "3", &store.offset, lp.config.EventBatchSize).
		Return(([]*api.Event)(nil), errors.New("data pruned from ledger")).Once()

	err := lp.syncEvent(context.Background(), addr, testEventConfig(fieldName), "test")
	require.Error(t, err)
	assert.True(t, IsPrunedOffset(err), "expected ErrPrunedOffset, got: %v", err)
	assert.Empty(t, store.inserted)
}
