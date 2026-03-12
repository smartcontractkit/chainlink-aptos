package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/shopspring/decimal"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-protos/cre/go/values"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/report/platform"
	rtypes "github.com/smartcontractkit/chainlink-aptos/relayer/types"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target/mocks"
)

func TestNewWriteTargetID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		chainFamilyName string
		networkName     string
		chainID         string
		version         string
		tag             string
		expected        string
		expectError     bool
	}{
		{
			name:            "Valid input with network name",
			chainFamilyName: "aptos",
			networkName:     "mainnet",
			chainID:         "1",
			version:         "1.0.0",
			expected:        "write_aptos-mainnet@1.0.0",
			expectError:     false,
		},
		{
			name:            "Valid input without network name",
			chainFamilyName: "aptos",
			networkName:     "",
			chainID:         "1",
			version:         "1.0.0",
			expected:        "write_aptos-1@1.0.0",
			expectError:     false,
		},
		{
			name:            "Invalid input with empty chainFamilyName",
			chainFamilyName: "",
			networkName:     "mainnet",
			chainID:         "1",
			version:         "1.0.0",
			expected:        "",
			expectError:     true,
		},
		{
			name:            "Invalid input with empty version",
			chainFamilyName: "aptos",
			networkName:     "mainnet",
			chainID:         "1",
			version:         "",
			expected:        "",
			expectError:     true,
		},
		{
			name:            "Invalid input with empty networkName and chainID",
			chainFamilyName: "aptos",
			networkName:     "",
			chainID:         "",
			version:         "2.0.0",
			expected:        "",
			expectError:     true,
		},
		{
			name:            "Valid input with unknown network name",
			chainFamilyName: "aptos",
			networkName:     "unknown",
			chainID:         "1",
			version:         "2.0.1",
			expected:        "write_aptos-1@2.0.1",
			expectError:     false,
		},
		{
			name:            "Valid input with network name (testnet)",
			chainFamilyName: "aptos",
			networkName:     "testnet",
			chainID:         "2",
			version:         "1.0.3",
			expected:        "write_aptos-testnet@1.0.3",
			expectError:     false,
		},
		{
			name:            "Valid input with unknown network name and tag",
			chainFamilyName: "aptos",
			networkName:     "unknown",
			chainID:         "1",
			tag:             "region-b",
			version:         "2.0.1",
			expected:        "write_aptos-1:region-b@2.0.1",
			expectError:     false,
		},
		{
			name:            "Valid input with network name (testnet)",
			chainFamilyName: "aptos",
			networkName:     "testnet",
			chainID:         "2",
			tag:             "region-b",
			version:         "1.0.3",
			expected:        "write_aptos-testnet:region-b@1.0.3",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := NewWriteTargetID(tt.chainFamilyName, tt.networkName, tt.chainID, tt.tag, tt.version)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
				// ensure we meet capabilities requirements for the ID
				_, err := capabilities.NewCapabilityInfo(result, capabilities.CapabilityTypeTarget, CapabilityName)
				require.NoError(t, err)
			}
		})
	}
}

type mockedWriteTarget struct {
	cs *mocks.ChainService
	cr *mocks.ContractReader
	cw *mocks.ContractWriter
	wt *writeTarget
}

func newMockedWriteTarget(t *testing.T, lggr logger.Logger) mockedWriteTarget {
	cs := mocks.NewChainService(t)
	cr := mocks.NewContractReader(t)
	cw := mocks.NewContractWriter(t)
	beholderClient, err := beholder.NewStdoutClient()
	require.NoError(t, err)
	bh := &monitor.BeholderClient{Client: beholderClient, ProtoEmitter: monitor.NoopProtoEmitter{}}
	require.NoError(t, err)

	wt := newWriteTarget(WriteTargetOpts{
		ID: "write_aptos-1@1.0.0",
		Config: Config{
			ConfirmerPollPeriod: config.MustNewDuration(100 * time.Millisecond),
			ConfirmerTimeout:    config.MustNewDuration(300 * time.Millisecond),
		},
		ChainInfo:        rtypes.ChainInfo{},
		Logger:           lggr,
		Beholder:         bh,
		ChainService:     cs,
		ContractReader:   cr,
		ChainWriter:      cw,
		ConfigValidateFn: func(config ReqConfig) error { return nil },
		NodeAddress:      "",
		ForwarderAddress: "",
	})
	wt.decodeReport = func(report []byte, metadata capabilities.RequestMetadata) (*platform.Report, error) {
		return &platform.Report{}, nil
	}
	return mockedWriteTarget{
		cs: cs,
		cr: cr,
		cw: cw,
		wt: wt,
	}
}

func createValidRequest(t *testing.T) capabilities.CapabilityRequest {
	signedReport, err := values.Wrap(types.SignedReport{
		ID:     binary.BigEndian.AppendUint16(nil, 8),
		Report: []byte("Report payload"), // no need not include valid metadata, since report validation is mocked
	})
	require.NoError(t, err)
	inputs, err := values.NewMap(map[string]any{
		KeySignedReport: signedReport,
	})
	require.NoError(t, err)
	return capabilities.CapabilityRequest{
		Metadata: capabilities.RequestMetadata{
			WorkflowExecutionID: hex.EncodeToString([]byte("WorkflowExecutionID")),
		},
		Config: values.EmptyMap(),
		Inputs: inputs,
	}
}

func TestWriteTarget_Execute(t *testing.T) {
	t.Parallel()
	t.Run("Returns error if tx is not finalized before timeout", func(t *testing.T) {
		mockedWT := newMockedWriteTarget(t, logger.Test(t))
		mockedWT.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{}, nil).Once()
		// Mocks getTransmissionState. Signal that report was not transmitter to trigger creation of a new transaction.
		mockedWT.cr.EXPECT().GetLatestValue(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		// ContractWriter accepts transaction
		mockedWT.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		// Transaction never reaches terminal state
		mockedWT.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(commontypes.Pending, nil)

		request := createValidRequest(t)
		_, err := mockedWT.wt.Execute(t.Context(), request)
		require.EqualError(t, err, "platform.write_target.WriteError [ERR-0] - failed to wait until tx gets finalized: context deadline exceeded")
	})
	t.Run("Returns error if tx reaches terminal status, but report is not on chain", func(t *testing.T) {
		testCases := []struct {
			TransactionStatus commontypes.TransactionStatus
			ExpectedError     string
		}{
			{
				TransactionStatus: commontypes.Finalized,
				ExpectedError:     "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction was finalized, but report was not observed on chain before timeout",
			},
			{
				TransactionStatus: commontypes.Fatal,
				ExpectedError:     "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction failed and no other node managed to get report on chain before timeout",
			},
			{
				TransactionStatus: commontypes.Failed,
				ExpectedError:     "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction failed and no other node managed to get report on chain before timeout",
			},
		}
		for _, tc := range testCases {
			mockedWT := newMockedWriteTarget(t, logger.Test(t))
			mockedWT.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{}, nil)
			// Mocks getTransmissionState. Since return value is not modified - signals that report was not accepted.
			// First call is required to trigger transaction submission, subsequent calls to cause timeout error
			mockedWT.cr.EXPECT().GetLatestValue(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			// ContractWriter accepts transaction
			mockedWT.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			// Returns terminal transaction status
			mockedWT.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(tc.TransactionStatus, nil).Once()

			request := createValidRequest(t)
			_, err := mockedWT.wt.Execute(t.Context(), request)
			require.EqualError(t, err, tc.ExpectedError)
		}
	})
	t.Run("Returns success if report is on chains", func(t *testing.T) {
		testCases := []struct {
			TransactionStatus commontypes.TransactionStatus
			ExpectedLogMsg    string
		}{
			{
				TransactionStatus: commontypes.Finalized,
				ExpectedLogMsg:    "confirmed - transmission state visible",
			},
			{
				TransactionStatus: commontypes.Fatal,
				ExpectedLogMsg:    "confirmed - transmission state visible but submitted by another node. This node's tx failed",
			},
			{
				TransactionStatus: commontypes.Failed,
				ExpectedLogMsg:    "confirmed - transmission state visible but submitted by another node. This node's tx failed",
			},
		}
		for _, tc := range testCases {
			lggr, observed := logger.TestObserved(t, zapcore.InfoLevel)
			mockedWT := newMockedWriteTarget(t, lggr)
			mockedWT.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{Height: "12"}, nil)
			secondCall := false
			// On the first trigger transaction submission by setting transmitted to `false`, on second call return
			// true to signal that report is on chain.
			mockedWT.cr.EXPECT().GetLatestValue(mock.Anything, "-forwarder-getTransmissionState", mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
				func(ctx context.Context, s string, level primitives.ConfidenceLevel, inputs interface{}, rawTransmitted interface{}) error {
					transmitted := rawTransmitted.(*bool)
					*transmitted = secondCall // return false on the first call to trigger transaction
					secondCall = true
					return nil
				}).Twice()
			// Returns address of the report transmitter
			mockedWT.cr.EXPECT().GetLatestValue(mock.Anything, "-forwarder-getTransmitter", mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
				func(ctx context.Context, s string, level primitives.ConfidenceLevel, inputs interface{}, rawTransmitterAddr interface{}) error {
					transmitterAddr := rawTransmitterAddr.(*struct {
						Vec []string
					})
					transmitterAddr.Vec = []string{"0x0abc"}
					return nil
				}).Once()
			// signal that transaction was accepted by CW
			mockedWT.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			// signal that transaction is in terminal state and it's time to poll for transmission status
			mockedWT.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(tc.TransactionStatus, nil)
			// Get transaction fee (always called for terminal statuses)
			mockedWT.cw.EXPECT().GetTransactionFee(mock.Anything, mock.Anything).Return(decimal.NewFromInt(100), nil).Once()
			request := createValidRequest(t)
			result, err := mockedWT.wt.Execute(t.Context(), request)
			require.NoError(t, err)
			expected := capabilities.CapabilityResponse{
				Metadata: capabilities.ResponseMetadata{
					Metering: []capabilities.MeteringNodeDetail{{
						SpendUnit:  "GAS.",
						SpendValue: "100",
					}},
				},
			}
			require.Equal(t, expected, result)
			tests.RequireLogMessage(t, observed, tc.ExpectedLogMsg)
		}
	})
}
