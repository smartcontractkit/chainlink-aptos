package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-common/pkg/values"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-aptos/relayer/report/platform"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := NewWriteTargetID(tt.chainFamilyName, tt.networkName, tt.chainID, tt.version)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestWriteTarget_Execute(t *testing.T) {
	t.Parallel()
	type testContext struct {
		cs *mocks.ChainService
		cr *mocks.ContractReader
		cw *mocks.ContractWriter
		wt *writeTarget
	}
	newTestContext := func(t *testing.T, lggr logger.Logger) testContext {
		cs := mocks.NewChainService(t)
		cr := mocks.NewContractReader(t)
		cw := mocks.NewContractWriter(t)
		beholderClient, err := beholder.NewStdoutClient()
		require.NoError(t, err)
		bh, err := newMonitor(t.Context(), lggr, beholderClient)
		require.NoError(t, err)

		wt := newWriteTarget(WriteTargetOpts{
			ID: "write_aptos-1@1.0.0",
			Config: Config{
				ConfirmerPollPeriod: *config.MustNewDuration(100 * time.Millisecond),
				ConfirmerTimeout:    *config.MustNewDuration(300 * time.Millisecond),
			},
			ChainInfo:        ChainInfo{},
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
		return testContext{
			cs: cs,
			cr: cr,
			cw: cw,
			wt: wt,
		}
	}
	validRequest := func() capabilities.CapabilityRequest {
		signedReport, err := values.Wrap(types.SignedReport{
			ID:     binary.BigEndian.AppendUint16(nil, 8),
			Report: []byte("Awesome report"),
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
	}()

	t.Run("Returns error if tx is not finalized before timeout", func(t *testing.T) {
		testContext := newTestContext(t, logger.Test(t))
		testContext.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{}, nil).Once()
		testContext.cr.EXPECT().GetLatestValue(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		testContext.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		testContext.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(commontypes.Unconfirmed, nil)

		_, err := testContext.wt.Execute(t.Context(), validRequest)
		require.EqualError(t, err, "platform.write_target.WriteError [ERR-0] - failed to wait until tx gets finalized: context deadline exceeded")
	})
	runTxFinalizedButReportIsNotOnChain := func(t *testing.T, txStatus commontypes.TransactionStatus, expectedError string) {
		testContext := newTestContext(t, logger.Test(t))
		testContext.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{}, nil)
		testContext.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		testContext.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(txStatus, nil).Once()
		// returns that transmission is not on chain
		testContext.cr.EXPECT().GetLatestValue(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		_, err := testContext.wt.Execute(t.Context(), validRequest)
		require.EqualError(t, err, expectedError)
	}
	t.Run("Returns error if tx reaches final status, but report is not on chain", func(t *testing.T) {
		runTxFinalizedButReportIsNotOnChain(t, commontypes.Finalized, "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction was finalized, but report was not observed on chain before timeout")
		runTxFinalizedButReportIsNotOnChain(t, commontypes.Fatal, "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction failed and no other node managed to get report on chain before timeout")
		runTxFinalizedButReportIsNotOnChain(t, commontypes.Failed, "platform.write_target.WriteError [ERR-0] - write confirmation - failed: transaction failed and no other node managed to get report on chain before timeout")
	})
	runHappyPath := func(t *testing.T, lggr logger.Logger, transactionStatus commontypes.TransactionStatus) {
		testContext := newTestContext(t, lggr)
		testContext.cs.EXPECT().LatestHead(mock.Anything).Return(commontypes.Head{Height: "12"}, nil)
		secondCall := false
		testContext.cr.EXPECT().GetLatestValue(mock.Anything, "-forwarder-getTransmissionState", mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
			func(ctx context.Context, s string, level primitives.ConfidenceLevel, inputs interface{}, rawTransmitted interface{}) error {
				transmitted := rawTransmitted.(*bool)
				*transmitted = secondCall // return false on the first call to trigger transaction
				secondCall = true
				return nil
			}).Twice()
		testContext.cr.EXPECT().GetLatestValue(mock.Anything, "-forwarder-getTransmitter", mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
			func(ctx context.Context, s string, level primitives.ConfidenceLevel, inputs interface{}, rawTransmitterAddr interface{}) error {
				transmitterAddr := rawTransmitterAddr.(*struct {
					Vec []string
				})
				transmitterAddr.Vec = []string{"0x0abc"}
				return nil
			}).Once()
		testContext.cw.EXPECT().SubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		testContext.cw.EXPECT().GetTransactionStatus(mock.Anything, mock.Anything).Return(transactionStatus, nil)
		result, err := testContext.wt.Execute(t.Context(), validRequest)
		require.NoError(t, err)
		require.Equal(t, success(), result)
	}
	t.Run("Returns success if report is on chains", func(t *testing.T) {
		runHappyPath(t, logger.Test(t), commontypes.Finalized)
	})
	t.Run("Returns success and logs info, if tx failed but report end-up on chain", func(t *testing.T) {
		for _, txStatus := range []commontypes.TransactionStatus{commontypes.Failed, commontypes.Fatal} {
			lggr, observed := logger.TestObserved(t, zapcore.InfoLevel)
			runHappyPath(t, lggr, txStatus)
			tests.RequireLogMessage(t, observed, "confirmed - transmission state visible but submitted by another node. This node's tx failed")
		}
	})
}
