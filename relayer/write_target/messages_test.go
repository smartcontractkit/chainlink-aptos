package write_target

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	wt "github.com/smartcontractkit/chainlink-aptos/relayer/monitoring/pb/platform/write-target"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	rtypes "github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

func TestBuildWriteAccepted(t *testing.T) {
	t.Parallel()

	builder := NewMessageBuilder(
		rtypes.ChainInfo{
			ChainFamilyName: "aptos",
			ChainID:         "1",
			NetworkName:     "localnet",
			NetworkNameFull: "aptos-localnet",
		},
		capabilities.MustNewCapabilityInfo("write_aptos-localnet@1.0.0", capabilities.CapabilityTypeTarget, CapabilityName),
	)

	req := createValidRequest(t)
	info := &requestInfo{
		tsStart:   1234,
		node:      "0xnode",
		forwarder: "0xforwarder",
		receiver:  "0xreceiver",
		request:   req,
		reportInfo: &reportInfo{
			reportID: 8,
		},
	}

	msg := builder.buildWriteAccepted(
		info,
		commontypes.Head{Height: "99", Hash: []byte{0xaa, 0xbb}, Timestamp: 7},
		uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
		&txm.TransactionResult{
			Status: commontypes.Finalized,
			TxHash: "0xdeadbeef",
		},
	)

	require.IsType(t, &wt.WriteAccepted{}, msg)
	require.Equal(t, "0xnode", msg.Node)
	require.Equal(t, "0xforwarder", msg.Forwarder)
	require.Equal(t, "0xreceiver", msg.Receiver)
	require.Equal(t, uint32(8), msg.ReportId)
	require.Equal(t, "99", msg.BlockHeight)
	require.Equal(t, "aabb", msg.BlockHash)
	require.Equal(t, uint64(7000), msg.BlockTimestamp)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", msg.TxId)
	require.Equal(t, "0xdeadbeef", msg.TxHash)
	require.Equal(t, "finalized", msg.TxStatus)
	require.Equal(t, "aptos", msg.MetaChainFamilyName)
	require.Equal(t, "1", msg.MetaChainId)
	require.Equal(t, "localnet", msg.MetaNetworkName)
	require.Equal(t, "aptos-localnet", msg.MetaNetworkNameFull)
	require.Equal(t, req.Metadata.WorkflowExecutionID, msg.MetaWorkflowExecutionId)
	require.Equal(t, "write_aptos-localnet@1.0.0", msg.MetaCapabilityId)
}
