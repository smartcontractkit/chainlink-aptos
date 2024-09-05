package write_target

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"

	chain "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chainwriter"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

func NewAptosWriteTarget(ctx context.Context, chain chain.Chain, lggr logger.Logger, beholder *beholder.Client) (capabilities.TargetCapability, error) {
	// generate ID based on chain selector
	// id := fmt.Sprintf("write_%v@1.0.0", chain.ID())
	// chainName, err := chainselectors.NameFromChainId(chain.ID().Uint64())
	// if err == nil {
	// 	id = fmt.Sprintf("write_%v@1.0.0", chainName)
	// }

	id := fmt.Sprintf("write_aptos@1.0.0")

	config := chain.Config().Workflow

	client, err := chain.GetClient()
	if err != nil {
		return nil, err
	}

	// Initialize a reader to check whether a value was already transmitted on chain
	cr := chainreader.NewChainReader(logger.Named(lggr, "ChainReader"), client, chainreader.ChainReaderConfig{
		Modules: map[string]*chainreader.ChainReaderModule{
			"forwarder": {
				Functions: map[string]*chainreader.ChainReaderFunction{
					"getTransmissionState": {
						Name: "get_transmission_state",
						Params: []codec.AptosFunctionParam{
							{
								Name:     "Receiver",
								Type:     "address",
								Required: true,
							},
							{
								Name:     "WorkflowExecutionID",
								Type:     "vector<u8>",
								Required: true,
							},
							{
								Name:     "ReportID",
								Type:     "u16",
								Required: true,
							},
						},
					},
				},
			},
		},
	})
	// if err != nil {
	// 	return nil, err
	// }
	err = cr.Bind(ctx, []commontypes.BoundContract{{
		Address: config.ForwarderAddress,
		Name:    "forwarder",
	}})
	if err != nil {
		return nil, err
	}

	cwConfig := chainwriter.ChainWriterConfig{
		Modules: map[string]*chainwriter.ChainWriterModule{
			"forwarder": {
				Functions: map[string]*chainwriter.ChainWriterFunction{
					"report": {
						PublicKey: config.PublicKey,
						Params: []codec.AptosFunctionParam{
							{
								Name:     "Receiver",
								Type:     "address",
								Required: true,
							},
							{
								Name:     "RawReport",
								Type:     "vector<u8>", // report_context | metadata | report
								Required: true,
							},
							{
								Name:     "Signatures",
								Type:     "vector<vector<u8>>",
								Required: true,
							},
						},
					},
				},
			},
		},
	}

	cw := chainwriter.NewChainWriter(logger.Named(lggr, "ChainWriter"), chain.TxManager(), cwConfig)

	// Create the WT capability
	opts := WriteTargetOpts{
		ID:                id,
		Logger:            lggr,
		Beholder:          beholder,
		ContractReader:    cr,
		ChainWriter:       cw,
		ChainWriterConfig: cwConfig,
		ForwarderAddress:  config.ForwarderAddress,
	}
	return NewWriteTarget(opts), nil
}
