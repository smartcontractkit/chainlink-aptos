package write_target

import (
	"context"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"

	chain "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chainwriter"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/utils"
)

func NewAptosWriteTarget(ctx context.Context, chain chain.Chain, lggr logger.Logger) (capabilities.TargetCapability, error) {
	// generate ID based on chain selector
	// id := fmt.Sprintf("write_%v@1.0.0", chain.ID())
	// chainName, err := chainselectors.NameFromChainId(chain.ID().Uint64())
	// if err == nil {
	// 	id = fmt.Sprintf("write_%v@1.0.0", chainName)
	// }

	id := fmt.Sprintf("write_aptos@1.0.0")
	lggr = logger.Named(lggr, id)

	config := chain.Config().Workflow

	client, err := chain.GetClient()
	if err != nil {
		return nil, err
	}

	// Set up a specific Beholder client for the Aptos WT
	beholder := NewAptosWriteTargetMonitor(ctx, lggr)

	// Initialize a reader to check whether a value was already transmitted on chain
	cr := chainreader.NewChainReader(lggr, client, chainreader.ChainReaderConfig{
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

	cw := chainwriter.NewChainWriter(lggr, chain.TxManager(), cwConfig)

	validate := func(config Config) error {
		address := aptos.AccountAddress{}
		if err = address.ParseStringRelaxed(config.Address); err != nil {
			return fmt.Errorf("'%v' is not a valid Aptos address", config.Address)
		}
		return nil
	}

	transmitter, err := getTransmitter(cwConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get transmitter: %+w", err)
	}

	// Create the WT capability
	opts := WriteTargetOpts{
		ID:                 id,
		Logger:             lggr,
		Beholder:           beholder,
		ChainService:       chain,
		ContractReader:     cr,
		ChainWriter:        cw,
		ConfigValidateFn:   validate,
		TransmitterAddress: transmitter,
		ForwarderAddress:   config.ForwarderAddress,
	}
	return NewWriteTarget(opts), nil
}

// getTransmitter sources the transmitter address from the CW config
func getTransmitter(cwConfig chainwriter.ChainWriterConfig) (string, error) {
	// Try to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
	moduleConfig, ok := cwConfig.Modules[contractName]
	if !ok {
		return "", fmt.Errorf("no such contract: %s", contractName)
	}

	functionConfig, ok := moduleConfig.Functions[contractMethodName_report]
	if !ok {
		return "", fmt.Errorf("no such method: %s", contractMethodName_report)
	}

	// Notice: reusing logic from the TXM which sources the transmitter this way
	transmitter := functionConfig.FromAddress
	if transmitter == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		ed25519PublicKey, err := utils.HexToEd25519PublicKey(functionConfig.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to convert public key: %+w", err)
		}
		acc := utils.Ed25519PublicKeyToAccount(ed25519PublicKey)
		transmitter = acc.String()
	}
	return transmitter, nil
}
