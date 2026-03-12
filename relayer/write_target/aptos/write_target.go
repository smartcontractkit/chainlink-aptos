package write_target

import (
	"context"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/shopspring/decimal"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainwriter"
	aptosconfig "github.com/smartcontractkit/chainlink-aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

// contractWriterWrapper wraps the common ContractWriter interface and adds GetTransactionFee method
type contractWriterWrapper struct {
	commontypes.ContractWriter
	txm *txm.AptosTxm
}

func (w *contractWriterWrapper) GetTransactionFee(ctx context.Context, transactionID string) (decimal.Decimal, error) {
	fee, err := w.txm.GetTransactionFee(ctx, transactionID)
	if err != nil {
		return decimal.Decimal{}, err
	}
	return decimal.NewFromBigInt(fee, -8), nil // Convert from octas (1e-8 APT) to APT
}

const version = "1.0.0"

func NewAptosWriteTarget(ctx context.Context, chain chain.Chain, lggr logger.Logger) (capabilities.TargetCapability, error) {
	config := chain.Config()

	// TODO: generate ID based on chain selector (we're currently using Aptos Go SDK to get name for chain ID)
	// chainName, err := chainselectors.NameFromChainId(chain.ID().Uint64())

	// Construct the ID for the WT (e.g., "write_aptos-localnet@1.0.0")
	id, err := write_target.NewWriteTargetID(aptosconfig.ChainFamilyName, config.NetworkName, config.ChainID, *config.WriteTargetCap.Tag, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create write target ID: %+w", err)
	}

	// All subcomponents constructed by this WT will use the same logger
	lggr = logger.Named(lggr, id)

	client, err := chain.GetClient()
	if err != nil {
		return nil, err
	}

	// Set up a specific Beholder client for the Aptos WT
	beholder, err := NewAptosWriteTargetMonitor(ctx, lggr)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos WT monitor client: %+w", err)
	}

	// Initialize a reader to check whether a value was already transmitted on chain
	cr := chainreader.NewChainReader(lggr, client, crconfig.ChainReaderConfig{
		Modules: map[string]*crconfig.ChainReaderModule{
			"forwarder": {
				Functions: map[string]*crconfig.ChainReaderFunction{
					"getTransmissionState": {
						Name: "get_transmission_state",
						Params: []crconfig.AptosFunctionParam{
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
					"getTransmitter": {
						Name: "get_transmitter",
						Params: []crconfig.AptosFunctionParam{
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
	}, chain.DataSource(), chain.LogPoller())

	err = cr.Bind(ctx, []commontypes.BoundContract{{
		Address: config.Workflow.ForwarderAddress,
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
						PublicKey: config.Workflow.PublicKey,
						Params: []crconfig.AptosFunctionParam{
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
		FeeStrategy: chainwriter.DefaultFeeStrategy,
	}

	baseCw := chainwriter.NewChainWriter(lggr, client, chain.TxManager(), cwConfig)

	// Create a wrapper that implements both the common ContractWriter interface and adds GetTransactionFee
	cw := &contractWriterWrapper{
		ContractWriter: baseCw,
		txm:            chain.TxManager(),
	}

	validate := func(config write_target.ReqConfig) error {
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

	// Construct the chain information from the config
	chainInfo := types.ChainInfo{
		ChainFamilyName: aptosconfig.ChainFamilyName, // static for this plugin
		ChainID:         config.ChainID,
		NetworkName:     config.NetworkName,
		NetworkNameFull: config.NetworkNameFull,
	}

	// Create the WT capability
	opts := write_target.WriteTargetOpts{
		ID:     id,
		Logger: lggr,
		Config: *config.WriteTargetCap,
		// TODO: simplify by passing via ChainService.GetChainStatus fn
		ChainInfo:        chainInfo,
		Beholder:         beholder,
		ChainService:     chain,
		ContractReader:   cr,
		ChainWriter:      cw,
		ConfigValidateFn: validate,
		NodeAddress:      transmitter,
		ForwarderAddress: config.Workflow.ForwarderAddress,
	}
	return write_target.NewWriteTarget(opts), nil
}

// getTransmitter sources the transmitter address from the CW config
func getTransmitter(cwConfig chainwriter.ChainWriterConfig) (string, error) {
	// Try to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
	moduleConfig, ok := cwConfig.Modules[write_target.ContractName]
	if !ok {
		return "", fmt.Errorf("no such contract: %s", write_target.ContractName)
	}

	functionConfig, ok := moduleConfig.Functions[write_target.ContractMethodName_report]
	if !ok {
		return "", fmt.Errorf("no such method: %s", write_target.ContractMethodName_report)
	}

	// Notice: reusing logic from the TXM which sources the transmitter this way
	transmitter := functionConfig.FromAddress
	if transmitter == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		ed25519PublicKey, err := utils.HexPublicKeyToEd25519PublicKey(functionConfig.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to convert public key: %+w", err)
		}
		acc := utils.Ed25519PublicKeyToAddress(ed25519PublicKey)
		transmitter = acc.String()
	}
	return transmitter, nil
}
